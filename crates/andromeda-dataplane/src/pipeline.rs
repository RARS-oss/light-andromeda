//! The per-packet forwarding pipeline, independent of the AF_XDP socket layer.
//!
//! Two entry points mirror the two directions a virtual switch sees:
//!
//! * [`Pipeline::on_tenant_frame`] — a raw inner Ethernet frame arrived from a
//!   tenant port. Resolve its destination in the fabric, optionally SNAT it (if it
//!   is leaving the VPC toward a gateway), Andromeda-encapsulate it, and hand back
//!   the bytes to transmit on the underlay port.
//! * [`Pipeline::on_underlay_frame`] — an encapsulated frame arrived from the
//!   underlay. Decapsulate it, optionally reverse-NAT the inner packet, and hand
//!   back the inner frame to deliver to the tenant port.
//!
//! Everything operates on caller-provided buffers; the only owned allocation is a
//! reused scratch buffer, so the steady state is allocation-free.

use andromeda_control::Fabric;
use andromeda_core::ethernet::{self, EthFrame, EthFrameMut, MacAddr};
use andromeda_core::ipv4::Ipv4View;
use andromeda_core::overlay::{self, EncapParams};
use andromeda_core::five_tuple_of;
use andromeda_nat::{apply as nat_apply, Direction, NatEngine};
use std::net::Ipv4Addr;

/// Static configuration for one switch instance (single-VPC MVP; multi-VPC is a
/// map keyed by ingress port in a later iteration).
#[derive(Clone, Debug)]
pub struct PipelineConfig {
    /// This switch's underlay address (outer source IP for encapsulated packets).
    pub local_node_ip: Ipv4Addr,
    /// Outer source MAC (this switch's underlay NIC).
    pub outer_src_mac: MacAddr,
    /// Outer destination MAC (the underlay next hop — a gateway/peer L2 address).
    pub outer_dst_mac: MacAddr,
    /// The VNI this switch serves.
    pub vni: u32,
    /// If set, flows leaving the VPC are SNAT'd to this address.
    pub nat_ip: Option<Ipv4Addr>,
    /// If set, destinations with no in-VPC endpoint are sent here (default route).
    pub gateway_node_ip: Option<Ipv4Addr>,
}

/// The outcome of feeding one frame to the pipeline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Transmit the first `usize` bytes of the output buffer.
    Forward(usize),
    /// Drop the frame; the reason is a static label for stats/logging.
    Drop(&'static str),
    /// Not ours — let the caller decide (e.g. hand back to the kernel).
    Pass,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PipelineStats {
    pub encapped: u64,
    pub decapped: u64,
    pub natted: u64,
    pub dropped: u64,
    pub passed: u64,
}

/// The forwarding engine: fabric map + NAT + config + reusable scratch.
pub struct Pipeline {
    cfg: PipelineConfig,
    pub fabric: Fabric,
    pub nat: NatEngine,
    scratch: Vec<u8>,
    ip_id: u16,
    stats: PipelineStats,
}

impl Pipeline {
    #[must_use]
    pub fn new(cfg: PipelineConfig, fabric: Fabric, nat: NatEngine) -> Self {
        Self { cfg, fabric, nat, scratch: Vec::with_capacity(2048), ip_id: 0, stats: PipelineStats::default() }
    }

    #[must_use]
    pub fn stats(&self) -> PipelineStats {
        self.stats
    }

    #[must_use]
    pub fn config(&self) -> &PipelineConfig {
        &self.cfg
    }

    fn next_ip_id(&mut self) -> u16 {
        self.ip_id = self.ip_id.wrapping_add(1);
        self.ip_id
    }

    /// Tenant → underlay: resolve, optionally SNAT, encapsulate.
    pub fn on_tenant_frame(&mut self, inner: &[u8], out: &mut [u8], now: u64) -> Decision {
        let eth = match EthFrame::parse(inner) {
            Ok(e) => e,
            Err(_) => return self.drop("bad-inner-eth"),
        };
        if eth.ethertype() != ethernet::ethertype::IPV4 {
            // ARP/IPv6 flooding is out of scope for the MVP; drop.
            return self.drop("non-ipv4-inner");
        }
        let inner_dst = match Ipv4View::parse(eth.payload()) {
            Ok(ip) => ip.dst(),
            Err(_) => return self.drop("bad-inner-ip"),
        };

        // Decide next hop: in-VPC endpoint, or default route to the gateway.
        let (dst_node, new_dst_mac, do_snat) = match self.fabric.resolve(self.cfg.vni, inner_dst) {
            Some(nh) => (nh.node_ip, Some(nh.inner_mac), false),
            None => match self.cfg.gateway_node_ip {
                Some(gw) => (gw, None, self.cfg.nat_ip.is_some()),
                None => return self.drop("no-route"),
            },
        };

        // Copy into scratch so we can mutate (RX frame is borrowed immutably).
        self.scratch.clear();
        self.scratch.extend_from_slice(inner);

        // Overlay L2 adjacency: point the inner frame at the resolved endpoint MAC.
        if let Some(m) = new_dst_mac {
            if let Ok(mut e) = EthFrameMut::parse(&mut self.scratch) {
                e.set_dst(m);
            }
        }

        // SNAT on egress from the VPC.
        if do_snat {
            if let Some(t) = five_tuple_of(&self.scratch[ethernet::ETH_HDR_LEN..]) {
                let rw = self.nat.process(t, Direction::Outbound, now);
                if !rw.is_noop() {
                    let _ = nat_apply(&mut self.scratch[ethernet::ETH_HDR_LEN..], &rw);
                    self.stats.natted += 1;
                }
            }
        }

        // Per-flow entropy for underlay ECMP / node spreading.
        let flow = five_tuple_of(&self.scratch[ethernet::ETH_HDR_LEN..])
            .map(|t| overlay::flow_hash(t.src_ip, t.dst_ip, t.protocol, t.src_port, t.dst_port))
            .unwrap_or(0);

        let params = EncapParams {
            outer_src_mac: self.cfg.outer_src_mac,
            outer_dst_mac: self.cfg.outer_dst_mac,
            outer_src_ip: self.cfg.local_node_ip,
            outer_dst_ip: dst_node,
            vni: self.cfg.vni,
            flow_hash: flow,
            ip_id: self.next_ip_id(),
        };

        // scratch is borrowed immutably here while out is written — disjoint, OK.
        let inner_bytes = std::mem::take(&mut self.scratch);
        let res = overlay::encap(out, &inner_bytes, &params);
        self.scratch = inner_bytes; // give the buffer back for reuse
        match res {
            Ok(n) => {
                self.stats.encapped += 1;
                Decision::Forward(n)
            }
            Err(_) => self.drop("encap-out-too-small"),
        }
    }

    /// Underlay → tenant: decapsulate, optionally reverse-NAT, deliver inner frame.
    pub fn on_underlay_frame(&mut self, frame: &[u8], out: &mut [u8], now: u64) -> Decision {
        let (inner_len, is_ipv4) = match overlay::decap(frame) {
            Ok(Some(d)) => {
                if d.header.vni != self.cfg.vni {
                    return self.drop("wrong-vni");
                }
                if out.len() < d.inner.len() {
                    return self.drop("decap-out-too-small");
                }
                out[..d.inner.len()].copy_from_slice(d.inner);
                let is_ipv4 = EthFrame::parse(d.inner)
                    .map(|e| e.ethertype() == ethernet::ethertype::IPV4)
                    .unwrap_or(false);
                (d.inner.len(), is_ipv4)
            }
            Ok(None) => {
                self.stats.passed += 1;
                return Decision::Pass;
            }
            Err(_) => return self.drop("bad-encap"),
        };

        // Reverse NAT on the delivered inner packet (SNAT-reply / DNAT).
        if self.cfg.nat_ip.is_some() && is_ipv4 {
            let ip_off = ethernet::ETH_HDR_LEN;
            if let Some(t) = five_tuple_of(&out[ip_off..inner_len]) {
                let rw = self.nat.process(t, Direction::Inbound, now);
                if !rw.is_noop() {
                    let _ = nat_apply(&mut out[ip_off..inner_len], &rw);
                    self.stats.natted += 1;
                }
            }
        }

        self.stats.decapped += 1;
        Decision::Forward(inner_len)
    }

    fn drop(&mut self, why: &'static str) -> Decision {
        self.stats.dropped += 1;
        Decision::Drop(why)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use andromeda_control::{Endpoint, Vpc};
    use andromeda_core::ipv4::{self, proto};
    use andromeda_core::udp;

    fn mac(n: u8) -> MacAddr {
        MacAddr([0x02, 0, 0, 0, 0, n])
    }

    /// Build an inner Ethernet frame carrying a UDP/IPv4 packet.
    fn tenant_udp_frame(src: &str, dst: &str, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let src: Ipv4Addr = src.parse().unwrap();
        let dst: Ipv4Addr = dst.parse().unwrap();
        let mut udp_dg = vec![0u8; udp::UDP_HDR_LEN + payload.len()];
        udp::write_header(&mut udp_dg, sport, dport, payload.len() as u16);
        udp_dg[udp::UDP_HDR_LEN..].copy_from_slice(payload);
        let c = udp::compute_checksum(src, dst, &udp_dg);
        udp_dg[6..8].copy_from_slice(&c.to_be_bytes());

        let mut ippkt = vec![0u8; ipv4::IPV4_MIN_HDR_LEN + udp_dg.len()];
        ipv4::write_header(&mut ippkt[..20], src, dst, proto::UDP, 64, 1, true, udp_dg.len() as u16);
        ippkt[20..].copy_from_slice(&udp_dg);

        let mut frame = vec![0u8; ethernet::ETH_HDR_LEN + ippkt.len()];
        ethernet::write_header(&mut frame[..14], mac(0xbb), mac(0xaa), ethernet::ethertype::IPV4);
        frame[14..].copy_from_slice(&ippkt);
        frame
    }

    fn two_node_pipeline() -> Pipeline {
        let mut fabric = Fabric::new("192.168.1.1".parse().unwrap());
        fabric.add_vpc(Vpc { vni: 100, name: "t".into(), cidr: ("10.0.0.0".parse().unwrap(), 24) });
        fabric.add_endpoint(Endpoint {
            vni: 100,
            inner_ip: "10.0.0.20".parse().unwrap(),
            inner_mac: mac(0x20),
            node_ip: "192.168.1.2".parse().unwrap(),
            local: false,
        });
        let cfg = PipelineConfig {
            local_node_ip: "192.168.1.1".parse().unwrap(),
            outer_src_mac: mac(0x01),
            outer_dst_mac: mac(0x02),
            vni: 100,
            nat_ip: None,
            gateway_node_ip: None,
        };
        let nat = NatEngine::new("203.0.113.7".parse().unwrap(), 20000, 20100);
        Pipeline::new(cfg, fabric, nat)
    }

    #[test]
    fn east_west_encap_then_peer_decap_roundtrips() {
        let mut node1 = two_node_pipeline();
        let frame = tenant_udp_frame("10.0.0.10", "10.0.0.20", 1111, 2222, b"east-west");

        let mut wire = vec![0u8; 2048];
        let n = match node1.on_tenant_frame(&frame, &mut wire, 1) {
            Decision::Forward(n) => n,
            other => panic!("expected Forward, got {other:?}"),
        };
        // The encapsulated packet is Andromeda traffic on the wire.
        assert!(overlay::decap(&wire[..n]).unwrap().is_some());

        // Peer node (same VNI) decapsulates and recovers the inner frame with the
        // inner destination MAC rewritten to the resolved endpoint.
        let mut node2 = two_node_pipeline();
        let mut delivered = vec![0u8; 2048];
        let m = match node2.on_underlay_frame(&wire[..n], &mut delivered, 2) {
            Decision::Forward(m) => m,
            other => panic!("expected Forward, got {other:?}"),
        };
        let eth = EthFrame::parse(&delivered[..m]).unwrap();
        assert_eq!(eth.dst(), mac(0x20), "inner dst MAC rewritten to endpoint");
        let ip = Ipv4View::parse(eth.payload()).unwrap();
        assert_eq!(ip.dst(), "10.0.0.20".parse::<Ipv4Addr>().unwrap());
        assert!(ip.checksum_valid());
        assert_eq!(node1.stats().encapped, 1);
        assert_eq!(node2.stats().decapped, 1);
    }

    #[test]
    fn unknown_destination_without_gateway_drops() {
        let mut node1 = two_node_pipeline();
        let frame = tenant_udp_frame("10.0.0.10", "10.0.0.99", 1, 2, b"x");
        let mut wire = vec![0u8; 2048];
        assert!(matches!(node1.on_tenant_frame(&frame, &mut wire, 1), Decision::Drop("no-route")));
    }

    #[test]
    fn egress_to_gateway_applies_snat() {
        // Configure a gateway + NAT; destination outside the VPC → SNAT + encap to gw.
        let mut p = two_node_pipeline();
        p.cfg.gateway_node_ip = Some("192.168.1.254".parse().unwrap());
        p.cfg.nat_ip = Some("203.0.113.7".parse().unwrap());

        let frame = tenant_udp_frame("10.0.0.10", "8.8.8.8", 40000, 53, b"dns");
        let mut wire = vec![0u8; 2048];
        let n = match p.on_tenant_frame(&frame, &mut wire, 1) {
            Decision::Forward(n) => n,
            other => panic!("got {other:?}"),
        };
        assert_eq!(p.stats().natted, 1);

        // Decap and confirm the inner source was rewritten to the NAT address.
        let d = overlay::decap(&wire[..n]).unwrap().unwrap();
        let ip = Ipv4View::parse(&d.inner[ethernet::ETH_HDR_LEN..]).unwrap();
        assert_eq!(ip.src(), "203.0.113.7".parse::<Ipv4Addr>().unwrap());
        assert!(ip.checksum_valid());
    }

    #[test]
    fn foreign_frame_passes() {
        let mut p = two_node_pipeline();
        // A plain (non-encapsulated) IPv4/UDP frame to some random port → Pass.
        let frame = tenant_udp_frame("1.2.3.4", "5.6.7.8", 1, 2, b"z");
        let mut out = vec![0u8; 2048];
        assert_eq!(p.on_underlay_frame(&frame, &mut out, 1), Decision::Pass);
    }
}
