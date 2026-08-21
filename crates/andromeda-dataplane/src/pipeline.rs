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
use andromeda_core::ethernet::{self, EthFrame, MacAddr};
use andromeda_core::ipv4::Ipv4View;
use andromeda_core::overlay::{self, EncapParams};
use andromeda_core::{arp, five_tuple_of};
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
    /// The virtual MAC this switch answers tenant ARP requests with (distributed
    /// overlay gateway). Tenants send to this MAC; the switch rewrites the inner
    /// destination MAC to the real endpoint during encapsulation.
    pub virtual_gateway_mac: MacAddr,
    /// Compute the outer UDP checksum on encapsulation. Default `false` (transmit 0,
    /// legal for IPv4 tunnels per RFC 6935 and standard for VXLAN) keeps the hot path
    /// off a full pass over the payload. Set `true` for strict outer integrity.
    pub outer_udp_checksum: bool,
}

/// The outcome of feeding one frame to the pipeline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Transmit the first `usize` bytes of the output buffer on the *egress* port.
    Forward(usize),
    /// Transmit the first `usize` bytes of the output buffer back out the *ingress*
    /// port (used for ARP replies to the tenant).
    Reply(usize),
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
    pub arp_replied: u64,
    pub dropped: u64,
    pub passed: u64,
}

/// The forwarding engine: fabric map + NAT + config.
pub struct Pipeline {
    cfg: PipelineConfig,
    pub fabric: Fabric,
    pub nat: NatEngine,
    ip_id: u16,
    stats: PipelineStats,
}

/// Compute the 16-bit ECMP flow hash from a parsed inner IPv4 header (0 if the L4
/// protocol has no ports, e.g. ICMP).
fn flow_hash_of(ip: &Ipv4View) -> u16 {
    use andromeda_core::ipv4::proto;
    use andromeda_core::tcp::TcpView;
    use andromeda_core::udp::UdpView;
    match ip.protocol() {
        p if p == proto::TCP => TcpView::parse(ip.payload())
            .map(|t| overlay::flow_hash(ip.src(), ip.dst(), p, t.src_port(), t.dst_port()))
            .unwrap_or(0),
        p if p == proto::UDP => UdpView::parse(ip.payload())
            .map(|u| overlay::flow_hash(ip.src(), ip.dst(), p, u.src_port(), u.dst_port()))
            .unwrap_or(0),
        _ => 0,
    }
}

impl Pipeline {
    #[must_use]
    pub fn new(cfg: PipelineConfig, fabric: Fabric, nat: NatEngine) -> Self {
        Self {
            cfg,
            fabric,
            nat,
            ip_id: 0,
            stats: PipelineStats::default(),
        }
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
    ///
    /// Hot path: one parse of the inner IPv4 header, one copy of the inner frame
    /// into the output buffer, and the overlay header written in place — no scratch
    /// buffer and (by default) no outer UDP checksum pass over the payload.
    pub fn on_tenant_frame(&mut self, inner: &[u8], out: &mut [u8], now: u64) -> Decision {
        let eth = match EthFrame::parse(inner) {
            Ok(e) => e,
            Err(_) => return self.drop("bad-inner-eth"),
        };
        let ethertype = eth.ethertype();

        // Proxy-ARP: answer tenant "who has X?" with the virtual gateway MAC so the
        // tenant can send without knowing the far endpoint's real L2 address.
        if ethertype == ethernet::ethertype::ARP {
            match arp::ArpView::parse(eth.payload()) {
                Ok(a) if a.is_request() && a.target_ip() != a.sender_ip() => {
                    match arp::write_reply(out, eth.payload(), self.cfg.virtual_gateway_mac) {
                        Ok(n) => {
                            self.stats.arp_replied += 1;
                            return Decision::Reply(n);
                        }
                        Err(_) => return self.drop("arp-build"),
                    }
                }
                _ => return self.drop("arp-ignored"),
            }
        }
        if ethertype != ethernet::ethertype::IPV4 {
            return self.drop("non-ipv4-inner");
        }

        // Single parse of the inner IPv4 header → destination + flow entropy.
        let ip = match Ipv4View::parse(eth.payload()) {
            Ok(ip) => ip,
            Err(_) => return self.drop("bad-inner-ip"),
        };
        let inner_dst = ip.dst();
        let mut flow = flow_hash_of(&ip);

        // Decide next hop: in-VPC endpoint, or default route to the gateway.
        let (dst_node, new_dst_mac, do_snat) = match self.fabric.resolve(self.cfg.vni, inner_dst) {
            Some(nh) => (nh.node_ip, Some(nh.inner_mac), false),
            None => match self.cfg.gateway_node_ip {
                Some(gw) => (gw, None, self.cfg.nat_ip.is_some()),
                None => return self.drop("no-route"),
            },
        };

        // Place the inner frame directly in the output buffer (the single copy),
        // then build the overlay header in front of it.
        let ioff = overlay::OVERLAY_OVERHEAD;
        let end = ioff + inner.len();
        if out.len() < end {
            return self.drop("encap-out-too-small");
        }
        out[ioff..end].copy_from_slice(inner);

        // Overlay L2 adjacency: rewrite the inner destination MAC in place.
        if let Some(m) = new_dst_mac {
            out[ioff..ioff + 6].copy_from_slice(&m.0);
        }

        // SNAT on egress from the VPC; recompute flow entropy from the new tuple.
        if do_snat {
            let ip_off = ioff + ethernet::ETH_HDR_LEN;
            if let Some(t) = five_tuple_of(&out[ip_off..end]) {
                let rw = self.nat.process(t, Direction::Outbound, now);
                if !rw.is_noop() {
                    let _ = nat_apply(&mut out[ip_off..end], &rw);
                    self.stats.natted += 1;
                }
            }
            if let Ok(ip2) = Ipv4View::parse(&out[ip_off..end]) {
                flow = flow_hash_of(&ip2);
            }
        }

        let params = EncapParams {
            outer_src_mac: self.cfg.outer_src_mac,
            outer_dst_mac: self.cfg.outer_dst_mac,
            outer_src_ip: self.cfg.local_node_ip,
            outer_dst_ip: dst_node,
            vni: self.cfg.vni,
            flow_hash: flow,
            ip_id: self.next_ip_id(),
            outer_udp_checksum: self.cfg.outer_udp_checksum,
        };
        match overlay::encap_in_place(out, inner.len(), &params) {
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
        ipv4::write_header(
            &mut ippkt[..20],
            src,
            dst,
            proto::UDP,
            64,
            1,
            true,
            udp_dg.len() as u16,
        );
        ippkt[20..].copy_from_slice(&udp_dg);

        let mut frame = vec![0u8; ethernet::ETH_HDR_LEN + ippkt.len()];
        ethernet::write_header(
            &mut frame[..14],
            mac(0xbb),
            mac(0xaa),
            ethernet::ethertype::IPV4,
        );
        frame[14..].copy_from_slice(&ippkt);
        frame
    }

    fn two_node_pipeline() -> Pipeline {
        let mut fabric = Fabric::new("192.168.1.1".parse().unwrap());
        fabric.add_vpc(Vpc {
            vni: 100,
            name: "t".into(),
            cidr: ("10.0.0.0".parse().unwrap(), 24),
        });
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
            virtual_gateway_mac: mac(0xff),
            outer_udp_checksum: false,
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
        assert!(matches!(
            node1.on_tenant_frame(&frame, &mut wire, 1),
            Decision::Drop("no-route")
        ));
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
    fn proxy_arp_replies_to_tenant() {
        let mut p = two_node_pipeline();
        // Tenant 10.0.0.10 asks "who has 10.0.0.20?"
        let mut req = vec![0u8; arp::ARP_FRAME_LEN];
        ethernet::write_header(
            &mut req[..14],
            MacAddr::BROADCAST,
            mac(0x0a),
            ethernet::ethertype::ARP,
        );
        let pl = &mut req[14..];
        pl[0..2].copy_from_slice(&1u16.to_be_bytes());
        pl[2..4].copy_from_slice(&ethernet::ethertype::IPV4.to_be_bytes());
        pl[4] = 6;
        pl[5] = 4;
        pl[6..8].copy_from_slice(&arp::oper::REQUEST.to_be_bytes());
        pl[8..14].copy_from_slice(&mac(0x0a).0);
        pl[14..18].copy_from_slice(&Ipv4Addr::new(10, 0, 0, 10).octets());
        pl[24..28].copy_from_slice(&Ipv4Addr::new(10, 0, 0, 20).octets());

        let mut out = vec![0u8; 128];
        match p.on_tenant_frame(&req, &mut out, 1) {
            Decision::Reply(n) => {
                let eth = EthFrame::parse(&out[..n]).unwrap();
                assert_eq!(eth.ethertype(), ethernet::ethertype::ARP);
                assert_eq!(eth.dst(), mac(0x0a)); // replied to the requester
                let a = arp::ArpView::parse(eth.payload()).unwrap();
                assert_eq!(a.oper(), arp::oper::REPLY);
                assert_eq!(a.sender_mac(), mac(0xff)); // virtual gateway MAC
            }
            other => panic!("expected Reply, got {other:?}"),
        }
        assert_eq!(p.stats().arp_replied, 1);
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
