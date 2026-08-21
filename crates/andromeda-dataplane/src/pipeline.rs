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
//! Everything operates on caller-provided buffers — no per-packet allocation. The
//! outer header is precomputed once into a template and only its variable fields
//! are patched per packet; [`Pipeline::on_tenant_frame_inplace`] is the zero-copy
//! variant that stamps the header into an AF_XDP frame's headroom with no payload copy.

use andromeda_control::Fabric;
use andromeda_core::ethernet::{self, EthFrame, MacAddr};
use andromeda_core::ipv4::Ipv4View;
use andromeda_core::overlay;
use andromeda_core::{arp, five_tuple_of};
use andromeda_nat::{apply as nat_apply, Direction, NatEngine};
use std::net::Ipv4Addr;

/// Static configuration for one switch instance. `vni` is the *default* VPC used by
/// [`Pipeline::on_tenant_frame`]; a multi-VPC switch calls
/// [`Pipeline::encap_for_vni`] with the ingress port's VNI, and decapsulation accepts
/// any VNI present in the fabric.
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

/// One frame inside a shared buffer (an AF_XDP UMEM holds many). The inner frame
/// occupies `buf[offset + OVERLAY_OVERHEAD .. offset + OVERLAY_OVERHEAD + inner_len]`,
/// leaving the first `OVERLAY_OVERHEAD` bytes as headroom for the overlay header.
#[derive(Clone, Copy, Debug)]
pub struct FrameSlot {
    pub offset: usize,
    pub inner_len: usize,
}

/// Precomputed constant outer header (Ethernet + IPv4 + UDP) for the fast encap
/// path — everything that does not change per packet, baked once from the config so
/// forwarding only patches the variable fields.
#[derive(Clone)]
struct OuterTemplate {
    /// Outer Ethernet(14) + IPv4(20) + UDP(8), constants filled, variable fields 0.
    prefix: [u8; 42],
    /// One's-complement sum of the constant IPv4 header words (all but total length,
    /// identification, and the destination address).
    ip_csum_base: u32,
}

impl OuterTemplate {
    fn new(cfg: &PipelineConfig) -> Self {
        let mut p = [0u8; 42];
        ethernet::write_header(
            &mut p[..14],
            cfg.outer_dst_mac,
            cfg.outer_src_mac,
            ethernet::ethertype::IPV4,
        );
        p[14] = 0x45; // version 4, IHL 5
        p[20..22].copy_from_slice(&0x4000u16.to_be_bytes()); // flags: DF
        p[22] = 64; // ttl
        p[23] = andromeda_core::ipv4::proto::UDP;
        p[26..30].copy_from_slice(&cfg.local_node_ip.octets()); // source address
        p[36..38].copy_from_slice(&overlay::ANDROMEDA_UDP_PORT.to_be_bytes()); // udp dst port
        let ip_csum_base = 0x4500
            + 0x4000
            + 0x4011 // ttl(64)<<8 | proto(17)
            + u16::from_be_bytes([p[26], p[27]]) as u32
            + u16::from_be_bytes([p[28], p[29]]) as u32;
        Self {
            prefix: p,
            ip_csum_base,
        }
    }
}

/// The forwarding engine: fabric map + NAT + config.
pub struct Pipeline {
    cfg: PipelineConfig,
    pub fabric: Fabric,
    pub nat: NatEngine,
    tmpl: OuterTemplate,
    ip_id: u16,
    stats: PipelineStats,
}

/// Compute the 16-bit ECMP flow hash from a parsed inner IPv4 header (0 if the L4
/// protocol has no ports, e.g. ICMP). Reads the L4 ports directly — for TCP and UDP
/// alike they are the first two 16-bit words of the L4 header — instead of building
/// a full segment view.
#[inline]
fn flow_hash_of(ip: &Ipv4View) -> u16 {
    use andromeda_core::ipv4::proto;
    let p = ip.protocol();
    if p == proto::TCP || p == proto::UDP {
        let l4 = ip.payload();
        if l4.len() >= 4 {
            let sp = u16::from_be_bytes([l4[0], l4[1]]);
            let dp = u16::from_be_bytes([l4[2], l4[3]]);
            return overlay::flow_hash(ip.src(), ip.dst(), p, sp, dp);
        }
    }
    0
}

impl Pipeline {
    #[must_use]
    pub fn new(cfg: PipelineConfig, fabric: Fabric, nat: NatEngine) -> Self {
        let tmpl = OuterTemplate::new(&cfg);
        Self {
            cfg,
            fabric,
            nat,
            tmpl,
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

    /// Evict NAT bindings (conntrack + SNAT port pool) idle longer than
    /// `idle_timeout` (same time unit as the `now` passed to the frame handlers).
    /// The forwarding loop must call this periodically, or the port pool and
    /// conntrack tables never reclaim. Returns the number of SNAT ports freed.
    pub fn gc(&mut self, now: u64, idle_timeout: u64) -> usize {
        self.nat.gc(now, idle_timeout)
    }

    fn next_ip_id(&mut self) -> u16 {
        self.ip_id = self.ip_id.wrapping_add(1);
        self.ip_id
    }

    /// Tenant → underlay for the switch's configured VNI (single-VPC path).
    pub fn on_tenant_frame(&mut self, inner: &[u8], out: &mut [u8], now: u64) -> Decision {
        self.encap_for_vni(inner, out, now, self.cfg.vni)
    }

    /// Tenant → underlay for a specific `vni` (the ingress tenant): resolve within
    /// that VPC, optionally SNAT, encapsulate. A multi-VPC switch calls this with the
    /// VNI of the port the frame arrived on. Because the fabric is keyed by
    /// (VNI, inner-IP), the **same inner address in two VPCs resolves to two different
    /// endpoints** — that is tenant isolation.
    ///
    /// Hot path: one parse of the inner IPv4 header, one copy of the inner frame into
    /// the output buffer, and the overlay header written in place.
    pub fn encap_for_vni(&mut self, inner: &[u8], out: &mut [u8], now: u64, vni: u32) -> Decision {
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

        // Decide next hop *within this VNI*, or default route to the gateway.
        let (dst_node, new_dst_mac, do_snat) = match self.fabric.resolve(vni, inner_dst) {
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

        // Stamp the precomputed outer header (patch only the variable fields).
        let ip_id = self.next_ip_id();
        self.stamp_outer(out, inner.len(), dst_node, flow, ip_id, vni);
        self.stats.encapped += 1;
        Decision::Forward(end)
    }

    /// Zero-copy encap: the inner frame is **already** at
    /// `frame[OVERLAY_OVERHEAD .. OVERLAY_OVERHEAD + inner_len]` (e.g. an AF_XDP UMEM
    /// frame with 50 bytes of headroom reserved), so encapsulation writes only the
    /// overlay header in front of it — no copy of the payload at all. This is the
    /// shared-UMEM datapath; [`on_tenant_frame`] is the two-buffer (RX→TX) variant.
    pub fn on_tenant_frame_inplace(
        &mut self,
        frame: &mut [u8],
        inner_len: usize,
        now: u64,
    ) -> Decision {
        let ioff = overlay::OVERLAY_OVERHEAD;
        let end = ioff + inner_len;
        if frame.len() < end {
            return self.drop("frame-too-small");
        }

        // Parse the inner header in place.
        let (inner_dst, flow0) = {
            let eth = match EthFrame::parse(&frame[ioff..end]) {
                Ok(e) => e,
                Err(_) => return self.drop("bad-inner-eth"),
            };
            if eth.ethertype() != ethernet::ethertype::IPV4 {
                return self.drop("non-ipv4-inner");
            }
            match Ipv4View::parse(eth.payload()) {
                Ok(ip) => (ip.dst(), flow_hash_of(&ip)),
                Err(_) => return self.drop("bad-inner-ip"),
            }
        };
        let mut flow = flow0;

        let (dst_node, new_dst_mac, do_snat) = match self.fabric.resolve(self.cfg.vni, inner_dst) {
            Some(nh) => (nh.node_ip, Some(nh.inner_mac), false),
            None => match self.cfg.gateway_node_ip {
                Some(gw) => (gw, None, self.cfg.nat_ip.is_some()),
                None => return self.drop("no-route"),
            },
        };

        if let Some(m) = new_dst_mac {
            frame[ioff..ioff + 6].copy_from_slice(&m.0);
        }
        if do_snat {
            let ip_off = ioff + ethernet::ETH_HDR_LEN;
            if let Some(t) = five_tuple_of(&frame[ip_off..end]) {
                let rw = self.nat.process(t, Direction::Outbound, now);
                if !rw.is_noop() {
                    let _ = nat_apply(&mut frame[ip_off..end], &rw);
                    self.stats.natted += 1;
                }
            }
            if let Ok(ip2) = Ipv4View::parse(&frame[ip_off..end]) {
                flow = flow_hash_of(&ip2);
            }
        }

        let ip_id = self.next_ip_id();
        self.stamp_outer(frame, inner_len, dst_node, flow, ip_id, self.cfg.vni);
        self.stats.encapped += 1;
        Decision::Forward(end)
    }

    /// Batched zero-copy encap over many frames packed in one buffer. Equivalent to
    /// calling [`Pipeline::on_tenant_frame_inplace`] per slot, but hoists the IPv4-id
    /// and stat counters into locals so the inner loop carries no per-packet memory
    /// dependency, and gives the compiler a tight, branch-predictable loop to pipeline
    /// across independent frames. Returns the number of frames encapsulated.
    pub fn encap_batch_inplace(&mut self, buf: &mut [u8], slots: &[FrameSlot], now: u64) -> usize {
        let ioff = overlay::OVERLAY_OVERHEAD;
        let mut ip_id = self.ip_id;
        let mut forwarded = 0u64;
        let mut natted = 0u64;

        for s in slots {
            let end = s.offset + ioff + s.inner_len;
            if buf.len() < end {
                continue;
            }
            let frame = &mut buf[s.offset..end];

            let (inner_dst, mut flow) = {
                let eth = match EthFrame::parse(&frame[ioff..]) {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                if eth.ethertype() != ethernet::ethertype::IPV4 {
                    continue;
                }
                match Ipv4View::parse(eth.payload()) {
                    Ok(ip) => (ip.dst(), flow_hash_of(&ip)),
                    Err(_) => continue,
                }
            };

            let (dst_node, new_dst_mac, do_snat) =
                match self.fabric.resolve(self.cfg.vni, inner_dst) {
                    Some(nh) => (nh.node_ip, Some(nh.inner_mac), false),
                    None => match self.cfg.gateway_node_ip {
                        Some(gw) => (gw, None, self.cfg.nat_ip.is_some()),
                        None => continue,
                    },
                };

            if let Some(m) = new_dst_mac {
                frame[ioff..ioff + 6].copy_from_slice(&m.0);
            }
            if do_snat {
                let ip_off = ioff + ethernet::ETH_HDR_LEN;
                if let Some(t) = five_tuple_of(&frame[ip_off..]) {
                    let rw = self.nat.process(t, Direction::Outbound, now);
                    if !rw.is_noop() {
                        let _ = nat_apply(&mut frame[ip_off..], &rw);
                        natted += 1;
                    }
                }
                if let Ok(ip2) = Ipv4View::parse(&frame[ip_off..]) {
                    flow = flow_hash_of(&ip2);
                }
            }

            ip_id = ip_id.wrapping_add(1);
            self.stamp_outer(frame, s.inner_len, dst_node, flow, ip_id, self.cfg.vni);
            forwarded += 1;
        }

        self.ip_id = ip_id;
        self.stats.encapped += forwarded;
        self.stats.natted += natted;
        forwarded as usize
    }

    /// Fast encap: copy the precomputed 42-byte Ethernet+IPv4+UDP header prefix,
    /// patch the per-packet fields (destination, lengths, id, flow), and fold a
    /// five-term IPv4 checksum from the template's constant base. The Andromeda
    /// header follows at `[42..50]`; the inner frame is already at `[50..]`.
    #[inline]
    fn stamp_outer(
        &self,
        out: &mut [u8],
        inner_len: usize,
        dst_ip: Ipv4Addr,
        flow: u16,
        ip_id: u16,
        vni: u32,
    ) {
        use andromeda_core::ipv4::IPV4_MIN_HDR_LEN;

        out[..42].copy_from_slice(&self.tmpl.prefix);

        let total_len = (IPV4_MIN_HDR_LEN + 8 + overlay::ANDROMEDA_HDR_LEN + inner_len) as u16;
        out[16..18].copy_from_slice(&total_len.to_be_bytes());
        out[18..20].copy_from_slice(&ip_id.to_be_bytes());
        let d = dst_ip.octets();
        out[30..34].copy_from_slice(&d);

        // IPv4 header checksum = ~(constant base + total_length + id + dst hi + dst lo).
        let sum = self.tmpl.ip_csum_base
            + total_len as u32
            + ip_id as u32
            + u16::from_be_bytes([d[0], d[1]]) as u32
            + u16::from_be_bytes([d[2], d[3]]) as u32;
        let csum = !andromeda_core::checksum::fold(sum);
        out[24..26].copy_from_slice(&csum.to_be_bytes());

        // Outer UDP: source port carries flow entropy; length covers udp+andromeda+inner.
        out[34..36].copy_from_slice(&(flow | 0xc000).to_be_bytes());
        let udp_len = (8 + overlay::ANDROMEDA_HDR_LEN + inner_len) as u16;
        out[38..40].copy_from_slice(&udp_len.to_be_bytes());

        // Andromeda header (tagged with this frame's VNI).
        overlay::AndromedaHdr::new(vni, flow).encode(&mut out[42..50]);

        // Strict mode (rare): fill the outer UDP checksum over the whole payload.
        if self.cfg.outer_udp_checksum {
            let end = overlay::OVERLAY_OVERHEAD + inner_len;
            let c = andromeda_core::udp::compute_checksum(
                self.cfg.local_node_ip,
                dst_ip,
                &out[34..end],
            );
            out[40..42].copy_from_slice(&c.to_be_bytes());
        }
    }

    /// Underlay → tenant: decapsulate, optionally reverse-NAT, deliver inner frame.
    pub fn on_underlay_frame(&mut self, frame: &[u8], out: &mut [u8], now: u64) -> Decision {
        let (inner_len, is_ipv4) = match overlay::decap(frame) {
            Ok(Some(d)) => {
                // Accept any VNI this switch serves (its configured one, or any VPC
                // present in the fabric) — a multi-VPC switch decaps them all.
                if d.header.vni != self.cfg.vni && self.fabric.vpc(d.header.vni).is_none() {
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
    fn multi_vpc_isolates_same_inner_ip() {
        // Two tenants that BOTH use 10.0.0.5, on one switch, kept apart by VNI.
        let mut fabric = Fabric::new("192.168.1.1".parse().unwrap());
        for (vni, mac_n, node) in [(100u32, 0x11u8, "192.168.1.2"), (200, 0x22, "192.168.1.3")] {
            fabric.add_vpc(Vpc {
                vni,
                name: format!("vpc-{vni}"),
                cidr: ("10.0.0.0".parse().unwrap(), 24),
            });
            fabric.add_endpoint(Endpoint {
                vni,
                inner_ip: "10.0.0.5".parse().unwrap(),
                inner_mac: mac(mac_n),
                node_ip: node.parse().unwrap(),
                local: false,
            });
        }
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
        let mut p = Pipeline::new(
            cfg,
            fabric,
            NatEngine::new("203.0.113.7".parse().unwrap(), 20000, 20100),
        );

        // Same inner packet to 10.0.0.5, encapsulated for two different tenants.
        let frame = tenant_udp_frame("10.0.0.9", "10.0.0.5", 1111, 2222, b"iso");
        let mut w1 = vec![0u8; 2048];
        let n1 = match p.encap_for_vni(&frame, &mut w1, 1, 100) {
            Decision::Forward(n) => n,
            o => panic!("vni100: {o:?}"),
        };
        let mut w2 = vec![0u8; 2048];
        let n2 = match p.encap_for_vni(&frame, &mut w2, 1, 200) {
            Decision::Forward(n) => n,
            o => panic!("vni200: {o:?}"),
        };

        let d1 = overlay::decap(&w1[..n1]).unwrap().unwrap();
        let d2 = overlay::decap(&w2[..n2]).unwrap().unwrap();

        // Different VNI on the wire, different physical node, different inner MAC —
        // the same tenant IP goes to two isolated places.
        assert_eq!(d1.header.vni, 100);
        assert_eq!(d2.header.vni, 200);
        assert_eq!(d1.outer_dst_ip, "192.168.1.2".parse::<Ipv4Addr>().unwrap());
        assert_eq!(d2.outer_dst_ip, "192.168.1.3".parse::<Ipv4Addr>().unwrap());
        assert_eq!(EthFrame::parse(d1.inner).unwrap().dst(), mac(0x11));
        assert_eq!(EthFrame::parse(d2.inner).unwrap().dst(), mac(0x22));

        // The switch decaps both served VNIs, but drops an unknown one.
        let mut deliver = vec![0u8; 2048];
        assert!(matches!(
            p.on_underlay_frame(&w1[..n1], &mut deliver, 1),
            Decision::Forward(_)
        ));
        assert!(matches!(
            p.on_underlay_frame(&w2[..n2], &mut deliver, 1),
            Decision::Forward(_)
        ));
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
    fn outer_ipv4_checksum_valid_via_template() {
        // The templated fast path builds the outer IPv4 checksum incrementally;
        // make sure it actually verifies (nothing else in the suite checks it).
        let mut node1 = two_node_pipeline();
        let frame = tenant_udp_frame("10.0.0.10", "10.0.0.20", 1111, 2222, b"x");
        let mut wire = vec![0u8; 2048];
        let n = match node1.on_tenant_frame(&frame, &mut wire, 1) {
            Decision::Forward(n) => n,
            other => panic!("expected Forward, got {other:?}"),
        };
        let outer_ip = Ipv4View::parse(&wire[ethernet::ETH_HDR_LEN..n]).unwrap();
        assert!(
            outer_ip.checksum_valid(),
            "templated outer IPv4 checksum must verify"
        );
        assert_eq!(outer_ip.protocol(), andromeda_core::ipv4::proto::UDP);

        // The zero-copy path must produce a byte-identical packet.
        let mut zc = vec![0u8; 2048];
        let ioff = overlay::OVERLAY_OVERHEAD;
        zc[ioff..ioff + frame.len()].copy_from_slice(&frame);
        let mut node1b = two_node_pipeline();
        let m = match node1b.on_tenant_frame_inplace(&mut zc, frame.len(), 1) {
            Decision::Forward(m) => m,
            other => panic!("expected Forward, got {other:?}"),
        };
        assert_eq!(
            &wire[..n],
            &zc[..m],
            "copy and zero-copy paths must agree byte for byte"
        );
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
