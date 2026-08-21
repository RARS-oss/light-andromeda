//! # andromeda-nat
//!
//! Stateful network address translation for the Andromeda virtual switch:
//!
//! * **SNAT / PAT (masquerade):** tenant flows leaving the VPC toward the
//!   underlay have their source rewritten to a shared NAT address and a
//!   dynamically-allocated port. A conntrack entry lets the reply be reversed.
//! * **DNAT (port forwarding):** inbound flows hitting `nat_ip:ext_port` are
//!   redirected to an internal endpoint, and the server's reply is un-DNAT'd.
//!
//! The engine is *pure*: [`NatEngine::process`] takes a 5-tuple + direction +
//! logical timestamp and returns a [`Rewrite`] describing what to change. The
//! byte-level mutation lives in [`apply`], which patches L3/L4 checksums
//! incrementally via `andromeda-core`. This split keeps the policy layer trivially
//! unit-testable without synthesizing real packets.

use andromeda_core::ipv4::{proto, Ipv4View, Ipv4ViewMut};
use andromeda_core::tcp::TcpViewMut;
use andromeda_core::udp::UdpViewMut;
use andromeda_core::{FiveTuple, ParseError};
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

/// Which way a packet is crossing the NAT boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// From the private/tenant side toward the underlay (candidate for SNAT).
    Outbound,
    /// From the underlay toward the private side (candidate for DNAT / SNAT-reply).
    Inbound,
}

/// A description of the header edits to apply to a packet. `None` fields are left as-is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rewrite {
    pub new_src_ip: Option<Ipv4Addr>,
    pub new_dst_ip: Option<Ipv4Addr>,
    pub new_src_port: Option<u16>,
    pub new_dst_port: Option<u16>,
}

impl Rewrite {
    #[must_use]
    pub fn is_noop(&self) -> bool {
        self.new_src_ip.is_none()
            && self.new_dst_ip.is_none()
            && self.new_src_port.is_none()
            && self.new_dst_port.is_none()
    }
}

/// A static destination-NAT (port-forward) rule: `nat_ip:ext_port/proto` → `to_ip:to_port`.
#[derive(Clone, Copy, Debug)]
pub struct DnatRule {
    pub protocol: u8,
    pub ext_port: u16,
    pub to_ip: Ipv4Addr,
    pub to_port: u16,
}

#[derive(Clone, Copy, Debug)]
struct Binding {
    // The original private endpoint (for SNAT reverse) or external endpoint (for DNAT reverse).
    ip: Ipv4Addr,
    port: u16,
    last_seen: u64,
}

/// Runtime counters, handy for the CLI/benchmarks.
#[derive(Clone, Copy, Debug, Default)]
pub struct NatStats {
    pub snat_created: u64,
    pub snat_hits: u64,
    pub dnat_created: u64,
    pub dnat_hits: u64,
    pub reversed: u64,
    pub port_exhausted: u64,
    pub expired: u64,
}

/// The NAT engine. One instance per virtual switch (per VPC egress).
pub struct NatEngine {
    nat_ip: Ipv4Addr,
    port_min: u16,
    port_max: u16,
    next_port: u32,
    used_ports: HashSet<u16>,

    dnat_rules: Vec<DnatRule>,

    /// SNAT forward: original outbound tuple → allocated (nat_ip, nat_port).
    snat_fwd: HashMap<FiveTuple, Binding>,
    /// SNAT reverse: expected reply tuple → original private (ip, port).
    snat_rev: HashMap<FiveTuple, Binding>,
    /// DNAT reverse: internal server's reply tuple → restore external (ip, port).
    dnat_rev: HashMap<FiveTuple, Binding>,

    stats: NatStats,
}

impl NatEngine {
    #[must_use]
    pub fn new(nat_ip: Ipv4Addr, port_min: u16, port_max: u16) -> Self {
        assert!(port_min <= port_max, "invalid port range");
        Self {
            nat_ip,
            port_min,
            port_max,
            next_port: port_min as u32,
            used_ports: HashSet::new(),
            dnat_rules: Vec::new(),
            snat_fwd: HashMap::new(),
            snat_rev: HashMap::new(),
            dnat_rev: HashMap::new(),
            stats: NatStats::default(),
        }
    }

    pub fn add_dnat_rule(&mut self, rule: DnatRule) {
        self.dnat_rules.push(rule);
    }

    #[must_use]
    pub fn stats(&self) -> NatStats {
        self.stats
    }

    #[must_use]
    pub fn active_bindings(&self) -> usize {
        self.snat_fwd.len()
    }

    /// Decide the rewrite for a packet identified by `tuple` moving in `direction`
    /// at logical time `now` (any monotonically increasing unit — millis work).
    pub fn process(&mut self, tuple: FiveTuple, direction: Direction, now: u64) -> Rewrite {
        match direction {
            Direction::Outbound => self.process_outbound(tuple, now),
            Direction::Inbound => self.process_inbound(tuple, now),
        }
    }

    fn process_outbound(&mut self, tuple: FiveTuple, now: u64) -> Rewrite {
        // 1) Is this an internal server replying to a DNAT'd connection? Un-DNAT the source.
        if let Some(b) = self.dnat_rev.get_mut(&tuple) {
            b.last_seen = now;
            self.stats.reversed += 1;
            return Rewrite {
                new_src_ip: Some(b.ip),
                new_src_port: Some(b.port),
                ..Default::default()
            };
        }

        // 2) Existing SNAT binding? Reuse it.
        if let Some(b) = self.snat_fwd.get_mut(&tuple) {
            b.last_seen = now;
            self.stats.snat_hits += 1;
            return Rewrite {
                new_src_ip: Some(self.nat_ip),
                new_src_port: Some(b.port),
                ..Default::default()
            };
        }

        // 3) New outbound flow → allocate a NAT port and install conntrack.
        let Some(nat_port) = self.alloc_port(tuple.src_port) else {
            self.stats.port_exhausted += 1;
            // No translation possible; forward unchanged (will likely be dropped upstream).
            return Rewrite::default();
        };

        self.snat_fwd.insert(
            tuple,
            Binding {
                ip: self.nat_ip,
                port: nat_port,
                last_seen: now,
            },
        );

        // Reply we expect back: from remote → nat_ip:nat_port.
        let reply = FiveTuple {
            src_ip: tuple.dst_ip,
            dst_ip: self.nat_ip,
            protocol: tuple.protocol,
            src_port: tuple.dst_port,
            dst_port: nat_port,
        };
        self.snat_rev.insert(
            reply,
            Binding {
                ip: tuple.src_ip,
                port: tuple.src_port,
                last_seen: now,
            },
        );

        self.stats.snat_created += 1;
        Rewrite {
            new_src_ip: Some(self.nat_ip),
            new_src_port: Some(nat_port),
            ..Default::default()
        }
    }

    fn process_inbound(&mut self, tuple: FiveTuple, now: u64) -> Rewrite {
        // 1) Reply to an outbound SNAT flow? Reverse dst back to the private endpoint.
        if let Some(b) = self.snat_rev.get_mut(&tuple) {
            b.last_seen = now;
            self.stats.reversed += 1;
            return Rewrite {
                new_dst_ip: Some(b.ip),
                new_dst_port: Some(b.port),
                ..Default::default()
            };
        }

        // 2) New inbound connection hitting a DNAT rule?
        if tuple.dst_ip == self.nat_ip {
            if let Some(rule) = self
                .dnat_rules
                .iter()
                .find(|r| r.protocol == tuple.protocol && r.ext_port == tuple.dst_port)
                .copied()
            {
                // Install the reverse binding so the server's reply is un-DNAT'd.
                // Unlike the SNAT path (self-limited by the port pool), the DNAT
                // reverse table is keyed by the *source* 5-tuple, so spoofed inbound
                // packets from many sources could grow it without bound. Cap it: when
                // full, still forward the packet but skip reverse-tracking rather than
                // exhaust memory (a legitimate flow can re-establish after `gc`).
                const MAX_DNAT_BINDINGS: usize = 1 << 16;
                let server_reply = FiveTuple {
                    src_ip: rule.to_ip,
                    dst_ip: tuple.src_ip,
                    protocol: tuple.protocol,
                    src_port: rule.to_port,
                    dst_port: tuple.src_port,
                };
                if self.dnat_rev.len() < MAX_DNAT_BINDINGS {
                    self.dnat_rev.insert(
                        server_reply,
                        Binding {
                            ip: self.nat_ip,
                            port: rule.ext_port,
                            last_seen: now,
                        },
                    );
                    self.stats.dnat_created += 1;
                }
                return Rewrite {
                    new_dst_ip: Some(rule.to_ip),
                    new_dst_port: Some(rule.to_port),
                    ..Default::default()
                };
            }
        }

        Rewrite::default()
    }

    /// Allocate a free port, preferring to preserve `preferred` if available.
    fn alloc_port(&mut self, preferred: u16) -> Option<u16> {
        if preferred >= self.port_min
            && preferred <= self.port_max
            && !self.used_ports.contains(&preferred)
        {
            self.used_ports.insert(preferred);
            return Some(preferred);
        }
        let span = (self.port_max - self.port_min) as u32 + 1;
        for _ in 0..span {
            let p = self.next_port as u16;
            self.next_port += 1;
            if self.next_port > self.port_max as u32 {
                self.next_port = self.port_min as u32;
            }
            if !self.used_ports.contains(&p) {
                self.used_ports.insert(p);
                return Some(p);
            }
        }
        None
    }

    /// Evict bindings idle for longer than `timeout` (same unit as `now`). Returns evicted count.
    pub fn gc(&mut self, now: u64, timeout: u64) -> usize {
        let cutoff = now.saturating_sub(timeout);
        let mut freed_ports = Vec::new();

        self.snat_fwd.retain(|_, b| {
            let keep = b.last_seen >= cutoff;
            if !keep {
                freed_ports.push(b.port);
            }
            keep
        });
        self.snat_rev.retain(|_, b| b.last_seen >= cutoff);
        self.dnat_rev.retain(|_, b| b.last_seen >= cutoff);

        for p in &freed_ports {
            self.used_ports.remove(p);
        }
        let n = freed_ports.len();
        self.stats.expired += n as u64;
        n
    }
}

/// Apply a [`Rewrite`] to an IPv4 packet in place, fixing all affected checksums
/// incrementally. `pkt` must start at the IPv4 header.
pub fn apply(pkt: &mut [u8], rw: &Rewrite) -> Result<(), ParseError> {
    if rw.is_noop() {
        return Ok(());
    }

    // Snapshot what we need before taking the mutable borrow.
    let (ihl, protocol, old_src, old_dst) = {
        let v = Ipv4View::parse(pkt)?;
        (
            v.ihl_bytes(),
            v.protocol(),
            u32::from(v.src()),
            u32::from(v.dst()),
        )
    };

    // 1) Rewrite addresses in the IPv4 header (fixes the IPv4 header checksum).
    let (mut new_src, mut new_dst) = (old_src, old_dst);
    {
        let mut ip = Ipv4ViewMut::parse(pkt)?;
        if let Some(s) = rw.new_src_ip {
            let (_, n) = ip.set_src(s);
            new_src = n;
        }
        if let Some(d) = rw.new_dst_ip {
            let (_, n) = ip.set_dst(d);
            new_dst = n;
        }
    }

    // 2) Patch the L4 checksum for the address deltas (pseudo-header) and ports.
    let l4 = &mut pkt[ihl..];
    match protocol {
        p if p == proto::TCP => {
            let mut t = TcpViewMut::parse(l4)?;
            if new_src != old_src {
                t.patch_checksum_dword(old_src, new_src);
            }
            if new_dst != old_dst {
                t.patch_checksum_dword(old_dst, new_dst);
            }
            if let Some(p) = rw.new_src_port {
                t.set_src_port(p);
            }
            if let Some(p) = rw.new_dst_port {
                t.set_dst_port(p);
            }
        }
        p if p == proto::UDP => {
            let mut u = UdpViewMut::parse(l4)?;
            if new_src != old_src {
                u.patch_checksum_dword(old_src, new_src);
            }
            if new_dst != old_dst {
                u.patch_checksum_dword(old_dst, new_dst);
            }
            if let Some(p) = rw.new_src_port {
                u.set_src_port(p);
            }
            if let Some(p) = rw.new_dst_port {
                u.set_dst_port(p);
            }
        }
        // ICMP and others: the ICMP checksum does not cover IP addresses, so an
        // address-only rewrite needs no L4 fixup. Port fields don't apply.
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use andromeda_core::ipv4;
    use andromeda_core::tcp;
    use andromeda_core::udp;

    fn tuple(s: &str, sp: u16, d: &str, dp: u16, pr: u8) -> FiveTuple {
        FiveTuple {
            src_ip: s.parse().unwrap(),
            dst_ip: d.parse().unwrap(),
            protocol: pr,
            src_port: sp,
            dst_port: dp,
        }
    }

    #[test]
    fn snat_allocates_and_reverses() {
        let mut nat = NatEngine::new("203.0.113.7".parse().unwrap(), 20000, 20010);
        let out = tuple("10.0.0.5", 40000, "1.1.1.1", 443, proto::TCP);

        let rw = nat.process(out, Direction::Outbound, 1);
        assert_eq!(rw.new_src_ip, Some("203.0.113.7".parse().unwrap()));
        let nat_port = rw.new_src_port.unwrap();

        // Same flow again → stable binding, no new allocation.
        let rw2 = nat.process(out, Direction::Outbound, 2);
        assert_eq!(rw2.new_src_port, Some(nat_port));
        assert_eq!(nat.stats().snat_created, 1);
        assert_eq!(nat.stats().snat_hits, 1);

        // Reply comes back to nat_ip:nat_port → reversed to the private endpoint.
        let reply = tuple("1.1.1.1", 443, "203.0.113.7", nat_port, proto::TCP);
        let rrw = nat.process(reply, Direction::Inbound, 3);
        assert_eq!(rrw.new_dst_ip, Some("10.0.0.5".parse().unwrap()));
        assert_eq!(rrw.new_dst_port, Some(40000));
    }

    #[test]
    fn dnat_forwards_and_reverses() {
        let mut nat = NatEngine::new("203.0.113.7".parse().unwrap(), 20000, 20010);
        nat.add_dnat_rule(DnatRule {
            protocol: proto::TCP,
            ext_port: 80,
            to_ip: "10.0.0.9".parse().unwrap(),
            to_port: 8080,
        });

        let inbound = tuple("8.8.8.8", 51000, "203.0.113.7", 80, proto::TCP);
        let rw = nat.process(inbound, Direction::Inbound, 1);
        assert_eq!(rw.new_dst_ip, Some("10.0.0.9".parse().unwrap()));
        assert_eq!(rw.new_dst_port, Some(8080));

        // Server reply must be un-DNAT'd back to the external identity.
        let server_reply = tuple("10.0.0.9", 8080, "8.8.8.8", 51000, proto::TCP);
        let rrw = nat.process(server_reply, Direction::Outbound, 2);
        assert_eq!(rrw.new_src_ip, Some("203.0.113.7".parse().unwrap()));
        assert_eq!(rrw.new_src_port, Some(80));
    }

    #[test]
    fn gc_frees_ports() {
        let mut nat = NatEngine::new("203.0.113.7".parse().unwrap(), 20000, 20001);
        nat.process(
            tuple("10.0.0.1", 1, "1.1.1.1", 80, proto::TCP),
            Direction::Outbound,
            100,
        );
        nat.process(
            tuple("10.0.0.2", 2, "1.1.1.1", 80, proto::TCP),
            Direction::Outbound,
            100,
        );
        assert_eq!(nat.active_bindings(), 2);
        // Idle timeout of 50 at now=200 → both (last_seen 100) evicted.
        let evicted = nat.gc(200, 50);
        assert_eq!(evicted, 2);
        assert_eq!(nat.active_bindings(), 0);
    }

    #[test]
    fn apply_snat_to_real_tcp_packet_keeps_checksums_valid() {
        // Build IPv4 + TCP packet: 10.0.0.5:40000 -> 1.1.1.1:443.
        let src: Ipv4Addr = "10.0.0.5".parse().unwrap();
        let dst: Ipv4Addr = "1.1.1.1".parse().unwrap();
        let mut tcp_seg = vec![
            0x9c, 0x40, 0x01, 0xbb, // 40000 -> 443
            0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0x72, 0x10, 0, 0, 0, 0,
        ];
        let c = tcp::compute_checksum(src, dst, &tcp_seg);
        tcp_seg[16..18].copy_from_slice(&c.to_be_bytes());

        let mut pkt = vec![0u8; ipv4::IPV4_MIN_HDR_LEN + tcp_seg.len()];
        ipv4::write_header(
            &mut pkt[..20],
            src,
            dst,
            proto::TCP,
            64,
            1,
            true,
            tcp_seg.len() as u16,
        );
        pkt[20..].copy_from_slice(&tcp_seg);

        // SNAT src -> 203.0.113.7:20000.
        let rw = Rewrite {
            new_src_ip: Some("203.0.113.7".parse().unwrap()),
            new_src_port: Some(20000),
            ..Default::default()
        };
        apply(&mut pkt, &rw).unwrap();

        let v = ipv4::Ipv4View::parse(&pkt).unwrap();
        assert!(v.checksum_valid(), "IPv4 checksum valid after SNAT");
        assert_eq!(v.src(), "203.0.113.7".parse::<Ipv4Addr>().unwrap());

        // TCP checksum must verify against the NEW pseudo-header.
        let new_src: Ipv4Addr = "203.0.113.7".parse().unwrap();
        let mut seg = pkt[20..].to_vec();
        let stored = tcp::TcpView::parse(&seg).unwrap().checksum();
        seg[16] = 0;
        seg[17] = 0;
        let recomputed = tcp::compute_checksum(new_src, dst, &seg);
        assert_eq!(stored, recomputed, "TCP checksum valid after SNAT");
        assert_eq!(tcp::TcpView::parse(&pkt[20..]).unwrap().src_port(), 20000);
    }

    #[test]
    fn apply_dnat_to_real_udp_packet_keeps_checksums_valid() {
        let src: Ipv4Addr = "8.8.8.8".parse().unwrap();
        let dst: Ipv4Addr = "203.0.113.7".parse().unwrap();
        let payload = b"query";
        let mut udp_dg = vec![0u8; udp::UDP_HDR_LEN + payload.len()];
        udp::write_header(&mut udp_dg, 51000, 53, payload.len() as u16);
        udp_dg[udp::UDP_HDR_LEN..].copy_from_slice(payload);
        let c = udp::compute_checksum(src, dst, &udp_dg);
        udp_dg[6..8].copy_from_slice(&c.to_be_bytes());

        let mut pkt = vec![0u8; ipv4::IPV4_MIN_HDR_LEN + udp_dg.len()];
        ipv4::write_header(
            &mut pkt[..20],
            src,
            dst,
            proto::UDP,
            64,
            1,
            true,
            udp_dg.len() as u16,
        );
        pkt[20..].copy_from_slice(&udp_dg);

        // DNAT dst -> 10.0.0.9:5353.
        let rw = Rewrite {
            new_dst_ip: Some("10.0.0.9".parse().unwrap()),
            new_dst_port: Some(5353),
            ..Default::default()
        };
        apply(&mut pkt, &rw).unwrap();

        let v = ipv4::Ipv4View::parse(&pkt).unwrap();
        assert!(v.checksum_valid());
        let new_dst: Ipv4Addr = "10.0.0.9".parse().unwrap();
        let mut dg = pkt[20..].to_vec();
        let stored = udp::UdpView::parse(&dg).unwrap().checksum();
        dg[6] = 0;
        dg[7] = 0;
        let recomputed = udp::compute_checksum(src, new_dst, &dg);
        assert_eq!(stored, recomputed);
        assert_eq!(udp::UdpView::parse(&pkt[20..]).unwrap().dst_port(), 5353);
    }
}
