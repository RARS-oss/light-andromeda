//! The Andromeda overlay encapsulation.
//!
//! An inner Ethernet frame belonging to a tenant VPC is wrapped as:
//!
//! ```text
//!   [ outer Ethernet ][ outer IPv4 ][ outer UDP ][ Andromeda hdr ][ inner Ethernet frame ... ]
//!     14 bytes          20 bytes      8 bytes      8 bytes
//! ```
//!
//! This is the same shape as VXLAN/GENEVE (L2-over-UDP), but with our own 8-byte
//! header that additionally carries a *flow hash* used to spread a tenant's
//! traffic across multiple physical paths/nodes (ECMP), which is the load-
//! balancing behaviour the platform advertises.
//!
//! Andromeda header layout (8 bytes):
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | Ver | Flags |  Inner proto  |           Flow hash           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                     VNI (24 bits)              |  Hop limit  |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use crate::ethernet::{self, MacAddr};
use crate::ipv4;
use crate::udp;
use crate::ParseError;
use std::net::Ipv4Addr;

/// Destination UDP port that identifies Andromeda-encapsulated traffic on the wire.
/// (VXLAN uses 4789, GENEVE 6081; we deliberately pick our own.)
pub const ANDROMEDA_UDP_PORT: u16 = 43481;

/// Current header version.
pub const ANDROMEDA_VERSION: u8 = 1;

/// Size of the Andromeda header itself.
pub const ANDROMEDA_HDR_LEN: usize = 8;

/// Total bytes of encapsulation added around an inner L2 frame.
pub const OVERLAY_OVERHEAD: usize =
    ethernet::ETH_HDR_LEN + ipv4::IPV4_MIN_HDR_LEN + udp::UDP_HDR_LEN + ANDROMEDA_HDR_LEN;

pub mod flags {
    /// This is a control-plane message (route/endpoint update), not tenant data.
    pub const CONTROL: u8 = 0x8;
    /// Reserved for a future OAM/liveness channel.
    pub const OAM: u8 = 0x4;
}

pub mod inner_proto {
    /// Inner payload is a full Ethernet frame (L2 overlay — the default).
    pub const ETHERNET: u8 = 0;
    /// Inner payload is a bare IPv4 packet (L3 overlay).
    pub const IPV4: u8 = 1;
}

/// Decoded Andromeda header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AndromedaHdr {
    pub version: u8,
    pub flags: u8,
    pub inner_proto: u8,
    pub flow_hash: u16,
    pub vni: u32, // 24-bit
    pub hop_limit: u8,
}

impl AndromedaHdr {
    #[must_use]
    pub fn new(vni: u32, flow_hash: u16) -> Self {
        Self {
            version: ANDROMEDA_VERSION,
            flags: 0,
            inner_proto: inner_proto::ETHERNET,
            flow_hash,
            vni: vni & 0x00ff_ffff,
            hop_limit: 64,
        }
    }

    #[must_use]
    pub fn is_control(&self) -> bool {
        self.flags & flags::CONTROL != 0
    }

    /// Serialize into 8 bytes.
    pub fn encode(&self, out: &mut [u8]) {
        out[0] = (self.version << 4) | (self.flags & 0x0f);
        out[1] = self.inner_proto;
        out[2..4].copy_from_slice(&self.flow_hash.to_be_bytes());
        let vni = self.vni & 0x00ff_ffff;
        out[4] = (vni >> 16) as u8;
        out[5] = (vni >> 8) as u8;
        out[6] = vni as u8;
        out[7] = self.hop_limit;
    }

    /// Parse from the first 8 bytes of `buf`.
    pub fn decode(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < ANDROMEDA_HDR_LEN {
            return Err(ParseError::TooShort {
                what: "andromeda",
                need: ANDROMEDA_HDR_LEN,
                got: buf.len(),
            });
        }
        let version = buf[0] >> 4;
        if version != ANDROMEDA_VERSION {
            return Err(ParseError::BadVersion { what: "andromeda", version });
        }
        Ok(Self {
            version,
            flags: buf[0] & 0x0f,
            inner_proto: buf[1],
            flow_hash: u16::from_be_bytes([buf[2], buf[3]]),
            vni: (u32::from(buf[4]) << 16) | (u32::from(buf[5]) << 8) | u32::from(buf[6]),
            hop_limit: buf[7],
        })
    }
}

/// A 16-bit flow hash over the inner 5-tuple, used to pick an outer path/node.
/// FNV-1a folded to 16 bits — cheap, stable, and good enough for ECMP spread.
#[must_use]
pub fn flow_hash(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, src_port: u16, dst_port: u16) -> u16 {
    const OFFSET: u32 = 0x811c_9dc5;
    const PRIME: u32 = 0x0100_0193;
    let mut h = OFFSET;
    let mut mix = |b: u8| {
        h ^= b as u32;
        h = h.wrapping_mul(PRIME);
    };
    for b in src.octets() {
        mix(b);
    }
    for b in dst.octets() {
        mix(b);
    }
    mix(protocol);
    for b in src_port.to_be_bytes() {
        mix(b);
    }
    for b in dst_port.to_be_bytes() {
        mix(b);
    }
    // Fold 32 -> 16.
    ((h >> 16) ^ (h & 0xffff)) as u16
}

/// Parameters for one encapsulation.
pub struct EncapParams {
    pub outer_src_mac: MacAddr,
    pub outer_dst_mac: MacAddr,
    pub outer_src_ip: Ipv4Addr,
    pub outer_dst_ip: Ipv4Addr,
    pub vni: u32,
    pub flow_hash: u16,
    /// Outer IPv4 identification field (bump per packet if you like).
    pub ip_id: u16,
}

/// Encapsulate `inner` (a complete Ethernet frame) into `out`, returning the
/// number of bytes written. `out` must be at least `OVERLAY_OVERHEAD + inner.len()`.
pub fn encap(out: &mut [u8], inner: &[u8], p: &EncapParams) -> Result<usize, ParseError> {
    let total = OVERLAY_OVERHEAD + inner.len();
    if out.len() < total {
        return Err(ParseError::BufferTooSmall { need: total, got: out.len() });
    }

    let eth_end = ethernet::ETH_HDR_LEN;
    let ip_end = eth_end + ipv4::IPV4_MIN_HDR_LEN;
    let udp_end = ip_end + udp::UDP_HDR_LEN;
    let andro_end = udp_end + ANDROMEDA_HDR_LEN;

    // Outer Ethernet.
    ethernet::write_header(
        &mut out[..eth_end],
        p.outer_dst_mac,
        p.outer_src_mac,
        ethernet::ethertype::IPV4,
    );

    // L4 payload length = UDP header + Andromeda header + inner frame.
    let udp_payload_len = (ANDROMEDA_HDR_LEN + inner.len()) as u16;
    let ip_payload_len = udp::UDP_HDR_LEN as u16 + udp_payload_len;

    // Outer IPv4 (DF set: overlay endpoints must not fragment; PMTU is the tenant's problem).
    ipv4::write_header(
        &mut out[eth_end..ip_end],
        p.outer_src_ip,
        p.outer_dst_ip,
        ipv4::proto::UDP,
        64,
        p.ip_id,
        true,
        ip_payload_len,
    );

    // Outer UDP (src port = flow hash → per-flow entropy for the underlay's own ECMP).
    udp::write_header(
        &mut out[ip_end..udp_end],
        p.flow_hash | 0xc000, // keep it in the ephemeral range
        ANDROMEDA_UDP_PORT,
        udp_payload_len,
    );

    // Andromeda header.
    let mut hdr = AndromedaHdr::new(p.vni, p.flow_hash);
    hdr.inner_proto = inner_proto::ETHERNET;
    hdr.encode(&mut out[udp_end..andro_end]);

    // Inner frame.
    out[andro_end..total].copy_from_slice(inner);

    // Outer UDP checksum over pseudo-header + (udp hdr + andromeda + inner).
    let c = udp::compute_checksum(p.outer_src_ip, p.outer_dst_ip, &out[ip_end..total]);
    out[ip_end + 6..ip_end + 8].copy_from_slice(&c.to_be_bytes());

    Ok(total)
}

/// A decapsulated Andromeda packet: the header plus a slice pointing at the inner frame.
pub struct Decapsulated<'a> {
    pub header: AndromedaHdr,
    pub inner: &'a [u8],
    pub outer_src_ip: Ipv4Addr,
    pub outer_dst_ip: Ipv4Addr,
}

/// Attempt to decapsulate a received outer Ethernet frame. Returns `Ok(None)` if
/// the frame is simply not Andromeda traffic (wrong ethertype/proto/port) so the
/// caller can fall through to other handling; `Err` only on malformed headers.
pub fn decap(frame: &[u8]) -> Result<Option<Decapsulated<'_>>, ParseError> {
    let eth = ethernet::EthFrame::parse(frame)?;
    if eth.ethertype() != ethernet::ethertype::IPV4 {
        return Ok(None);
    }
    let ip = ipv4::Ipv4View::parse(eth.payload())?;
    if ip.protocol() != ipv4::proto::UDP {
        return Ok(None);
    }
    let l4 = ip.payload();
    let udp_v = udp::UdpView::parse(l4)?;
    if udp_v.dst_port() != ANDROMEDA_UDP_PORT {
        return Ok(None);
    }
    let after_udp = &l4[udp::UDP_HDR_LEN..];
    let header = AndromedaHdr::decode(after_udp)?;
    let inner = &after_udp[ANDROMEDA_HDR_LEN..];
    Ok(Some(Decapsulated {
        header,
        inner,
        outer_src_ip: ip.src(),
        outer_dst_ip: ip.dst(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ethernet::EthFrame;

    fn inner_frame() -> Vec<u8> {
        // A tiny inner Ethernet frame: dst/src MAC + IPv4 ethertype + 8 payload bytes.
        let mut v = ethernet::MacAddr([0x02, 0, 0, 0, 0, 0x0b]).0.to_vec();
        v.extend_from_slice(&ethernet::MacAddr([0x02, 0, 0, 0, 0, 0x0a]).0);
        v.extend_from_slice(&ethernet::ethertype::IPV4.to_be_bytes());
        v.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        v
    }

    #[test]
    fn header_roundtrip() {
        let mut h = AndromedaHdr::new(0x00_abcd, 0x1234);
        h.flags = flags::CONTROL;
        h.hop_limit = 32;
        let mut buf = [0u8; 8];
        h.encode(&mut buf);
        let d = AndromedaHdr::decode(&buf).unwrap();
        assert_eq!(d, h);
        assert!(d.is_control());
        assert_eq!(d.vni, 0x00_abcd);
    }

    #[test]
    fn encap_then_decap_roundtrips_inner() {
        let inner = inner_frame();
        let mut out = vec![0u8; OVERLAY_OVERHEAD + inner.len()];
        let p = EncapParams {
            outer_src_mac: MacAddr([0x02, 0, 0, 0, 0xaa, 1]),
            outer_dst_mac: MacAddr([0x02, 0, 0, 0, 0xaa, 2]),
            outer_src_ip: Ipv4Addr::new(192, 168, 0, 1),
            outer_dst_ip: Ipv4Addr::new(192, 168, 0, 2),
            vni: 0x00_0064,
            flow_hash: 0xbeef,
            ip_id: 0x4242,
        };
        let n = encap(&mut out, &inner, &p).unwrap();
        assert_eq!(n, OVERLAY_OVERHEAD + inner.len());

        // Outer IPv4 checksum must be valid.
        let eth = EthFrame::parse(&out[..n]).unwrap();
        let ip = ipv4::Ipv4View::parse(eth.payload()).unwrap();
        assert!(ip.checksum_valid());

        // Outer UDP checksum must verify (recompute over l4 with checksum field zeroed == stored).
        let mut l4 = ip.payload().to_vec();
        let stored_udp_ck = udp::UdpView::parse(&l4).unwrap().checksum();
        l4[6] = 0;
        l4[7] = 0;
        let recomputed = udp::compute_checksum(p.outer_src_ip, p.outer_dst_ip, &l4);
        assert_eq!(stored_udp_ck, recomputed);

        // Decap recovers the exact inner frame.
        let d = decap(&out[..n]).unwrap().unwrap();
        assert_eq!(d.header.vni, 0x00_0064);
        assert_eq!(d.header.flow_hash, 0xbeef);
        assert_eq!(d.inner, &inner[..]);
    }

    #[test]
    fn decap_ignores_non_andromeda() {
        // Plain ARP frame → not Andromeda, Ok(None).
        let mut v = vec![0xffu8; 6];
        v.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
        v.extend_from_slice(&ethernet::ethertype::ARP.to_be_bytes());
        v.extend_from_slice(&[0u8; 28]);
        assert!(decap(&v).unwrap().is_none());
    }

    #[test]
    fn flow_hash_is_stable_and_varies() {
        let a = flow_hash(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2), 6, 1234, 80);
        let b = flow_hash(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2), 6, 1234, 80);
        let c = flow_hash(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2), 6, 1235, 80);
        assert_eq!(a, b, "same tuple → same hash");
        assert_ne!(a, c, "different port → (very likely) different hash");
    }
}
