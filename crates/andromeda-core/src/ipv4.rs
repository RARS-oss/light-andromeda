//! IPv4 parsing and in-place rewriting.
//!
//! The mutable view exposes `set_src`/`set_dst` that fix up the header checksum
//! incrementally (RFC 1624). The NAT layer sits on top and additionally fixes the
//! L4 checksum, because for TCP/UDP the addresses are covered by the pseudo-header.

use crate::checksum;
use crate::ParseError;
use std::net::Ipv4Addr;

pub const IPV4_MIN_HDR_LEN: usize = 20;

pub mod proto {
    pub const ICMP: u8 = 1;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
}

/// Read-only IPv4 view.
#[derive(Clone, Copy)]
pub struct Ipv4View<'a> {
    buf: &'a [u8],
}

impl<'a> Ipv4View<'a> {
    pub fn parse(buf: &'a [u8]) -> Result<Self, ParseError> {
        if buf.len() < IPV4_MIN_HDR_LEN {
            return Err(ParseError::TooShort {
                what: "ipv4",
                need: IPV4_MIN_HDR_LEN,
                got: buf.len(),
            });
        }
        let version = buf[0] >> 4;
        if version != 4 {
            return Err(ParseError::BadVersion {
                what: "ipv4",
                version,
            });
        }
        let ihl = (buf[0] & 0x0f) as usize * 4;
        if ihl < IPV4_MIN_HDR_LEN || ihl > buf.len() {
            return Err(ParseError::BadHeaderLen {
                what: "ipv4",
                len: ihl,
            });
        }
        let total = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        // total_length may be larger than the captured slice for a truncated
        // capture, but it must at least cover the header.
        if total < ihl {
            return Err(ParseError::BadHeaderLen {
                what: "ipv4-total",
                len: total,
            });
        }
        Ok(Self { buf })
    }

    #[must_use]
    pub fn ihl_bytes(&self) -> usize {
        (self.buf[0] & 0x0f) as usize * 4
    }
    #[must_use]
    pub fn dscp_ecn(&self) -> u8 {
        self.buf[1]
    }
    #[must_use]
    pub fn total_length(&self) -> u16 {
        u16::from_be_bytes([self.buf[2], self.buf[3]])
    }
    #[must_use]
    pub fn identification(&self) -> u16 {
        u16::from_be_bytes([self.buf[4], self.buf[5]])
    }
    #[must_use]
    pub fn flags_frag(&self) -> u16 {
        u16::from_be_bytes([self.buf[6], self.buf[7]])
    }
    #[must_use]
    pub fn dont_fragment(&self) -> bool {
        self.flags_frag() & 0x4000 != 0
    }
    #[must_use]
    pub fn more_fragments(&self) -> bool {
        self.flags_frag() & 0x2000 != 0
    }
    #[must_use]
    pub fn fragment_offset(&self) -> u16 {
        (self.flags_frag() & 0x1fff) * 8
    }
    #[must_use]
    pub fn ttl(&self) -> u8 {
        self.buf[8]
    }
    #[must_use]
    pub fn protocol(&self) -> u8 {
        self.buf[9]
    }
    #[must_use]
    pub fn header_checksum(&self) -> u16 {
        u16::from_be_bytes([self.buf[10], self.buf[11]])
    }
    #[must_use]
    pub fn src(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.buf[12], self.buf[13], self.buf[14], self.buf[15])
    }
    #[must_use]
    pub fn dst(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.buf[16], self.buf[17], self.buf[18], self.buf[19])
    }

    /// True if the stored header checksum is correct.
    #[must_use]
    pub fn checksum_valid(&self) -> bool {
        checksum::checksum(&self.buf[..self.ihl_bytes()]) == 0
    }

    /// The L4 payload (after IHL bytes). Bounded by the captured buffer.
    #[must_use]
    pub fn payload(&self) -> &'a [u8] {
        &self.buf[self.ihl_bytes()..]
    }

    #[must_use]
    pub fn bytes(&self) -> &'a [u8] {
        self.buf
    }
}

/// Mutable IPv4 view for in-place rewrites.
pub struct Ipv4ViewMut<'a> {
    buf: &'a mut [u8],
}

impl<'a> Ipv4ViewMut<'a> {
    pub fn parse(buf: &'a mut [u8]) -> Result<Self, ParseError> {
        // Validate via the read-only path first.
        Ipv4View::parse(buf)?;
        Ok(Self { buf })
    }

    #[must_use]
    pub fn ihl_bytes(&self) -> usize {
        (self.buf[0] & 0x0f) as usize * 4
    }
    #[must_use]
    pub fn protocol(&self) -> u8 {
        self.buf[9]
    }
    #[must_use]
    pub fn src(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.buf[12], self.buf[13], self.buf[14], self.buf[15])
    }
    #[must_use]
    pub fn dst(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.buf[16], self.buf[17], self.buf[18], self.buf[19])
    }
    #[must_use]
    pub fn header_checksum(&self) -> u16 {
        u16::from_be_bytes([self.buf[10], self.buf[11]])
    }

    fn set_header_checksum(&mut self, c: u16) {
        self.buf[10..12].copy_from_slice(&c.to_be_bytes());
    }

    /// Rewrite the source address and fix the header checksum incrementally.
    /// Returns `(old, new)` as u32 so the caller can also patch the L4 checksum.
    pub fn set_src(&mut self, new: Ipv4Addr) -> (u32, u32) {
        let old = u32::from(self.src());
        let new_u = u32::from(new);
        let c = checksum::update_dword(self.header_checksum(), old, new_u);
        self.buf[12..16].copy_from_slice(&new.octets());
        self.set_header_checksum(c);
        (old, new_u)
    }

    /// Rewrite the destination address and fix the header checksum incrementally.
    pub fn set_dst(&mut self, new: Ipv4Addr) -> (u32, u32) {
        let old = u32::from(self.dst());
        let new_u = u32::from(new);
        let c = checksum::update_dword(self.header_checksum(), old, new_u);
        self.buf[16..20].copy_from_slice(&new.octets());
        self.set_header_checksum(c);
        (old, new_u)
    }

    /// Decrement TTL by one, fixing the header checksum. Returns the new TTL.
    /// Returns `None` if TTL was already 0 (packet should be dropped/ICMP'd).
    pub fn decrement_ttl(&mut self) -> Option<u8> {
        let ttl = self.buf[8];
        if ttl == 0 {
            return None;
        }
        // TTL and protocol share a 16-bit word (bytes 8,9). Update that word.
        let old_word = u16::from_be_bytes([self.buf[8], self.buf[9]]);
        let new_ttl = ttl - 1;
        let new_word = u16::from_be_bytes([new_ttl, self.buf[9]]);
        let c = checksum::update_word(self.header_checksum(), old_word, new_word);
        self.buf[8] = new_ttl;
        self.set_header_checksum(c);
        Some(new_ttl)
    }

    #[must_use]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let ihl = self.ihl_bytes();
        &mut self.buf[ihl..]
    }
}

/// Compute the IPv4 pseudo-header partial sum used by TCP/UDP checksums.
/// Returns an unfolded 32-bit accumulator (feed more data, then finalize).
#[must_use]
pub fn pseudo_header_sum(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, l4_len: u16) -> u32 {
    let mut acc = 0u32;
    acc = checksum::accumulate(acc, &src.octets());
    acc = checksum::accumulate(acc, &dst.octets());
    acc = acc.wrapping_add(protocol as u32); // zero byte + protocol
    acc = acc.wrapping_add(l4_len as u32);
    acc
}

/// Build a minimal 20-byte IPv4 header into `buf` and set the checksum.
/// `payload_len` is the number of L4 bytes that will follow the header.
#[allow(clippy::too_many_arguments)]
#[inline]
pub fn write_header(
    buf: &mut [u8],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: u8,
    ttl: u8,
    identification: u16,
    dont_fragment: bool,
    payload_len: u16,
) -> usize {
    buf[0] = 0x45; // version 4, IHL 5
    buf[1] = 0x00; // DSCP/ECN
    let total = IPV4_MIN_HDR_LEN as u16 + payload_len;
    buf[2..4].copy_from_slice(&total.to_be_bytes());
    buf[4..6].copy_from_slice(&identification.to_be_bytes());
    let flags: u16 = if dont_fragment { 0x4000 } else { 0 };
    buf[6..8].copy_from_slice(&flags.to_be_bytes());
    buf[8] = ttl;
    buf[9] = protocol;
    buf[10] = 0;
    buf[11] = 0;
    buf[12..16].copy_from_slice(&src.octets());
    buf[16..20].copy_from_slice(&dst.octets());
    let c = checksum::checksum(&buf[..IPV4_MIN_HDR_LEN]);
    buf[10..12].copy_from_slice(&c.to_be_bytes());
    IPV4_MIN_HDR_LEN
}

#[cfg(test)]
mod tests {
    use super::*;

    fn real_packet() -> Vec<u8> {
        // 172.16.10.99 -> 172.16.10.12, TCP, DF, ttl 64, id 0x1c46.
        vec![
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0xb1, 0xe6, 0xac, 0x10,
            0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c,
        ]
    }

    #[test]
    fn parses_real_header() {
        let p = real_packet();
        let v = Ipv4View::parse(&p).unwrap();
        assert_eq!(v.ihl_bytes(), 20);
        assert_eq!(v.total_length(), 0x3c);
        assert_eq!(v.ttl(), 64);
        assert_eq!(v.protocol(), proto::TCP);
        assert!(v.dont_fragment());
        assert!(!v.more_fragments());
        assert_eq!(v.src(), Ipv4Addr::new(172, 16, 10, 99));
        assert_eq!(v.dst(), Ipv4Addr::new(172, 16, 10, 12));
        assert!(v.checksum_valid(), "known-good packet must verify");
    }

    #[test]
    fn snat_keeps_header_checksum_valid() {
        let mut p = real_packet();
        {
            let mut v = Ipv4ViewMut::parse(&mut p).unwrap();
            v.set_src(Ipv4Addr::new(10, 0, 0, 7));
        }
        let v = Ipv4View::parse(&p).unwrap();
        assert_eq!(v.src(), Ipv4Addr::new(10, 0, 0, 7));
        assert!(
            v.checksum_valid(),
            "header checksum must stay valid after SNAT"
        );
    }

    #[test]
    fn ttl_decrement_keeps_checksum_valid() {
        let mut p = real_packet();
        {
            let mut v = Ipv4ViewMut::parse(&mut p).unwrap();
            assert_eq!(v.decrement_ttl(), Some(63));
        }
        let v = Ipv4View::parse(&p).unwrap();
        assert_eq!(v.ttl(), 63);
        assert!(v.checksum_valid());
    }

    #[test]
    fn write_header_produces_valid_checksum() {
        let mut buf = [0u8; 20];
        write_header(
            &mut buf,
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            proto::UDP,
            64,
            0x4242,
            true,
            100,
        );
        let v = Ipv4View::parse(&buf).unwrap();
        assert!(v.checksum_valid());
        assert_eq!(v.total_length(), 120);
        assert_eq!(v.protocol(), proto::UDP);
    }

    #[test]
    fn rejects_ipv6_version() {
        let mut p = real_packet();
        p[0] = 0x60;
        assert!(Ipv4View::parse(&p).is_err());
    }
}
