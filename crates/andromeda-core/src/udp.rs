//! UDP parsing and in-place port/checksum rewriting.
//!
//! Because the UDP checksum covers the IPv4 pseudo-header (which includes the
//! addresses), a NAT rewrite of an address OR a port must patch this checksum.
//! We expose primitives to patch by 16-bit delta so the NAT layer never rescans
//! the payload. UDP over IPv4 may also carry checksum 0 ("not computed"): in that
//! case we leave it untouched.

use crate::checksum;
use crate::ParseError;

pub const UDP_HDR_LEN: usize = 8;

#[derive(Clone, Copy)]
pub struct UdpView<'a> {
    buf: &'a [u8],
}

impl<'a> UdpView<'a> {
    pub fn parse(buf: &'a [u8]) -> Result<Self, ParseError> {
        if buf.len() < UDP_HDR_LEN {
            return Err(ParseError::TooShort {
                what: "udp",
                need: UDP_HDR_LEN,
                got: buf.len(),
            });
        }
        Ok(Self { buf })
    }

    #[must_use]
    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes([self.buf[0], self.buf[1]])
    }
    #[must_use]
    pub fn dst_port(&self) -> u16 {
        u16::from_be_bytes([self.buf[2], self.buf[3]])
    }
    #[must_use]
    pub fn length(&self) -> u16 {
        u16::from_be_bytes([self.buf[4], self.buf[5]])
    }
    #[must_use]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.buf[6], self.buf[7]])
    }
    #[must_use]
    pub fn payload(&self) -> &'a [u8] {
        &self.buf[UDP_HDR_LEN..]
    }
}

pub struct UdpViewMut<'a> {
    buf: &'a mut [u8],
}

impl<'a> UdpViewMut<'a> {
    pub fn parse(buf: &'a mut [u8]) -> Result<Self, ParseError> {
        if buf.len() < UDP_HDR_LEN {
            return Err(ParseError::TooShort {
                what: "udp",
                need: UDP_HDR_LEN,
                got: buf.len(),
            });
        }
        Ok(Self { buf })
    }

    #[must_use]
    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes([self.buf[0], self.buf[1]])
    }
    #[must_use]
    pub fn dst_port(&self) -> u16 {
        u16::from_be_bytes([self.buf[2], self.buf[3]])
    }
    #[must_use]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.buf[6], self.buf[7]])
    }

    fn set_checksum(&mut self, c: u16) {
        self.buf[6..8].copy_from_slice(&c.to_be_bytes());
    }

    /// UDP-over-IPv4 permits a 0 checksum meaning "not computed". Don't touch it.
    #[must_use]
    pub fn checksum_disabled(&self) -> bool {
        self.checksum() == 0
    }

    /// Patch the checksum for a changed 16-bit word (a port, or half an address
    /// in the pseudo-header). No-op when checksum is disabled (0).
    pub fn patch_checksum_word(&mut self, old: u16, new: u16) {
        if self.checksum_disabled() {
            return;
        }
        let c = checksum::update_word(self.checksum(), old, new);
        // RFC 768: a computed checksum of 0 is transmitted as 0xffff.
        self.set_checksum(if c == 0 { 0xffff } else { c });
    }

    /// Patch the checksum for a changed 32-bit address (pseudo-header). No-op when disabled.
    pub fn patch_checksum_dword(&mut self, old: u32, new: u32) {
        self.patch_checksum_word((old >> 16) as u16, (new >> 16) as u16);
        self.patch_checksum_word((old & 0xffff) as u16, (new & 0xffff) as u16);
    }

    pub fn set_src_port(&mut self, port: u16) {
        let old = self.src_port();
        self.buf[0..2].copy_from_slice(&port.to_be_bytes());
        self.patch_checksum_word(old, port);
    }

    pub fn set_dst_port(&mut self, port: u16) {
        let old = self.dst_port();
        self.buf[2..4].copy_from_slice(&port.to_be_bytes());
        self.patch_checksum_word(old, port);
    }
}

/// Compute a fresh UDP checksum over the pseudo-header + UDP header + payload.
/// `l4` is the UDP header followed by its payload. Used when building overlay
/// packets from scratch. Returns the value to store (0 becomes 0xffff).
#[must_use]
pub fn compute_checksum(src: std::net::Ipv4Addr, dst: std::net::Ipv4Addr, l4: &[u8]) -> u16 {
    let pseudo = crate::ipv4::pseudo_header_sum(src, dst, crate::ipv4::proto::UDP, l4.len() as u16);
    let acc = checksum::accumulate(pseudo, l4);
    let c = checksum::finalize(acc);
    if c == 0 {
        0xffff
    } else {
        c
    }
}

/// Write an 8-byte UDP header. Caller fills payload separately then may call
/// [`compute_checksum`] over header+payload and store it.
#[inline]
pub fn write_header(buf: &mut [u8], src_port: u16, dst_port: u16, payload_len: u16) -> usize {
    buf[0..2].copy_from_slice(&src_port.to_be_bytes());
    buf[2..4].copy_from_slice(&dst_port.to_be_bytes());
    let len = UDP_HDR_LEN as u16 + payload_len;
    buf[4..6].copy_from_slice(&len.to_be_bytes());
    buf[6..8].copy_from_slice(&[0, 0]); // checksum filled later
    UDP_HDR_LEN
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn dnat_port_keeps_checksum_consistent() {
        // Build a UDP datagram, compute its checksum, rewrite dst port, verify
        // the patched checksum equals a full recompute.
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let payload = b"hello-andromeda";
        let mut dgram = vec![0u8; UDP_HDR_LEN + payload.len()];
        write_header(&mut dgram, 4242, 53, payload.len() as u16);
        dgram[UDP_HDR_LEN..].copy_from_slice(payload);
        let c = compute_checksum(src, dst, &dgram);
        dgram[6..8].copy_from_slice(&c.to_be_bytes());

        {
            let mut v = UdpViewMut::parse(&mut dgram).unwrap();
            v.set_dst_port(5353);
        }

        // Full recompute after the change.
        let mut check = dgram.clone();
        check[6..8].copy_from_slice(&[0, 0]);
        let full = compute_checksum(src, dst, &check);
        let stored = u16::from_be_bytes([dgram[6], dgram[7]]);
        assert_eq!(
            stored, full,
            "incremental port patch must equal full recompute"
        );
        assert_eq!(UdpView::parse(&dgram).unwrap().dst_port(), 5353);
    }

    #[test]
    fn disabled_checksum_left_alone() {
        let mut dgram = vec![0u8; UDP_HDR_LEN + 4];
        write_header(&mut dgram, 1, 2, 4);
        // checksum stays 0
        let mut v = UdpViewMut::parse(&mut dgram).unwrap();
        v.set_dst_port(9999);
        assert_eq!(v.checksum(), 0, "disabled checksum must remain 0");
    }
}
