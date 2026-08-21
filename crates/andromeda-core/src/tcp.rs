//! TCP header parsing and in-place port/checksum rewriting.
//!
//! We only ever touch the fixed part of the TCP header (ports + checksum). We
//! never reassemble or track sequence numbers here — connection tracking lives
//! in `andromeda-nat` and keys on the 5-tuple. The TCP checksum, like UDP, covers
//! the pseudo-header, so address rewrites must patch it too.

use crate::checksum;
use crate::ParseError;

pub const TCP_MIN_HDR_LEN: usize = 20;

pub mod flag {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
}

#[derive(Clone, Copy)]
pub struct TcpView<'a> {
    buf: &'a [u8],
}

impl<'a> TcpView<'a> {
    pub fn parse(buf: &'a [u8]) -> Result<Self, ParseError> {
        if buf.len() < TCP_MIN_HDR_LEN {
            return Err(ParseError::TooShort { what: "tcp", need: TCP_MIN_HDR_LEN, got: buf.len() });
        }
        let data_off = (buf[12] >> 4) as usize * 4;
        if data_off < TCP_MIN_HDR_LEN || data_off > buf.len() {
            return Err(ParseError::BadHeaderLen { what: "tcp", len: data_off });
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
    pub fn seq(&self) -> u32 {
        u32::from_be_bytes([self.buf[4], self.buf[5], self.buf[6], self.buf[7]])
    }
    #[must_use]
    pub fn ack(&self) -> u32 {
        u32::from_be_bytes([self.buf[8], self.buf[9], self.buf[10], self.buf[11]])
    }
    #[must_use]
    pub fn data_offset(&self) -> usize {
        (self.buf[12] >> 4) as usize * 4
    }
    #[must_use]
    pub fn flags(&self) -> u8 {
        self.buf[13]
    }
    #[must_use]
    pub fn has_flag(&self, f: u8) -> bool {
        self.flags() & f != 0
    }
    #[must_use]
    pub fn window(&self) -> u16 {
        u16::from_be_bytes([self.buf[14], self.buf[15]])
    }
    #[must_use]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.buf[16], self.buf[17]])
    }
    #[must_use]
    pub fn payload(&self) -> &'a [u8] {
        &self.buf[self.data_offset()..]
    }
}

pub struct TcpViewMut<'a> {
    buf: &'a mut [u8],
}

impl<'a> TcpViewMut<'a> {
    pub fn parse(buf: &'a mut [u8]) -> Result<Self, ParseError> {
        TcpView::parse(buf)?;
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
        u16::from_be_bytes([self.buf[16], self.buf[17]])
    }

    fn set_checksum(&mut self, c: u16) {
        self.buf[16..18].copy_from_slice(&c.to_be_bytes());
    }

    pub fn patch_checksum_word(&mut self, old: u16, new: u16) {
        let c = checksum::update_word(self.checksum(), old, new);
        self.set_checksum(c);
    }

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

/// Compute a fresh TCP checksum over pseudo-header + TCP segment. `l4` is the TCP
/// header followed by payload. Used in tests and when synthesizing segments.
#[must_use]
pub fn compute_checksum(src: std::net::Ipv4Addr, dst: std::net::Ipv4Addr, l4: &[u8]) -> u16 {
    let pseudo = crate::ipv4::pseudo_header_sum(src, dst, crate::ipv4::proto::TCP, l4.len() as u16);
    let acc = checksum::accumulate(pseudo, l4);
    checksum::finalize(acc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn syn_segment() -> Vec<u8> {
        // A 20-byte TCP header, SYN set, ports 49152 -> 80.
        let mut seg = vec![
            0xc0, 0x00, 0x00, 0x50, // src 49152, dst 80
            0x00, 0x00, 0x00, 0x01, // seq
            0x00, 0x00, 0x00, 0x00, // ack
            0x50, 0x02, 0x72, 0x10, // data offset 5, flags SYN, window
            0x00, 0x00, 0x00, 0x00, // checksum, urgent
        ];
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let c = compute_checksum(src, dst, &seg);
        seg[16..18].copy_from_slice(&c.to_be_bytes());
        seg
    }

    #[test]
    fn parse_flags_and_ports() {
        let seg = syn_segment();
        let v = TcpView::parse(&seg).unwrap();
        assert_eq!(v.src_port(), 49152);
        assert_eq!(v.dst_port(), 80);
        assert_eq!(v.data_offset(), 20);
        assert!(v.has_flag(flag::SYN));
        assert!(!v.has_flag(flag::ACK));
    }

    #[test]
    fn address_rewrite_patch_matches_recompute() {
        let mut seg = syn_segment();
        let old_src = Ipv4Addr::new(10, 0, 0, 1);
        let new_src = Ipv4Addr::new(203, 0, 113, 5);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        {
            let mut v = TcpViewMut::parse(&mut seg).unwrap();
            v.patch_checksum_dword(u32::from(old_src), u32::from(new_src));
        }
        // Recompute as if the segment were sent from the new source.
        let mut check = seg.clone();
        check[16..18].copy_from_slice(&[0, 0]);
        let full = compute_checksum(new_src, dst, &check);
        assert_eq!(u16::from_be_bytes([seg[16], seg[17]]), full);
    }
}
