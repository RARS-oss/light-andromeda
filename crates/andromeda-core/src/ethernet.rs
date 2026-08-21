//! Ethernet II frame parsing/building (zero-copy views over a byte buffer).
//!
//! We deliberately do NOT support 802.1Q VLAN tags here — the overlay design
//! carries the virtual-network id in the Andromeda header instead, which is the
//! whole point of an encap-based VPC (you don't burn a 4096-VLAN namespace).

use crate::ParseError;
use core::fmt;

/// Length of a fixed Ethernet II header (dst + src + ethertype), no VLAN.
pub const ETH_HDR_LEN: usize = 14;

/// EtherType values we care about.
pub mod ethertype {
    pub const IPV4: u16 = 0x0800;
    pub const ARP: u16 = 0x0806;
    pub const IPV6: u16 = 0x86dd;
}

/// A 48-bit MAC address.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const BROADCAST: MacAddr = MacAddr([0xff; 6]);
    pub const ZERO: MacAddr = MacAddr([0; 6]);

    #[must_use]
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    #[must_use]
    pub fn is_broadcast(&self) -> bool {
        *self == Self::BROADCAST
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl core::str::FromStr for MacAddr {
    type Err = MacParseError;

    /// Parse `aa:bb:cc:dd:ee:ff` (colon- or dash-separated hex octets).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut octets = [0u8; 6];
        let mut n = 0;
        for part in s.split([':', '-']) {
            if n == 6 {
                return Err(MacParseError);
            }
            octets[n] = u8::from_str_radix(part, 16).map_err(|_| MacParseError)?;
            n += 1;
        }
        if n != 6 {
            return Err(MacParseError);
        }
        Ok(MacAddr(octets))
    }
}

/// Error returned when a MAC address string is malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacParseError;

impl fmt::Display for MacParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid MAC address (expected aa:bb:cc:dd:ee:ff)")
    }
}

impl std::error::Error for MacParseError {}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        )
    }
}

/// Read-only view over an Ethernet frame.
#[derive(Clone, Copy)]
pub struct EthFrame<'a> {
    buf: &'a [u8],
}

impl<'a> EthFrame<'a> {
    /// Parse the header, validating there is at least a full 14-byte header.
    pub fn parse(buf: &'a [u8]) -> Result<Self, ParseError> {
        if buf.len() < ETH_HDR_LEN {
            return Err(ParseError::TooShort {
                what: "ethernet",
                need: ETH_HDR_LEN,
                got: buf.len(),
            });
        }
        Ok(Self { buf })
    }

    #[must_use]
    pub fn dst(&self) -> MacAddr {
        let mut m = [0u8; 6];
        m.copy_from_slice(&self.buf[0..6]);
        MacAddr(m)
    }

    #[must_use]
    pub fn src(&self) -> MacAddr {
        let mut m = [0u8; 6];
        m.copy_from_slice(&self.buf[6..12]);
        MacAddr(m)
    }

    #[must_use]
    pub fn ethertype(&self) -> u16 {
        u16::from_be_bytes([self.buf[12], self.buf[13]])
    }

    /// The L3 payload (everything after the 14-byte header).
    #[must_use]
    pub fn payload(&self) -> &'a [u8] {
        &self.buf[ETH_HDR_LEN..]
    }

    /// The full frame bytes.
    #[must_use]
    pub fn bytes(&self) -> &'a [u8] {
        self.buf
    }
}

/// Mutable view — used to rewrite MACs in place (L2 forwarding).
pub struct EthFrameMut<'a> {
    buf: &'a mut [u8],
}

impl<'a> EthFrameMut<'a> {
    pub fn parse(buf: &'a mut [u8]) -> Result<Self, ParseError> {
        if buf.len() < ETH_HDR_LEN {
            return Err(ParseError::TooShort {
                what: "ethernet",
                need: ETH_HDR_LEN,
                got: buf.len(),
            });
        }
        Ok(Self { buf })
    }

    pub fn set_dst(&mut self, m: MacAddr) {
        self.buf[0..6].copy_from_slice(&m.0);
    }

    pub fn set_src(&mut self, m: MacAddr) {
        self.buf[6..12].copy_from_slice(&m.0);
    }

    pub fn set_ethertype(&mut self, ty: u16) {
        self.buf[12..14].copy_from_slice(&ty.to_be_bytes());
    }

    #[must_use]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.buf[ETH_HDR_LEN..]
    }
}

/// Write an Ethernet II header into the first 14 bytes of `buf`.
/// Returns the number of bytes written (`ETH_HDR_LEN`).
pub fn write_header(buf: &mut [u8], dst: MacAddr, src: MacAddr, ethertype: u16) -> usize {
    buf[0..6].copy_from_slice(&dst.0);
    buf[6..12].copy_from_slice(&src.0);
    buf[12..14].copy_from_slice(&ethertype.to_be_bytes());
    ETH_HDR_LEN
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<u8> {
        let mut v = vec![
            0x02, 0x00, 0x00, 0x00, 0x00, 0x02, // dst
            0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // src
            0x08, 0x00, // ipv4
        ];
        v.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // payload
        v
    }

    #[test]
    fn parse_fields() {
        let v = sample();
        let f = EthFrame::parse(&v).unwrap();
        assert_eq!(f.dst(), MacAddr([0x02, 0, 0, 0, 0, 0x02]));
        assert_eq!(f.src(), MacAddr([0x02, 0, 0, 0, 0, 0x01]));
        assert_eq!(f.ethertype(), ethertype::IPV4);
        assert_eq!(f.payload(), &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn too_short_rejected() {
        assert!(EthFrame::parse(&[0u8; 13]).is_err());
    }

    #[test]
    fn mac_display_and_flags() {
        assert_eq!(
            MacAddr([0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]).to_string(),
            "02:aa:bb:cc:dd:ee"
        );
        assert!(MacAddr::BROADCAST.is_broadcast());
        assert!(MacAddr::BROADCAST.is_multicast());
        assert!(!MacAddr([0x02, 0, 0, 0, 0, 1]).is_multicast());
    }

    #[test]
    fn mac_from_str() {
        assert_eq!(
            "02:aa:bb:cc:dd:ee".parse::<MacAddr>().unwrap(),
            MacAddr([0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee])
        );
        assert_eq!(
            "02-00-00-00-00-01".parse::<MacAddr>().unwrap(),
            MacAddr([0x02, 0, 0, 0, 0, 1])
        );
        assert!("02:aa:bb".parse::<MacAddr>().is_err());
        assert!("zz:aa:bb:cc:dd:ee".parse::<MacAddr>().is_err());
        assert!("02:aa:bb:cc:dd:ee:ff".parse::<MacAddr>().is_err());
    }

    #[test]
    fn write_roundtrip() {
        let mut buf = [0u8; 14];
        write_header(
            &mut buf,
            MacAddr::BROADCAST,
            MacAddr([2, 0, 0, 0, 0, 1]),
            ethertype::ARP,
        );
        let f = EthFrame::parse(&buf).unwrap();
        assert_eq!(f.dst(), MacAddr::BROADCAST);
        assert_eq!(f.ethertype(), ethertype::ARP);
    }
}
