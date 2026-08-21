//! Minimal ARP (for IPv4-over-Ethernet) parsing and reply generation.
//!
//! The switch runs a *proxy ARP* responder on the tenant port: when a tenant asks
//! "who has 10.0.0.20?", the switch answers with a single virtual gateway MAC. The
//! tenant then sends its frames to that MAC, and the switch rewrites the inner
//! destination MAC to the real endpoint during encapsulation. This is how a
//! distributed overlay gateway removes the need for tenants to know each other's
//! real L2 addresses.

use crate::ethernet::{self, MacAddr};
use crate::ParseError;
use std::net::Ipv4Addr;

/// Length of an Ethernet+IPv4 ARP payload (after the 14-byte Ethernet header).
pub const ARP_LEN: usize = 28;
/// Full frame length of an Ethernet ARP (header + payload).
pub const ARP_FRAME_LEN: usize = ethernet::ETH_HDR_LEN + ARP_LEN;

pub mod oper {
    pub const REQUEST: u16 = 1;
    pub const REPLY: u16 = 2;
}

/// A parsed ARP payload (the 28 bytes after the Ethernet header).
#[derive(Clone, Copy, Debug)]
pub struct ArpView<'a> {
    buf: &'a [u8],
}

impl<'a> ArpView<'a> {
    /// Parse the ARP payload. Only Ethernet/IPv4 ARP (htype=1, ptype=0x0800) is accepted.
    pub fn parse(buf: &'a [u8]) -> Result<Self, ParseError> {
        if buf.len() < ARP_LEN {
            return Err(ParseError::TooShort {
                what: "arp",
                need: ARP_LEN,
                got: buf.len(),
            });
        }
        let htype = u16::from_be_bytes([buf[0], buf[1]]);
        let ptype = u16::from_be_bytes([buf[2], buf[3]]);
        if htype != 1 || ptype != ethernet::ethertype::IPV4 || buf[4] != 6 || buf[5] != 4 {
            return Err(ParseError::BadHeaderLen {
                what: "arp",
                len: buf.len(),
            });
        }
        Ok(Self { buf })
    }

    #[must_use]
    pub fn oper(&self) -> u16 {
        u16::from_be_bytes([self.buf[6], self.buf[7]])
    }
    #[must_use]
    pub fn is_request(&self) -> bool {
        self.oper() == oper::REQUEST
    }
    #[must_use]
    pub fn sender_mac(&self) -> MacAddr {
        let mut m = [0u8; 6];
        m.copy_from_slice(&self.buf[8..14]);
        MacAddr(m)
    }
    #[must_use]
    pub fn sender_ip(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.buf[14], self.buf[15], self.buf[16], self.buf[17])
    }
    #[must_use]
    pub fn target_ip(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.buf[24], self.buf[25], self.buf[26], self.buf[27])
    }
}

/// Build a full Ethernet ARP *reply* into `out`, answering `request` with
/// `answer_mac` as the hardware address of the requested target IP.
///
/// Returns the number of bytes written (`ARP_FRAME_LEN`), or an error if `out` is
/// too small. `request_payload` is the 28-byte ARP payload of the incoming request.
pub fn write_reply(
    out: &mut [u8],
    request_payload: &[u8],
    answer_mac: MacAddr,
) -> Result<usize, ParseError> {
    if out.len() < ARP_FRAME_LEN {
        return Err(ParseError::BufferTooSmall {
            need: ARP_FRAME_LEN,
            got: out.len(),
        });
    }
    let req = ArpView::parse(request_payload)?;
    let requester_mac = req.sender_mac();
    let requester_ip = req.sender_ip();
    let asked_ip = req.target_ip();

    // Ethernet: to the requester, from the virtual gateway.
    ethernet::write_header(
        &mut out[..14],
        requester_mac,
        answer_mac,
        ethernet::ethertype::ARP,
    );

    // ARP payload.
    let p = &mut out[14..ARP_FRAME_LEN];
    p[0..2].copy_from_slice(&1u16.to_be_bytes()); // htype Ethernet
    p[2..4].copy_from_slice(&ethernet::ethertype::IPV4.to_be_bytes()); // ptype IPv4
    p[4] = 6; // hlen
    p[5] = 4; // plen
    p[6..8].copy_from_slice(&oper::REPLY.to_be_bytes());
    p[8..14].copy_from_slice(&answer_mac.0); // sender HW = gateway
    p[14..18].copy_from_slice(&asked_ip.octets()); // sender IP = the IP asked about
    p[18..24].copy_from_slice(&requester_mac.0); // target HW = requester
    p[24..28].copy_from_slice(&requester_ip.octets()); // target IP = requester
    Ok(ARP_FRAME_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arp_request(sender_mac: MacAddr, sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Vec<u8> {
        let mut f = vec![0u8; ARP_FRAME_LEN];
        ethernet::write_header(
            &mut f[..14],
            MacAddr::BROADCAST,
            sender_mac,
            ethernet::ethertype::ARP,
        );
        let p = &mut f[14..];
        p[0..2].copy_from_slice(&1u16.to_be_bytes());
        p[2..4].copy_from_slice(&ethernet::ethertype::IPV4.to_be_bytes());
        p[4] = 6;
        p[5] = 4;
        p[6..8].copy_from_slice(&oper::REQUEST.to_be_bytes());
        p[8..14].copy_from_slice(&sender_mac.0);
        p[14..18].copy_from_slice(&sender_ip.octets());
        // target HW unknown (zero)
        p[24..28].copy_from_slice(&target_ip.octets());
        f
    }

    #[test]
    fn parse_request_fields() {
        let f = arp_request(
            MacAddr([0x02, 0, 0, 0, 0, 0x0a]),
            "10.0.0.10".parse().unwrap(),
            "10.0.0.20".parse().unwrap(),
        );
        let a = ArpView::parse(&f[14..]).unwrap();
        assert!(a.is_request());
        assert_eq!(a.sender_ip(), "10.0.0.10".parse::<Ipv4Addr>().unwrap());
        assert_eq!(a.target_ip(), "10.0.0.20".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn reply_is_well_formed() {
        let req = arp_request(
            MacAddr([0x02, 0, 0, 0, 0, 0x0a]),
            "10.0.0.10".parse().unwrap(),
            "10.0.0.20".parse().unwrap(),
        );
        let vmac = MacAddr([0x02, 0, 0, 0, 0, 0xff]);
        let mut out = vec![0u8; 64];
        let n = write_reply(&mut out, &req[14..], vmac).unwrap();
        assert_eq!(n, ARP_FRAME_LEN);

        let eth = ethernet::EthFrame::parse(&out[..n]).unwrap();
        assert_eq!(eth.ethertype(), ethernet::ethertype::ARP);
        assert_eq!(eth.dst(), MacAddr([0x02, 0, 0, 0, 0, 0x0a])); // back to requester
        assert_eq!(eth.src(), vmac);

        let a = ArpView::parse(eth.payload()).unwrap();
        assert_eq!(a.oper(), oper::REPLY);
        assert_eq!(a.sender_mac(), vmac);
        assert_eq!(a.sender_ip(), "10.0.0.20".parse::<Ipv4Addr>().unwrap()); // answering for the asked IP
        assert_eq!(a.target_ip(), "10.0.0.10".parse::<Ipv4Addr>().unwrap());
    }
}
