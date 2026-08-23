//! ICMPv4 "Destination Unreachable — Fragmentation Needed" (Type 3, Code 4).
//!
//! Used by the overlay's Path-MTU Discovery. The overlay prepends 50 bytes; when a
//! tenant sends a `DF` (don't-fragment) datagram too large to fit under that header on
//! the underlay MTU, the switch must not silently blackhole it. Instead it replies with
//! this ICMP, carrying the next-hop MTU (RFC 1191), so the tenant's TCP lowers its MSS
//! and large sessions keep flowing instead of stalling.

use crate::checksum;
use crate::ethernet::{self, MacAddr};
use crate::ipv4::{self, Ipv4View};
use crate::ParseError;
use std::net::Ipv4Addr;

/// Bytes in the fixed ICMP header (type, code, checksum, unused/next-hop-mtu).
pub const ICMP_HDR_LEN: usize = 8;

pub mod icmp_type {
    /// Destination Unreachable.
    pub const DEST_UNREACHABLE: u8 = 3;
}
pub mod icmp_code {
    /// Fragmentation needed and Don't-Fragment set (the PMTUD code).
    pub const FRAG_NEEDED: u8 = 4;
}

/// Build, into `out`, a complete inner L2 frame carrying an ICMPv4 "Fragmentation
/// Needed" (Type 3, Code 4) addressed back to the sender of `orig_frame`.
///
/// `orig_frame` is the tenant's original Ethernet frame (Eth + IPv4 + …). The reply is
/// `Eth(src=gateway_mac, dst=orig sender MAC) / IPv4(src=gateway_ip, dst=orig source) /
/// ICMP(next_hop_mtu, then the original IP header + first 8 bytes of its payload)` — the
/// quoted datagram per RFC 792, and the next-hop MTU in the low 16 bits per RFC 1191.
/// Returns the number of bytes written. Never panics: a malformed or too-short input
/// returns `Err`.
pub fn write_frag_needed(
    out: &mut [u8],
    orig_frame: &[u8],
    gateway_mac: MacAddr,
    gateway_ip: Ipv4Addr,
    next_hop_mtu: u16,
) -> Result<usize, ParseError> {
    let eth = ethernet::EthFrame::parse(orig_frame)?;
    let ip = Ipv4View::parse(eth.payload())?;

    // RFC 792 / RFC 1191: quote the offending IP header + the first 8 bytes after it
    // (enough for TCP/UDP ports so the tenant can match the connection), clamped to
    // whatever is actually present.
    let ip_bytes = ip.bytes();
    let quote_len = (ip.ihl_bytes() + 8).min(ip_bytes.len());

    let eth_end = ethernet::ETH_HDR_LEN;
    let ip_end = eth_end + ipv4::IPV4_MIN_HDR_LEN;
    let icmp_end = ip_end + ICMP_HDR_LEN + quote_len;
    if out.len() < icmp_end {
        return Err(ParseError::BufferTooSmall {
            need: icmp_end,
            got: out.len(),
        });
    }

    // Inner Ethernet: from the virtual gateway back to the original sender.
    ethernet::write_header(
        &mut out[..eth_end],
        eth.src(),
        gateway_mac,
        ethernet::ethertype::IPV4,
    );

    // IPv4: gateway → original source, proto ICMP. The ICMP message itself is small and
    // must not be marked DF.
    let icmp_len = ICMP_HDR_LEN + quote_len;
    ipv4::write_header(
        &mut out[eth_end..ip_end],
        gateway_ip,
        ip.src(),
        ipv4::proto::ICMP,
        64,
        0,
        false,
        icmp_len as u16,
    );

    // ICMP: type / code / checksum / unused(2) / next-hop-MTU(2), then the quoted datagram.
    {
        let icmp = &mut out[ip_end..icmp_end];
        icmp[0] = icmp_type::DEST_UNREACHABLE;
        icmp[1] = icmp_code::FRAG_NEEDED;
        icmp[2] = 0; // checksum, computed below
        icmp[3] = 0;
        icmp[4] = 0; // unused (must be zero)
        icmp[5] = 0;
        icmp[6..8].copy_from_slice(&next_hop_mtu.to_be_bytes());
        icmp[ICMP_HDR_LEN..].copy_from_slice(&ip_bytes[..quote_len]);
    }
    let c = checksum::checksum(&out[ip_end..icmp_end]);
    out[ip_end + 2..ip_end + 4].copy_from_slice(&c.to_be_bytes());

    Ok(icmp_end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ethernet::MacAddr;

    /// Build a plausible tenant frame: Eth / IPv4(TCP) with a payload.
    fn tenant_frame() -> Vec<u8> {
        let mut f = vec![0u8; 14 + 20 + 20 + 40];
        ethernet::write_header(
            &mut f[..14],
            MacAddr([2, 0, 0, 0, 0, 0xff]), // dst = gateway
            MacAddr([2, 0, 0, 0, 0, 0x0a]), // src = tenant
            ethernet::ethertype::IPV4,
        );
        ipv4::write_header(
            &mut f[14..34],
            "10.0.0.10".parse().unwrap(),
            "10.0.0.20".parse().unwrap(),
            ipv4::proto::TCP,
            64,
            0x1234,
            true,
            (20 + 40) as u16,
        );
        // A couple of recognizable TCP ports in the first 8 payload bytes.
        f[34..36].copy_from_slice(&1234u16.to_be_bytes());
        f[36..38].copy_from_slice(&80u16.to_be_bytes());
        f
    }

    #[test]
    fn frag_needed_is_well_formed() {
        let orig = tenant_frame();
        let mut out = vec![0u8; 1500];
        let n = write_frag_needed(
            &mut out,
            &orig,
            MacAddr([2, 0, 0, 0, 0, 0xff]),
            "10.0.0.1".parse().unwrap(),
            1450,
        )
        .unwrap();

        let eth = ethernet::EthFrame::parse(&out[..n]).unwrap();
        assert_eq!(eth.ethertype(), ethernet::ethertype::IPV4);
        // Reply goes back to the tenant, from the gateway MAC.
        assert_eq!(eth.dst(), MacAddr([2, 0, 0, 0, 0, 0x0a]));
        assert_eq!(eth.src(), MacAddr([2, 0, 0, 0, 0, 0xff]));

        let ip = Ipv4View::parse(eth.payload()).unwrap();
        assert_eq!(ip.protocol(), ipv4::proto::ICMP);
        assert_eq!(ip.src(), "10.0.0.1".parse::<Ipv4Addr>().unwrap()); // gateway
        assert_eq!(ip.dst(), "10.0.0.10".parse::<Ipv4Addr>().unwrap()); // original source
        assert!(ip.checksum_valid(), "outer IP checksum must be valid");

        let icmp = ip.payload();
        assert_eq!(icmp[0], icmp_type::DEST_UNREACHABLE);
        assert_eq!(icmp[1], icmp_code::FRAG_NEEDED);
        assert_eq!(u16::from_be_bytes([icmp[6], icmp[7]]), 1450); // next-hop MTU
                                                                  // The quote begins with the original IP header (starts with 0x45).
        assert_eq!(icmp[ICMP_HDR_LEN], 0x45);
        // And carries the original ports (bytes 8..10 of the quoted IP payload).
        let ports_off = ICMP_HDR_LEN + 20;
        assert_eq!(
            u16::from_be_bytes([icmp[ports_off], icmp[ports_off + 1]]),
            1234
        );
    }

    #[test]
    fn frag_needed_icmp_checksum_valid() {
        let orig = tenant_frame();
        let mut out = vec![0u8; 1500];
        let n = write_frag_needed(
            &mut out,
            &orig,
            MacAddr([2, 0, 0, 0, 0, 0xff]),
            "10.0.0.1".parse().unwrap(),
            1450,
        )
        .unwrap();
        let ip = Ipv4View::parse(&out[14..n]).unwrap();
        // ICMP checksum covers the whole ICMP message; a valid message sums to 0.
        assert_eq!(checksum::checksum(ip.payload()), 0);
    }

    #[test]
    fn too_small_buffer_errs_without_panic() {
        let orig = tenant_frame();
        let mut out = vec![0u8; 20]; // far too small
        assert!(write_frag_needed(
            &mut out,
            &orig,
            MacAddr([2, 0, 0, 0, 0, 0xff]),
            "10.0.0.1".parse().unwrap(),
            1450,
        )
        .is_err());
    }

    #[test]
    fn garbage_input_errs_without_panic() {
        let mut out = vec![0u8; 1500];
        // Too short to be an Ethernet+IPv4 frame.
        assert!(write_frag_needed(
            &mut out,
            &[0u8; 10],
            MacAddr([2, 0, 0, 0, 0, 0xff]),
            "10.0.0.1".parse().unwrap(),
            1450,
        )
        .is_err());
    }
}
