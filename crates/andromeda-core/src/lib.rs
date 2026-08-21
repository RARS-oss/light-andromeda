//! # andromeda-core
//!
//! Dependency-free, zero-copy parsing and building of the packet formats the
//! Light-Andromeda dataplane touches: Ethernet, IPv4, UDP, TCP, and the custom
//! **Andromeda** overlay encapsulation. Everything works over borrowed byte
//! slices — no allocations on the packet path — because this code runs once per
//! packet inside the AF_XDP receive loop.
//!
//! The design rule: the hot path only ever *views* and *patches* bytes in the
//! UMEM frame it was handed. Address/port rewrites use incremental checksum
//! updates (see [`checksum`]) so we never rescan payloads.

#![forbid(unsafe_code)]

use std::fmt;
use std::net::Ipv4Addr;

pub mod arp;
pub mod checksum;
pub mod ethernet;
pub mod ipv4;
pub mod overlay;
pub mod tcp;
pub mod udp;

/// Errors from parsing/validating on-wire structures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Buffer shorter than the minimum header size.
    TooShort {
        what: &'static str,
        need: usize,
        got: usize,
    },
    /// Version nibble did not match the expected protocol version.
    BadVersion { what: &'static str, version: u8 },
    /// A declared header length was nonsensical (too small or past the buffer).
    BadHeaderLen { what: &'static str, len: usize },
    /// An output buffer was too small to build the requested packet.
    BufferTooSmall { need: usize, got: usize },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::TooShort { what, need, got } => {
                write!(f, "{what}: buffer too short (need {need}, got {got})")
            }
            ParseError::BadVersion { what, version } => {
                write!(f, "{what}: unexpected version {version}")
            }
            ParseError::BadHeaderLen { what, len } => {
                write!(f, "{what}: invalid header length {len}")
            }
            ParseError::BufferTooSmall { need, got } => {
                write!(f, "output buffer too small (need {need}, got {got})")
            }
        }
    }
}

impl std::error::Error for ParseError {}

/// The canonical connection key: source/dest IP + L4 protocol + source/dest port.
/// Used by NAT conntrack and as the load-balancing hash input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FiveTuple {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub protocol: u8,
    pub src_port: u16,
    pub dst_port: u16,
}

impl FiveTuple {
    /// Reverse direction: swap src/dst. Used to match reply packets to a conntrack entry.
    #[must_use]
    pub fn reversed(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            protocol: self.protocol,
            src_port: self.dst_port,
            dst_port: self.src_port,
        }
    }
}

impl fmt::Display for FiveTuple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{} -> {}:{} proto={}",
            self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol
        )
    }
}

/// Parse an inner IPv4 packet's 5-tuple, if it is TCP or UDP. Returns `None` for
/// other protocols (ICMP, etc.) where ports are meaningless.
///
/// `ipv4_packet` must start at the IPv4 header.
#[must_use]
pub fn five_tuple_of(ipv4_packet: &[u8]) -> Option<FiveTuple> {
    let ip = ipv4::Ipv4View::parse(ipv4_packet).ok()?;
    let proto = ip.protocol();
    let (src_port, dst_port) = match proto {
        p if p == ipv4::proto::TCP => {
            let t = tcp::TcpView::parse(ip.payload()).ok()?;
            (t.src_port(), t.dst_port())
        }
        p if p == ipv4::proto::UDP => {
            let u = udp::UdpView::parse(ip.payload()).ok()?;
            (u.src_port(), u.dst_port())
        }
        _ => return None,
    };
    Some(FiveTuple {
        src_ip: ip.src(),
        dst_ip: ip.dst(),
        protocol: proto,
        src_port,
        dst_port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn five_tuple_reverse() {
        let t = FiveTuple {
            src_ip: Ipv4Addr::new(10, 0, 0, 1),
            dst_ip: Ipv4Addr::new(10, 0, 0, 2),
            protocol: 6,
            src_port: 1234,
            dst_port: 80,
        };
        let r = t.reversed();
        assert_eq!(r.src_ip, t.dst_ip);
        assert_eq!(r.src_port, t.dst_port);
        assert_eq!(r.reversed(), t);
    }
}
