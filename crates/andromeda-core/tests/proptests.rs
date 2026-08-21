//! Property-based / fuzz tests for `andromeda-core`.
//!
//! Unit tests check known-good vectors; these check *invariants over a wide space of
//! random inputs* — the kind of coverage that catches the parser that panics on one
//! unusual byte pattern, or the round-trip that loses data for some length. Run with
//! `cargo test -p andromeda-core`; each `proptest!` block runs 256 random cases by
//! default and shrinks any failure to a minimal counterexample.

use andromeda_core::checksum::{checksum, update_word};
use andromeda_core::ethernet::{EthFrame, EthFrameMut, MacAddr};
use andromeda_core::ipv4::{Ipv4View, Ipv4ViewMut};
use andromeda_core::overlay::{self, AndromedaHdr, EncapParams, OVERLAY_OVERHEAD};
use andromeda_core::tcp::TcpView;
use andromeda_core::udp::UdpView;
use andromeda_core::{arp, five_tuple_of};
use proptest::prelude::*;
use std::net::Ipv4Addr;

proptest! {
    /// No parser may ever panic on arbitrary bytes — malformed input must return
    /// `Err`/`None`, never crash. This is the classic fuzz target for a wire parser.
    #[test]
    fn parsers_never_panic(data in prop::collection::vec(any::<u8>(), 0..2048)) {
        let _ = EthFrame::parse(&data);
        let _ = Ipv4View::parse(&data);
        let _ = UdpView::parse(&data);
        let _ = TcpView::parse(&data);
        let _ = arp::ArpView::parse(&data);
        let _ = AndromedaHdr::decode(&data);
        let _ = five_tuple_of(&data);
        let _ = overlay::decap(&data);
        // Mutable views must be equally robust.
        let mut d2 = data.clone();
        let _ = EthFrameMut::parse(&mut d2);
        let _ = Ipv4ViewMut::parse(&mut d2);
    }

    /// Encapsulation is lossless: decapsulating recovers the exact inner frame, VNI,
    /// and flow hash, for any inner payload and any header field values.
    #[test]
    fn encap_decap_roundtrips(
        inner in prop::collection::vec(any::<u8>(), 0..1400),
        vni in 0u32..0x0100_0000,
        flow in any::<u16>(),
        ip_id in any::<u16>(),
    ) {
        let mut out = vec![0u8; OVERLAY_OVERHEAD + inner.len()];
        let params = EncapParams {
            outer_src_mac: MacAddr([2, 0, 0, 0, 0, 1]),
            outer_dst_mac: MacAddr([2, 0, 0, 0, 0, 2]),
            outer_src_ip: Ipv4Addr::new(192, 168, 0, 1),
            outer_dst_ip: Ipv4Addr::new(192, 168, 0, 2),
            vni,
            flow_hash: flow,
            ip_id,
            outer_udp_checksum: true,
        };
        let n = overlay::encap(&mut out, &inner, &params).unwrap();
        prop_assert_eq!(n, OVERLAY_OVERHEAD + inner.len());

        // Outer IPv4 checksum must always be valid.
        let eth = EthFrame::parse(&out[..n]).unwrap();
        let ip = Ipv4View::parse(eth.payload()).unwrap();
        prop_assert!(ip.checksum_valid());

        let d = overlay::decap(&out[..n]).unwrap().unwrap();
        prop_assert_eq!(d.inner, &inner[..]);
        prop_assert_eq!(d.header.vni, vni);
        prop_assert_eq!(d.header.flow_hash, flow);
    }

    /// The Andromeda header survives an encode → decode round trip for all field
    /// values (within their bit widths).
    #[test]
    fn andromeda_header_roundtrips(
        vni in 0u32..0x0100_0000,
        flow in any::<u16>(),
        flags in 0u8..16,
        inner_proto in any::<u8>(),
        hop in any::<u8>(),
    ) {
        let mut h = AndromedaHdr::new(vni, flow);
        h.flags = flags;
        h.inner_proto = inner_proto;
        h.hop_limit = hop;
        let mut buf = [0u8; 8];
        h.encode(&mut buf);
        let got = AndromedaHdr::decode(&buf).unwrap();
        prop_assert_eq!(got, h);
    }

    /// RFC 1624 incremental checksum update equals a full recompute, for an arbitrary
    /// buffer and an arbitrary 16-bit word change at an arbitrary aligned offset.
    #[test]
    fn incremental_checksum_matches_recompute(
        data in prop::collection::vec(any::<u8>(), 2..128),
        widx in any::<usize>(),
        new in any::<u16>(),
    ) {
        // Work on an even-length buffer and an aligned 16-bit word.
        let mut buf = data;
        if buf.len() % 2 == 1 {
            buf.push(0);
        }
        let words = buf.len() / 2;
        let idx = (widx % words) * 2;

        let c0 = checksum(&buf);
        let old = u16::from_be_bytes([buf[idx], buf[idx + 1]]);
        buf[idx..idx + 2].copy_from_slice(&new.to_be_bytes());

        let incremental = update_word(c0, old, new);
        let full = checksum(&buf);
        prop_assert_eq!(incremental, full);
    }

    /// SNAT-style source rewrite keeps the IPv4 header checksum valid for arbitrary
    /// original and new addresses.
    #[test]
    fn ipv4_src_rewrite_keeps_checksum_valid(
        a in any::<u32>(),
        b in any::<u32>(),
        new in any::<u32>(),
    ) {
        // Build a minimal valid IPv4 header (20 bytes) with arbitrary addresses.
        let mut pkt = vec![0u8; 20];
        andromeda_core::ipv4::write_header(
            &mut pkt,
            Ipv4Addr::from(a),
            Ipv4Addr::from(b),
            andromeda_core::ipv4::proto::UDP,
            64,
            1,
            true,
            0,
        );
        prop_assert!(Ipv4View::parse(&pkt).unwrap().checksum_valid());

        {
            let mut v = Ipv4ViewMut::parse(&mut pkt).unwrap();
            v.set_src(Ipv4Addr::from(new));
        }
        let v = Ipv4View::parse(&pkt).unwrap();
        prop_assert_eq!(v.src(), Ipv4Addr::from(new));
        prop_assert!(v.checksum_valid());
    }
}
