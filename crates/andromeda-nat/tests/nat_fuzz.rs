//! Property/fuzz tests for the NAT in-place `apply` path — it mutates
//! attacker-controlled packet bytes, so it must never panic on malformed input.

use andromeda_nat::{apply, Rewrite};
use proptest::prelude::*;
use std::net::Ipv4Addr;

proptest! {
    /// `apply` on arbitrary bytes with an arbitrary rewrite must never panic — it
    /// parses via bounds-checked views and returns `Err` on anything malformed.
    #[test]
    fn nat_apply_never_panics(
        pkt in prop::collection::vec(any::<u8>(), 0..512),
        addr in any::<u32>(),
        sp in any::<u16>(),
        dp in any::<u16>(),
        do_src in any::<bool>(),
        do_dst in any::<bool>(),
        do_sp in any::<bool>(),
        do_dp in any::<bool>(),
    ) {
        let mut buf = pkt;
        let rw = Rewrite {
            new_src_ip: do_src.then(|| Ipv4Addr::from(addr)),
            new_dst_ip: do_dst.then(|| Ipv4Addr::from(!addr)),
            new_src_port: do_sp.then_some(sp),
            new_dst_port: do_dp.then_some(dp),
        };
        // Must not panic; a malformed packet just returns Err.
        let _ = apply(&mut buf, &rw);
    }
}
