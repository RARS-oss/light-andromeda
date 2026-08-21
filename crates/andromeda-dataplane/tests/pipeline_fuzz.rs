//! Property/fuzz tests for the forwarding pipeline. The pipeline is fed
//! attacker-controlled frames from the wire, so none of its entry points may panic
//! on arbitrary bytes — including the raw slice arithmetic in the encap/decap paths.

use andromeda_control::{Endpoint, Fabric, Vpc};
use andromeda_core::ethernet::MacAddr;
use andromeda_core::overlay::OVERLAY_OVERHEAD;
use andromeda_dataplane::{FrameSlot, Pipeline, PipelineConfig};
use andromeda_nat::NatEngine;
use proptest::prelude::*;

fn pipeline() -> Pipeline {
    let mut fabric = Fabric::new("192.168.1.1".parse().unwrap());
    fabric.add_vpc(Vpc {
        vni: 100,
        name: "t".into(),
        cidr: ("10.0.0.0".parse().unwrap(), 24),
    });
    fabric.add_endpoint(Endpoint {
        vni: 100,
        inner_ip: "10.0.0.20".parse().unwrap(),
        inner_mac: MacAddr([2, 0, 0, 0, 0, 0x20]),
        node_ip: "192.168.1.2".parse().unwrap(),
        local: false,
    });
    let cfg = PipelineConfig {
        local_node_ip: "192.168.1.1".parse().unwrap(),
        outer_src_mac: MacAddr([2, 0, 0, 0, 0, 1]),
        outer_dst_mac: MacAddr([2, 0, 0, 0, 0, 2]),
        vni: 100,
        nat_ip: Some("203.0.113.7".parse().unwrap()),
        gateway_node_ip: Some("192.168.1.254".parse().unwrap()),
        virtual_gateway_mac: MacAddr([2, 0, 0, 0, 0, 0xff]),
        outer_udp_checksum: false,
    };
    Pipeline::new(
        cfg,
        fabric,
        NatEngine::new("203.0.113.7".parse().unwrap(), 20000, 60000),
    )
}

proptest! {
    /// No pipeline entry point panics on arbitrary frames (tenant encap, underlay
    /// decap, zero-copy in-place encap, and the batch path).
    #[test]
    fn pipeline_never_panics(data in prop::collection::vec(any::<u8>(), 0..1600)) {
        let mut p = pipeline();
        let mut out = vec![0u8; 2048];
        let _ = p.on_tenant_frame(&data, &mut out, 0);
        let _ = p.on_underlay_frame(&data, &mut out, 0);

        // Zero-copy variants: place the random bytes as the inner frame in a UMEM-like
        // buffer and exercise the in-place and batch encap paths.
        let inner_len = data.len().min(2048 - OVERLAY_OVERHEAD);
        let mut buf = vec![0u8; 2048];
        buf[OVERLAY_OVERHEAD..OVERLAY_OVERHEAD + inner_len].copy_from_slice(&data[..inner_len]);
        let _ = p.on_tenant_frame_inplace(&mut buf, inner_len, 0);
        let slots = [FrameSlot { offset: 0, inner_len }];
        let _ = p.encap_batch_inplace(&mut buf, &slots, 0);
    }

    /// `encap_for_vni` (the multi-VPC entry) must not panic for any VNI or frame.
    #[test]
    fn encap_for_vni_never_panics(
        data in prop::collection::vec(any::<u8>(), 0..1600),
        vni in 0u32..0x0100_0000,
    ) {
        let mut p = pipeline();
        let mut out = vec![0u8; 2048];
        let _ = p.encap_for_vni(&data, &mut out, 0, vni);
    }
}
