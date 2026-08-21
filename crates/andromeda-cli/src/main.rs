//! `andromeda` — command-line front end for the Light-Andromeda switch.
//!
//! This is a placeholder entry point. The AF_XDP `run` subcommand (attach to an
//! interface, spin the RX/TX rings, drive the pipeline) is wired in the next
//! iteration; today it exercises the pipeline over an in-memory frame so the
//! binary does something real end-to-end.

use andromeda_control::{Endpoint, Fabric, Vpc};
use andromeda_core::ethernet::{self, MacAddr};
use andromeda_dataplane::{Decision, Pipeline, PipelineConfig};
use andromeda_nat::NatEngine;
use std::net::Ipv4Addr;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("selftest") => selftest(),
        Some("version") | None => {
            println!("andromeda {} — user-space VPC overlay dataplane", env!("CARGO_PKG_VERSION"));
            println!("subcommands: selftest | version   (run <iface> lands next iteration)");
        }
        Some(other) => {
            eprintln!("unknown subcommand: {other}");
            std::process::exit(2);
        }
    }
}

/// Push one tenant frame through a two-node pipeline and report the result.
fn selftest() {
    let mut fabric = Fabric::new("192.168.1.1".parse().unwrap());
    fabric.add_vpc(Vpc { vni: 100, name: "demo".into(), cidr: ("10.0.0.0".parse().unwrap(), 24) });
    fabric.add_endpoint(Endpoint {
        vni: 100,
        inner_ip: "10.0.0.20".parse().unwrap(),
        inner_mac: MacAddr([0x02, 0, 0, 0, 0, 0x20]),
        node_ip: "192.168.1.2".parse().unwrap(),
        local: false,
    });
    let cfg = PipelineConfig {
        local_node_ip: "192.168.1.1".parse().unwrap(),
        outer_src_mac: MacAddr([0x02, 0, 0, 0, 0, 0x01]),
        outer_dst_mac: MacAddr([0x02, 0, 0, 0, 0, 0x02]),
        vni: 100,
        nat_ip: None,
        gateway_node_ip: None,
    };
    let mut p = Pipeline::new(cfg, fabric, NatEngine::new("203.0.113.7".parse().unwrap(), 20000, 30000));

    let inner = demo_frame("10.0.0.10", "10.0.0.20");
    let mut wire = vec![0u8; 2048];
    match p.on_tenant_frame(&inner, &mut wire, 1) {
        Decision::Forward(n) => {
            println!("encapsulated {} inner bytes -> {} wire bytes (VNI 100)", inner.len(), n);
            println!("stats: {:?}", p.stats());
        }
        other => println!("unexpected: {other:?}"),
    }
}

fn demo_frame(src: &str, dst: &str) -> Vec<u8> {
    use andromeda_core::ipv4::{self, proto};
    let src: Ipv4Addr = src.parse().unwrap();
    let dst: Ipv4Addr = dst.parse().unwrap();
    let payload = b"hello from the tenant";
    let mut ip = vec![0u8; ipv4::IPV4_MIN_HDR_LEN + payload.len()];
    ipv4::write_header(&mut ip[..20], src, dst, proto::UDP, 64, 1, true, payload.len() as u16);
    ip[20..].copy_from_slice(payload);
    let mut frame = vec![0u8; ethernet::ETH_HDR_LEN + ip.len()];
    ethernet::write_header(
        &mut frame[..14],
        MacAddr([0x02, 0, 0, 0, 0, 0x0b]),
        MacAddr([0x02, 0, 0, 0, 0, 0x0a]),
        ethernet::ethertype::IPV4,
    );
    frame[14..].copy_from_slice(&ip);
    frame
}
