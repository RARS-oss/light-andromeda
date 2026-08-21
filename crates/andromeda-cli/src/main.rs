//! `andromeda` — command-line front end for the Light-Andromeda switch.
//!
//! * `selftest`            — run the pipeline over an in-memory frame (no privileges).
//! * `run <iface> ...`     — bind AF_XDP to an interface and forward live traffic
//!                           (feature `afxdp`, Linux + libxdp, needs root).

use andromeda_control::{Endpoint, Fabric, Vpc};
use andromeda_core::ethernet::{self, MacAddr};
use andromeda_dataplane::{Decision, Pipeline, PipelineConfig};
use andromeda_nat::NatEngine;
use std::net::Ipv4Addr;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("selftest") => selftest(),
        Some("run") => run_cmd(&args[2..]),
        Some("version") | Some("--version") | None => print_version(),
        Some("help") | Some("--help") | Some("-h") => print_help(),
        Some(other) => {
            eprintln!("unknown subcommand: {other}\n");
            print_help();
            std::process::exit(2);
        }
    }
}

fn print_version() {
    println!("andromeda {} — user-space VPC overlay dataplane", env!("CARGO_PKG_VERSION"));
}

fn print_help() {
    println!(
        "andromeda — Light-Andromeda switch\n\n\
         USAGE:\n  \
           andromeda selftest\n  \
           andromeda run <iface> [options]\n\n\
         run options:\n  \
           --queue <n>         RX/TX queue id (default 0)\n  \
           --mode <m>          dump | encap | decap (default dump)\n  \
           --vni <n>           virtual network id (default 100)\n  \
           --local-node <ip>   this switch's underlay IP (default 192.168.1.1)\n  \
           --peer-node <ip>    encap destination / default gateway (default 192.168.1.2)\n  \
           --nat-ip <ip>       enable SNAT to this address on egress\n  \
           --count <n>         stop after n received frames\n  \
           --secs <n>          stop after n seconds\n  \
           --batch <n>         RX/TX batch size (default 64)\n  \
           --skb               force generic/SKB XDP mode\n  \
           --drv               force native/driver XDP mode\n\n\
         'run' requires the binary built with --features afxdp and CAP_NET_ADMIN (root)."
    );
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
    use andromeda_core::udp;
    let src: Ipv4Addr = src.parse().unwrap();
    let dst: Ipv4Addr = dst.parse().unwrap();
    let payload = b"hello from the tenant";
    let mut dg = vec![0u8; udp::UDP_HDR_LEN + payload.len()];
    udp::write_header(&mut dg, 40000, 4242, payload.len() as u16);
    dg[udp::UDP_HDR_LEN..].copy_from_slice(payload);
    let c = udp::compute_checksum(src, dst, &dg);
    dg[6..8].copy_from_slice(&c.to_be_bytes());

    let mut ip = vec![0u8; ipv4::IPV4_MIN_HDR_LEN + dg.len()];
    ipv4::write_header(&mut ip[..20], src, dst, proto::UDP, 64, 1, true, dg.len() as u16);
    ip[20..].copy_from_slice(&dg);

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

// ---- run subcommand -------------------------------------------------------

#[cfg(not(feature = "afxdp"))]
fn run_cmd(_args: &[String]) {
    eprintln!(
        "the `run` subcommand needs the AF_XDP datapath.\n\
         rebuild with:  cargo build --release -p andromeda-cli --features afxdp\n\
         then run as root:  sudo ./andromeda run <iface> --mode encap"
    );
    std::process::exit(1);
}

#[cfg(feature = "afxdp")]
fn run_cmd(args: &[String]) {
    use andromeda_dataplane::afxdp::{self, Mode, RunOpts, XdpMode, XskConfig, XskSocket};

    let Some(iface) = args.first().filter(|a| !a.starts_with("--")).cloned() else {
        eprintln!("usage: andromeda run <iface> [options]  (see `andromeda help`)");
        std::process::exit(2);
    };

    // Defaults.
    let mut queue: u32 = 0;
    let mut mode = Mode::Dump;
    let mut vni: u32 = 100;
    let mut local_node: Ipv4Addr = "192.168.1.1".parse().unwrap();
    let mut peer_node: Ipv4Addr = "192.168.1.2".parse().unwrap();
    let mut nat_ip: Option<Ipv4Addr> = None;
    let mut max_packets: Option<u64> = None;
    let mut max_secs: Option<u64> = None;
    let mut batch: u32 = 64;
    let mut xdp_mode = XdpMode::Auto;

    let mut it = args[1..].iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--queue" => queue = next_parse(&mut it, "--queue"),
            "--mode" => {
                mode = match next_str(&mut it, "--mode").as_str() {
                    "dump" => Mode::Dump,
                    "encap" => Mode::Encap,
                    "decap" => Mode::Decap,
                    other => {
                        eprintln!("bad --mode {other}");
                        std::process::exit(2);
                    }
                }
            }
            "--vni" => vni = next_parse(&mut it, "--vni"),
            "--local-node" => local_node = next_parse(&mut it, "--local-node"),
            "--peer-node" => peer_node = next_parse(&mut it, "--peer-node"),
            "--nat-ip" => nat_ip = Some(next_parse(&mut it, "--nat-ip")),
            "--count" => max_packets = Some(next_parse(&mut it, "--count")),
            "--secs" => max_secs = Some(next_parse(&mut it, "--secs")),
            "--batch" => batch = next_parse(&mut it, "--batch"),
            "--skb" => xdp_mode = XdpMode::Skb,
            "--drv" => xdp_mode = XdpMode::Drv,
            other => {
                eprintln!("unknown option: {other}");
                std::process::exit(2);
            }
        }
    }

    // Build the pipeline: no endpoints, so every inner IPv4 packet is encapsulated
    // toward the peer node (default route); NAT applied on egress if --nat-ip given.
    let mut fabric = Fabric::new(local_node);
    fabric.add_vpc(Vpc { vni, name: format!("vpc-{vni}"), cidr: ("0.0.0.0".parse().unwrap(), 0) });
    let cfg = PipelineConfig {
        local_node_ip: local_node,
        outer_src_mac: MacAddr([0x02, 0, 0, 0, 0xa1, 0x01]),
        outer_dst_mac: MacAddr([0x02, 0, 0, 0, 0xa1, 0x02]),
        vni,
        nat_ip,
        gateway_node_ip: Some(peer_node),
    };
    let nat = NatEngine::new(nat_ip.unwrap_or(local_node), 20000, 60000);
    let mut pipeline = Pipeline::new(cfg, fabric, nat);

    let xcfg = XskConfig { xdp_mode, ..Default::default() };
    println!(
        "binding AF_XDP to {iface} queue {queue} (mode={mode:?}, vni={vni}) ...",
    );
    let mut sock = match XskSocket::open(&iface, queue, &xcfg) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("failed to open AF_XDP socket on {iface}: {e}");
            if e.raw_os_error() == Some(1) {
                eprintln!("(EPERM: run as root, e.g. `sudo andromeda run ...`)");
            }
            eprintln!("tip: try `--skb` if the driver rejects native XDP.");
            std::process::exit(1);
        }
    };
    println!("bound. fd={}, free frames={}. Ctrl-C to stop.", sock.fd(), sock.free_frames());

    afxdp::install_sigint_handler();
    let opts = RunOpts { mode, max_packets, max_secs, batch };
    match afxdp::run(&mut sock, &mut pipeline, opts) {
        Ok(stats) => {
            println!("\n--- done ---");
            println!("rx={} tx={} dropped={} decapped={} bytes_in={}",
                stats.rx, stats.tx, stats.dropped, stats.decapped, stats.bytes_in);
            println!("pipeline: {:?}", pipeline.stats());
        }
        Err(e) => {
            eprintln!("run error: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(feature = "afxdp")]
fn next_str<'a>(it: &mut impl Iterator<Item = &'a String>, flag: &str) -> String {
    match it.next() {
        Some(v) => v.clone(),
        None => {
            eprintln!("missing value for {flag}");
            std::process::exit(2);
        }
    }
}

#[cfg(feature = "afxdp")]
fn next_parse<'a, T>(it: &mut impl Iterator<Item = &'a String>, flag: &str) -> T
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let s = next_str(it, flag);
    match s.parse::<T>() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("bad value for {flag}: {s} ({e})");
            std::process::exit(2);
        }
    }
}
