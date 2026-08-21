//! `andromeda` — command-line front end for the Light-Andromeda switch.
//!
//! Subcommands: `selftest`, `bench`, `inspect` (no privileges); `run` and `switch`
//! bind AF_XDP to an interface and forward live traffic (feature `afxdp`, Linux +
//! libxdp, needs root).

use andromeda_control::{Endpoint, Fabric, Vpc};
use andromeda_core::ethernet::{self, MacAddr};
use andromeda_dataplane::{Decision, Pipeline, PipelineConfig};
use andromeda_nat::NatEngine;
use std::net::Ipv4Addr;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("selftest") => selftest(),
        Some("bench") => bench_cmd(&args[2..]),
        Some("inspect") => inspect_cmd(&args[2..]),
        Some("run") => run_cmd(&args[2..]),
        Some("switch") => switch_cmd(&args[2..]),
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
    println!(
        "andromeda {} — user-space VPC overlay dataplane",
        env!("CARGO_PKG_VERSION")
    );
}

fn print_help() {
    println!(
        "andromeda — Light-Andromeda switch\n\n\
         USAGE:\n  \
           andromeda selftest\n  \
           andromeda bench [iterations]\n  \
           andromeda inspect [hex]        decode a packet (or a synthesized overlay one)\n  \
           andromeda run <iface> [options]\n  \
           andromeda switch --tenant <if> --underlay <if> [--config f.toml] [options]\n\n\
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
    fabric.add_vpc(Vpc {
        vni: 100,
        name: "demo".into(),
        cidr: ("10.0.0.0".parse().unwrap(), 24),
    });
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
        virtual_gateway_mac: MacAddr([0x02, 0, 0, 0, 0, 0xff]),
        outer_udp_checksum: false,
    };
    let mut p = Pipeline::new(
        cfg,
        fabric,
        NatEngine::new("203.0.113.7".parse().unwrap(), 20000, 30000),
    );

    let inner = demo_frame("10.0.0.10", "10.0.0.20");
    let mut wire = vec![0u8; 2048];
    match p.on_tenant_frame(&inner, &mut wire, 1) {
        Decision::Forward(n) => {
            println!(
                "encapsulated {} inner bytes -> {} wire bytes (VNI 100)",
                inner.len(),
                n
            );
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
    ipv4::write_header(
        &mut ip[..20],
        src,
        dst,
        proto::UDP,
        64,
        1,
        true,
        dg.len() as u16,
    );
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

// ---- inspect subcommand ---------------------------------------------------

/// Decode a packet layer by layer. With no argument, synthesizes a real Andromeda
/// overlay packet and decodes it — handy for seeing the format without a capture.
fn inspect_cmd(args: &[String]) {
    let bytes = match args.first() {
        Some(hex) => match parse_hex(hex) {
            Some(b) => b,
            None => {
                eprintln!("could not parse hex input");
                std::process::exit(2);
            }
        },
        None => {
            println!("(no input given — decoding a synthesized Andromeda overlay packet)\n");
            synth_overlay_packet()
        }
    };
    println!("{} bytes\n", bytes.len());
    decode_frame(&bytes, 0);
}

fn parse_hex(s: &str) -> Option<Vec<u8>> {
    let cleaned: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if cleaned.is_empty() || !cleaned.len().is_multiple_of(2) {
        return None;
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).ok())
        .collect()
}

fn synth_overlay_packet() -> Vec<u8> {
    use andromeda_core::ethernet::MacAddr;
    use andromeda_core::overlay::{self, EncapParams};
    let inner = udp_tenant_frame("10.0.0.10", "10.0.0.20", 40000, 4242, 12);
    let mut out = vec![0u8; overlay::OVERLAY_OVERHEAD + inner.len()];
    let p = EncapParams {
        outer_src_mac: MacAddr([0x02, 0, 0, 0, 0xa1, 0x01]),
        outer_dst_mac: MacAddr([0x02, 0, 0, 0, 0xa1, 0x02]),
        outer_src_ip: "192.168.1.1".parse().unwrap(),
        outer_dst_ip: "192.168.1.2".parse().unwrap(),
        vni: 100,
        flow_hash: overlay::flow_hash(
            "10.0.0.10".parse().unwrap(),
            "10.0.0.20".parse().unwrap(),
            17,
            40000,
            4242,
        ),
        ip_id: 0x4242,
        outer_udp_checksum: true,
    };
    let n = overlay::encap(&mut out, &inner, &p).unwrap();
    out.truncate(n);
    out
}

fn decode_frame(bytes: &[u8], depth: usize) {
    use andromeda_core::arp::ArpView;
    use andromeda_core::ethernet::{ethertype, EthFrame};
    use andromeda_core::ipv4::{proto, Ipv4View};
    use andromeda_core::overlay::{self, AndromedaHdr};
    use andromeda_core::tcp::TcpView;
    use andromeda_core::udp::UdpView;

    let pad = "  ".repeat(depth);
    let Ok(eth) = EthFrame::parse(bytes) else {
        println!("{pad}[!] truncated Ethernet frame");
        return;
    };
    let et = eth.ethertype();
    let etn = match et {
        ethertype::IPV4 => "IPv4",
        ethertype::ARP => "ARP",
        ethertype::IPV6 => "IPv6",
        _ => "?",
    };
    println!(
        "{pad}Ethernet  {} -> {}  ethertype 0x{et:04x} ({etn})",
        eth.src(),
        eth.dst()
    );

    match et {
        ethertype::ARP => {
            if let Ok(a) = ArpView::parse(eth.payload()) {
                let op = if a.is_request() { "request" } else { "reply" };
                println!(
                    "{pad}  ARP {op}: {} ({}) asks/answers {}",
                    a.sender_ip(),
                    a.sender_mac(),
                    a.target_ip()
                );
            }
        }
        ethertype::IPV4 => {
            let Ok(ip) = Ipv4View::parse(eth.payload()) else {
                println!("{pad}  [!] truncated IPv4");
                return;
            };
            let pn = match ip.protocol() {
                proto::TCP => "TCP",
                proto::UDP => "UDP",
                proto::ICMP => "ICMP",
                _ => "?",
            };
            println!(
                "{pad}  IPv4  {} -> {}  proto {} ({pn})  ttl {}  len {}  cksum {}",
                ip.src(),
                ip.dst(),
                ip.protocol(),
                ip.ttl(),
                ip.total_length(),
                if ip.checksum_valid() { "ok" } else { "BAD" },
            );
            match ip.protocol() {
                proto::UDP => {
                    if let Ok(u) = UdpView::parse(ip.payload()) {
                        println!(
                            "{pad}    UDP  {} -> {}  len {}",
                            u.src_port(),
                            u.dst_port(),
                            u.length()
                        );
                        if u.dst_port() == overlay::ANDROMEDA_UDP_PORT {
                            let after = &ip.payload()[andromeda_core::udp::UDP_HDR_LEN..];
                            if let Ok(h) = AndromedaHdr::decode(after) {
                                println!(
                                    "{pad}      Andromeda  v{}  VNI {}  flow 0x{:04x}  hop {}  {}",
                                    h.version,
                                    h.vni,
                                    h.flow_hash,
                                    h.hop_limit,
                                    if h.is_control() { "[control]" } else { "" },
                                );
                                let inner = &after[andromeda_core::overlay::ANDROMEDA_HDR_LEN..];
                                println!("{pad}      -- inner frame --");
                                decode_frame(inner, depth + 4);
                            }
                        }
                    }
                }
                proto::TCP => {
                    if let Ok(t) = TcpView::parse(ip.payload()) {
                        println!(
                            "{pad}    TCP  {} -> {}  seq {}  flags 0x{:02x}",
                            t.src_port(),
                            t.dst_port(),
                            t.seq(),
                            t.flags(),
                        );
                    }
                }
                _ => {}
            }
        }
        _ => {}
    }
}

// ---- bench subcommand -----------------------------------------------------

/// Micro-benchmark the forwarding core (no sockets): how fast can one core parse,
/// (optionally) SNAT, and Andromeda-encapsulate a packet? Pure logic, no root.
fn bench_cmd(args: &[String]) {
    use andromeda_dataplane::Decision;

    let iters: u64 = args
        .first()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5_000_000);

    for &payload_len in &[18usize, 1354usize] {
        // 18 -> ~64B inner frame; 1354 -> ~1400B inner frame.
        let frame = udp_tenant_frame("10.0.0.10", "10.0.0.20", 40000, 4242, payload_len);
        let inner_len = frame.len();

        // east-west encap: destination is a known endpoint (no NAT).
        let mut ew = build_pipeline(true, false);
        // egress + SNAT: destination outside the VPC, gateway + nat configured.
        let mut nat = build_pipeline(false, true);

        let mut out = vec![0u8; 2048];

        let ew_ns = time_loop(iters, || {
            matches!(
                ew.on_tenant_frame(&frame, &mut out, 0),
                Decision::Forward(_)
            )
        });
        let nat_ns = time_loop(iters, || {
            matches!(
                nat.on_tenant_frame(&frame, &mut out, 0),
                Decision::Forward(_)
            )
        });

        // Zero-copy: the inner frame is already in the buffer at the overlay offset
        // (as it would be in an AF_XDP UMEM frame with reserved headroom); encap only
        // stamps the header — no payload copy.
        let ioff = andromeda_core::overlay::OVERLAY_OVERHEAD;
        let mut zc = vec![0u8; 2048];
        zc[ioff..ioff + inner_len].copy_from_slice(&frame);
        let mut ewz = build_pipeline(true, false);
        let zc_ns = time_loop(iters, || {
            matches!(
                ewz.on_tenant_frame_inplace(&mut zc, inner_len, 0),
                Decision::Forward(_)
            )
        });

        println!("\ninner frame = {inner_len} bytes  ({iters} iterations)");
        report("encap (east-west, copy)", ew_ns, iters, inner_len);
        report("encap zero-copy (in-place)", zc_ns, iters, inner_len);
        report("encap + SNAT (egress)", nat_ns, iters, inner_len);
    }
}

fn time_loop<F: FnMut() -> bool>(iters: u64, mut f: F) -> u64 {
    use std::time::Instant;
    let t0 = Instant::now();
    let mut ok = 0u64;
    for _ in 0..iters {
        if f() {
            ok += 1;
        }
    }
    // Guard against the optimizer eliding the loop.
    std::hint::black_box(ok);
    t0.elapsed().as_nanos() as u64
}

fn report(label: &str, total_ns: u64, iters: u64, inner_len: usize) {
    let ns_per = total_ns as f64 / iters as f64;
    let mpps = 1000.0 / ns_per; // 1e9/ns_per packets/s, expressed in Mpps
                                // Throughput of the encapsulated wire bytes.
    let wire = inner_len as f64 + 50.0; // overlay overhead
    let gbps = mpps * 1e6 * wire * 8.0 / 1e9;
    println!("  {label:<24} {ns_per:6.1} ns/pkt   {mpps:6.2} Mpps   {gbps:6.2} Gbit/s (wire)");
}

fn build_pipeline(east_west: bool, snat: bool) -> Pipeline {
    let mut fabric = Fabric::new("192.168.1.1".parse().unwrap());
    fabric.add_vpc(Vpc {
        vni: 100,
        name: "b".into(),
        cidr: ("10.0.0.0".parse().unwrap(), 24),
    });
    if east_west {
        fabric.add_endpoint(Endpoint {
            vni: 100,
            inner_ip: "10.0.0.20".parse().unwrap(),
            inner_mac: MacAddr([0x02, 0, 0, 0, 0, 0x20]),
            node_ip: "192.168.1.2".parse().unwrap(),
            local: false,
        });
    }
    let cfg = PipelineConfig {
        local_node_ip: "192.168.1.1".parse().unwrap(),
        outer_src_mac: MacAddr([0x02, 0, 0, 0, 0, 0x01]),
        outer_dst_mac: MacAddr([0x02, 0, 0, 0, 0, 0x02]),
        vni: 100,
        nat_ip: if snat {
            Some("203.0.113.7".parse().unwrap())
        } else {
            None
        },
        gateway_node_ip: if snat {
            Some("192.168.1.254".parse().unwrap())
        } else {
            None
        },
        virtual_gateway_mac: MacAddr([0x02, 0, 0, 0, 0, 0xff]),
        outer_udp_checksum: false,
    };
    Pipeline::new(
        cfg,
        fabric,
        NatEngine::new("203.0.113.7".parse().unwrap(), 20000, 60000),
    )
}

fn udp_tenant_frame(src: &str, dst: &str, sp: u16, dp: u16, payload_len: usize) -> Vec<u8> {
    use andromeda_core::ipv4::{self, proto};
    use andromeda_core::udp;
    let src: Ipv4Addr = src.parse().unwrap();
    let dst: Ipv4Addr = dst.parse().unwrap();
    let payload = vec![0xabu8; payload_len];
    let mut dg = vec![0u8; udp::UDP_HDR_LEN + payload.len()];
    udp::write_header(&mut dg, sp, dp, payload.len() as u16);
    dg[udp::UDP_HDR_LEN..].copy_from_slice(&payload);
    let c = udp::compute_checksum(src, dst, &dg);
    dg[6..8].copy_from_slice(&c.to_be_bytes());
    let mut ip = vec![0u8; ipv4::IPV4_MIN_HDR_LEN + dg.len()];
    ipv4::write_header(
        &mut ip[..20],
        src,
        dst,
        proto::UDP,
        64,
        1,
        true,
        dg.len() as u16,
    );
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
    fabric.add_vpc(Vpc {
        vni,
        name: format!("vpc-{vni}"),
        cidr: ("0.0.0.0".parse().unwrap(), 0),
    });
    let cfg = PipelineConfig {
        local_node_ip: local_node,
        outer_src_mac: MacAddr([0x02, 0, 0, 0, 0xa1, 0x01]),
        outer_dst_mac: MacAddr([0x02, 0, 0, 0, 0xa1, 0x02]),
        vni,
        nat_ip,
        gateway_node_ip: Some(peer_node),
        virtual_gateway_mac: MacAddr([0x02, 0, 0, 0, 0, 0xff]),
        outer_udp_checksum: false,
    };
    let nat = NatEngine::new(nat_ip.unwrap_or(local_node), 20000, 60000);
    let mut pipeline = Pipeline::new(cfg, fabric, nat);

    let xcfg = XskConfig {
        xdp_mode,
        ..Default::default()
    };
    println!("binding AF_XDP to {iface} queue {queue} (mode={mode:?}, vni={vni}) ...",);
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
    println!(
        "bound. fd={}, free frames={}. Ctrl-C to stop.",
        sock.fd(),
        sock.free_frames()
    );

    afxdp::install_sigint_handler();
    let opts = RunOpts {
        mode,
        max_packets,
        max_secs,
        batch,
    };
    match afxdp::run(&mut sock, &mut pipeline, opts) {
        Ok(stats) => {
            println!("\n--- done ---");
            println!(
                "rx={} tx={} dropped={} decapped={} bytes_in={}",
                stats.rx, stats.tx, stats.dropped, stats.decapped, stats.bytes_in
            );
            println!("pipeline: {:?}", pipeline.stats());
        }
        Err(e) => {
            eprintln!("run error: {e}");
            std::process::exit(1);
        }
    }
}

// ---- switch subcommand (two-interface node) -------------------------------

#[cfg(not(feature = "afxdp"))]
fn switch_cmd(_args: &[String]) {
    eprintln!(
        "the `switch` subcommand needs the AF_XDP datapath.\n\
         rebuild with:  cargo build --release -p andromeda-cli --features afxdp"
    );
    std::process::exit(1);
}

#[cfg(feature = "afxdp")]
fn switch_cmd(args: &[String]) {
    use andromeda_dataplane::afxdp::{self, Mode, RunOpts, XdpMode, XskConfig, XskSocket};

    let mut tenant_if: Option<String> = None;
    let mut underlay_if: Option<String> = None;
    let mut config_path: Option<String> = None;
    let mut vni: u32 = 100;
    let mut local_node: Ipv4Addr = "192.168.1.1".parse().unwrap();
    let mut peer_node: Ipv4Addr = "192.168.1.2".parse().unwrap();
    let mut nat_ip: Option<Ipv4Addr> = None;
    let mut max_secs: Option<u64> = None;
    let mut batch: u32 = 64;
    let mut xdp_mode = XdpMode::Auto;

    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--tenant" => tenant_if = Some(next_str(&mut it, "--tenant")),
            "--underlay" => underlay_if = Some(next_str(&mut it, "--underlay")),
            "--config" => config_path = Some(next_str(&mut it, "--config")),
            "--vni" => vni = next_parse(&mut it, "--vni"),
            "--local-node" => local_node = next_parse(&mut it, "--local-node"),
            "--peer-node" => peer_node = next_parse(&mut it, "--peer-node"),
            "--nat-ip" => nat_ip = Some(next_parse(&mut it, "--nat-ip")),
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

    let (Some(tif), Some(uif)) = (tenant_if, underlay_if) else {
        eprintln!("usage: andromeda switch --tenant <if> --underlay <if> [--config f.toml | --vni N --local-node IP --peer-node IP ...]");
        std::process::exit(2);
    };

    // Build the fabric + pipeline config: from a TOML file if given (endpoints with
    // real MACs → proper inner-MAC rewrite), otherwise from flags.
    let (fabric, cfg, nat) = if let Some(cp) = config_path {
        let nc = match andromeda_control::NodeConfig::load(std::path::Path::new(&cp)) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(2);
            }
        };
        println!(
            "loaded config: vni={} endpoints={} nat={:?}",
            nc.vni,
            nc.endpoints.len(),
            nc.nat_ip
        );
        let cfg = PipelineConfig {
            local_node_ip: nc.local_node,
            outer_src_mac: MacAddr([0x02, 0, 0, 0, 0xa1, 0x01]),
            outer_dst_mac: MacAddr([0x02, 0, 0, 0, 0xa1, 0x02]),
            vni: nc.vni,
            nat_ip: nc.nat_ip,
            gateway_node_ip: nc.peer_node,
            virtual_gateway_mac: nc.virtual_gateway_mac,
            outer_udp_checksum: false,
        };
        let nat = NatEngine::new(nc.nat_ip.unwrap_or(nc.local_node), 20000, 60000);
        (nc.build_fabric(), cfg, nat)
    } else {
        let mut fabric = Fabric::new(local_node);
        fabric.add_vpc(Vpc {
            vni,
            name: format!("vpc-{vni}"),
            cidr: ("0.0.0.0".parse().unwrap(), 0),
        });
        let cfg = PipelineConfig {
            local_node_ip: local_node,
            outer_src_mac: MacAddr([0x02, 0, 0, 0, 0xa1, 0x01]),
            outer_dst_mac: MacAddr([0x02, 0, 0, 0, 0xa1, 0x02]),
            vni,
            nat_ip,
            gateway_node_ip: Some(peer_node),
            virtual_gateway_mac: MacAddr([0x02, 0, 0, 0, 0, 0xff]),
            outer_udp_checksum: false,
        };
        let nat = NatEngine::new(nat_ip.unwrap_or(local_node), 20000, 60000);
        (fabric, cfg, nat)
    };
    let mut pipeline = Pipeline::new(cfg, fabric, nat);

    let xcfg = XskConfig {
        xdp_mode,
        ..Default::default()
    };
    println!("switch: tenant={tif} underlay={uif} vni={vni} local={local_node} peer={peer_node}");
    let mut tenant = match XskSocket::open(&tif, 0, &xcfg) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("open tenant {tif}: {e} (need root; try --skb)");
            std::process::exit(1);
        }
    };
    let mut underlay = match XskSocket::open(&uif, 0, &xcfg) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("open underlay {uif}: {e} (need root; try --skb)");
            std::process::exit(1);
        }
    };
    println!("bound both ports. Ctrl-C to stop.");

    afxdp::install_sigint_handler();
    let opts = RunOpts {
        mode: Mode::Encap,
        max_packets: None,
        max_secs,
        batch,
    };
    match afxdp::run_switch(&mut tenant, &mut underlay, &mut pipeline, opts) {
        Ok(stats) => {
            println!("\n--- done ---");
            println!(
                "rx={} tx={} decapped={} dropped={} bytes_in={}",
                stats.rx, stats.tx, stats.decapped, stats.dropped, stats.bytes_in
            );
            println!("pipeline: {:?}", pipeline.stats());
        }
        Err(e) => {
            eprintln!("switch error: {e}");
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
