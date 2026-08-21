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
           andromeda bench [n] [--json]   perf table, mean +/- sd over trials\n  \
           andromeda bench --sweep        working-set sweep (cache-hierarchy experiment)\n  \
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

/// Micro-benchmark the forwarding core (no sockets). Reports mean +/- sample
/// standard deviation and best over repeated trials, so the numbers come with an
/// error bar instead of a single noisy sample. `--sweep` maps throughput against
/// working-set size (the cache-hierarchy experiment); `--json` emits machine-readable data.
struct BenchRow {
    path: &'static str,
    frame_bytes: usize,
    mean_ns: f64,
    std_ns: f64,
    min_ns: f64,
    reps: usize,
}

/// Sample mean, sample standard deviation (n-1), and minimum.
fn stats(s: &[f64]) -> (f64, f64, f64) {
    let n = s.len() as f64;
    let mean = s.iter().sum::<f64>() / n;
    let var = if s.len() > 1 {
        s.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0)
    } else {
        0.0
    };
    let min = s.iter().copied().fold(f64::INFINITY, f64::min);
    (mean, var.sqrt(), min)
}

/// Run `reps` trials of `iters` calls, each processing `n_per` packets; return the
/// per-trial ns-per-packet samples (best of a warmup discarded implicitly by taking
/// the minimum in the caller).
fn measure<F: FnMut() -> bool>(reps: usize, iters: u64, n_per: u64, mut f: F) -> Vec<f64> {
    // One warmup trial (not recorded) to page in and reach steady frequency.
    time_loop(iters, &mut f);
    (0..reps)
        .map(|_| time_loop(iters, &mut f) as f64 / (iters * n_per) as f64)
        .collect()
}

fn bench_cmd(args: &[String]) {
    if args.iter().any(|a| a == "--sweep") {
        return bench_sweep(args.iter().any(|a| a == "--json"));
    }
    use andromeda_core::overlay::OVERLAY_OVERHEAD;
    use andromeda_dataplane::{Decision, FrameSlot};

    let json = args.iter().any(|a| a == "--json");
    let total: u64 = args
        .iter()
        .find(|a| !a.is_empty() && a.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|s| s.parse().ok())
        .unwrap_or(21_000_000);
    const REPS: usize = 7;
    let iters = (total / REPS as u64).max(1);

    let mut rows: Vec<BenchRow> = Vec::new();

    for &payload_len in &[18usize, 1354usize] {
        let frame = udp_tenant_frame("10.0.0.10", "10.0.0.20", 40000, 4242, payload_len);
        let inner_len = frame.len();
        let ioff = OVERLAY_OVERHEAD;

        let mut push = |path, s: Vec<f64>| {
            let (mean, std, min) = stats(&s);
            rows.push(BenchRow {
                path,
                frame_bytes: inner_len,
                mean_ns: mean,
                std_ns: std,
                min_ns: min,
                reps: s.len(),
            });
        };

        let mut ew = build_pipeline(true, false);
        let mut nat = build_pipeline(false, true);
        let mut out = vec![0u8; 2048];
        push(
            "encap copy (east-west)",
            measure(REPS, iters, 1, || {
                matches!(
                    ew.on_tenant_frame(&frame, &mut out, 0),
                    Decision::Forward(_)
                )
            }),
        );
        push(
            "encap copy + SNAT",
            measure(REPS, iters, 1, || {
                matches!(
                    nat.on_tenant_frame(&frame, &mut out, 0),
                    Decision::Forward(_)
                )
            }),
        );

        let mut ewz = build_pipeline(true, false);
        let mut zc = vec![0u8; 2048];
        zc[ioff..ioff + inner_len].copy_from_slice(&frame);
        push(
            "encap zero-copy (1 hot frame)",
            measure(REPS, iters, 1, || {
                matches!(
                    ewz.on_tenant_frame_inplace(&mut zc, inner_len, 0),
                    Decision::Forward(_)
                )
            }),
        );

        const BATCH: usize = 32;
        const STRIDE: usize = 2048;
        let mut ewb = build_pipeline(true, false);
        let mut umem = vec![0u8; BATCH * STRIDE];
        let slots: Vec<FrameSlot> = (0..BATCH)
            .map(|i| {
                let off = i * STRIDE;
                umem[off + ioff..off + ioff + inner_len].copy_from_slice(&frame);
                FrameSlot {
                    offset: off,
                    inner_len,
                }
            })
            .collect();
        let bi = iters / BATCH as u64;
        push(
            "encap zero-copy (batch 32)",
            measure(REPS, bi, BATCH as u64, || {
                ewb.encap_batch_inplace(&mut umem, &slots, 0) == BATCH
            }),
        );

        let mut dz = build_pipeline(true, false);
        let mut wire = vec![0u8; 2048];
        let n = match dz.on_tenant_frame(&frame, &mut wire, 0) {
            Decision::Forward(n) => n,
            _ => 0,
        };
        let encapped: Vec<u8> = wire[..n].to_vec();
        let mut dd = build_pipeline(true, false);
        let mut dout = vec![0u8; 2048];
        push(
            "decap (underlay->tenant)",
            measure(REPS, iters, 1, || {
                matches!(
                    dd.on_underlay_frame(&encapped, &mut dout, 0),
                    Decision::Forward(_)
                )
            }),
        );
    }

    if json {
        print!("[");
        for (i, r) in rows.iter().enumerate() {
            let mpps = 1000.0 / r.mean_ns;
            print!(
                "{}{{\"path\":\"{}\",\"frame_bytes\":{},\"mean_ns\":{:.3},\"std_ns\":{:.3},\"min_ns\":{:.3},\"reps\":{},\"mpps\":{:.2}}}",
                if i == 0 { "" } else { "," }, r.path, r.frame_bytes, r.mean_ns, r.std_ns, r.min_ns, r.reps, mpps
            );
        }
        println!("]");
    } else {
        println!(
            "forwarding-core microbenchmark  (mean +/- sd over {REPS} trials, 1 warmup discarded)"
        );
        let mut last = 0usize;
        for r in &rows {
            if r.frame_bytes != last {
                println!("\ninner frame = {} bytes", r.frame_bytes);
                last = r.frame_bytes;
            }
            let mpps = 1000.0 / r.mean_ns;
            println!(
                "  {:<30} {:6.2} +/- {:.2} ns/pkt  (best {:5.2})   {:6.2} Mpps",
                r.path, r.mean_ns, r.std_ns, r.min_ns, mpps
            );
        }
    }
}

/// Working-set sweep: throughput of the zero-copy batch encap as the resident data
/// grows from a few KB (L1) to tens of MB (DRAM), under two access orders:
/// **sequential** (prefetcher-friendly, as this benchmark packs frames) and
/// **shuffled** (random frame order, defeating the prefetcher — closer to how a NIC
/// hands back recycled UMEM frames). Comparing the two isolates the cache hierarchy's
/// contribution and tests whether the datapath is compute- or memory-bound.
fn bench_sweep(json: bool) {
    use andromeda_core::overlay::OVERLAY_OVERHEAD;
    use andromeda_dataplane::FrameSlot;

    let payload_len = 18usize; // ~64-byte inner frame
    let frame = udp_tenant_frame("10.0.0.10", "10.0.0.20", 40000, 4242, payload_len);
    let inner_len = frame.len();
    let stride = (OVERLAY_OVERHEAD + inner_len).div_ceil(64) * 64; // 128 B, cache-line aligned
    let targets_kb: [usize; 20] = [
        4, 8, 16, 24, 32, 48, 64, 96, 128, 256, 384, 512, 768, 1024, 2048, 4096, 8192, 16384,
        32768, 65536,
    ];

    // Deterministic xorshift Fisher-Yates shuffle (no external rng).
    fn shuffle(v: &mut [FrameSlot]) {
        let mut s: u32 = 0x9e3779b9;
        let mut rng = || {
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            s
        };
        for i in (1..v.len()).rev() {
            let j = (rng() as usize) % (i + 1);
            v.swap(i, j);
        }
    }

    let bench_one = |slots: &[FrameSlot], umem: &mut [u8], n_frames: usize| -> f64 {
        let mut p = build_pipeline(true, false);
        let calls = (40_000_000u64 / n_frames as u64).max(4);
        p.encap_batch_inplace(umem, slots, 0); // warmup
        let mut best = f64::INFINITY;
        for _ in 0..2 {
            let ns = time_loop(calls, || p.encap_batch_inplace(umem, slots, 0) == n_frames);
            best = best.min(ns as f64 / (calls * n_frames as u64) as f64);
        }
        1000.0 / best // Mpps
    };

    if !json {
        println!(
            "working-set sweep: zero-copy batch encap, {inner_len}B inner, {stride}B/frame stride"
        );
        println!("AMD Ryzen 5 5600 — L1d 32KB/core, L2 512KB/core, L3 32MB shared\n");
        println!("  working set     frames    seq Mpps   shuffled Mpps");
    }
    let mut out = String::from("[");
    for (i, &ws_kb) in targets_kb.iter().enumerate() {
        let n_frames = ((ws_kb * 1024) / stride).max(1);
        let mut umem = vec![0u8; n_frames * stride];
        let mut seq: Vec<FrameSlot> = (0..n_frames)
            .map(|j| {
                let off = j * stride;
                umem[off + OVERLAY_OVERHEAD..off + OVERLAY_OVERHEAD + inner_len]
                    .copy_from_slice(&frame);
                FrameSlot {
                    offset: off,
                    inner_len,
                }
            })
            .collect();
        let seq_mpps = bench_one(&seq, &mut umem, n_frames);
        shuffle(&mut seq);
        let shuf_mpps = bench_one(&seq, &mut umem, n_frames);

        if json {
            use std::fmt::Write;
            let _ = write!(
                out,
                "{}{{\"ws_kb\":{},\"frames\":{},\"seq_mpps\":{:.2},\"shuffled_mpps\":{:.2}}}",
                if i == 0 { "" } else { "," },
                ws_kb,
                n_frames,
                seq_mpps,
                shuf_mpps
            );
        } else {
            let ws_label = if ws_kb >= 1024 {
                format!("{} MB", ws_kb / 1024)
            } else {
                format!("{ws_kb} KB")
            };
            println!("  {ws_label:>10}   {n_frames:>9}    {seq_mpps:7.2}      {shuf_mpps:7.2}");
        }
    }
    if json {
        out.push(']');
        println!("{out}");
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
