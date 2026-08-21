# Light-Andromeda

**A user-space, kernel-bypass network-virtualization dataplane — a miniature of the
software-defined networking layer cloud providers run under every VM.**

Light-Andromeda takes tenant traffic, wraps it in a custom L2-over-UDP overlay
(its own 8-byte *Andromeda* header, in the spirit of VXLAN/GENEVE and Google's
[Andromeda](https://research.google/pubs/andromeda-performance-isolation-and-velocity-at-scale-in-cloud-network-virtualization/)
SDN stack), forwards it between nodes according to a centrally-programmed fabric
map, and performs stateful **SNAT/DNAT** on the fly — all in user space, with the
packet path built to run on top of **AF_XDP** so frames bypass the host kernel's
network stack entirely.

> Portfolio note: this project exists to demonstrate that I understand how modern
> cloud hypervisors and SDN work at the host level — wire formats parsed byte by
> byte, incremental checksum math, connection tracking, overlay encapsulation, and
> zero-copy user-space packet processing.

---

## Why this is interesting (the concepts on display)

| Concept | Where it lives |
|---|---|
| **OS bypass / user-space packet processing** | AF_XDP RX/TX rings over a shared UMEM (dataplane crate) |
| **Manual wire-format parsing** | `andromeda-core`: Ethernet / IPv4 / UDP / TCP parsed and built by hand, zero-copy over borrowed byte slices |
| **Incremental checksums (RFC 1624)** | Address/port rewrites patch L3+L4 checksums by 16-bit delta instead of rescanning payloads |
| **Overlay encapsulation (VPC)** | Custom Andromeda header carrying a 24-bit VNI + a flow hash for ECMP spreading |
| **SDN control plane** | A fabric map: `(VNI, inner-IP) → underlay node + inner MAC`, distributed to every switch |
| **Stateful NAT** | SNAT/PAT with a port allocator and conntrack; DNAT port-forwarding with reverse bindings |
| **Systems Rust** | `#![forbid(unsafe_code)]` in the core, allocation-free hot path, workspace of focused crates |

---

## Architecture

```
        VPC 100 (10.0.0.0/24)                             VPC 100 (10.0.0.0/24)
   ┌───────────────────────────┐                     ┌───────────────────────────┐
   │  tenant 10.0.0.10          │                     │  tenant 10.0.0.20          │
   │        │ inner Eth frame   │                     │        ▲ inner Eth frame   │
   │        ▼                   │                     │        │                   │
   │  ┌───────────────┐         │   Andromeda overlay │   ┌───────────────┐        │
   │  │  andromeda     │  encap  │   (L2-over-UDP)     │   │  andromeda    │ decap  │
   │  │  switch (XDP)  │─────────┼─────────────────────┼──▶│  switch (XDP) │        │
   │  └───────────────┘         │   UDP :43481        │   └───────────────┘        │
   │   node 192.168.1.1         │   VNI=100           │    node 192.168.1.2        │
   └───────────────────────────┘                     └───────────────────────────┘
            underlay  ◀───────────  physical / veth fabric  ───────────▶  underlay

   Encapsulated frame on the wire:
   ┌────────────┬────────────┬──────────┬────────────────┬───────────────────────┐
   │ outer Eth  │ outer IPv4 │ outer UDP│ Andromeda hdr  │  inner Ethernet frame  │
   │  14 bytes  │  20 bytes  │  8 bytes │    8 bytes     │  (the tenant's packet) │
   └────────────┴────────────┴──────────┴────────────────┴───────────────────────┘
                                          └── 50 bytes of overlay overhead ──┘
```

### The Andromeda header (8 bytes)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Ver | Flags |  Inner proto  |           Flow hash           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     VNI (24 bits)              |  Hop limit  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

* **Ver** — header version (currently 1).
* **Flags** — `CONTROL` (control-plane message), `OAM` (reserved liveness channel).
* **Inner proto** — `0` = inner Ethernet (L2 overlay), `1` = bare IPv4 (L3 overlay).
* **Flow hash** — 16-bit FNV-1a over the inner 5-tuple; also copied into the outer
  UDP source port so the *underlay's* own ECMP spreads a tenant's flows across paths.
* **VNI** — 24-bit virtual network id (the tenant/VPC).
* **Hop limit** — overlay TTL, guards against encapsulation loops.

---

## Repository layout

```
light-andromeda/
├── crates/
│   ├── andromeda-core/       # zero-copy Eth/IPv4/UDP/TCP/ARP parsing + Andromeda encap + checksums
│   ├── andromeda-nat/        # stateful SNAT/PAT + DNAT with conntrack
│   ├── andromeda-control/    # VPC/endpoint model, TOML fabric config, forwarding lookup (SDN map)
│   ├── andromeda-dataplane/  # forwarding pipeline + AF_XDP ring loop (csrc/xsk_shim.c)
│   └── andromeda-cli/        # `andromeda`: selftest / bench / inspect / run / switch
├── configs/                  # example fabric TOML configs
├── scripts/                  # veth/netns demos (single-node + two-node)
└── docs/                     # architecture + design notes
```

Each crate is small and single-purpose, and the two hardest, most reusable pieces
(`core` and `nat`) are dependency-free and fully unit-tested.

---

## Status

**Done and tested (40 unit tests, all green; `cargo fmt` + `clippy -D warnings` clean, CI on GitHub Actions):**

- [x] Byte-exact Ethernet / IPv4 / UDP / TCP parsing and building
- [x] Internet checksum + incremental update (verified against full recompute)
- [x] Andromeda overlay encap/decap round-trip with valid outer checksums
- [x] Stateful SNAT/PAT with port allocation, conntrack, and reverse translation
- [x] DNAT port-forwarding with server-reply un-NAT
- [x] Control-plane fabric map and cross-node forwarding resolution
- [x] End-to-end forwarding pipeline (tenant→encap→peer→decap) over in-memory buffers

- [x] **AF_XDP socket layer**: UMEM + FILL/COMPLETION/RX/TX rings via a thin FFI
      shim over the system `libxdp`; real kernel bypass, verified on Linux 6.6
- [x] `andromeda run <iface>`: attach to an interface and forward live traffic
      (`--mode dump|encap|decap`)
- [x] veth/netns demo script proving bypass + capturing the overlay on the wire

- [x] **Two-interface switch** (`andromeda switch --tenant <if> --underlay <if>`):
      full tenant→encap→underlay→decap→tenant path — a **real ping travels through
      the overlay** across two independent user-space switches
- [x] Two-node veth/netns demo script

- [x] **Declarative TOML fabric config** (`--config node.toml`): endpoints, VNI,
      gateway, NAT, virtual gateway MAC
- [x] **Proxy-ARP responder** on the tenant port — the demo needs no static
      neighbours; the switch is the tenant's distributed gateway
- [x] Live per-second throughput stats, an `inspect` packet decoder, and a
      forwarding-core benchmark

**Possible next steps:**

- [ ] Multi-VPC on one switch (VNI keyed by ingress port); IPv6 / ND
- [ ] MAC learning instead of a fully-provisioned endpoint table
- [ ] Shared-UMEM zero-copy between the two ports; native (driver) XDP throughput

## Poke at it (no root, no Linux needed)

**Visual playground:** open [`docs/playground.html`](docs/playground.html) in a
browser (or host it on GitHub Pages) — an interactive tool that builds a tenant
packet and shows it wrapped in the Andromeda overlay: color-linked layer stack and
hex dump, live checksums, and the flow hash → outer UDP source port. Its byte-level
logic is verified to match `andromeda inspect` exactly.

Or from the terminal:

```
$ andromeda inspect          # decodes a synthesized overlay packet, layer by layer
Ethernet  02:00:00:00:a1:01 -> 02:00:00:00:a1:02  ethertype 0x0800 (IPv4)
  IPv4  192.168.1.1 -> 192.168.1.2  proto 17 (UDP)  ttl 64  len 90  cksum ok
    UDP  65402 -> 43481  len 70
      Andromeda  v1  VNI 100  flow 0x3f7a  hop 64
      -- inner frame --
        Ethernet  02:00:00:00:00:0a -> 02:00:00:00:00:0b  ethertype 0x0800 (IPv4)
          IPv4  10.0.0.10 -> 10.0.0.20  proto 17 (UDP)  ttl 64  len 40  cksum ok
            UDP  40000 -> 4242  len 20
```

`andromeda inspect <hex>` decodes any packet you paste (spaces/colons ignored) —
feed it a `tcpdump -x` line and watch it unwrap the overlay. `andromeda bench`
prints the forwarding-core throughput, and `andromeda selftest` runs the pipeline
end to end. None of these need root or an AF_XDP-capable kernel.

## Seeing it work

`sudo ./scripts/demo.sh bypass` runs the switch in dump mode and pings it from an
isolated namespace. The pings get **zero replies** — because the AF_XDP program
lifts them into user space before the kernel's IP stack ever sees them. That 100%
"loss" *is* the proof of bypass:

```
rx=28 ...                     # frames received directly in user space
--- 10.10.0.1 ping statistics ---
3 packets transmitted, 0 received, 100% packet loss
```

`sudo ./scripts/demo.sh encap` runs the switch in encap mode and captures the wire
on the peer. Each tenant ping comes back wrapped in the Andromeda overlay
(`tcpdump` mis-labels UDP/43481, but the bytes are ours):

```
IP 192.168.1.1.49152 > 192.168.1.2.43481:  (outer IPv4 + UDP to the Andromeda port)
  0x0018:  ... a9d9 0072 812b 1000 0000 0000 6440   UDP dport=0xa9d9(43481)
                                 ^^^^ Andromeda: ver=1  ^^^^^^ VNI=0x64=100, hop=64
  0x0024:  0a71 0388 a35b 16b4 786a d3fc 0800 4500   inner Ethernet frame ...
  0x0034:  0054 ...      4001 ... 0a0a 0002 0a0a 0001   inner IPv4 10.10.0.2 -> 10.10.0.1 (ICMP)
```

`sudo ./scripts/demo-2node.sh` builds two nodes (each from a generated TOML config)
and pings **through** the overlay — tenant 10.0.0.10 reaches tenant 10.0.0.20 across
two separate user-space switches, each encapsulating one direction and
decapsulating the other. There are **no static ARP entries**: each switch proxy-ARPs
its tenant as the distributed gateway.

```
PING 10.0.0.20 (10.0.0.20) 56(84) bytes of data.
64 bytes from 10.0.0.20: icmp_seq=1 ttl=64 time=0.381 ms
--- 10.0.0.20 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss

# the switch prints a live line each second:
[+  3s] rx  25 ( 10 pps)  tx  5 ( 4 pps)  encap 2 decap 2 arp 1 drop 20
```

---

## Build & test

Requires a recent stable Rust toolchain. The dataplane's AF_XDP layer additionally
needs `libxdp`/`libbpf` and a Linux kernel with `CONFIG_XDP_SOCKETS=y` (verified on
kernel 6.6).

```bash
# everything except the AF_XDP socket layer is pure, portable Rust:
cargo test --workspace

# run the in-memory end-to-end demo:
cargo run -p andromeda-cli -- selftest

# build the real datapath (needs libxdp-dev / libbpf-dev on Linux):
cargo build --release -p andromeda-cli --features afxdp

# see it forward live traffic on a veth pair (needs root):
sudo ./scripts/demo.sh encap
```

---

## Performance

`andromeda bench` micro-benchmarks the forwarding core (parse → resolve → optional
SNAT → encapsulate) on a single core, in cache, with no socket overhead — an upper
bound on what the datapath logic itself costs:

| inner frame | encap (copy, RX→TX) | encap zero-copy (in-place) | encap + SNAT |
|---|---|---|---|
| 60 B  | 64.6 Mpps · 15.5 ns | **89 Mpps** · 11.2 ns | 17.8 Mpps · 56 ns |
| 1396 B | 33.2 Mpps · 30 ns | **88 Mpps** · 11.3 ns | 13.9 Mpps · 72 ns |

Starting from a first cut at **19 Mpps** (52 ns), the encap path is now **3.4×**
faster copying and **~4.7×** faster zero-copy — every change is standard dataplane
practice:

- **Header templating** — the constant outer Ethernet+IPv4+UDP header is built once
  into a 42-byte template; forwarding copies it and patches only the variable fields,
  folding the IPv4 checksum from a precomputed base (5 adds, not a 20-byte scan).
- **Zero-copy in-place encap** (`on_tenant_frame_inplace`) — when the inner frame is
  already in the UMEM frame with reserved headroom, the header is stamped in front of
  it with **no payload copy at all**, so cost is independent of frame size (the
  `copy` column carries an RX→TX memcpy that this one avoids).
- **Zero outer UDP checksum by default** (RFC 6935; what VXLAN does) — no per-packet
  pass over the payload. Inner IPv4/TCP/UDP checksums stay exact.
- **`FxHashMap`** for the fabric resolve (not SipHash), a **multiply-xor flow hash**
  with independent (parallel) mixes instead of a 13-deep FNV chain, `#[inline]` on the
  hot builders, and `lto = "fat"`.

These are microbench numbers (single core, in cache) — the ceiling of the logic, not
a live socket. A real AF_XDP datapath adds `poll`/wakeup cost, and veth in SKB mode
is well below a real NIC in native mode. Run `andromeda bench` on your own hardware.

## Design notes

**Zero-copy hot path.** Parsers are *views* over a borrowed `&[u8]`/`&mut [u8]` —
the packet lives once, in the AF_XDP UMEM frame, and we only ever read or patch
bytes in place. No per-packet allocation on the forwarding path.

**Incremental checksums.** When NAT rewrites an address or port, we do *not*
recompute the TCP/UDP checksum over the payload. We adjust the stored checksum by
the one's-complement delta of just the changed 16-bit words (RFC 1624). The test
suite proves the incremental result is bit-identical to a from-scratch recompute.

**Policy/mechanism split.** The NAT engine decides *what* to change
(`process(tuple, direction) → Rewrite`) as pure logic; a separate `apply()` mutates
bytes and fixes checksums. This makes the tricky stateful logic testable without
synthesizing packets, and keeps the byte-twiddling in one auditable place.

**Why AF_XDP and not raw sockets.** AF_XDP delivers frames straight from the driver
(or the generic XDP hook) into a user-space ring, skipping the kernel's networking
stack and its per-packet `sk_buff` allocation. That is the actual "OS bypass" that
cloud dataplanes rely on to hit line rate — and the thing this project is here to
demonstrate.

## License

MIT.
