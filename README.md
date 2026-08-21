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
│   ├── andromeda-core/       # zero-copy L2/L3/L4 parsing + Andromeda encap + checksums
│   ├── andromeda-nat/        # stateful SNAT/PAT + DNAT with conntrack
│   ├── andromeda-control/    # VPC/endpoint model + overlay forwarding lookup (SDN map)
│   ├── andromeda-dataplane/  # forwarding pipeline; AF_XDP ring loop (in progress)
│   └── andromeda-cli/        # `andromeda` binary: run the switch, manage fabric, benchmark
├── scripts/                  # veth/netns topology setup for the multi-node demo
└── docs/                     # architecture + design notes
```

Each crate is small and single-purpose, and the two hardest, most reusable pieces
(`core` and `nat`) are dependency-free and fully unit-tested.

---

## Status

**Done and tested (33 unit tests, all green):**

- [x] Byte-exact Ethernet / IPv4 / UDP / TCP parsing and building
- [x] Internet checksum + incremental update (verified against full recompute)
- [x] Andromeda overlay encap/decap round-trip with valid outer checksums
- [x] Stateful SNAT/PAT with port allocation, conntrack, and reverse translation
- [x] DNAT port-forwarding with server-reply un-NAT
- [x] Control-plane fabric map and cross-node forwarding resolution
- [x] End-to-end forwarding pipeline (tenant→encap→peer→decap) over in-memory buffers

**In progress:**

- [ ] AF_XDP socket layer: UMEM + FILL/COMPLETION/RX/TX rings, real kernel bypass
- [ ] `andromeda run <iface>`: attach to a veth and forward live traffic
- [ ] Multi-node veth/netns demo (`scripts/`) with real `ping`/`iperf` across the overlay
- [ ] Latency & throughput benchmarks vs. the kernel path

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
```

---

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
