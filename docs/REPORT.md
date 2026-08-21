# Light-Andromeda: a user-space, kernel-bypass VPC overlay dataplane

*A design-and-measurement study of a miniature software-defined-networking dataplane:
custom overlay encapsulation, stateful NAT, and an AF_XDP fast path — implemented
from scratch, verified, and characterized with controlled experiments.*

---

## Abstract

Cloud providers do not give a virtual machine a real network; they give it the
*illusion* of one — a private address space realized as an overlay stitched across a
shared physical fabric by software on every host (Google's is **Andromeda** [1]; the
industry pattern is **SDN** with **L2-over-UDP** encapsulation [2, 3]). This work
reimplements that dataplane in miniature to study it at the level a host actually
operates: frames parsed byte by byte, wrapped in a custom overlay header, forwarded
by a centrally-programmed map, address-translated in flight, and moved **in user
space past the kernel's network stack** via `AF_XDP` [4].

We make three contributions. **(1)** A complete, correct, and dependency-light
implementation (Rust; `#![forbid(unsafe_code)]` outside the FFI layer) whose wire
format is verified two independent ways and through which a real ICMP echo traverses
two switches end-to-end. **(2)** A performance study that takes the encapsulation
core from **19 to ~80 Mpps on a single core** through six changes, each reported with
a stated methodology and error bars. **(3)** A controlled cache experiment — throughput
vs. working-set size under *sequential* and *shuffled* access — that answers whether
the datapath is compute- or memory-bound. The answer is *both, depending on locality*:
compute-bound at ~80 Mpps while the hot set is cache-resident and access is
prefetch-friendly, and memory-latency-bound (down to ~9 Mpps) under random access to
a working set beyond the L2/L3 caches. That result **corrects an earlier informal
"memory-bound" claim** and is, we think, the most interesting thing the project has
to say.

---

## 1. Introduction

**The problem.** Tenant A's VM at `10.0.0.10` must reach its other VM at `10.0.0.20`.
They may sit on different physical hosts, on a fabric that knows nothing about
`10.0.0.0/24` and that also carries other tenants who *reuse* `10.0.0.0/24`. Host
software must intercept the raw frame, decide which physical host currently holds the
destination, wrap the frame so the fabric can carry it without understanding tenant
addresses (and without cross-tenant collisions), unwrap it on the far host, and do so
fast enough to never be the bottleneck. Correct isolation and speed are the whole
problem; this report is about both.

**Why kernel bypass.** The Linux stack allocates an `sk_buff` per packet and walks a
long, general-purpose path. For a dataplane that does one specific thing per packet,
that overhead dominates. `AF_XDP` attaches at the driver's earliest hook and
redirects raw frames into a user-space ring over a shared memory region (UMEM), with
no `sk_buff` and no stack traversal [4]. That is the "OS bypass" studied here.

**Contributions and scope.** This is a portfolio/learning artifact, not a production
system, and its scope is deliberately narrow (§8). Its value is a *clean, verified,
and honestly-measured* mini-implementation of a large idea, including a controlled
experiment that revises the author's own initial conclusion.

---

## 2. Background and related work

**Overlay formats.** VXLAN [2] and GENEVE [3] encapsulate a tenant L2 frame in
UDP/IP, tagging it with a 24-bit virtual network id (VNI) so overlapping tenant
address spaces stay isolated. Light-Andromeda's 8-byte header is the same idea with
one addition: a 16-bit flow hash carried both in the header and in the outer UDP
source port, so the underlay's own ECMP can spread a tenant's flows without parsing
the tunnel.

**Production SDN dataplanes.** Google's **Andromeda** [1] is the direct inspiration:
a host dataplane with a centrally-programmed map and a hierarchy of fast/slow paths
(the "Hoverboard" model), heavily offloaded. Google's **Snap** [5] moves networking
into a userspace microkernel. Both are large distributed systems; this project models
only the innermost per-packet transform.

**Kernel bypass and userspace dataplanes.** XDP [6] runs eBPF at the driver hook;
`AF_XDP` [4] extends it to deliver raw frames to userspace. **DPDK** and FD.io's
**VPP** [7] are the reference userspace dataplanes; VPP's *vector packet processing*
(amortizing per-packet overhead across a batch) directly motivated the batch path in
§5. Production l2/l3-forwarding on DPDK reaches tens to >100 Mpps per core, but with
poll-mode drivers, huge pages, and NIC offloads this project does not use.

**In-kernel overlays.** **Cilium** takes the opposite tack — VXLAN/GENEVE handled by
eBPF *inside* the kernel. Light-Andromeda deliberately explores the userspace side to
study AF_XDP directly.

**Positioning.** Relative to all of the above this is a single-core, single-VPC,
IPv4, software-only reimplementation. It contributes no new mechanism; it contributes
a *measured, reproducible characterization* of a clean implementation, and it is
honest about the regime in which its numbers hold.

---

## 3. Design

The system splits, as real SDN does, into a **data plane** (fast, per-packet) and a
**control plane** (slow — "where does `10.0.0.20` live?").

```
                          ┌──────────── control plane ────────────┐
                          │  Fabric: (VNI, inner-IP) → node + MAC   │
                          │  loaded from declarative TOML           │
                          └───────────────────┬────────────────────┘
                                              │ programs
  tenant veth ─▶ AF_XDP RX ─▶ ┌───────────────▼──────────────┐ ─▶ AF_XDP TX ─▶ underlay
                 (bypass)     │  parse → resolve → NAT →       │
                              │  encapsulate / decapsulate     │
                              └────────────────────────────────┘
```

**Wire format.** Inner Ethernet frame wrapped as `[outer Eth(14)][outer IPv4(20)]
[outer UDP(8)][Andromeda(8)][inner frame]` — 50 bytes of overhead. The Andromeda
header carries version/flags, inner-protocol, the 16-bit flow hash, a 24-bit VNI, and
an overlay hop limit.

**Distributed gateway.** Tenants never learn each other's MACs. Each switch answers
every tenant ARP with one virtual gateway MAC and, on encapsulation, rewrites the
inner destination MAC to the real endpoint's (from the fabric) — so the multi-node
demo needs no static neighbours.

**Policy/mechanism split in NAT.** The NAT engine *decides* (`process(5-tuple,
direction) → Rewrite`) as pure logic; a separate `apply()` mutates bytes and fixes
checksums. This makes the stateful logic unit-testable without synthesizing packets.

---

## 4. Implementation

Rust workspace, five crates. `andromeda-core` (wire formats, checksums, overlay) is
dependency-free and `#![forbid(unsafe_code)]`; `unsafe` is confined to the ~170-line C
shim over the system `libxdp` and its Rust FFI. Two implementation choices carry the
performance story and are detailed in §5: **header templating** (precompute the
constant outer header once; per packet, patch only the variable fields and fold a
five-term IPv4 checksum) and **zero-copy in-place encap** (when the inner frame is
already in a UMEM frame with reserved headroom, stamp the header in front of it with
no payload copy).

---

## 5. Methodology

All microbenchmark numbers are from **one core of an AMD Ryzen 5 5600 (Zen 3; L1d
32 KB/core, L2 512 KB/core, L3 32 MB shared)**, Rust `--release` with `opt-level=3`,
`lto="fat"`, `codegen-units=1`, `panic="abort"`, running under WSL2 (Linux 6.6).

**Protocol.** Each data point runs one discarded **warm-up** trial, then **7 timed
trials**; we report the **mean ± sample standard deviation** (n = 7) and the best
(min) trial. Each trial times millions of iterations via `std::time::Instant`; a
`std::hint::black_box` on the accumulated result prevents the optimizer from eliding
the loop. Reproduce with `andromeda bench` (matrix) and `andromeda bench --sweep`
(the cache experiment); `--json` emits machine-readable output.

**Threats this cannot remove** are stated in §8; chief among them are CPU
frequency scaling (no `cpupower` pinning under WSL2) and the absence of hardware
performance counters (`perf` has no PMU here), so we reason from throughput and an
analytical model rather than measured IPC/miss rates.

---

## 6. Evaluation

### 6.1 Forwarding-core throughput (mean ± sd, n = 7)

| path | 60 B frame | 1396 B frame |
|---|---|---|
| encap · copy (RX→TX) | 15.7 ± 0.3 ns · **64 Mpps** | 29.0 ± 0.3 ns · 34 Mpps |
| encap · zero-copy (1 frame) | 14.5 ± 0.7 ns · 69 Mpps | 14.2 ± 0.2 ns · 70 Mpps |
| encap · zero-copy (batch) | 13.4 ± 2.1 ns · 75 Mpps | 12.1 ± 0.1 ns · **83 Mpps** |
| decap | 10.6 ± 0.3 ns · **95 Mpps** | 19.7 ± 0.2 ns · 51 Mpps |
| encap + SNAT (conntrack) | 57 ± 1.4 ns · 17 Mpps | 75 ± 4.5 ns · 13 Mpps |

Observations. **(i)** Zero-copy encap is essentially frame-size independent (it never
touches the payload); the copy path is not (it memcpys the inner frame). **(ii)**
**Decap is the fastest path** — it validates and copies out but builds no header — and
is the one path that clears ~100 Mpps on a good trial (best 10.2 ns → 98 Mpps).
**(iii)** SNAT costs ~4× a plain encap: the honest price of a conntrack hash
lookup/insert plus incremental-checksum fixups, *not* a payload rescan.

### 6.2 The optimization trajectory

Six changes took 60-byte east-west encap from the first working cut to the operating
point above. Each is standard dataplane practice; none games the benchmark.

| step | ns/pkt (best) | what changed |
|---|---|---|
| first working cut | 52 | scratch buffer, double copy, full outer UDP checksum, SipHash |
| single-copy, no outer UDP cksum | 22 | `encap_in_place`; checksum 0 (RFC 6935 [8], as VXLAN); `FxHashMap` |
| `#[inline]` + fat LTO | 20 | whole-program inlining of the hot builders |
| parallel flow hash | 16 | multiply-xor mix replaces a 13-deep FNV dependency chain |
| header templating | 15.5 | precomputed outer header; 5-add incremental IPv4 checksum |
| zero-copy in-place | 12–14 | header into UMEM headroom; **no payload copy** |

The large jumps are *removing work*, not cleverness: stop copying twice; stop
scanning the payload for a checksum the spec lets you omit; replace a collision-
resistant per-packet hash (SipHash) with a fast one; precompute the constant header.

### 6.3 Compute- or memory-bound? A controlled cache experiment

The batch path (many frames) did not beat the single-hot-frame path, which *suggested*
a memory bound. That reasoning is too crude — a single reused frame is L1-resident and
flatters the result. To test it properly we sweep the **working-set size** (contiguous
128-byte frames, 4 KB → 64 MB) under two **access orders**: sequential (as packed) and
a deterministic **shuffle** (random frame order, defeating the hardware prefetcher, and
closer to how a NIC hands back recycled UMEM frames). Throughput (Mpps), best of 2:

| working set | sequential | shuffled | regime |
|---:|---:|---:|---|
| 16 KB | 80 | 82 | fits L1 |
| 128 KB | 82 | 81 | fits L2 |
| 256 KB | 82 | 76 | fits L2 |
| 512 KB | 80 | **59** | L2 edge |
| 1 MB | 81 | 54 | L3 |
| 4 MB | 82 | 54 | L3 |
| 8 MB | 82 | 37 | L3 |
| 16 MB | 80 | **13** | L3→DRAM |
| 64 MB | 79 | **8.7** | DRAM |

**This refutes the memory-bandwidth hypothesis and replaces it with a sharper claim.**
Under sequential access, throughput is **flat at ~80 Mpps across five orders of
magnitude of working set** — the prefetcher hides all latency, so the datapath is
**compute-bound**. Under random access the same code tracks the **cache hierarchy
exactly**: level with sequential inside L2, a knee at the 512 KB L2 boundary, a slower
decline through L3, and a collapse to **~9 Mpps (a 9× slowdown)** once the working set
exceeds L3 and every packet pays a DRAM miss — i.e. **memory-latency-bound**.

The operating regime therefore depends on locality, not on the code. A real switch's
hot state is a few thousand UMEM frames (single-digit MB) recycled in roughly FIFO
order — between these curves, but near the compute ceiling for well-behaved traffic.
The practical lesson: past ~80 Mpps/core, the lever is *locality and less memory
traffic* (larger frames, true zero-copy everywhere, NIC offload), not a cleverer inner
loop — which is also why SIMD, and a single-flow next-hop cache that would only "win"
on this single-flow benchmark, were deliberately *not* pursued.

### 6.4 An analytical (roofline) model

Two ceilings bracket the measurements. **Compute:** 12.2 ns/packet at ~4.4 GHz is
~54 cycles/packet for parse + hash + fabric lookup + 42-byte header stamp + a
five-term checksum — a plausible retirement rate for this instruction mix, and the
sequential-access asymptote. **Memory bandwidth** is *not* the limit: at 80 Mpps the
path touches on the order of 100 bytes/packet ≈ 8 GB/s, far under single-core cache
bandwidth (the sequential curve confirms this — flat even at 64 MB). The **memory-
latency wall** is separate: at 64 MB shuffled, 115 ns/packet ≈ one largely-uncovered
DRAM access per packet (~80–100 ns), matching the collapse. The design sits at the
compute ceiling and only falls off the latency wall when locality is destroyed —
exactly what §6.3 shows.

### 6.5 Live AF_XDP evaluation

Microbenchmarks measure the logic ceiling; a live socket adds the I/O it ignores.
On WSL2 veth (generic/SKB XDP, copy mode, single core), fed 64-byte UDP by a
`sendmmsg` generator in a peer namespace: the switch **pulled and encapsulated 100 %
of the offered load with zero receive drops**, up to the **~2.6 Mpps** the generator
could offer across 8 processes; **TX back onto the veth saturated near ~0.6 Mpps** in
copy mode, dropping the rest at the TX ring. The overlay adds **~0.2 ms** RTT over the
kernel path. The live ceiling here is the veth + generic-XDP + copy-mode I/O path and
the generator — **not the dataplane**, which was never the bottleneck. Native-mode,
zero-copy AF_XDP on a real NIC would close this gap; demonstrating it is future work
(§9), not a WSL2 experiment.

### 6.6 Correctness

41 unit tests cover every parser, checksum path, NAT operation, the fabric and config
loader, the pipeline, and proxy-ARP. Checksum invariants are asserted against
known-good vectors and against full-recompute baselines (the incremental update is
proven bit-identical). Two stronger checks: **(a)** the browser playground
re-implements the byte assembly in JavaScript and a packet it builds decodes
**byte-for-byte identically** under the Rust decoder (two independent implementations
agreeing on the wire format); **(b)** the copy and zero-copy encap paths are asserted
byte-identical. End-to-end, a real `ping` crosses two switches over the overlay:
4/4, 0 % loss.

---

## 7. Discussion

The headline is not the peak number; it is that the peak number *has a regime*. A
common failure in systems benchmarking is to report a single cache-hot figure as "the"
throughput. The §6.3 experiment shows how misleading that is here: the same binary
runs at 80 Mpps or 9 Mpps depending only on access locality. Reporting the sequential
asymptote without the shuffled curve would overstate real-world performance by up to
9×. The honest summary is a *pair of curves*, and the design's job is to keep traffic
in the favorable regime (small hot working set, sequential-ish frame reuse).

## 8. Threats to validity

- **Frequency scaling.** No `cpupower`/pinning under WSL2; sustained trials run below
  peak boost. The warm-up + mean±sd protocol reduces but does not remove this; treat
  absolute Mpps as ±10 %, and prefer the *shape* of §6.3 to its absolute values.
- **No hardware counters.** `perf` has no PMU under WSL2, so IPC/miss-rate claims are
  modelled (§6.4), not measured.
- **Virtualization.** WSL2 adds scheduler and timer noise; a bare-metal Linux host
  would give cleaner numbers.
- **Access-pattern brackets.** Sequential is prefetcher-ideal; shuffled is worst-case.
  Real UMEM recycling lies between; §6.3 brackets rather than pinpoints the operating
  point.
- **Excluded costs.** The microbench omits syscalls, NIC DMA, and interrupt/poll
  overhead; §6.5 addresses these only qualitatively and in a weak (SKB/veth) environment.
- **Single core / socket.** L3 is shared with five other cores; contention is untested.

## 9. Future work

Native-mode, zero-copy AF_XDP on a real NIC with an honest line-rate number and PMU
data; multi-VPC per switch (VNI by ingress port) and IPv6/ND; MAC learning instead of
a provisioned table; shared-UMEM zero-copy across both switch ports; and a SIMD /
vectorized batch stamp — worthwhile only for the compute-bound regime §6.3 identifies.

## 10. Conclusion

Light-Andromeda is a small but complete overlay dataplane that is correct (verified
two ways, real ping end-to-end), fast (19 → ~80 Mpps/core through disciplined
work-removal), and — most usefully — *honestly characterized*: a controlled
working-set × access-pattern experiment shows the datapath is compute-bound when
cache-resident and memory-latency-bound otherwise, correcting the author's own first
guess. The intent was depth and intellectual honesty on the core mechanism over
breadth of features.

## Appendix A. Reproducibility

```bash
cargo test --workspace                       # 41 tests
cargo run -p andromeda-cli --release -- bench          # §6.1 matrix (mean±sd)
cargo run -p andromeda-cli --release -- bench --sweep  # §6.3 cache experiment
cargo run -p andromeda-cli --release -- bench --json   # machine-readable
# live datapath (Linux + libxdp-dev + libbpf-dev, root):
cargo build --release -p andromeda-cli --features afxdp
sudo ./scripts/demo-2node.sh                 # ping through the overlay
```

Machine: AMD Ryzen 5 5600, WSL2 (Linux 6.6), Rust stable, release profile as in §5.

## References

[1] M. Dalton et al. *Andromeda: Performance, Isolation, and Velocity at Scale in
Cloud Network Virtualization.* NSDI 2018.
[2] M. Mahalingam et al. *VXLAN.* RFC 7348, 2014.
[3] J. Gross et al. *GENEVE.* RFC 8926, 2020.
[4] *AF_XDP.* Linux kernel documentation; M. Karlsson and B. Töpel.
[5] M. Marty et al. *Snap: a Microkernel Approach to Host Networking.* SOSP 2019.
[6] T. Høiland-Jørgensen et al. *The eXpress Data Path.* CoNEXT 2018.
[7] D. Barach et al. *FD.io VPP: Vector Packet Processing.* 
[8] M. Eubanks et al. *UDP Checksums for Tunneled Packets.* RFC 6935, 2013.
[9] A. Rijsinghani. *Computation of the Internet Checksum via Incremental Update.*
RFC 1624, 1994.
