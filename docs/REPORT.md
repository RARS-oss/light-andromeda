# Light-Andromeda: a user-space, kernel-bypass VPC overlay dataplane

*A technical report on the design, implementation, verification, and performance
engineering of a miniature software-defined networking dataplane.*

---

## Abstract

Cloud providers do not give a virtual machine a real network. They give it the
*illusion* of one — a private address space that is really an overlay stitched
across a shared physical fabric by software running on every host. Google calls
their version **Andromeda**; the industry calls the pattern **SDN** (software-
defined networking) with **L2-over-UDP encapsulation** (VXLAN, GENEVE).

**Light-Andromeda** is a from-scratch, working miniature of that dataplane, built
to understand it at the level a host actually operates: packets parsed byte by
byte, wrapped in a custom overlay header, forwarded by a centrally-programmed
fabric map, address-translated on the fly, and moved **in user space past the
kernel's networking stack** using `AF_XDP`. A real ICMP echo travels end-to-end
across two independent user-space switches, over the overlay, and back — with no
static ARP and no kernel forwarding in the middle.

This report documents the architecture, the wire format, the correctness strategy,
and — at length — the performance work that took the encapsulation core from
**19 Mpps to ~90 Mpps on a single core**, including the experiment that showed the
datapath is *memory-bound, not compute-bound*, and an honest account of where the
numbers stop being the dataplane's fault.

---

## 1. Background

**The problem.** Tenant A's VM at `10.0.0.10` wants to talk to tenant A's other VM
at `10.0.0.20`. Those two VMs may sit on different physical hosts, on a fabric that
knows nothing about `10.0.0.0/24` and may be carrying a hundred other tenants who
*also* use `10.0.0.0/24`. The host software must:

1. Intercept the VM's raw Ethernet frame before it hits the wire.
2. Decide which physical host currently hosts `10.0.0.20`.
3. Wrap the frame so it can cross the physical fabric without the fabric needing to
   understand tenant addresses — and so the tenant's `10.0.0.0/24` doesn't collide
   with anyone else's.
4. Unwrap it on the far host and deliver it to the right VM.
5. Do all of this fast enough to not be the bottleneck (millions of packets/sec).

That is network virtualization, and (4)+(5) are why it is hard.

**Why user space / kernel bypass.** The Linux network stack allocates an `sk_buff`
per packet and walks a long, general-purpose path. For a dataplane that does one
specific thing per packet, that overhead dominates. `AF_XDP` lets a program attach
at the driver's earliest hook (XDP) and **redirect raw frames into a user-space
ring buffer over a shared memory region (UMEM)** — no `sk_buff`, no stack traversal.
That is the "OS bypass" this project demonstrates.

---

## 2. Architecture

A Rust workspace of small, single-purpose crates:

```
                          ┌──────────── control plane ────────────┐
                          │  andromeda-control                     │
                          │  Fabric: (VNI, inner-IP) → node + MAC   │
                          │  loaded from a declarative TOML config  │
                          └───────────────────┬────────────────────┘
                                              │ programs
  tenant veth ──▶ AF_XDP RX ──▶ ┌─────────────▼──────────────┐ ──▶ AF_XDP TX ──▶ underlay
                  (bypass)      │      andromeda-dataplane     │
                                │  parse → resolve → NAT →     │
                                │  encap/decap  (Pipeline)     │
                                └──────┬─────────────┬─────────┘
                                       │             │
                              andromeda-core   andromeda-nat
                              (wire formats,   (SNAT/DNAT +
                               checksums,       conntrack)
                               Andromeda encap)
```

| Crate | Responsibility | Notable property |
|---|---|---|
| `andromeda-core` | Zero-copy parse/build of Ethernet, IPv4, UDP, TCP, ARP; internet checksums; the Andromeda overlay format | **Dependency-free, `#![forbid(unsafe_code)]`** |
| `andromeda-nat` | Stateful SNAT/PAT + DNAT with connection tracking | Pure *decision* + in-place *apply*, incremental checksums |
| `andromeda-control` | Fabric map + TOML config | The SDN "map of the world" |
| `andromeda-dataplane` | The per-packet pipeline + the AF_XDP socket loop | Two-buffer and zero-copy encap paths |
| `andromeda-cli` | `andromeda` binary: selftest / bench / inspect / run / switch | — |

The **data plane** (fast, per-packet) and **control plane** (slow, "where does
`10.0.0.20` live?") are cleanly separated — the same split a real SDN uses.

---

## 3. The Andromeda wire format

An inner tenant Ethernet frame is wrapped as **L2-over-UDP**, the same shape as
VXLAN/GENEVE, with a custom 8-byte header:

```
[ outer Ethernet ][ outer IPv4 ][ outer UDP ][ Andromeda(8) ][ inner Ethernet frame … ]
     14               20             8            8            (the tenant's packet)
 └──────────────────── 50 bytes of overlay overhead ─────────┘
```

```
Andromeda header
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Ver | Flags |  Inner proto  |           Flow hash           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     VNI (24 bits)              |  Hop limit  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **VNI (24 bit)** — the tenant/VPC id, so overlapping tenant address spaces stay
  isolated (this is what makes `10.0.0.0/24` safe to reuse).
- **Flow hash (16 bit)** — a hash of the inner 5-tuple, also copied into the *outer*
  UDP source port so the underlay's own ECMP spreads a tenant's flows across paths
  without looking inside the tunnel.
- **Hop limit** — an overlay TTL guarding against encapsulation loops.

The header is dissectable interactively with `andromeda inspect` and in the browser
playground (`docs/playground.html`).

---

## 4. The datapath

**Egress (tenant → underlay).** Parse the inner Ethernet/IPv4; look the inner
destination up in the fabric; if it leaves the VPC, SNAT it; wrap it in the overlay
toward the destination node; hand the bytes to TX. **Ingress (underlay → tenant).**
Verify it's Andromeda traffic (outer UDP port + VNI), strip the overlay, optionally
reverse-NAT, and deliver the inner frame to the tenant port.

Three design decisions carry most of the weight:

**Zero-copy views.** Every parser is a *view* over a borrowed byte slice; the packet
lives once, in the UMEM frame, and the code only reads or patches bytes in place.

**Incremental checksums (RFC 1624).** When NAT rewrites an address or a port, the
L3/L4 checksums are **not** recomputed over the payload — they are adjusted by the
one's-complement delta of just the changed 16-bit words. A test proves the
incremental result is bit-identical to a from-scratch recompute.

**Distributed gateway (proxy-ARP).** Tenants never learn each other's real MACs.
Each switch answers every tenant ARP with one virtual gateway MAC; on encapsulation
it rewrites the inner destination MAC to the real endpoint's (from the fabric). This
is why the two-node demo needs no static neighbours.

---

## 5. Correctness

- **41 unit tests** cover every parser, every checksum path, NAT (SNAT/DNAT/GC),
  the fabric, the config loader, the pipeline, and proxy-ARP.
- **Checksum invariants** are asserted against known-good packet vectors and against
  full-recompute baselines.
- **Cross-implementation round-trip.** The browser playground re-implements the exact
  byte assembly in JavaScript; a packet it builds decodes **byte-for-byte identically**
  under the Rust `andromeda inspect` (verified: outer + inner IPv4 checksums valid,
  VNI/flow/ports match). Two independent implementations agreeing is strong evidence
  the wire format is specified, not accidental.
- **Two path-equivalence test:** the copy and zero-copy encap paths must produce
  byte-identical output.
- **End-to-end:** a real `ping` traverses two switches over the overlay — 4/4, 0% loss.

---

## 6. Performance engineering

All numbers below: single core of an **AMD Ryzen 5 5600 (Zen 3)**, `--release`
(`opt-level=3`, `lto="fat"`), in-cache microbenchmark of the forwarding logic
(no sockets). Reproduce with `andromeda bench` / `andromeda bench --json`.

### 6.1 The journey (60-byte inner frame, east-west encap)

| Step | ns/pkt | Mpps | What changed |
|---|---|---|---|
| First working cut | 52 | 19 | scratch buffer, double copy, full outer UDP checksum, SipHash resolve |
| Single-copy + no outer UDP cksum | 22 | 45 | `encap_in_place`; outer UDP checksum 0 (RFC 6935 / VXLAN); `FxHashMap` |
| `#[inline]` + fat LTO | 19.8 | 50 | hot builders inline; whole-program optimization |
| Fast flow hash | 16 | 60 | multiply-xor mix (parallel) replaces a 13-deep FNV dependency chain |
| **Header templating** | **15.5** | **65** | constant outer header precomputed; only variable fields patched, 5-add checksum |
| **Zero-copy in-place** | **11** | **~90** | header stamped into UMEM headroom; **no payload copy** |

That is **3.4× faster copying** and **~4.7× faster zero-copy**. Every change is
standard dataplane practice; none of it games the benchmark.

### 6.2 Full result matrix

| path | 60 B | 1396 B |
|---|---|---|
| encap copy (east-west) | 65 Mpps · 15 ns | 33 Mpps · 30 ns |
| encap zero-copy (1 hot frame) | ~90 Mpps · 11 ns | ~91 Mpps · 11 ns |
| encap zero-copy (batch, 64 KB working set) | ~85 Mpps · 12 ns | ~85 Mpps · 12 ns |
| **decap** | **~108 Mpps · 9 ns** | 37 Mpps · 27 ns |
| encap + SNAT (conntrack) | ~17 Mpps · 58 ns | ~14 Mpps · 72 ns |

Notes worth reading:

- **Decap exceeds 100 Mpps** on small frames — it validates and copies out but builds
  no header, so it is genuinely cheaper than encap.
- **SNAT is ~4× slower** than plain encap — that is the honest cost of connection
  tracking (a hash-map lookup/insert) plus the incremental checksum fixups, *not* a
  payload rescan. It is the price of statefulness.
- The "wire Gbit/s" for large frames looks enormous (>300) precisely because the
  zero-copy path never touches the payload; it is not a line-rate claim.

### 6.3 The key finding: memory-bound, not compute-bound

Batching 32 frames per call to amortize overhead and remove per-packet counter
dependencies **did not help** — ~85 Mpps batched vs ~90 Mpps for a single, L1-hot
frame. The single-frame path reuses one buffer that stays in L1; the batch touches a
64 KB working set that spills to L2, and *that* is the difference.

The implication is important and non-obvious: **the encap datapath is bounded by
memory movement, not arithmetic.** Adding SIMD to the header stamping — the usual
next step — would optimize the part that is already cheap. The honest way past
~90 Mpps single-core is *less* per-packet memory traffic (true zero-copy everywhere,
larger frames, or hardware offload), or *more* cores — not a cleverer inner loop.

This is why the project does **not** ship a fake "100 Mpps" number from, say, a
single-flow next-hop cache with a 100% hit rate: on the single-flow benchmark that
would "work" and mean nothing.

---

## 7. Live evaluation

Microbenchmarks measure the *logic ceiling*. A live socket adds the I/O the ceiling
ignores. Measured on the WSL2 veth setup (generic/SKB XDP, copy mode, single core),
feeding the switch 64-byte UDP from a `sendmmsg` generator in a peer namespace:

- **RX + encapsulate:** the switch pulled and encapsulated **100 % of the offered
  load with zero RX drops** — up to the **~2.6 Mpps** the generator could offer.
  The receive/processing path was never the bottleneck.
- **TX back onto the veth** saturated near **~0.6 Mpps** in SKB copy mode; beyond that,
  frames were dropped at the TX ring.
- **Latency:** the two-node overlay adds **~0.2 ms** RTT over the kernel path on veth.

So the live ceiling here is the **veth + generic-XDP + copy-mode I/O path and the
generator**, not the dataplane. On a real NIC with native XDP and zero-copy this gap
closes dramatically; demonstrating that is future work, not a WSL2 experiment.

---

## 8. Limitations & threats to validity

- **Microbench caveats.** Single core, in cache, no NUMA, no cache-cold frames from a
  real NIC DMA. The numbers are an upper bound on the logic, clearly labelled as such.
- **WSL2 / veth / SKB.** Generic XDP in copy mode over veth is well below a real NIC
  in native/zero-copy mode; the live numbers reflect that environment, not the design.
- **Scope.** Single VPC per switch, IPv4 only, a fully-provisioned endpoint table
  (no MAC learning), no fragmentation/PMTU, no encryption (the flag bit is reserved).
  These are deliberate — the point was depth on the core mechanism, not breadth.

## 9. Future work

- **Native-mode / zero-copy AF_XDP on a real NIC** and an honest line-rate number.
- **Multi-VPC** on one switch (VNI keyed by ingress port), **IPv6 + ND**.
- **MAC learning** instead of a provisioned endpoint table.
- **Shared-UMEM** between the two ports so the two-interface switch is zero-copy too.
- **SIMD** batch header-stamping — worth it only once the path is no longer memory-bound.

## 10. Reproduce

```bash
cargo test --workspace                 # 41 tests, portable
cargo run -p andromeda-cli -- bench            # performance table
cargo run -p andromeda-cli -- bench --json     # machine-readable
cargo run -p andromeda-cli -- inspect          # decode a synthesized overlay packet

# real datapath (Linux + libxdp-dev + libbpf-dev, root):
cargo build --release -p andromeda-cli --features afxdp
sudo ./scripts/demo-2node.sh                   # ping through the overlay
```

## References

- Dalton et al., *Andromeda: Performance, Isolation, and Velocity at Scale in Cloud
  Network Virtualization*, NSDI 2018.
- RFC 7348 (VXLAN), RFC 8926 (GENEVE) — L2-over-UDP overlays.
- RFC 1624 — incremental internet checksum update.
- RFC 6935 — zero UDP checksum for IPv6/IPv4 tunnels.
- `AF_XDP` and `libxdp` — kernel documentation and the xdp-project.

---

*Light-Andromeda is a portfolio/learning project — a deliberately small but complete
and honest implementation of a large idea.*
