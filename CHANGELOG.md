# Changelog

All notable changes to Light-Andromeda are recorded here. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions follow SemVer (0.x: minor =
features, patch = fixes).

## [0.2.0]

Production edge cases, a live control plane, and the groundwork for hardware-class
performance — every software-verifiable part landed and tested; the hardware-dependent
parts (true zero-copy, PMU counters, tail-latency) ship as validated code paths measured
on bare-metal via `scripts/hw-validate.sh`.

### Added
- **Overlay Path-MTU Discovery.** A tenant `DF` datagram too large to fit under the
  50-byte overlay header now triggers an ICMP "Fragmentation Needed" (Type 3/Code 4,
  next-hop MTU per RFC 1191) back to the tenant, on every encap path (copy, zero-copy
  in-place, and batch), instead of a silent blackhole. New `andromeda-core::icmp`.
  Configurable via TOML `underlay_mtu` and `virtual_gateway_ip`.
- **Dynamic control plane.** The fabric map now lives behind an `ArcSwap`, hot-reloadable
  with zero packet loss and no restart. A Unix-socket server (`reload <config.toml>` /
  `ping`) drives it: `andromeda switch --control <sock>`.
- **Native driver mode + zero-copy AF_XDP.** `--zerocopy` requests an `XDP_ZEROCOPY`
  native-driver bind, transparently falling back to copy mode where the driver can't do
  it (veth/virtio), and reports the mode actually achieved.
- **Lock-free SPSC ring** (`andromeda-dataplane::spsc`) for per-core packet hand-off,
  **model-checked with `loom`** plus a 200k-item real-threaded FIFO stress test; and
  `pin_current_thread_to_core` — the building blocks of multi-queue scaling.
- **`scripts/hw-validate.sh`** — an unattended environment/performance report that runs
  the bench in the best available mode and clearly labels what a box cannot validate
  (native ZC / PMU / tail-latency), so rented-bare-metal numbers stay honest.

### Changed
- NAT garbage collection is now wired into the forwarding loops (idle bindings and their
  ports reclaim on a 1s tick), so the SNAT port pool no longer leaks under churn.

### Security
- Bounded untrusted inputs and fuzzed every packet-path entry point; RX descriptor length
  and UMEM slot clamping in the C shim; reverse-DNAT table cap.

## [0.1.0]

Initial release: a complete, verified user-space VPC overlay dataplane.

- Byte-exact Ethernet/IPv4/UDP/TCP/ARP parsing and building (zero-copy, no `unsafe` in
  the core), incremental RFC 1624 checksums.
- The Andromeda L2-over-UDP overlay (8-byte header, 24-bit VNI, flow hash), stateful
  SNAT/DNAT with conntrack, an SDN fabric map from declarative TOML, proxy-ARP gateway,
  and multi-VPC tenant isolation.
- A real AF_XDP kernel-bypass datapath (C shim over system `libxdp` + Rust FFI) through
  which a real ICMP echo traverses two switches end-to-end.
- Encapsulation optimized 19 → ~80 Mpps on one core, characterized with a controlled
  working-set × access-pattern cache experiment (compute- vs memory-bound), reported with
  mean ± sd and a roofline model.
