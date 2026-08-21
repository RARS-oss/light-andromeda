#!/usr/bin/env bash
#
# Hardware-counter benchmark: run the forwarding-core microbenchmark under
# `perf stat` to MEASURE (not model) whether it is compute- or memory-bound.
#
# This needs a real Linux host with a PMU — it does NOT work under WSL2 or most
# VMs, which expose no performance counters. On such a host it prints a clear
# message and exits. Run on bare-metal Linux:
#
#   sudo ./scripts/bench-perf.sh
#
# What it reports and how to read it (from docs/REPORT.md §6.4, the roofline):
#   * instructions per cycle (IPC) — high (>2) with low miss rates ⇒ compute-bound.
#   * LLC-load-misses per packet — near 0 ⇒ the working set stays in cache; large
#     ⇒ memory-latency-bound (the shuffled/large-working-set regime).
#
set -uo pipefail

BIN="${ANDROMEDA_BIN:-./target/release/andromeda}"
ITERS="${ITERS:-40000000}"

if ! command -v perf >/dev/null 2>&1; then
    echo "perf not found. Install it:  sudo apt-get install linux-tools-common linux-tools-\$(uname -r)" >&2
    exit 1
fi
if [[ ! -x "$BIN" ]]; then
    echo "binary not found: $BIN — build it first:" >&2
    echo "  cargo build --release -p andromeda-cli" >&2
    exit 1
fi

# Probe whether the PMU is actually available (WSL/VMs return an error here).
if ! perf stat -e cycles true >/dev/null 2>&1; then
    echo "This host exposes no hardware performance counters (PMU)." >&2
    echo "You are likely under WSL2 or a VM. Run on bare-metal Linux for perf data." >&2
    echo "The throughput sweep still works without a PMU:  $BIN bench --sweep" >&2
    exit 2
fi

echo "== perf stat over the encap microbenchmark ($ITERS iterations) =="
echo "== reading: IPC high + LLC-miss/pkt ~0  ⇒ compute-bound (the cache-resident regime) =="
echo

perf stat -e \
task-clock,cycles,instructions,branches,branch-misses,\
L1-dcache-loads,L1-dcache-load-misses,LLC-loads,LLC-load-misses \
  "$BIN" bench "$ITERS"

echo
echo "Per-packet figures: divide the counts above by (iterations × paths measured)."
echo "For the memory-bound regime, compare against:  $BIN bench --sweep"
