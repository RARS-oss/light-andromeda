#!/usr/bin/env bash
# hw-validate.sh — honest, unattended environment + performance report for Light-Andromeda.
#
# Runs whatever THIS box actually supports and clearly labels what it cannot do, so the
# same script produces a comparable report on a laptop/WSL2 (software only) and on a rented
# bare-metal box with a real NIC (native AF_XDP + zero-copy + PMU). Nothing here fabricates
# a number: a capability that is missing is reported as "NOT AVAILABLE (needs X)".
#
# Usage:
#   ./scripts/hw-validate.sh                 # software-only report (no root, any box/WSL)
#   sudo ./scripts/hw-validate.sh --iface eth0   # also probe a real NIC's XDP/RSS capability
#   ./scripts/hw-validate.sh --out /tmp/report   # choose output dir
#
# Then paste the printed summary (and, if asked, the files under the report dir) back.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IFACE=""
OUT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --iface) IFACE="${2:-}"; shift 2 ;;
    --out)   OUT="${2:-}"; shift 2 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
OUT="${OUT:-$REPO_ROOT/hw-report-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUT"

have() { command -v "$1" >/dev/null 2>&1; }
section() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
note()    { printf '  %s\n' "$1"; }
ok()      { printf '  \033[32m[ok]\033[0m %s\n' "$1"; }
miss()    { printf '  \033[33m[NOT AVAILABLE]\033[0m %s\n' "$1"; }

SUMMARY="$OUT/summary.txt"
exec > >(tee "$SUMMARY") 2>&1   # everything printed also lands in summary.txt

echo "Light-Andromeda hardware-validation report"
echo "generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')   host: $(hostname)"
echo "report dir: $OUT"

# ---------------------------------------------------------------------------
section "1. Machine"
uname -a | tee "$OUT/uname.txt" | sed 's/^/  /'
if grep -qi microsoft /proc/version 2>/dev/null; then
  miss "running under WSL2 — expect generic/SKB XDP only, no true zero-copy, PMU usually absent"
fi
if have lscpu; then
  lscpu > "$OUT/lscpu.txt"
  lscpu | grep -Ei 'model name|^cpu\(s\)|thread|core|socket|l1d|l2|l3|mhz' | sed 's/^/  /'
fi
# isolated cores help tail-latency; report whether any are isolated
if [[ -r /sys/devices/system/cpu/isolated ]]; then
  ISO="$(cat /sys/devices/system/cpu/isolated)"
  [[ -n "$ISO" ]] && ok "isolated CPUs: $ISO" || note "isolated CPUs: none (fine for software test; use isolcpus for tail-latency runs)"
fi

# ---------------------------------------------------------------------------
section "2. Kernel XDP / AF_XDP support"
KVER="$(uname -r)"
note "kernel: $KVER"
if [[ -r /boot/config-"$KVER" ]]; then
  grep -E 'CONFIG_XDP_SOCKETS|CONFIG_BPF_SYSCALL' /boot/config-"$KVER" 2>/dev/null | sed 's/^/  /' \
    || note "(kernel config present but XDP flags not found)"
elif zcat /proc/config.gz 2>/dev/null | grep -qE 'CONFIG_XDP_SOCKETS=y'; then
  ok "CONFIG_XDP_SOCKETS=y (from /proc/config.gz)"
else
  note "kernel build config not readable — cannot confirm CONFIG_XDP_SOCKETS (usually =y on modern distros)"
fi

# ---------------------------------------------------------------------------
section "3. NIC capability"
KNOWN_ZC='mlx5_core|ice|i40e|ixgbe|igc|igb|ena|stmmac'   # drivers with some AF_XDP ZC support
if [[ -z "$IFACE" ]]; then
  miss "no --iface given: skipping NIC/XDP-mode probe (pass --iface <dev> on a bare-metal box)"
  if have ip; then
    note "candidate interfaces on this host:"
    ip -o link show 2>/dev/null | awk -F': ' '{print "    "$2}' | grep -v '^    lo$' || true
  fi
else
  note "probing interface: $IFACE"
  if have ethtool; then
    ethtool -i "$IFACE" > "$OUT/ethtool-i.txt" 2>&1 || true
    DRV="$(awk -F': ' '/^driver:/{print $2}' "$OUT/ethtool-i.txt")"
    note "driver: ${DRV:-unknown}"
    if [[ "${DRV:-}" =~ ^($KNOWN_ZC)$ ]]; then
      ok "driver '$DRV' is on the AF_XDP zero-copy capable list — native ZC is worth attempting"
    else
      miss "driver '${DRV:-unknown}' is not a known AF_XDP zero-copy driver (virtio_net/ENA-lite etc. → SKB/copy only)"
    fi
    ethtool -l "$IFACE" > "$OUT/ethtool-l.txt" 2>&1 || true
    QN="$(awk '/Combined:/{print $2; exit}' "$OUT/ethtool-l.txt" 2>/dev/null)"
    note "RSS/combined queues: ${QN:-unknown}  (multi-queue needed for the per-core scaling test)"
    ethtool -g "$IFACE" > "$OUT/ethtool-g.txt" 2>&1 || true
  else
    miss "ethtool not installed (apt-get install ethtool) — cannot read driver/queues"
  fi
fi

# ---------------------------------------------------------------------------
section "4. PMU / perf counters"
if have perf && perf stat -e instructions -x, true >/dev/null 2>"$OUT/perf-probe.txt"; then
  if grep -qi 'not supported\|not counted\|<not' "$OUT/perf-probe.txt"; then
    miss "perf present but hardware counters not exposed (VM vPMU off) — no IPC/cache-miss numbers"
  else
    ok "hardware PMU counters available — will capture IPC / cache-miss / branch-miss in the bench"
    PMU_OK=1
  fi
else
  miss "perf/PMU unavailable — IPC & cache-miss profile can only be captured on bare-metal with a PMU"
fi

# ---------------------------------------------------------------------------
section "5. Software benchmark (always runs — no NIC/root needed)"
if have cargo; then
  ( cd "$REPO_ROOT" && cargo build --release -p andromeda-cli >/dev/null 2>"$OUT/build.txt" ) \
    && ok "release binary built" || { miss "cargo build failed — see $OUT/build.txt"; }
  BIN="$REPO_ROOT/target/release/andromeda"
  if [[ -x "$BIN" ]]; then
    note "selftest:"; "$BIN" selftest 2>&1 | tee "$OUT/selftest.txt" | sed 's/^/    /' || true
    note "bench (JSON → $OUT/bench.json):"
    "$BIN" bench --json > "$OUT/bench.json" 2>/dev/null && sed 's/^/    /' "$OUT/bench.json" | head -40 || note "    (bench --json not available in this build)"
    note "cache sweep (working-set × access pattern → $OUT/sweep.txt):"
    "$BIN" bench --sweep > "$OUT/sweep.txt" 2>/dev/null && sed 's/^/    /' "$OUT/sweep.txt" | head -30 || note "    (bench --sweep not available)"
    # Same bench under perf, if the PMU is real — this is the honest hardware profile.
    if [[ "${PMU_OK:-0}" == 1 ]]; then
      note "perf-counter profile of the bench → $OUT/perf-bench.txt:"
      perf stat -e cycles,instructions,L1-dcache-load-misses,LLC-load-misses,branch-misses \
        "$BIN" bench 2>"$OUT/perf-bench.txt" >/dev/null || true
      sed 's/^/    /' "$OUT/perf-bench.txt" | grep -Ei 'insn per cycle|instructions|cycles|miss' || true
    fi
  fi
else
  miss "cargo not found — install rustup to run the software bench"
fi

# ---------------------------------------------------------------------------
section "6. AF_XDP zero-copy bind (needs --iface + root + libxdp)"
if [[ -z "$IFACE" ]]; then
  miss "skipped: no --iface (pass --iface <dev> on a bare-metal box to test real zero-copy)"
elif [[ "$(id -u)" != 0 ]]; then
  miss "skipped: AF_XDP bind needs root (re-run: sudo $0 --iface $IFACE)"
elif ! ( cd "$REPO_ROOT" && cargo build --release -p andromeda-cli --features afxdp >/dev/null 2>"$OUT/afxdp-build.txt" ); then
  miss "afxdp build failed — install: libxdp-dev libbpf-dev clang m4 pkg-config (see $OUT/afxdp-build.txt)"
else
  BIN="$REPO_ROOT/target/release/andromeda"
  note "requesting zero-copy on $IFACE for 1s (transparently falls back to copy if unsupported):"
  "$BIN" run "$IFACE" --zerocopy --secs 1 > "$OUT/afxdp-bind.txt" 2>&1 || true
  grep -iE "bind mode|^bound|EPERM|failed to open" "$OUT/afxdp-bind.txt" | sed 's/^/    /' || true
  if grep -qi "native zero-copy" "$OUT/afxdp-bind.txt"; then
    ok "TRUE ZERO-COPY achieved on $IFACE — this is the number to benchmark"
  elif grep -qi "bind mode: copy" "$OUT/afxdp-bind.txt"; then
    miss "bound in COPY mode: this driver has no AF_XDP zero-copy (expected on veth/virtio)"
  else
    miss "could not bind (need root + a real NIC + libxdp; see $OUT/afxdp-bind.txt)"
  fi
fi

# ---------------------------------------------------------------------------
section "Summary"
echo "  full report + raw logs: $OUT"
echo "  paste back: $SUMMARY   (and $OUT/perf-bench.txt if a PMU was present)"
echo
echo "  What this box CAN validate now is marked [ok]; what it can't is marked [NOT AVAILABLE]"
echo "  with the reason. For native zero-copy + PMU + tail-latency, rent BARE-METAL with an"
echo "  mlx5/ice/i40e/ixgbe NIC (not a GPU VM) and re-run with --iface."
