#!/usr/bin/env bash
#
# Light-Andromeda end-to-end demo on a veth pair.
#
# Sets up an isolated veth topology, runs the AF_XDP switch on one end, sends
# tenant traffic from the other end, and shows (a) that packets reach user space
# past the kernel stack, and (b) the Andromeda-encapsulated packets on the wire.
#
# Requires: root (CAP_NET_ADMIN), a kernel with CONFIG_XDP_SOCKETS, libxdp, and
# the binary built with the afxdp feature:
#   cargo build --release -p andromeda-cli --features afxdp
#
# Usage:
#   sudo ./scripts/demo.sh [bypass|encap]   (default: encap)
#
set -euo pipefail

MODE="${1:-encap}"
BIN="${ANDROMEDA_BIN:-$(command -v andromeda || echo ./target/release/andromeda)}"
HOST_IF="an0"
NS="andro"
PEER_IF="an1"
HOST_IP="10.10.0.1"
PEER_IP="10.10.0.2"
VNI=100
PEER_NODE="192.168.1.2"

if [[ ! -x "$BIN" ]]; then
    echo "binary not found: $BIN" >&2
    echo "build it: cargo build --release -p andromeda-cli --features afxdp" >&2
    echo "or set ANDROMEDA_BIN=/path/to/andromeda" >&2
    exit 1
fi

cleanup() {
    ip netns del "$NS" 2>/dev/null || true
    ip link del "$HOST_IF" 2>/dev/null || true
}
trap cleanup EXIT
cleanup

echo "== building topology: $HOST_IF (host) <-> $PEER_IF (netns $NS) =="
ip link add "$HOST_IF" type veth peer name "$PEER_IF"
ip netns add "$NS"
ip link set "$PEER_IF" netns "$NS"
ip addr add "$HOST_IP/24" dev "$HOST_IF"
ip link set "$HOST_IF" up
ip netns exec "$NS" ip addr add "$PEER_IP/24" dev "$PEER_IF"
ip netns exec "$NS" ip link set "$PEER_IF" up
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" sysctl -q -w net.ipv6.conf.all.disable_ipv6=1 || true
# Static neighbour so the tenant emits IP directly (its ARP would go unanswered,
# because the switch redirects everything away from the host stack).
HOST_MAC="$(cat /sys/class/net/$HOST_IF/address)"
ip netns exec "$NS" ip neigh replace "$HOST_IP" lladdr "$HOST_MAC" dev "$PEER_IF"

if [[ "$MODE" == "bypass" ]]; then
    echo "== running switch in DUMP mode (proves user-space RX / kernel bypass) =="
    "$BIN" run "$HOST_IF" --mode dump --secs 6 --skb &
    RUNPID=$!
    sleep 1.5
    echo "== tenant pings $HOST_IP — replies should be ZERO (packets bypass the kernel) =="
    ip netns exec "$NS" ping -c 4 -i 0.4 -W 1 "$HOST_IP" || true
    wait "$RUNPID" || true
else
    echo "== capturing overlay packets on the peer (udp port 43481) =="
    ip netns exec "$NS" timeout 7 tcpdump -nvXi "$PEER_IF" udp port 43481 &
    TDPID=$!
    sleep 0.5
    echo "== running switch in ENCAP mode (wraps tenant frames into the Andromeda overlay) =="
    "$BIN" run "$HOST_IF" --mode encap --secs 6 --skb --peer-node "$PEER_NODE" --vni "$VNI" &
    RUNPID=$!
    sleep 1.5
    echo "== tenant pings $HOST_IP — each ping is encapsulated and sent to $PEER_NODE =="
    ip netns exec "$NS" ping -c 4 -i 0.4 -W 1 "$HOST_IP" >/dev/null 2>&1 || true
    wait "$RUNPID" || true
    wait "$TDPID" 2>/dev/null || true
fi

echo "== done =="
