#!/usr/bin/env bash
#
# Two-node end-to-end overlay demo: a real ping travels THROUGH the Andromeda
# overlay, hop-by-hop across two independent user-space AF_XDP switches.
#
#   netns t1 (10.0.0.10)                                   netns t2 (10.0.0.20)
#     t1a ── t1b ─[ switch 1 ]─ u1 ══════ u2 ─[ switch 2 ]─ t2b ── t2a
#            tenant│underlay          overlay        underlay│tenant
#
# switch 1 encapsulates tenant1's frames and sends them over the underlay;
# switch 2 decapsulates them onto tenant2 — and vice-versa for the replies.
#
# Requires root, libxdp, and the afxdp build:
#   cargo build --release -p andromeda-cli --features afxdp
#
# Usage: sudo ./scripts/demo-2node.sh
#
set -uo pipefail

BIN="${ANDROMEDA_BIN:-$(command -v andromeda || echo ./target/release/andromeda)}"
if [[ ! -x "$BIN" ]]; then
    echo "binary not found: $BIN (build with --features afxdp, or set ANDROMEDA_BIN)" >&2
    exit 1
fi

S1=""; S2=""
cleanup() {
    [[ -n "$S1" ]] && kill -INT "$S1" 2>/dev/null
    [[ -n "$S2" ]] && kill -INT "$S2" 2>/dev/null
    sleep 0.3
    ip netns del t1 2>/dev/null || true
    ip netns del t2 2>/dev/null || true
    ip link del t1b 2>/dev/null || true
    ip link del t2b 2>/dev/null || true
    ip link del u1 2>/dev/null || true
}
trap cleanup EXIT
cleanup

# tenant 1
ip netns add t1
ip link add t1a type veth peer name t1b
ip link set t1a netns t1
ip netns exec t1 ip addr add 10.0.0.10/24 dev t1a
ip netns exec t1 ip link set t1a up
ip netns exec t1 ip link set lo up
ip netns exec t1 sysctl -q -w net.ipv6.conf.all.disable_ipv6=1
ip link set t1b up

# tenant 2
ip netns add t2
ip link add t2a type veth peer name t2b
ip link set t2a netns t2
ip netns exec t2 ip addr add 10.0.0.20/24 dev t2a
ip netns exec t2 ip link set t2a up
ip netns exec t2 ip link set lo up
ip netns exec t2 sysctl -q -w net.ipv6.conf.all.disable_ipv6=1
ip link set t2b up

# underlay between the nodes
ip link add u1 type veth peer name u2
ip link set u1 up
ip link set u2 up

# static neighbours: each tenant addresses the far tenant's MAC directly, so no
# ARP is needed (the switches don't run an ARP responder in this MVP).
T1AMAC=$(ip netns exec t1 cat /sys/class/net/t1a/address)
T2AMAC=$(ip netns exec t2 cat /sys/class/net/t2a/address)
ip netns exec t1 ip neigh replace 10.0.0.20 lladdr "$T2AMAC" dev t1a
ip netns exec t2 ip neigh replace 10.0.0.10 lladdr "$T1AMAC" dev t2a

echo "== starting node 1 switch (t1b <-> u1) =="
"$BIN" switch --tenant t1b --underlay u1 --vni 100 \
    --local-node 192.168.1.1 --peer-node 192.168.1.2 --skb --secs 15 >/tmp/sw1.log 2>&1 &
S1=$!
echo "== starting node 2 switch (t2b <-> u2) =="
"$BIN" switch --tenant t2b --underlay u2 --vni 100 \
    --local-node 192.168.1.2 --peer-node 192.168.1.1 --skb --secs 15 >/tmp/sw2.log 2>&1 &
S2=$!
sleep 2.5

echo "== ping 10.0.0.10 -> 10.0.0.20 through the overlay =="
ip netns exec t1 ping -c 4 -i 0.5 -W 2 10.0.0.20
RC=$?

kill -INT "$S1" "$S2" 2>/dev/null; sleep 0.4
echo "== node 1 =="; grep -vE 'libbpf:|libxdp:' /tmp/sw1.log | tail -3
echo "== node 2 =="; grep -vE 'libbpf:|libxdp:' /tmp/sw2.log | tail -3
exit $RC
