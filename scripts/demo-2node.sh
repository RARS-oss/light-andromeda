#!/usr/bin/env bash
#
# Two-node end-to-end overlay demo: a real ping travels THROUGH the Andromeda
# overlay, hop-by-hop across two independent user-space AF_XDP switches — with
# NO static ARP entries (the switches answer tenant ARP themselves).
#
#   netns t1 (10.0.0.10)                                   netns t2 (10.0.0.20)
#     t1a ── t1b ─[ switch 1 ]─ u1 ══════ u2 ─[ switch 2 ]─ t2b ── t2a
#            tenant│underlay          overlay        underlay│tenant
#
# Each switch: proxy-ARPs the tenant, encapsulates the tenant's frames onto the
# underlay, and decapsulates the peer's frames onto the tenant. The fabric (which
# endpoint lives where, and its MAC) comes from a generated TOML config.
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

S1=""; S2=""; WORK=""
cleanup() {
    [[ -n "$S1" ]] && kill -INT "$S1" 2>/dev/null
    [[ -n "$S2" ]] && kill -INT "$S2" 2>/dev/null
    sleep 0.3
    ip netns del t1 2>/dev/null || true
    ip netns del t2 2>/dev/null || true
    ip link del t1b 2>/dev/null || true
    ip link del t2b 2>/dev/null || true
    ip link del u1 2>/dev/null || true
    [[ -n "$WORK" ]] && rm -rf "$WORK"
}
trap cleanup EXIT
cleanup
# Private, 0700, symlink-safe scratch dir for configs and logs (root runs this).
WORK="$(mktemp -d "${TMPDIR:-/tmp}/andromeda.XXXXXX")"

# --- topology: two tenants + an underlay link, all veths ---
ip netns add t1
ip link add t1a type veth peer name t1b
ip link set t1a netns t1
ip netns exec t1 ip addr add 10.0.0.10/24 dev t1a
ip netns exec t1 ip link set t1a up
ip netns exec t1 ip link set lo up
ip netns exec t1 sysctl -q -w net.ipv6.conf.all.disable_ipv6=1
ip link set t1b up

ip netns add t2
ip link add t2a type veth peer name t2b
ip link set t2a netns t2
ip netns exec t2 ip addr add 10.0.0.20/24 dev t2a
ip netns exec t2 ip link set t2a up
ip netns exec t2 ip link set lo up
ip netns exec t2 sysctl -q -w net.ipv6.conf.all.disable_ipv6=1
ip link set t2b up

ip link add u1 type veth peer name u2
ip link set u1 up
ip link set u2 up

# --- generate fabric configs with the tenants' real MACs ---
T1AMAC=$(ip netns exec t1 cat /sys/class/net/t1a/address)
T2AMAC=$(ip netns exec t2 cat /sys/class/net/t2a/address)

gen_cfg() {  # $1 = local_node, $2 = peer_node
    cat <<CFG
local_node          = "$1"
peer_node           = "$2"
vni                 = 100
virtual_gateway_mac = "02:00:00:00:00:ff"
vpc_cidr            = "10.0.0.0/24"

[[endpoint]]
inner_ip  = "10.0.0.10"
inner_mac = "$T1AMAC"
node_ip   = "192.168.1.1"

[[endpoint]]
inner_ip  = "10.0.0.20"
inner_mac = "$T2AMAC"
node_ip   = "192.168.1.2"
CFG
}
gen_cfg 192.168.1.1 192.168.1.2 > "$WORK/node1.toml"
gen_cfg 192.168.1.2 192.168.1.1 > "$WORK/node2.toml"

echo "== starting node 1 switch (t1b <-> u1) =="
"$BIN" switch --tenant t1b --underlay u1 --config "$WORK/node1.toml" --skb --secs 15 >"$WORK/sw1.log" 2>&1 &
S1=$!
echo "== starting node 2 switch (t2b <-> u2) =="
"$BIN" switch --tenant t2b --underlay u2 --config "$WORK/node2.toml" --skb --secs 15 >"$WORK/sw2.log" 2>&1 &
S2=$!
sleep 2.5

echo "== ping 10.0.0.10 -> 10.0.0.20 through the overlay (proxy-ARP, no static neigh) =="
ip netns exec t1 ping -c 4 -i 0.5 -W 2 10.0.0.20
RC=$?

kill -INT "$S1" "$S2" 2>/dev/null; sleep 0.4
echo "== node 1 (live stats) =="; grep -vE 'libbpf:|libxdp:' "$WORK/sw1.log" | tail -6
exit $RC
