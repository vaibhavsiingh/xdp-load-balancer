#!/usr/bin/env bash
# Network-namespace demo of the XDP DSR load balancer. Needs root.
#
#   make                         build first, as your user
#   sudo scripts/demo.sh up      build the topology, start backends + lbctl
#   sudo scripts/demo.sh test    spread requests, kill a backend, watch failover
#   sudo scripts/demo.sh down    tear everything down
#   sudo scripts/demo.sh all     up + test + down
#
# sudo FLOW_CACHE=off scripts/demo.sh up   disables the flow cache (for benchmarking)
#
# Topology (one L2 segment, 10.0.0.0/24, joined by a bridge in the root ns):
#   client .2   lb .1 (VIP .100, XDP on eth0)   be1 .11   be2 .12   be3 .13
# Backends hold the VIP on lo, so they reply straight to the client.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
RUN=$ROOT/build/demo
VIP=10.0.0.100
BACKENDS=(be1 be2 be3)

[[ $EUID -eq 0 ]] || { echo "run as root (sudo)"; exit 1; }
mkdir -p "$RUN"

in_ns() { local ns=$1; shift; ip netns exec "$ns" "$@"; }

add_host() {  # name, last-octet
  local ns=$1 ip=$2
  ip netns add "$ns"
  ip link add "v-$ns" type veth peer name eth0 netns "$ns"
  ip link set "v-$ns" master br-lb up
  in_ns "$ns" ip link set lo up
  in_ns "$ns" ip addr add "10.0.0.$ip/24" dev eth0
  in_ns "$ns" ip link set eth0 up
  in_ns "$ns" ethtool -K eth0 tx off rx off >/dev/null 2>&1 || true
}

up() {
  [[ -x $ROOT/build/lbctl ]] || { echo "run 'make' first (as your user, not root)"; exit 1; }
  ip link add br-lb type bridge
  ip link set br-lb up
  add_host client 2
  add_host lb 1
  in_ns lb ip addr add "$VIP/32" dev eth0           # kernel answers ARP for the VIP
  local i=11
  for be in "${BACKENDS[@]}"; do
    add_host "$be" $i
    in_ns "$be" ip addr add "$VIP/32" dev lo        # DSR: accept traffic for the VIP...
    in_ns "$be" sysctl -qw net.ipv4.conf.all.arp_ignore=1       # ...but never ARP for it
    in_ns "$be" sysctl -qw net.ipv4.conf.all.arp_announce=2
    NAME=$be in_ns "$be" python3 "$ROOT/scripts/backend.py" &
    echo $! > "$RUN/$be.pid"
    i=$((i + 1))
  done

  cat > "$RUN/lb.conf" <<CONF
iface eth0
vip $VIP
xdp_mode generic
flow_cache ${FLOW_CACHE:-on}
health interval=500 timeout=300 rise=2 fall=2
backend 10.0.0.11 8080
backend 10.0.0.12 8080
backend 10.0.0.13 8080
CONF
  # Only the network namespace needs to be the LB's; maps are pinned in the
  # shared bpffs, so `lbctl stats` works from the root namespace.
  nsenter --net=/run/netns/lb "$ROOT/build/lbctl" run \
      -c "$RUN/lb.conf" >"$RUN/lbctl.log" 2>&1 &
  echo $! > "$RUN/lbctl.pid"
  sleep 3
  cat "$RUN/lbctl.log"
}

requests() {  # n -> counts per backend
  for _ in $(seq "$1"); do
    in_ns client curl -s --max-time 2 "http://$VIP:8080/" || echo "FAILED"
  done | sort | uniq -c
}

test_failover() {
  echo "== 30 requests across 3 healthy backends"
  requests 30
  echo "== counters"
  "$ROOT/build/lbctl" stats
  echo "== killing be2, waiting for health check to notice"
  kill "$(cat "$RUN/be2.pid")"
  sleep 2.5
  echo "== 30 requests, be2 should be gone"
  requests 30
  echo "== lbctl log"
  tail -n 8 "$RUN/lbctl.log"
}

down() {
  for f in "$RUN"/*.pid; do
    [[ -e $f ]] || continue
    kill "$(cat "$f")" 2>/dev/null || true
    rm -f "$f"
  done
  sleep 1   # lbctl detaches XDP on SIGTERM
  for ns in client lb "${BACKENDS[@]}"; do
    ip netns del "$ns" 2>/dev/null || true
    ip link del "v-$ns" 2>/dev/null || true
  done
  ip link del br-lb 2>/dev/null || true
}

case "${1:-}" in
  up) up ;;
  test) test_failover ;;
  down) down ;;
  all) trap down EXIT; up; test_failover ;;
  *) echo "usage: $0 up|test|down|all"; exit 1 ;;
esac
