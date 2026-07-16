#!/usr/bin/env bash
# Run every benchmark and the failover demo, saving raw output to results/.
# Needs root; build first as your user with `make`.
#
#   sudo scripts/run_benchmarks.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=$ROOT/results
CPU=${CPU:-2}

[[ $EUID -eq 0 ]] || { echo "run as root (sudo)"; exit 1; }
[[ -x $ROOT/build/bench_prog && -x $ROOT/build/lbctl ]] || { echo "run 'make' first"; exit 1; }
mkdir -p "$OUT"
trap '"$ROOT/scripts/demo.sh" down >/dev/null 2>&1 || true' EXIT   # never leave the topology up

run() {  # name, command...
  local name=$1; shift
  echo "### $name: $*"
  "$@" 2>&1 | tee "$OUT/$name.txt"
}

{
  uname -r
  lscpu | grep -E 'Model name|^CPU\(s\)'
  clang --version | head -1
  bpftool version | head -1
} > "$OUT/environment.txt"

# 1. Program cost alone (BPF_PROG_TEST_RUN), with and without the flow cache.
run bench_prog_cache_on  "$ROOT/build/bench_prog" --cpu "$CPU"
run bench_prog_cache_off "$ROOT/build/bench_prog" --cpu "$CPU" --cache off

# 2. Failover demo: spread, kill a backend, spread again.
run demo_failover "$ROOT/scripts/demo.sh" all

# 3. pktgen through the demo topology, flow cache on and off.
for cache in on off; do
  FLOW_CACHE=$cache "$ROOT/scripts/demo.sh" up >/dev/null
  run "pktgen_cache_${cache}_1024flows" "$ROOT/scripts/bench.py" --duration 10 --flows 1024
  run "pktgen_cache_${cache}_1flow"     "$ROOT/scripts/bench.py" --duration 10 --flows 1
  "$ROOT/scripts/demo.sh" down
done

[[ -n ${SUDO_USER:-} ]] && chown -R "$SUDO_USER": "$OUT"
echo "done: results in $OUT"
