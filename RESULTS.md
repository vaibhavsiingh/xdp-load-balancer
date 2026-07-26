# Results

Measured with `sudo scripts/run_benchmarks.sh`. Raw output for
every number below is in [`results/`](results/).

| | |
|---|---|
| CPU | AMD Ryzen 7 5800HS (8 cores / 16 threads), laptop |
| Kernel | Linux 7.0.0-38-generic |
| Toolchain | clang 21.1.8, bpftool 7.7.0 |
| XDP mode | `bench_prog`: none (test run); demo and pktgen: generic, over veth |
| Backends | 3, Maglev table of 4093 slots |

The laptop was in normal use (browser open) during the run, so expect a few
percent of noise. Each microbenchmark figure is a median of 7 rounds.

## Summary

| | Flow cache off | Flow cache on |
|---|---|---|
| Program cost, isolated (`BPF_PROG_TEST_RUN`, median) | **73.4 ns** | **113.3 ns** |
| ...of which balancing (above the early-`XDP_PASS` floor) | **15.9 ns** | **54.5 ns** |
| Program cost, live traffic (pktgen, 1024 flows, `bpf_stats`) | 73.0 ns | 111.6 ns |
| Forwarded under pktgen (1024 flows) | 213,795 pps, 0 dropped | 214,704 pps, 0 dropped |
| Spread over 3 backends (1024 flows) | 33.0 / 34.0 / 33.0 % | 33.0 / 34.0 / 33.1 % |

- **Hashing and the Maglev lookup cost about 16 ns per packet.** The flow-cache
  lookup (an LRU hash map) adds about **39 ns** on top, more than all the rest
  of the balancing combined. The two benchmarks agree exactly on that: 54.5 − 15.9
  and 111.6 − 73.0 are both 38.6 ns.
- **The isolated and live figures match within 2%**, so the microbenchmark
  reflects how the program behaves under real traffic.
- **Throughput here is limited by the test setup, not the program.** All four
  pktgen runs forward about 215k pps whatever the program costs. That's the
  ceiling of one pktgen thread through veth, a bridge and generic XDP. At
  73 ns per packet, the program alone would fit roughly 13 Mpps on one core,
  so end-to-end throughput on a real NIC in native mode would be bounded by the
  driver, not by this code.
- **Every packet was accounted for**: pps sent, seen by XDP and forwarded agree
  within a few dozen pps in every run, with 0 TX errors and 0 drops.

## 1. Program cost in isolation

`build/bench_prog`: the kernel runs the program 20,000 times per flow on a
crafted 64-byte UDP packet, over 1024 flows, pinned to CPU 2. The *floor* is a
packet to a non-VIP address, which parses the headers and exits with
`XDP_PASS`. Subtracting it leaves the cost of the balancing itself.

| | Forward path | Floor | Balancing |
|---|---|---|---|
| Cache off | 73.4 ns (min 72.5) | 57.5 ns | **15.9 ns** |
| Cache on | 113.3 ns (min 109.2) | 58.8 ns | **54.5 ns** |

With the cache off, the path is `hash_flow` plus three array lookups
(`lookup_table`, `backends`, the stats maps), which the verifier inlines into a
few instructions each. With the cache on, every packet also does a hash-map
lookup that the kernel can't inline. Here every lookup is a hit, because the
warm-up fills the cache first.

## 2. Live traffic (pktgen)

`scripts/bench.py`: one pktgen thread in the demo's `client` namespace sends
64-byte UDP packets to the VIP for 10 s after a 2 s warm-up. Time per packet
comes from the kernel's BPF run-time statistics (`kernel.bpf_stats_enabled`).

| Flows | Cache | Forwarded | ns/pkt in XDP | Cache hits | Backend spread |
|---|---|---|---|---|---|
| 1024 | off | 213,795 pps | 73.0 | 0 % | 33.0 / 34.0 / 33.0 % |
| 1024 | on | 214,704 pps | 111.6 | 100 % | 33.0 / 34.0 / 33.1 % |
| 1 | off | 216,566 pps | 69.7 | 0 % | 0 / 100 / 0 % |
| 1 | on | 215,542 pps | 107.5 | 100 % | 0 / 100 / 0 % |

- **The spread is even.** Across 1024 flows the three backends receive 33–34%
  each, within 1 point of a perfect third.
- **A single flow always goes to one backend**, as it must: one 5-tuple means one
  hash and one Maglev slot. Spreading load needs many flows.
- **1024 flows cost about 3–4 ns per packet more than 1 flow**, likely because
  more map entries and table slots are in use, which means more cache misses.
- **Cache hits are 100% with the cache on** because all 1024 flows were inserted
  during the warm-up. In real traffic, each new connection's first packet misses.

## 3. Failover (`scripts/demo.sh all`)

Three Python HTTP backends. `lbctl` uses `interval=500 timeout=300 rise=2 fall=2`.
The demo sends 30 `curl` requests, kills be2, waits 2.5 s and sends 30 more.

| | be1 | be2 | be3 | Failed |
|---|---|---|---|---|
| 30 requests, 3 backends up | 15 | 9 | 6 | 0 |
| 30 requests, after be2 is killed | 12 | — | 18 | **0** |

Control-plane log ([`results/demo_failover.txt`](results/demo_failover.txt)):

```
04:30:54  backend 10.0.0.11:8080 is UP
04:30:54  backend 10.0.0.12:8080 is UP
04:30:54  lookup table: 4093/4093 slots updated, 2 healthy backend(s)
04:30:55  backend 10.0.0.13:8080 is UP
04:30:55  lookup table: 1384/4093 slots updated, 3 healthy backend(s)
04:30:58  backend 10.0.0.12:8080 is DOWN
04:30:58  lookup table: 1375/4093 slots updated, 2 healthy backend(s)
```

- **The table update is minimal.** be2 owned about a third of the table
  (≈1,364 slots), and 1,375 slots changed when it went down. So only about 11 of
  the survivors' ≈2,729 slots moved (≈0.4%). When be3 joined, 1,384 slots
  changed: its new share, plus about 20 moved between be1 and be2. This is the
  Maglev property working at full table size.
- **No request failed** after be2 was removed. The demo waits 2.5 s after the
  kill, so this shows traffic is correctly redistributed after detection. It
  doesn't measure the detection window itself (`fall` × `interval` ≈ 1 s here),
  during which new flows can still reach a dead backend.
- **The flow cache works as expected.** The counters show `rx_vip=210`,
  `flow_cache_hits=180`: 7 packets per HTTP request, with exactly one miss per
  request (the SYN of each of the 30 new connections) and every other packet
  served from the cache.
- **15 / 9 / 6 isn't a skew.** With only 30 flows, that's within normal random
  variation from an even split (χ² = 4.2, p ≈ 0.12). The 1024-flow pktgen
  runs above show the actual spread.

## 4. Correctness tests

`make test` needs no root:

| Suite | Result |
|---|---|
| `tests/test_lb.c`: Maglev (prime size, determinism, even spread, < 10% disruption on removal), health debouncing, bring-up and take-down write order, steady state writes nothing, MAC learning | **47 / 47 checks pass** |
| `tests/test_bench.py`: pktgen output parsing, metric calculation | **3 / 3 pass** |

The build is warning-free with `-Wall -Wextra -Werror` for both the BPF and
userspace code.

## Limits of these numbers

- **Not line rate.** veth with generic XDP goes through the kernel's skb path.
  For line-rate numbers, run pktgen from another host against a real NIC with
  `xdp_mode native`.
- **Warm cache.** `BPF_PROG_TEST_RUN` reruns the program on the same packet, so
  it's a lower bound. The live figure is close to it here because the test
  setup touches few flows. With millions of flows, flow-cache misses and inserts
  would cost more.
- **One machine, one run.** Laptop CPU frequency changes with load and power
  source. Rerun on your hardware with `sudo scripts/run_benchmarks.sh`.
