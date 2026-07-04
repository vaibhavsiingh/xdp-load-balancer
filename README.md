# Kernel-Bypass Load Balancer (eBPF/XDP)

A layer-4 load balancer that runs in the NIC driver's receive path via XDP,
before the kernel network stack touches the packet. C + libbpf throughout.

- **Fast path** (`bpf/xdp_lb.bpf.c`): hashes the 5-tuple (Jenkins lookup3),
  picks a backend from a Maglev table, rewrites the Ethernet header and
  returns `XDP_TX`. No allocation, no socket, no conntrack.
- **Direct Server Return**: only the L2 destination changes; the IP packet
  still says `dst = VIP`. Backends hold the VIP on `lo` and answer the client
  directly, so return traffic never passes through the LB.
- **Control plane** (`src/`): a userspace daemon that loads and attaches the
  program (libbpf skeleton), health-checks backends over TCP, learns their
  MACs, rebuilds the Maglev table and pushes only the changed slots into the
  live BPF maps. The XDP program is never reloaded.

```
client ──► LB (XDP: hash, rewrite dst MAC, XDP_TX) ──► backend
   ▲                                                      │
   └──────────── reply, src = VIP, bypasses LB ───────────┘
```

## Design notes

| Concern | Choice |
|---|---|
| Backend selection | Maglev table (4093 slots); removing a backend remaps ~only its own slots |
| Connection stickiness | LRU `flow_cache` map (5-tuple → backend) so table changes don't move live flows; `flow_cache off` removes the code from the program |
| Per-packet cost | VIP / LB MAC / cache switch are `.rodata` constants folded by the verifier; all global counters share one per-CPU struct (one lookup) |
| Fragments | all fragments of a datagram hash on the 3-tuple so they stay together |
| Non-VIP / non-TCP/UDP / frames not addressed to the LB MAC | `XDP_PASS` to the kernel (ARP, ICMP to the VIP, SSH, … keep working) |
| No healthy backend | `XDP_DROP`, counted |
| Failover ordering | bring-up: backend entry → table; take-down: table → backend flag, so new flows never hit a dying backend |
| Health checks | all backends probed in parallel with non-blocking connects in one `poll()` loop; `rise` / `fall` debouncing |

**Constraint of L2 DSR:** backends must be on the same L2 segment as the LB
interface, with the VIP on `lo` and `arp_ignore=1`, `arp_announce=2`.
The LB interface itself must own the VIP so the kernel answers ARP for it.
Changing the VIP, LB MAC or `flow_cache` needs a restart (they are load-time
constants); backends and health are fully live.

## Build & run

Requirements: `clang`, `bpftool`, `libbpf-dev`, Linux with BTF
(`/sys/kernel/btf/vmlinux`), root to run.

```sh
make                 # build/lbctl (BPF object embedded)
make test            # unit tests: Maglev, health, failover ordering (no root needed)

sudo scripts/demo.sh all     # netns demo: 3 backends, load spread, kill one, failover
```

Real deployment:

```sh
sudo build/lbctl run -c lb.conf.example --stats-interval 10
sudo build/lbctl stats [--json]      # from another shell
sudo build/lbctl detach -c lb.conf   # remove a stale attachment after a crash
```

`xdp_mode`: `auto` (driver if supported, else generic), `native`, `generic`, `offload`.
Use `generic` for veth / virtual NICs. Config format: see `lb.conf.example`.

## Layout

```
bpf/lb_common.h      structs & constants shared by kernel and userspace code
bpf/xdp_lb.bpf.c     XDP data plane
src/lbctl.c          daemon: config, libbpf load/attach, prober, stats CLI
src/balancer.c       health -> map reconciliation (testable via a `sink`)
src/maglev.c         consistent-hash table generation
src/health.h         rise/fall debouncing
scripts/demo.sh      network-namespace demo
scripts/bench.py     pktgen benchmark against the demo topology
tests/bench_prog.c   BPF_PROG_TEST_RUN microbenchmark of the XDP program
tests/               unit tests (no root needed)
```
