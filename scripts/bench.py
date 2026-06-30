#!/usr/bin/env python3
"""pktgen benchmark for the XDP load balancer. Run as root, after `demo.sh up`.

Generates UDP traffic to the VIP from the demo's `client` namespace with the
kernel's pktgen, then reports:

  * packets/s sent (pktgen) and handled by the XDP program
  * ns per packet spent *inside* the XDP program (kernel BPF run-time stats)
  * flow-cache hit ratio and the spread across backends

    sudo scripts/demo.sh up
    sudo scripts/bench.py --duration 10 --flows 1024 --size 64
    sudo scripts/demo.sh down

Caveat: the demo topology is veth + generic XDP, so absolute pps is bounded by
veth and the skb path, not by the XDP program. The ns/packet figure is the
meaningful one; for line-rate numbers run pktgen from another host at a real
NIC in native mode and read the same counters (`bpftool prog show`).
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time

LBCTL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "build", "lbctl")
BPF_STATS = "/proc/sys/kernel/bpf_stats_enabled"
SOFAR = re.compile(r"pkts-sofar:\s*(\d+)\s+errors:\s*(\d+)")


def sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, check=True, **kw).stdout


def in_ns(ns, script):
    """Run a shell script inside a network namespace."""
    return subprocess.run(["ip", "netns", "exec", ns, "sh", "-c", script],
                          capture_output=True, text=True)


def parse_sofar(text):
    """pktgen device file -> (packets sent, errors)."""
    m = SOFAR.search(text)
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


def summarize(a, b):
    """Two samples (see sample()) -> metrics for the interval between them."""
    dt = b["t"] - a["t"]
    d = lambda k: b[k] - a[k]  # noqa: E731
    xdp_pkts = d("run_cnt")
    stats = {k: b["stats"][k] - a["stats"][k] for k in b["stats"]}
    fwd = stats["forwarded"]
    return {
        "seconds": dt,
        "tx_pps": d("tx") / dt,
        "tx_errors": d("tx_err"),
        "xdp_pps": xdp_pkts / dt,
        "forwarded_pps": fwd / dt,
        "dropped": stats["dropped_no_backend"],
        "ns_per_pkt": d("run_ns") / xdp_pkts if xdp_pkts else float("nan"),
        "cache_hit_pct": 100 * stats["flow_cache_hits"] / stats["rx_vip"] if stats["rx_vip"] else 0.0,
        "per_backend": {k: b["be"].get(k, 0) - a["be"].get(k, 0) for k in b["be"]},
    }


class Bench:
    def __init__(self, args):
        self.args = args
        self.devs = [f"eth0@{t}" for t in range(args.threads)]

    def configure(self):
        a = self.args
        lb_mac = in_ns("lb", "cat /sys/class/net/eth0/address").stdout.strip()
        if not lb_mac:
            sys.exit("namespace 'lb' not found: run `sudo scripts/demo.sh up` first")
        sh(["modprobe", "pktgen"])
        lines = []
        for t in range(a.threads):
            lines.append(f'echo "rem_device_all" > /proc/net/pktgen/kpktgend_{t}')
        for t, dev in enumerate(self.devs):
            lines += [f'echo "add_device {dev}" > /proc/net/pktgen/kpktgend_{t}']
        for dev in self.devs:
            for cmd in ("count 0", "clone_skb 0", f"pkt_size {a.size}", "delay 0",
                        "dst 10.0.0.100", f"dst_mac {lb_mac}",
                        "udp_dst_min 9", "udp_dst_max 9",
                        "udp_src_min 1024", f"udp_src_max {1024 + a.flows - 1}",
                        "flag UDPSRC_RND", "flag QUEUE_MAP_CPU"):
                lines.append(f'echo "{cmd}" > /proc/net/pktgen/{dev}')
        r = in_ns("client", "\n".join(lines))
        if r.returncode != 0:
            sys.exit(f"pktgen setup failed: {r.stderr.strip()}")

    def sample(self):
        tx = tx_err = 0
        for dev in self.devs:
            sent, err = parse_sofar(in_ns("client", f"cat /proc/net/pktgen/{dev}").stdout)
            tx, tx_err = tx + sent, tx_err + err
        info = json.loads(sh(["bpftool", "-j", "prog", "show", "name", "xdp_lb"]))
        info = info[0] if isinstance(info, list) else info
        counters = json.loads(sh([LBCTL, "stats", "--json"]))
        backends = counters.pop("backends")
        return {
            "t": time.monotonic(), "tx": tx, "tx_err": tx_err,
            "run_cnt": info.get("run_cnt", 0), "run_ns": info.get("run_time_ns", 0),
            "stats": counters, "be": {x["idx"]: x["packets"] for x in backends},
        }

    def run(self):
        a = self.args
        self.configure()
        prev = open(BPF_STATS).read()
        open(BPF_STATS, "w").write("1")
        gen = subprocess.Popen(["ip", "netns", "exec", "client", "sh", "-c",
                                "echo start > /proc/net/pktgen/pgctrl"])
        try:
            time.sleep(a.warmup)
            first = self.sample()
            if first["tx"] == 0:
                sys.exit("pktgen is not sending; check `dmesg` and the device file in "
                         "/proc/net/pktgen/ inside the client namespace")
            start = self.sample()
            time.sleep(a.duration)
            end = self.sample()
        finally:
            in_ns("client", "echo stop > /proc/net/pktgen/pgctrl")
            gen.wait(timeout=10)
            in_ns("client", "\n".join(f'echo "rem_device_all" > /proc/net/pktgen/kpktgend_{t}'
                                      for t in range(a.threads)))
            open(BPF_STATS, "w").write(prev)
        return summarize(start, end)


def report(args, m):
    print(f"\npktgen -> VIP  size={args.size}B  flows={args.flows}  threads={args.threads}  "
          f"{m['seconds']:.1f}s")
    print(f"  sent by pktgen      {m['tx_pps']:>12,.0f} pps   ({m['tx_errors']} tx errors)")
    print(f"  seen by XDP         {m['xdp_pps']:>12,.0f} pps")
    print(f"  forwarded (XDP_TX)  {m['forwarded_pps']:>12,.0f} pps   ({m['dropped']} dropped, no backend)")
    print(f"  time in XDP program {m['ns_per_pkt']:>12.1f} ns/pkt   (includes bpf_stats timing overhead)")
    print(f"  flow cache hits     {m['cache_hit_pct']:>11.1f} %")
    total = sum(m["per_backend"].values()) or 1
    for idx, n in sorted(m["per_backend"].items()):
        print(f"  backend[{idx}]          {n:>12,} pkts  {100 * n / total:5.1f}%")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--duration", type=float, default=10, help="measurement seconds (default 10)")
    p.add_argument("--warmup", type=float, default=2, help="seconds before measuring (default 2)")
    p.add_argument("--size", type=int, default=64, help="packet size in bytes (default 64)")
    p.add_argument("--flows", type=int, default=1024,
                   help="distinct UDP source ports; 1 = single flow (default 1024)")
    p.add_argument("--threads", type=int, default=1, help="pktgen kernel threads/CPUs (default 1)")
    args = p.parse_args()
    if os.geteuid() != 0:
        sys.exit("run as root (sudo)")
    if not 1 <= args.flows <= 64000:
        sys.exit("--flows must be 1..64000")
    report(args, Bench(args).run())


if __name__ == "__main__":
    main()
