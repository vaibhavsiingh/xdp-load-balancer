import importlib.util
import math
import os
import unittest

_spec = importlib.util.spec_from_file_location(
    "bench", os.path.join(os.path.dirname(__file__), "..", "scripts", "bench.py"))
bench = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bench)

PKTGEN_OUT = """Params: count 0  min_pkt_size: 64  max_pkt_size: 64
Current:
     pkts-sofar: 123456  errors: 7
     started: 1us  stopped: 2us idle: 0us
"""


NAMES = ["rx_vip", "forwarded", "flow_cache_hits", "dropped_no_backend", "bytes_forwarded"]


def sample(t, tx, run_cnt, run_ns, stats, be):
    return {"t": t, "tx": tx, "tx_err": 0, "run_cnt": run_cnt, "run_ns": run_ns,
            "stats": dict(zip(NAMES, stats)), "be": be}


class BenchTest(unittest.TestCase):
    def test_parse_sofar(self):
        self.assertEqual(bench.parse_sofar(PKTGEN_OUT), (123456, 7))
        self.assertEqual(bench.parse_sofar("garbage"), (0, 0))

    def test_summarize(self):
        a = sample(0.0, 0, 0, 0, [0, 0, 0, 0, 0], {0: 0, 1: 0})
        b = sample(2.0, 2_000_000, 1_000_000, 50_000_000,
                   [1_000_000, 1_000_000, 900_000, 0, 64_000_000], {0: 600_000, 1: 400_000})
        m = bench.summarize(a, b)
        self.assertEqual(m["tx_pps"], 1_000_000)
        self.assertEqual(m["xdp_pps"], 500_000)
        self.assertEqual(m["ns_per_pkt"], 50)
        self.assertEqual(m["cache_hit_pct"], 90)
        self.assertEqual(m["per_backend"], {0: 600_000, 1: 400_000})

    def test_no_packets_gives_nan_not_crash(self):
        a = sample(0.0, 0, 0, 0, [0] * 5, {})
        b = sample(1.0, 0, 0, 0, [0] * 5, {})
        self.assertTrue(math.isnan(bench.summarize(a, b)["ns_per_pkt"]))


if __name__ == "__main__":
    unittest.main()
