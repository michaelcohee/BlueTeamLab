import json, os, shutil, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lab import common as C, hunt
from lab.normalize import normalize_session
from tests import synth as S


def build(fn):
    vd = tempfile.mkdtemp(prefix="dl-test-")
    sess = os.path.join(vd, "raw", "20261001T120000Z")
    os.makedirs(sess)
    w = S.Writer(sess)
    fn(w)
    w.flush_osquery()
    normalize_session(sess, os.path.join(vd, "norm"))
    return vd


def run(vd, since=0, rule=None, loopback=False):
    # no baseline built -> everything after `since` is in scope, nothing is "known"
    _, hits, _, _ = hunt.hunt(vd, since=S.start_str(since), only=[rule] if rule else None, include_loopback=loopback)
    return hits


def ids(hits):
    return sorted(h["rule_id"] for h in hits)


class RuleTests(unittest.TestCase):
    def setUp(self):
        self.vds = []
    def tearDown(self):
        for v in self.vds:
            shutil.rmtree(v, ignore_errors=True)
    def b(self, fn):
        vd = build(fn); self.vds.append(vd); return vd

    # ---- R1 shard fan-out
    def test_R1_fires(self):
        def f(w):
            rows = [S.conn_row(10 + i, "192.168.1.50", 40000 + i, "93.184.%d.1" % i, 443, 50000 + (i % 3))
                    for i in range(10)]
            w.conn(rows)
        vd = self.b(f)
        h = run(vd, rule="R1")
        self.assertEqual(len(h), 1)
        self.assertGreaterEqual(h[0]["metrics"]["new_endpoints"], 8)
        self.assertLess(h[0]["metrics"]["size_cv"], 0.15)
        self.assertTrue(h[0]["evidence"])

    def test_R1_no_fire_variable_sizes(self):
        def f(w):
            w.conn([S.conn_row(10 + i, "192.168.1.50", 40000 + i, "93.184.%d.1" % i, 443, (i + 1) * 9000)
                    for i in range(10)])
        self.assertEqual(run(self.b(f), rule="R1"), [])

    def test_R1_no_fire_few_endpoints(self):
        def f(w):
            w.conn([S.conn_row(10 + i, "192.168.1.50", 40000 + i, "93.184.%d.1" % (i % 3), 443, 50000)
                    for i in range(10)])
        self.assertEqual(run(self.b(f), rule="R1"), [])

    # ---- R2 volume spike (no baseline => p99 0, only the floor applies)
    def test_R2_fires_over_floor(self):
        def f(w):
            w.conn([S.conn_row(10 + i, "192.168.1.50", 40000 + i, "93.184.9.1", 443, 20 * 1024 * 1024)
                    for i in range(5)])
        h = run(self.b(f), rule="R2")
        self.assertEqual(len(h), 1)

    def test_R2_no_fire_under_floor(self):
        def f(w):
            w.conn([S.conn_row(10 + i, "192.168.1.50", 40000 + i, "93.184.9.1", 443, 1024) for i in range(5)])
        self.assertEqual(run(self.b(f), rule="R2"), [])

    # ---- R3 beaconing
    def test_R3_fires_regular(self):
        def f(w):
            w.conn([S.conn_row(100 + i * 30, "192.168.1.50", 40000 + i, "93.184.20.1", 443, 800) for i in range(12)])
        h = run(self.b(f), rule="R3")
        self.assertEqual(len(h), 1)
        self.assertLess(h[0]["metrics"]["jitter"], 0.10)

    def test_R3_no_fire_jittery(self):
        def f(w):
            gaps = [5, 90, 12, 200, 7, 160, 33, 15, 240, 9, 120]
            sec, rows = 100, []
            for i, g in enumerate(gaps):
                sec += g
                rows.append(S.conn_row(sec, "192.168.1.50", 40000 + i, "93.184.20.1", 443, 800))
            w.conn(rows)
        self.assertEqual(run(self.b(f), rule="R3"), [])

    # ---- R4 dns tunnel
    def test_R4_fires_long_random(self):
        def f(w):
            w.dns([S.dns_row(10 + i, "zX9qp%d7kfm2vbn4rt8wlq3hj.evil-cdn.example" % i) for i in range(5)])
        h = run(self.b(f), rule="R4")
        self.assertEqual(len(h), 1)
        self.assertGreater(h[0]["metrics"]["max_entropy"], 3.5)

    def test_R4_no_fire_normal(self):
        def f(w):
            w.dns([S.dns_row(10 + i, "www.apple.com") for i in range(5)])
        self.assertEqual(run(self.b(f), rule="R4"), [])

    # ---- R5 first-seen network binary (needs osquery process+socket attribution)
    def test_R5_fires_and_attributes(self):
        def f(w):
            w.osq_sample(5, processes=[S.proc_row(900, 1, "sneaky", "/tmp/sneaky", 3)],
                         sockets=[S.sock_row(900, 41000, "93.184.30.1", 443, "/tmp/sneaky")])
            w.conn([S.conn_row(6, "192.168.1.50", 41000, "93.184.30.1", 443, 500, uid="X1")])
        h = run(self.b(f), rule="R5")
        self.assertEqual(len(h), 1)
        self.assertEqual(h[0]["process_path"], "/tmp/sneaky")
        self.assertTrue(h[0]["proc_key"], "socket row should attribute a proc_key")

    # ---- R6 new persistence
    def test_R6_fires(self):
        def f(w):
            w.osq_sample(5, launchd=[{"label": "com.evil.agent", "path": "/Users/x/Library/LaunchAgents/com.evil.agent.plist",
                                      "program": "/tmp/evil", "program_arguments": "/tmp/evil --run", "run_at_load": "1"}])
        h = run(self.b(f), rule="R6")
        self.assertEqual(len(h), 1)
        self.assertIn("com.evil.agent", h[0]["summary"])

    def test_clean_session_quiet(self):
        def f(w):
            w.osq_sample(5, processes=[S.proc_row(500, 1, "mdworker", "/usr/libexec/mdworker", 1)],
                         sockets=[S.sock_row(500, 42000, "17.253.1.1", 443, "/usr/libexec/mdworker")])
            w.conn([S.conn_row(6, "192.168.1.50", 42000, "17.253.1.1", 443, 300, uid="A")])
            w.dns([S.dns_row(7, "www.apple.com")])
        h = run(self.b(f))
        # only R5 (first-seen, no baseline) should speak; R1-R4,R6 silent
        self.assertEqual(ids(h), ["R5"])


if __name__ == "__main__":
    unittest.main()
