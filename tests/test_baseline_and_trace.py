import json, os, shutil, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lab import common as C, hunt, horizontal, bookdiff
from lab.normalize import normalize_session
from lab.vbook import Book
from tests import synth as S


class BaselineTests(unittest.TestCase):
    def setUp(self): self.vd = tempfile.mkdtemp(prefix="dl-bl-")
    def tearDown(self): shutil.rmtree(self.vd, ignore_errors=True)

    def _session(self, name, fn):
        sess = os.path.join(self.vd, "raw", name); os.makedirs(sess)
        w = S.Writer(sess); fn(w); w.flush_osquery()
        normalize_session(sess, os.path.join(self.vd, "norm"))

    def test_baseline_suppresses_known_then_fires_on_new(self):
        # history: binary A talks to a known host. hunt window: A again (known) + B (new).
        def hist(w):
            w.osq_sample(5, processes=[S.proc_row(500, 1, "known", "/usr/bin/known", 3)],
                         sockets=[S.sock_row(500, 42000, "93.184.1.1", 443, "/usr/bin/known")])
            w.conn([S.conn_row(6, "192.168.1.50", 42000, "93.184.1.1", 443, 300, uid="H")])
        self._session("20261001T120000Z", hist)
        # build baseline over everything so far
        meta = hunt.build_baseline(self.vd, until=S.start_str(100))
        self.assertGreaterEqual(meta["events"], 1)

        def now(w):
            # known binary -> known host (should be suppressed by R5), and new binary -> new host (fires)
            w.osq_sample(205, processes=[S.proc_row(500, 1, "known", "/usr/bin/known", 203),
                                         S.proc_row(900, 1, "fresh", "/tmp/fresh", 204)],
                         sockets=[S.sock_row(500, 42001, "93.184.1.1", 443, "/usr/bin/known"),
                                  S.sock_row(900, 43000, "93.184.5.1", 443, "/tmp/fresh")])
            w.conn([S.conn_row(206, "192.168.1.50", 43000, "93.184.5.1", 443, 500, uid="N")])
        self._session("20261001T120330Z", now)
        _, hits, _, _ = hunt.hunt(self.vd, only=["R5"])  # since defaults to baseline until
        paths = sorted(h["process_path"] for h in hits)
        self.assertEqual(paths, ["/tmp/fresh"])  # known binary suppressed, fresh one fires


class TraceTests(unittest.TestCase):
    def setUp(self): self.vd = tempfile.mkdtemp(prefix="dl-tr-")
    def tearDown(self): shutil.rmtree(self.vd, ignore_errors=True)

    def test_hit_to_book_to_diff(self):
        sess = os.path.join(self.vd, "raw", "20261001T120000Z"); os.makedirs(sess)
        w = S.Writer(sess)
        w.osq_sample(5, processes=[S.proc_row(1, 0, "launchd", "/sbin/launchd", 0),
                                   S.proc_row(400, 1, "bash", "/bin/bash", 2),
                                   S.proc_row(900, 400, "sneaky", "/tmp/sneaky", 3)],
                     sockets=[S.sock_row(900, 41000, "93.184.30.1", 443, "/tmp/sneaky")])
        w.conn([S.conn_row(6, "192.168.1.50", 41000, "93.184.30.1", 443, 500, uid="X1")])
        w.eslogger([S.exec_row(3, 900, 400, "/tmp/sneaky", signer="", team="", args=["/tmp/sneaky","-q"])])
        w.flush_osquery()
        normalize_session(sess, os.path.join(self.vd, "norm"))
        _, hits, _, _ = hunt.hunt(self.vd, since=S.start_str(0), only=["R5"])
        self.assertTrue(hits)
        hid = hits[0]["hit_id"]

        path, book = horizontal.trace(self.vd, hid, "SIMULATION")
        self.assertTrue(book.title.startswith("[AUTO]"))
        # honesty: no confirmed/dropped
        self.assertFalse([l for l in book.links if l["status"] in ("confirmed", "dropped")])
        # must round-trip through the strict parser
        Book.load(path)
        # parent chain sneaky -> bash -> launchd present as process nodes
        pnames = [n["title"] for n in book.nodes if n["kind"] == "process"]
        self.assertEqual(len(pnames), 3)
        self.assertTrue(any("sneaky" in t for t in pnames))
        self.assertTrue(any(n["kind"] == "gap" for n in book.nodes))

        # a hand Book: same processes, but human confirmed the attribution link
        hand = Book("hand-" + hid, "Hand trace", "SIMULATION")
        for cur in ("proc-900-20261001T120003", "proc-400-20261001T120002", "proc-1-20261001T120000"):
            hand.add_node(cur, hand.id, "process", cur, "manual", "")
        hand.add_node("trigger", hand.id, "event", "trigger", "", "")
        hand.add_link("h1", "trigger", "proc-900-20261001T120003", "attributed-to", "confirmed", "lsof at capture")
        hand.add_link("h2", "proc-900-20261001T120003", "proc-400-20261001T120002", "spawned-by", "confirmed", "lstart match")
        hand.add_link("h3", "proc-400-20261001T120002", "proc-1-20261001T120000", "spawned-by", "confirmed", "lstart match")
        hp = os.path.join(self.vd, "hand.vbook"); hand.save(hp)

        r = bookdiff.compare(book, hand)
        self.assertEqual(r["processes"]["recall"], 1.0)  # auto found every process the human did
        self.assertEqual(r["honesty_violations"], [])
        # human upgraded id-match links to confirmed
        self.assertTrue(r["status_changes_by_human"])


if __name__ == "__main__":
    unittest.main()
