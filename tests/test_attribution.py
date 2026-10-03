import json, os, shutil, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lab import common as C, hunt
from lab.normalize import normalize_session
from tests import synth as S

_HAVE_DUCKDB = bool(os.environ.get("DUCKDB") or shutil.which("duckdb"))


def norm(fn):
    vd = tempfile.mkdtemp(prefix="dl-attr-")
    sess = os.path.join(vd, "raw", "20261001T120000Z"); os.makedirs(sess)
    w = S.Writer(sess); fn(w); w.flush_osquery()
    normalize_session(sess, os.path.join(vd, "norm"))
    rows = [json.loads(l) for l in open(os.path.join(vd, "norm", "20261001T120000Z.jsonl"))]
    return vd, rows


class Attribution(unittest.TestCase):
    def test_proto_disambiguation(self):
        # A UDP socket shares (local_port, remote_ip, remote_port) with a TCP conn.
        # The TCP conn must NOT attribute to the UDP-only process.
        def f(w):
            w.osq_sample(5, processes=[S.proc_row(900, 1, "udpproc", "/tmp/udpproc", 3)],
                         sockets=[S.sock_row(900, 41000, "93.184.30.1", 443, "/tmp/udpproc", proto="17")])
            w.conn([S.conn_row(6, "192.168.1.50", 41000, "93.184.30.1", 443, 500, proto="tcp")])
        _, rows = norm(f)
        conn = [r for r in rows if r["event_type"] == "net_conn"][0]
        self.assertEqual(conn["attribution"], "none")
        self.assertIsNone(conn["proc_key"])

    def test_exact_tuple_attributes(self):
        def f(w):
            w.osq_sample(5, processes=[S.proc_row(900, 1, "p", "/tmp/p", 3)],
                         sockets=[S.sock_row(900, 41000, "93.184.30.1", 443, "/tmp/p", proto="6")])
            w.conn([S.conn_row(6, "192.168.1.50", 41000, "93.184.30.1", 443, 500, proto="tcp")])
        _, rows = norm(f)
        conn = [r for r in rows if r["event_type"] == "net_conn"][0]
        self.assertEqual(conn["attribution"], "id-match")
        self.assertTrue(conn["proc_key"].endswith(":900:20261001T120003Z"))

    def test_capture_ts_null_for_zeek(self):
        def f(w):
            w.conn([S.conn_row(6, "192.168.1.50", 41000, "93.184.30.1", 443, 500)])
        _, rows = norm(f)
        conn = [r for r in rows if r["event_type"] == "net_conn"][0]
        self.assertIsNone(conn["capture_ts"])

    def test_zeek_local_orig_direction(self):
        # global IPv6 both ends; only Zeek's local_orig tells us it's outbound
        def f(w):
            r = S.conn_row(6, "2600:1:2:3::5", 41000, "2606:aa:bb::9", 443, 500)
            r["local_orig"] = True; r["local_resp"] = False
            w.conn([r])
        _, rows = norm(f)
        conn = [r for r in rows if r["event_type"] == "net_conn"][0]
        self.assertEqual(conn["direction"], "out")


@unittest.skipUnless(_HAVE_DUCKDB, "duckdb CLI not installed (Phase 0)")
class MultiInstance(unittest.TestCase):
    def test_R5_null_key_when_two_instances(self):
        vd = tempfile.mkdtemp(prefix="dl-mi-")
        sess = os.path.join(vd, "raw", "20261001T120000Z"); os.makedirs(sess)
        w = S.Writer(sess)
        # same binary path, two pids (two instances), both talk out to new hosts
        w.osq_sample(5, processes=[S.proc_row(900, 1, "dup", "/tmp/dup", 3),
                                   S.proc_row(901, 1, "dup", "/tmp/dup", 4)],
                     sockets=[S.sock_row(900, 41000, "93.184.1.1", 443, "/tmp/dup"),
                              S.sock_row(901, 41001, "93.184.2.1", 443, "/tmp/dup")])
        w.conn([S.conn_row(6, "192.168.1.50", 41000, "93.184.1.1", 443, 500, uid="A"),
                S.conn_row(7, "192.168.1.50", 41001, "93.184.2.1", 443, 500, uid="B")])
        w.flush_osquery(); normalize_session(sess, os.path.join(vd, "norm"))
        _, hits, _, _, _ = hunt.hunt(vd, since=S.start_str(0), only=["R5"])
        shutil.rmtree(vd, ignore_errors=True)
        self.assertEqual(len(hits), 1)
        self.assertIsNone(hits[0]["proc_key"])          # not an arbitrary instance
        self.assertEqual(hits[0]["metrics"]["process_instances"], 2)
        self.assertEqual(len(hits[0]["metrics"]["member_proc_keys"]), 2)


if __name__ == "__main__":
    unittest.main()
