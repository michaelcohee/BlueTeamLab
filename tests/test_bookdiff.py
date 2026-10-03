import os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lab import bookdiff
from lab.vbook import Book


def auto_book(hit="0123456789abcdef"):
    b = Book("auto-" + hit, "[AUTO] R5 first-seen: /tmp/x", "SIMULATION")
    b.add_node("trigger", b.id, "event", "R5 hit " + hit, "", "")
    b.add_node("proc-h-900-20261001T120003", b.id, "process", "x (pid 900)", "", "")
    b.add_link("l1", "trigger", "proc-h-900-20261001T120003", "attributed-to", "id-match", "tuple+window")
    return b


def hand_book(hit="0123456789abcdef", status="confirmed"):
    b = Book("hand-" + hit, "Hand trace " + hit, "SIMULATION")
    b.add_node("trigger", b.id, "event", "R5 hit " + hit, "", "")
    b.add_node("proc-h-900-20261001T120003", b.id, "process", "x (pid 900)", "", "")
    b.add_link("h1", "trigger", "proc-h-900-20261001T120003", "attributed-to", status, "lsof")
    return b


class BookDiff(unittest.TestCase):
    def test_same_hit_detected(self):
        r = bookdiff.compare(auto_book(), hand_book())
        self.assertTrue(r["hit_identity"]["same"])

    def test_mismatched_hit_flagged(self):
        r = bookdiff.compare(auto_book("aaaaaaaaaaaaaaaa"), hand_book("bbbbbbbbbbbbbbbb"))
        self.assertFalse(r["hit_identity"]["same"])
        self.assertIsNotNone(r["hit_identity"]["note"])

    def test_honesty_pass_for_real_auto(self):
        self.assertTrue(bookdiff.compare(auto_book(), hand_book())["honesty"]["auto_ok"])

    def test_honesty_fails_if_auto_has_confirmed(self):
        # a hand-edited "auto" book with a confirmed link must not pass as automated
        fake = auto_book()
        fake.links[0]["status"] = "confirmed"; fake.links[0]["basis"] = "x"
        r = bookdiff.compare(fake, hand_book())
        self.assertFalse(r["honesty"]["auto_ok"])

    def test_honesty_fails_if_not_tagged(self):
        fake = auto_book(); fake.title = "R5 first-seen"
        self.assertFalse(bookdiff.compare(fake, hand_book())["honesty"]["auto_ok"])

    def test_node_counts_present(self):
        r = bookdiff.compare(auto_book(), hand_book())
        self.assertIn("event", r["node_counts_by_kind"]["auto"])


if __name__ == "__main__":
    unittest.main()
