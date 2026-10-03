import os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lab.vbook import Book, VBookError
from lab.horizontal import AutoBook, HonestyError


class TestVbookRoundTrip(unittest.TestCase):
    def test_special_chars(self):
        b = Book("bk", "Title", "SIMULATION")
        b.add_node("n1", "bk", "observation", 'has "quotes" and \\back', "src", "line1\nline2\ttab")
        b.add_node("n2", "n1", "note", "child", "", "")
        b.add_link("l1", "n1", "n2", "relates", "untested", "")
        b2 = Book.loads(b.dumps())
        self.assertEqual(b2.nodes[0]["title"], 'has "quotes" and \\back')
        self.assertEqual(b2.nodes[0]["text"], "line1\nline2\ttab")
        self.assertEqual(b2.dumps(), b.dumps())

    def test_empty_trailing_fields(self):
        b = Book("bk", "T", "REAL")
        b.add_node("n", "bk", "gap", "g", "", "")
        self.assertIn('NODE "n" "bk" "gap" "g" "" ""', b.dumps())

    def test_rejects_bad_kind(self):
        self.assertRaises(VBookError, lambda: Book("b", "t", "MAYBE").validate())

    def test_rejects_dangling_link(self):
        b = Book("b", "t", "REAL"); b.add_node("n", "b", "note", "x")
        b.links.append({"id": "l", "from": "n", "to": "ghost", "relationship": "r", "status": "untested", "basis": ""})
        self.assertRaises(VBookError, b.validate)

    def test_rejects_cycle(self):
        b = Book("b", "t", "REAL")
        b.nodes = [{"id": "a", "parent": "x", "kind": "note", "title": "a", "source": "", "text": ""},
                   {"id": "x", "parent": "a", "kind": "note", "title": "x", "source": "", "text": ""}]
        self.assertRaises(VBookError, b.validate)

    def test_confirmed_needs_basis(self):
        b = Book("b", "t", "REAL"); b.add_node("n", "b", "note", "x")
        b.add_link("l", "n", "b", "r", "confirmed", "")
        self.assertRaises(VBookError, b.validate)
        b.links[0]["basis"] = "lsof at capture time"
        b.validate()

    def test_unknown_record(self):
        self.assertRaises(VBookError, lambda: Book.loads('VERTICAL 1\nBOOK "b" "t" "REAL"\nWIDGET "x"\n'))


class TestHonesty(unittest.TestCase):
    def test_auto_rejects_confirmed(self):
        b = AutoBook("[AUTO] x", "[AUTO] x", "SIMULATION"); b.add_node("n", "[AUTO] x", "note", "t")
        self.assertRaises(HonestyError, lambda: b.add_link("l", "n", "[AUTO] x", "r", "confirmed", "x"))

    def test_auto_requires_tag(self):
        b = AutoBook("id", "no tag", "REAL")
        self.assertRaises(HonestyError, b.validate)


if __name__ == "__main__":
    unittest.main()
