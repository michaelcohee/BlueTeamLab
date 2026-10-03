import os, shutil, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lab import common as C


class PathSafety(unittest.TestCase):
    def setUp(self): self.base = tempfile.mkdtemp(prefix="dl-safe-")
    def tearDown(self): shutil.rmtree(self.base, ignore_errors=True)

    def test_safe_join_ok(self):
        p = C.safe_join(self.base, "raw/s/conn.log")
        self.assertTrue(p.startswith(os.path.realpath(self.base) + os.sep))

    def test_safe_join_rejects_traversal(self):
        self.assertRaises(C.UnsafeRef, C.safe_join, self.base, "../../etc/passwd")

    def test_safe_join_rejects_absolute(self):
        self.assertRaises(C.UnsafeRef, C.safe_join, self.base, "/etc/passwd")

    def test_safe_join_rejects_symlink_escape(self):
        outside = tempfile.mkdtemp()
        try:
            os.symlink(outside, os.path.join(self.base, "link"))
            self.assertRaises(C.UnsafeRef, C.safe_join, self.base, "link/secret")
        finally:
            shutil.rmtree(outside, ignore_errors=True)

    def test_read_raw_line_unsafe_status(self):
        _, status = C.read_raw_line(self.base, {"file": "../../etc/passwd", "line": 1, "sha256": "x"})
        self.assertEqual(status, "unsafe")

    def test_refuse_repo_path_detects_git(self):
        repo = os.path.join(self.base, "repo"); os.makedirs(os.path.join(repo, ".git"))
        sub = os.path.join(repo, "data", "VerticalData"); os.makedirs(sub)
        self.assertRaises(SystemExit, C.refuse_repo_path, sub)

    def test_refuse_repo_path_allows_outside(self):
        C.refuse_repo_path(os.path.join(self.base, "VerticalData"))  # no .git above -> ok


if __name__ == "__main__":
    unittest.main()
