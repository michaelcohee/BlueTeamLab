"""dl — detection-lab command dispatcher."""
import sys

USAGE = """usage: dl <command> [args]
  normalize [SESSION...]          raw/<session> -> norm/<session>.jsonl
  baseline [--until TS]           learn normal from norm/ (events before TS)
  hunt [--since TS] [--rule Rn]   run rules/R*.sql -> hits/hits-<UTC>.jsonl
  trace HIT_ID --kind REAL|SIMULATION   Horizontal: hit -> [AUTO] .vbook
  diff AUTO.vbook HAND.vbook      score Horizontal against a hand trace
  check BOOK.vbook                parse + validate a Book with Vertical's rules
  test                            run the test suite (synthetic data only)
Data lives in $VERTICALDATA (default ~/VerticalData), never in this repo."""


def main(argv):
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(USAGE)
        return 0
    cmd, rest = argv[0], argv[1:]
    if cmd == "normalize":
        from . import normalize
        return normalize.main(rest)
    if cmd == "baseline":
        from . import hunt
        return hunt.main_baseline(rest)
    if cmd == "hunt":
        from . import hunt
        return hunt.main_hunt(rest)
    if cmd == "trace":
        from . import horizontal
        return horizontal.main(rest)
    if cmd == "diff":
        from . import bookdiff
        return bookdiff.main(rest)
    if cmd == "check":
        from .vbook import Book
        for p in rest:
            b = Book.load(p)
            print("%s: OK  %s [%s] %d nodes %d links" % (p, b.id, b.kind, len(b.nodes), len(b.links)))
        return 0
    if cmd == "test":
        import os
        import unittest
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        suite = unittest.defaultTestLoader.discover(os.path.join(root, "tests"), top_level_dir=root)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    print(USAGE)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
