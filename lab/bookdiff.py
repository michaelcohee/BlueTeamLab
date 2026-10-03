"""Score an [AUTO] Book (Horizontal) against Rali0s's hand-traced Book (Vertical).

  dl diff AUTO.vbook HAND.vbook [--json]

Matching (both Books follow the playbook ID convention proc-<pid>-<YYYYMMDDTHHMMSS>):
  * processes: by node id;
  * links: by unordered endpoint pair between matched process nodes (relationship names differ);
  * honesty: the auto Book must contain no confirmed/dropped links.
Reports precision/recall per category, links the human upgraded or dropped, and gap counts.
"""
import json
import sys

from .vbook import Book


def _prf(auto, hand):
    tp = len(auto & hand)
    p = tp / len(auto) if auto else None
    r = tp / len(hand) if hand else None
    f = (2 * p * r / (p + r)) if p and r else (0.0 if (p == 0 or r == 0) else None)
    return {"auto": len(auto), "hand": len(hand), "matched": tp,
            "precision": None if p is None else round(p, 3), "recall": None if r is None else round(r, 3),
            "f1": None if f is None else round(f, 3),
            "auto_only": sorted(auto - hand), "hand_only": sorted(hand - auto)}


def compare(auto, hand):
    a_proc = {n["id"] for n in auto.nodes if n["kind"] == "process"}
    h_proc = {n["id"] for n in hand.nodes if n["kind"] == "process"}

    def pairs(book, procs):
        out = {}
        for l in book.links:
            if l["from"] in procs and l["to"] in procs:
                out[frozenset((l["from"], l["to"]))] = l
        return out

    a_links, h_links = pairs(auto, a_proc), pairs(hand, h_proc)
    status = []
    for k in set(a_links) & set(h_links):
        if a_links[k]["status"] != h_links[k]["status"]:
            status.append({"pair": sorted(k), "auto": a_links[k]["status"], "hand": h_links[k]["status"],
                           "hand_basis": h_links[k]["basis"]})
    violations = [l["id"] for l in auto.links if l["status"] in ("confirmed", "dropped")]
    return {
        "auto_book": auto.id, "hand_book": hand.id,
        "processes": _prf(a_proc, h_proc),
        "process_links": _prf({"~".join(sorted(k)) for k in a_links}, {"~".join(sorted(k)) for k in h_links}),
        "status_changes_by_human": sorted(status, key=lambda s: s["pair"]),
        "gaps": {"auto": sum(1 for n in auto.nodes if n["kind"] == "gap"),
                 "hand": sum(1 for n in hand.nodes if n["kind"] == "gap")},
        "honesty_violations": violations,
    }


def render(r):
    out = ["auto %s  vs  hand %s" % (r["auto_book"], r["hand_book"])]
    for k in ("processes", "process_links"):
        m = r[k]
        out.append("%-14s auto %d · hand %d · matched %d · precision %s · recall %s · F1 %s" % (
            k, m["auto"], m["hand"], m["matched"], m["precision"], m["recall"], m["f1"]))
        if m["auto_only"]:
            out.append("   auto only: " + ", ".join(m["auto_only"]))
        if m["hand_only"]:
            out.append("   hand only: " + ", ".join(m["hand_only"]))
    for s in r["status_changes_by_human"]:
        out.append("status %s: auto %s -> hand %s (basis: %s)" % (" ~ ".join(s["pair"]), s["auto"], s["hand"], s["hand_basis"]))
    out.append("gaps: auto %(auto)d · hand %(hand)d" % r["gaps"])
    out.append("honesty: " + ("OK" if not r["honesty_violations"] else "VIOLATION " + ", ".join(r["honesty_violations"])))
    return "\n".join(out)


def main(argv):
    import argparse
    ap = argparse.ArgumentParser(prog="dl diff")
    ap.add_argument("auto")
    ap.add_argument("hand")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    r = compare(Book.load(a.auto), Book.load(a.hand))
    print(json.dumps(r, indent=2) if a.json else render(r))
    return 1 if r["honesty_violations"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
