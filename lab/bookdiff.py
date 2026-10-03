"""Score an [AUTO] Book (Horizontal) against Rali0s's hand-traced Book (Vertical).

  dl diff AUTO.vbook HAND.vbook [--json]

This is NOT an overall node/link agreement score. Only process nodes share an ID convention
across the two Books (proc-<host>-<pid>-<start>), so precision/recall is reported for the
PROCESS CHAIN only. Every other category (evidence, observations, gaps, the attribution link)
is reported as side-by-side counts, because auto and hand node IDs do not line up and matching
them by text would be guesswork. Same-hit identity is checked so two unrelated Books are not
scored against each other. The honesty gate confirms the auto Book really obeys Horizontal's
rules ([AUTO] title, links only untested/id-match) before any of this is trusted.
"""
import json
import re
import sys

from .vbook import Book

HIT_RE = re.compile(r"\bhit\s+([0-9a-f]{16})\b")
AUTO_STATUSES = ("untested", "id-match")


def _prf(auto, hand):
    tp = len(auto & hand)
    p = tp / len(auto) if auto else None
    r = tp / len(hand) if hand else None
    f = (2 * p * r / (p + r)) if p and r else (0.0 if (p == 0 or r == 0) else None)
    return {"auto": len(auto), "hand": len(hand), "matched": tp,
            "precision": None if p is None else round(p, 3), "recall": None if r is None else round(r, 3),
            "f1": None if f is None else round(f, 3),
            "auto_only": sorted(auto - hand), "hand_only": sorted(hand - auto)}


def _find_hit(book):
    m = HIT_RE.match("hit " + book.id.replace("auto-", "", 1)) if book.id.startswith("auto-") else None
    if m:
        return m.group(1)
    for n in book.nodes:
        for field in (n["title"], n["text"], n["source"]):
            m = HIT_RE.search(field or "")
            if m:
                return m.group(1)
    return None


def _kinds(book):
    out = {}
    for n in book.nodes:
        out[n["kind"]] = out.get(n["kind"], 0) + 1
    return out


def honesty(auto):
    """Verify a Book actually follows Horizontal's rules — so `dl diff` can't be used to pass
    off a hand-edited Book as an automated one."""
    problems = []
    if not auto.title.startswith("[AUTO]"):
        problems.append("title is not tagged [AUTO]")
    bad = sorted({l["status"] for l in auto.links if l["status"] not in AUTO_STATUSES})
    if bad:
        problems.append("link status(es) a human-only tool would not set: " + ", ".join(bad))
    return problems


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
    ah, hh = _find_hit(auto), _find_hit(hand)
    return {
        "auto_book": auto.id, "hand_book": hand.id,
        "hit_identity": {"auto": ah, "hand": hh,
                         "same": (ah is not None and ah == hh),
                         "note": None if (ah and ah == hh) else
                         "could not confirm both Books trace the same hit — scores may compare unrelated traces"},
        "process_chain": _prf(a_proc, h_proc),
        "process_links": _prf({"~".join(sorted(k)) for k in a_links}, {"~".join(sorted(k)) for k in h_links}),
        "status_changes_by_human": sorted(status, key=lambda s: s["pair"]),
        "node_counts_by_kind": {"auto": _kinds(auto), "hand": _kinds(hand)},
        "honesty": {"auto_ok": not honesty(auto), "problems": honesty(auto)},
    }


def render(r):
    out = ["auto %s  vs  hand %s" % (r["auto_book"], r["hand_book"]),
           "scope: PROCESS-CHAIN agreement + per-category counts (not an overall node/link score)"]
    hi = r["hit_identity"]
    out.append("hit identity: auto %s · hand %s · %s" % (hi["auto"], hi["hand"],
               "same hit" if hi["same"] else "MISMATCH — " + (hi["note"] or "")))
    for k in ("process_chain", "process_links"):
        m = r[k]
        out.append("%-14s auto %d · hand %d · matched %d · precision %s · recall %s · F1 %s" % (
            k, m["auto"], m["hand"], m["matched"], m["precision"], m["recall"], m["f1"]))
        if m["auto_only"]:
            out.append("   auto only: " + ", ".join(m["auto_only"]))
        if m["hand_only"]:
            out.append("   hand only: " + ", ".join(m["hand_only"]))
    for s in r["status_changes_by_human"]:
        out.append("status %s: auto %s -> hand %s (basis: %s)" % (" ~ ".join(s["pair"]), s["auto"], s["hand"], s["hand_basis"]))
    ac, hc = r["node_counts_by_kind"]["auto"], r["node_counts_by_kind"]["hand"]
    kinds = sorted(set(ac) | set(hc))
    out.append("node counts by kind (auto|hand): " + ", ".join("%s %d|%d" % (k, ac.get(k, 0), hc.get(k, 0)) for k in kinds))
    h = r["honesty"]
    out.append("honesty: " + ("auto Book obeys Horizontal rules" if h["auto_ok"] else "FAIL — " + "; ".join(h["problems"])))
    return "\n".join(out)


def main(argv):
    import argparse
    ap = argparse.ArgumentParser(prog="dl diff", description=__doc__.split("\n")[0])
    ap.add_argument("auto")
    ap.add_argument("hand")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    r = compare(Book.load(a.auto), Book.load(a.hand))
    print(json.dumps(r, indent=2) if a.json else render(r))
    return 0 if r["honesty"]["auto_ok"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
