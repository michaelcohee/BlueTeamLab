"""Horizontal — automated first-pass tracer. One hit in, one VERTICAL 1 Book out.

  dl trace HIT_ID --kind REAL|SIMULATION [--hits FILE] [--out DIR]

Honesty rules (enforced in code, see AutoBook):
  * links are only `untested` or `id-match` — never `confirmed` or `dropped`;
  * anything not in the data becomes a `gap` node naming the manual step that would close it;
  * no verdict, no containment, no shell commands, no network. Files in, one file out.

The Book is a draft for Rali0s's hand trace in Vertical; `dl diff` scores the two.
"""
import collections
import glob
import json
import os
import re
import sys

from . import common as C
from .vbook import Book, VBookError

AUTO_STATUSES = ("untested", "id-match")
MAX_TEXT = 4000
MAX_CHAIN = 12


class HonestyError(VBookError):
    pass


class AutoBook(Book):
    def add_link(self, id, frm, to, relationship, status, basis=""):
        if status not in AUTO_STATUSES:
            raise HonestyError("Horizontal may not set link status %r (only %s)" % (status, AUTO_STATUSES))
        return Book.add_link(self, id, frm, to, relationship, status, basis)

    def validate(self):
        Book.validate(self)
        for l in self.links:
            if l["status"] not in AUTO_STATUSES:
                raise HonestyError("link %s has status %s" % (l["id"], l["status"]))
        if not self.title.startswith("[AUTO]"):
            raise HonestyError("auto Book title must start with [AUTO]")


def proc_node_id(proc_key):
    """Playbook ID convention: proc-<host>-<pid>-<YYYYMMDDTHHMMSS> (hand and auto Books line up).

    Host is kept (slugged) so Books from two hosts can't collide on the same pid+start.
    """
    host, pid, start = proc_key.rsplit(":", 2)
    host = re.sub(r"[^A-Za-z0-9]+", "-", host).strip("-") or "host"
    return "proc-%s-%s-%s" % (host, pid, start.rstrip("Z"))


def ref_str(ref):
    if not ref:
        return ""
    s = "%s line %s sha256 %s" % (ref.get("file"), ref.get("line"), ref.get("sha256"))
    if ref.get("row") is not None:
        s += " row %s" % ref["row"]
    return s


def clip(s, n=MAX_TEXT):
    s = s or ""
    return s if len(s) <= n else s[:n] + " …[clipped %d chars]" % (len(s) - n)


def find_hit(vd, hit_id, hits_file=None):
    files = [hits_file] if hits_file else sorted(glob.glob(os.path.join(vd, "hits", "hits-*.jsonl")), reverse=True)
    for f in files:
        with C.open_text(f) as fh:
            for n, line in enumerate(fh, 1):
                text = line.rstrip("\n")
                if not text.strip():
                    continue
                h = json.loads(text)
                if h.get("hit_id") == hit_id:
                    rel = os.path.relpath(f, vd)
                    return h, {"file": rel, "line": n, "sha256": C.line_sha256(text)}
    raise SystemExit("hit %s not found in %s" % (hit_id, files or "hits/"))


def raw_text(vd, ref):
    text, status = C.read_raw_line(vd, ref)
    if text is not None and ref.get("row") is not None:
        try:
            rows = json.loads(text).get("rows") or []
            text = json.dumps(rows[ref["row"]], sort_keys=True)
        except (ValueError, IndexError, AttributeError):
            status = "changed"
    return text, status


class Index(object):
    """What the normalized data says about processes, for one trace."""

    def __init__(self, vd):
        self.seen = {}                         # proc_key -> first proc_seen
        self.execs = collections.defaultdict(list)
        self.by_proc = collections.defaultdict(list)    # proc_key -> net/socket events
        self.persist = collections.defaultdict(list)    # program path -> persistence events
        for f in sorted(glob.glob(os.path.join(vd, "norm", "*.jsonl"))):
            for e in C.read_jsonl(f):
                t, pk = e.get("event_type"), e.get("proc_key")
                if t == "proc_seen" and pk and pk not in self.seen:
                    self.seen[pk] = e
                elif t == "proc_exec" and pk:
                    self.execs[pk].append(e)
                elif t in ("net_conn", "socket_seen", "listen_port") and pk:
                    self.by_proc[pk].append(e)
                elif t == "persistence_item" and e.get("process_path"):
                    self.persist[e["process_path"]].append(e)


def build_book(vd, hit, hit_ref, kind, idx):
    if kind not in ("REAL", "SIMULATION"):
        raise SystemExit("--kind must be REAL or SIMULATION (say which; Horizontal will not guess)")
    short = (hit.get("process_path") or hit.get("group_key") or "")[-60:]
    b = AutoBook("auto-" + hit["hit_id"], "[AUTO] %s %s: %s" % (hit["rule_id"], hit.get("rule_name") or "", short), kind)
    gaps = []

    def gap(parent, gid, title, text):
        b.add_node(gid, parent, "gap", title, "Horizontal " + C.VERSION, text)
        gaps.append(gid)

    # 1-2. trigger + preserved raw lines
    trig = b.add_node("trigger", b.id, "event", "%s hit %s" % (hit["rule_id"], hit["hit_id"]),
                      "hits: " + ref_str(hit_ref),
                      "%s\nfirst %s · last %s\nrule %s (%s)\nmetrics %s\nprocess attribution: %s" % (
                          hit.get("summary"), hit.get("first_ts"), hit.get("last_ts"), hit.get("rule_name"),
                          hit.get("attack"), json.dumps(hit.get("metrics"), sort_keys=True), hit.get("attribution")))
    for i, ref in enumerate(hit.get("evidence") or [], 1):
        text, status = raw_text(vd, ref)
        nid = "ev-%d" % i
        if status == "ok":
            b.add_node(nid, trig, "observation", "Raw line %s:%s" % (ref["file"], ref["line"]), ref_str(ref), clip(text))
            b.add_link("lk-ev-%d" % i, nid, trig, "evidence-for", "untested",
                       "raw line present; sha256 matches hit")
        else:
            gap(trig, nid, "Raw line %s:%s %s" % (ref["file"], ref["line"], status), ref_str(ref) +
                "\nThe raw line is %s. Re-check the session folder before relying on this hit." % status)

    # 3-5. process + parent chain
    pk = hit.get("proc_key")
    if not pk:
        gap(b.id, "gap-process", "No process attributed",
            "The data did not tie this hit to a proc_key (Zeek has no process view; the osquery "
            "socket sample may have missed a short connection). Playbook step 3: identify the process "
            "by hand (lsof -nP -i at the time, ps -axo pid,ppid,lstart,user,comm).")
    else:
        chain, cur, hops = [], pk, 0
        while cur and hops < MAX_CHAIN:
            nid = proc_node_id(cur)
            info = idx.seen.get(cur) or {}
            ex = idx.execs.get(cur) or []
            path = info.get("process_path") or (ex[0].get("process_path") if ex else None)
            pid = cur.rsplit(":", 2)[1]
            if b.nodes and any(n["id"] == nid for n in b.nodes):
                break
            parent = b.id if not chain else chain[-1]
            title = "%s (pid %s)" % (os.path.basename(path) if path else "unknown", pid)
            b.add_node(nid, b.id, "process", title, ref_str(info.get("raw_ref")) or "proc_key only",
                       "proc_key %s\npath %s\nppid %s\nuser %s\nthreads at first sample %s" % (
                           cur, path, info.get("ppid"), info.get("user"), info.get("threads")))
            if not chain:
                b.add_link("lk-attr", trig, nid, "attributed-to", "id-match",
                           "normalizer: 5-tuple + time window vs osquery socket snapshot (or direct socket row)")
            else:
                b.add_link("lk-spawn-%d" % hops, chain[-1], nid, "spawned-by", "id-match",
                           "ppid + start time from the same osquery processes snapshot")
            chain.append(nid)
            hops += 1
            if pid in ("0", "1"):
                break
            nxt = info.get("parent_proc_key")
            if not nxt:
                gap(nid, "gap-parent-%d" % hops, "Parent of pid %s unresolved" % pid,
                    "ppid %s had no matching row in the same snapshot (exited, or not sampled). "
                    "Playbook step 5: walk the chain by hand." % info.get("ppid"))
                break
            cur = nxt

        top = chain[0]
        info = idx.seen.get(pk) or {}
        # 4. threads — count only; the thread view is manual
        gap(top, "gap-threads", "Thread detail not captured",
            "osquery reported %s threads at first sample. Playbook step 4: ps -M <pid> by hand." % info.get("threads"))
        # 6. binary
        ex = idx.execs.get(pk) or []
        if ex:
            e = ex[0]
            b.add_node("obs-binary", top, "observation", "Exec record (eslogger)", ref_str(e.get("raw_ref")),
                       "path %s\nsigning_id %s\nteam_id %s\nplatform_binary %s\ncdhash %s\nargs %s" % (
                           e.get("process_path"), e.get("signer"), e.get("team_id"), e.get("is_platform_binary"),
                           e.get("cdhash"), clip(e.get("cmdline"), 600)))
        gap(top, "gap-binary", "Signature and hash not verified",
            "Playbook step 6: codesign -dvv, spctl --assess -vv, shasum -a 256 on the binary path."
            + ("" if ex else " No eslogger exec record for this proc_key (started before collection?)."))
        # 7. network
        net = idx.by_proc.get(pk) or []
        if net:
            agg = collections.OrderedDict()
            for e in net:
                k = "%s %s:%s" % (e.get("proto"), e.get("dst_ip") or e.get("src_ip"), e.get("dst_port") or e.get("src_port"))
                a = agg.setdefault(k, {"n": 0, "bytes_out": 0, "first": e.get("ts"), "types": set(), "dom": e.get("dst_domain")})
                a["n"] += 1
                a["bytes_out"] += e.get("bytes_out") or 0
                a["types"].add(e["event_type"])
            lines = ["%s  x%d  out=%d  %s  first %s%s" % (k, v["n"], v["bytes_out"], "/".join(sorted(v["types"])),
                                                         v["first"], ("  " + v["dom"]) if v["dom"] else "")
                     for k, v in list(agg.items())[:40]]
            b.add_node("obs-network", top, "observation", "Network activity in data (%d endpoints)" % len(agg),
                       "norm events for this proc_key", "\n".join(lines))
        gap(top, "gap-network", "Live socket state not captured",
            "Playbook step 7: lsof -nP -i -a -p <pid> while the process runs. Only then can a hit→process "
            "link be raised to confirmed (by a human).")
        # 8. persistence
        path = info.get("process_path") or (ex[0].get("process_path") if ex else None)
        per = idx.persist.get(path) or [] if path else []
        if per:
            b.add_node("obs-persistence", top, "observation", "Persistence items run this binary",
                       ref_str(per[0].get("raw_ref")),
                       "\n".join("%s %s %s" % (p.get("item_kind"), p.get("item_label"), p.get("item_path")) for p in per[:20]))
        gap(top, "gap-persistence", "Background Task Management not checked",
            "Playbook step 8: sudo sfltool dumpbtm and the LaunchAgents/Daemons folders.")

    # R6 hits are about an item, not a process
    if hit["rule_id"] == "R6":
        gap(trig, "gap-item-owner", "Who created the item",
            "Check the plist owner, mtime and the installing process (eslogger exec around first_ts).")

    # 9-10. what Horizontal will not do
    gap(b.id, "gap-unified-log", "Unified log not collected",
        "log show --last 10m --predicate 'processID == <pid>' around first_ts, by hand.")
    b.add_node("note-verdict", b.id, "note", "No verdict (automated draft)", "Horizontal " + C.VERSION,
               "Horizontal does not decide benign/suspicious/malicious and takes no containment action. "
               "Trace this hit by hand in Vertical, then compare: dl diff <this book> <hand book>.\n"
               "Gaps recorded: %d" % len(gaps))
    b.validate()
    return b


def trace(vd, hit_id, kind, hits_file=None, out_dir=None):
    C.refuse_repo_path(vd)
    hit, hit_ref = find_hit(vd, hit_id, hits_file)
    book = build_book(vd, hit, hit_ref, kind, Index(vd))
    out_dir = out_dir or os.path.join(vd, "books", "auto")
    C.refuse_repo_path(out_dir)   # a REAL Book must never land inside a git work tree
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, book.id + ".vbook")
    book.save(path)
    return path, book


def main(argv):
    import argparse
    ap = argparse.ArgumentParser(prog="dl trace", description="Horizontal: hit -> [AUTO] Vertical Book")
    ap.add_argument("hit_id")
    ap.add_argument("--kind", required=True, choices=["REAL", "SIMULATION"])
    ap.add_argument("--hits", help="hits file (default: newest containing the id)")
    ap.add_argument("--out", help="output dir (default: $VERTICALDATA/books/auto)")
    a = ap.parse_args(argv)
    path, book = trace(C.data_dir(), a.hit_id, a.kind, a.hits, a.out)
    print("wrote %s  (%d nodes, %d links, %d gaps)" % (
        path, len(book.nodes), len(book.links), sum(1 for n in book.nodes if n["kind"] == "gap")))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
