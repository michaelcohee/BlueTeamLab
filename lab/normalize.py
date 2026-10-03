"""Tier 2a — normalize one collection session to the common schema.

Input : $VERTICALDATA/raw/<session>/  (Zeek JSON logs, osquery-*.jsonl, eslogger_exec.jsonl)
Output: $VERTICALDATA/norm/<session>.jsonl  + <session>.manifest.json

Rules this file enforces:
  * every event carries raw_ref {file, line, sha256} back to its source line;
  * proc_key = host:pid:start — if the start time is unknown, proc_key is null;
  * a Zeek connection gets a process only through a 5-tuple + time-window match against
    an osquery socket snapshot. That is recorded as attribution="id-match", never more.
"""
import bisect
import collections
import glob
import ipaddress
import json
import math
import os
import sys

from . import common as C

ATTR_BEFORE = 5.0    # seconds a socket snapshot may precede the Zeek conn start
ATTR_AFTER = 65.0    # ... and follow the conn end (osquery samples every 60 s)


# ---------------------------------------------------------------- helpers

def _ip(s):
    if s in (None, "", "*"):
        return None
    try:
        a = ipaddress.ip_address(str(s).split("%")[0])
    except ValueError:
        return None
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    return a


def ip_str(s):
    a = _ip(s)
    return str(a) if a else (s or None)


def _is_local(a):
    return a.is_private or a.is_loopback or a.is_link_local or (a.version == 4 and a in _CGNAT)


_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def direction(orig, resp, local_orig=None, local_resp=None):
    """Classify a connection. When Zeek was told its own networks (Site::local_nets), it tags
    each conn with local_orig/local_resp; we trust those when present (the only reliable way to
    call direction for global IPv6, where neither address looks private). Otherwise fall back to
    an RFC-1918/loopback/CGNAT heuristic, which cannot see outbound global IPv6 (documented)."""
    o, r = _ip(orig), _ip(resp)
    if o is None or r is None:
        return None
    if r.is_multicast or str(r) == "255.255.255.255" or (r.version == 4 and str(r).endswith(".255")):
        return "multicast"
    if o.is_loopback and r.is_loopback:
        return "loopback"
    if local_orig is not None or local_resp is not None:
        lo, lr = bool(local_orig), bool(local_resp)
    else:
        lo, lr = _is_local(o), _is_local(r)
    if lo and not lr:
        return "out"
    if lr and not lo:
        return "in"
    if lo and lr:
        return "lan"
    return "other"


def entropy(s):
    if not s:
        return 0.0
    n = float(len(s))
    return -sum((c / n) * math.log2(c / n) for c in collections.Counter(s).values())


def dns_features(q):
    """(base_domain, longest label length, highest label entropy) — base domain excluded.

    base domain = last two labels. Approximate: wrong for co.uk-style suffixes (documented).
    """
    q = (q or "").rstrip(".").lower()
    labels = [l for l in q.split(".") if l]
    if not labels:
        return None, None, None
    base = ".".join(labels[-2:])
    sub = labels[:-2] or labels[:1]
    return base, max(len(l) for l in sub), round(max(entropy(l) for l in sub), 3)


def event(**kw):
    e = dict.fromkeys(C.SCHEMA_FIELDS)
    e.update(kw)
    return e


# ---------------------------------------------------------------- session

class Session(object):
    def __init__(self, path, host=None):
        self.path = os.path.abspath(path)
        self.base = os.path.dirname(os.path.dirname(self.path))   # data dir
        self.name = os.path.basename(self.path)
        meta = {}
        mp = os.path.join(self.path, "session.json")
        if os.path.exists(mp):
            with open(mp) as fh:
                meta = json.load(fh)
        self.meta = meta
        self.host = host or meta.get("host") or "unknown-host"
        self.events = []
        self.inputs = []
        # attribution index: (local_port, remote_ip, remote_port) -> [(t, proc_key, pid, path, ref)]
        self.sock_index = collections.defaultdict(list)
        self.proc_info = {}        # proc_key -> dict
        self.dns_answers = collections.defaultdict(list)   # ip -> [(t, query)] sorted later
        self.sni_by_uid = {}

    def files(self, pattern):
        out = sorted(glob.glob(os.path.join(self.path, pattern)))
        for p in out:
            self.inputs.append(p)
        return out

    # -------------------------------------------------- osquery
    def osquery(self):
        seen = set()
        for path in self.files("osquery-*.jsonl*"):
            pidmap = {}
            cur_ts = None
            for ref, text in C.iter_raw_lines(path, self.base):
                try:
                    rec = json.loads(text)
                except ValueError:
                    continue
                t, cts = rec.get("t"), rec.get("capture_ts")
                cdt = C.parse_time(cts)
                if cts != cur_ts:
                    cur_ts, pidmap = cts, {}
                rows = rec.get("rows") or []
                handler = getattr(self, "_osq_" + str(t), None)
                if handler is None or cdt is None:
                    continue
                for i, row in enumerate(rows):
                    handler(row, cdt, dict(ref, row=i), pidmap, seen)
                if t == "processes":
                    # whole snapshot loaded first so a parent later in the list still resolves
                    for info in list(pidmap.values()):
                        self._emit_proc_seen(info, pidmap, seen)

    def _osq_processes(self, row, cdt, ref, pidmap, seen):
        pid = C.to_int(row.get("pid"))
        st = C.to_int(row.get("start_time"))
        sdt = C.parse_time(st) if st and st > 0 else None
        pk = C.proc_key(self.host, pid, sdt)
        info = {"pid": pid, "ppid": C.to_int(row.get("ppid")), "proc_key": pk,
                "proc_start": C.iso(sdt), "path": row.get("path") or None,
                "name": row.get("name") or None, "user": row.get("uid"),
                "threads": C.to_int(row.get("threads")), "ref": ref, "ts": cdt}
        pidmap[pid] = info

    def _emit_proc_seen(self, info, pidmap, seen):
        pk = info["proc_key"]
        if pk is None or ("proc", pk) in seen:
            return
        seen.add(("proc", pk))
        parent = pidmap.get(info["ppid"])
        ppk = parent["proc_key"] if parent else None
        self.proc_info[pk] = dict(info, parent_proc_key=ppk)
        self.events.append(event(
            ts=C.iso(info["ts"]), capture_ts=C.iso(info["ts"]), host=self.host, source="osquery",
            event_type="proc_seen", proc_key=pk, pid=info["pid"], ppid=info["ppid"],
            proc_start=info["proc_start"], parent_proc_key=ppk, process_path=info["path"],
            process_name=info["name"], user=info["user"], threads=info["threads"],
            raw_ref=info["ref"]))

    def _osq_process_open_sockets(self, row, cdt, ref, pidmap, seen):
        info = pidmap.get(C.to_int(row.get("pid")))
        pk = info["proc_key"] if info else None
        lport, rport = C.to_int(row.get("local_port")), C.to_int(row.get("remote_port"))
        lip, rip = ip_str(row.get("local_address")), ip_str(row.get("remote_address"))
        proto = {"6": "tcp", "17": "udp"}.get(str(row.get("protocol")), str(row.get("protocol")))
        if rport and rip and rip not in ("0.0.0.0", "::"):
            # Full 5-tuple key (proto + local ip too), so a reused local port or a different
            # protocol cannot collide into a false id-match. lip may be a wildcard bind
            # (0.0.0.0/::) in the snapshot; store it and let the matcher treat that as "any".
            self.sock_index[(proto, lport, rip, rport)].append(
                (cdt.timestamp(), pk, C.to_int(row.get("pid")), info["path"] if info else None, ref, lip))
        key = ("sock", pk, proto, lip, lport, rip, rport, row.get("state"))
        if key in seen:
            return
        seen.add(key)
        self.events.append(event(
            ts=C.iso(cdt), capture_ts=C.iso(cdt), host=self.host, source="osquery",
            event_type="socket_seen", proc_key=pk, pid=C.to_int(row.get("pid")),
            process_path=info["path"] if info else None, proc_start=info["proc_start"] if info else None,
            src_ip=lip, src_port=lport, dst_ip=rip, dst_port=rport, proto=proto,
            direction=direction(lip, rip) if rport else "listen", conn_state=row.get("state") or None,
            raw_ref=ref))

    def _osq_listening_ports(self, row, cdt, ref, pidmap, seen):
        info = pidmap.get(C.to_int(row.get("pid")))
        pk = info["proc_key"] if info else None
        proto = {"6": "tcp", "17": "udp"}.get(str(row.get("protocol")), str(row.get("protocol")))
        key = ("listen", pk, proto, row.get("address"), row.get("port"))
        if key in seen:
            return
        seen.add(key)
        self.events.append(event(
            ts=C.iso(cdt), capture_ts=C.iso(cdt), host=self.host, source="osquery",
            event_type="listen_port", proc_key=pk, pid=C.to_int(row.get("pid")),
            process_path=info["path"] if info else None, src_ip=ip_str(row.get("address")),
            src_port=C.to_int(row.get("port")), proto=proto, direction="listen", raw_ref=ref))

    def _persist(self, kind, label, item_path, program, args, cdt, ref, seen):
        key = ("persist", kind, label, item_path, program, args)
        if key in seen:
            return
        seen.add(key)
        self.events.append(event(
            ts=C.iso(cdt), capture_ts=C.iso(cdt), host=self.host, source="osquery",
            event_type="persistence_item", item_kind=kind, item_label=label or None,
            item_path=item_path or None, process_path=program or None,
            cmdline=(args or None) and args[:512], raw_ref=ref))

    def _osq_launchd(self, row, cdt, ref, pidmap, seen):
        args = row.get("program_arguments") or ""
        program = row.get("program") or (args.split(" ")[0] if args else None)
        # Classify by plist location: a LaunchDaemon runs as root at boot, a LaunchAgent in a
        # user session, a GUI login item is different again. R6 and the trace care which.
        p = (row.get("path") or "").lower()
        if "/launchdaemons/" in p:
            kind = "launchd:daemon"
        elif "/launchagents/" in p:
            kind = "launchd:agent"
        else:
            kind = "launchd:other"
        self._persist(kind, row.get("label"), row.get("path"), program, args, cdt, ref, seen)

    def _osq_startup_items(self, row, cdt, ref, pidmap, seen):
        self._persist("startup_item:" + (row.get("type") or "?"), row.get("name"), row.get("path"),
                      row.get("path"), row.get("args") or "", cdt, ref, seen)

    # -------------------------------------------------- eslogger
    def eslogger(self):
        for path in self.files("eslogger_exec.jsonl*"):
            for ref, text in C.iter_raw_lines(path, self.base):
                try:
                    msg = json.loads(text)
                except ValueError:
                    continue
                ex = (msg.get("event") or {}).get("exec")
                if not isinstance(ex, dict):
                    continue
                tgt = ex.get("target") or {}
                tok = tgt.get("audit_token") or {}
                pid = C.to_int(tok.get("pid"))
                sdt = C.parse_time(tgt.get("start_time"))
                pk = C.proc_key(self.host, pid, sdt)
                exe = (tgt.get("executable") or {}).get("path")
                args = ex.get("args")
                cmd = " ".join(str(a) for a in args)[:512] if isinstance(args, list) else None
                ts = C.parse_time(msg.get("time"))
                self.events.append(event(
                    ts=C.iso(ts), capture_ts=None, host=self.host, source="eslogger",
                    event_type="proc_exec", proc_key=pk, pid=pid, ppid=C.to_int(tgt.get("ppid")),
                    proc_start=C.iso(sdt), process_path=exe,
                    process_name=os.path.basename(exe) if exe else None,
                    user=None if tok.get("euid") is None else str(tok.get("euid")),
                    signer=tgt.get("signing_id") or None, team_id=tgt.get("team_id") or None,
                    is_platform_binary=tgt.get("is_platform_binary"), cdhash=tgt.get("cdhash") or None,
                    cmdline=cmd, raw_ref=ref))

    # -------------------------------------------------- zeek
    def zeek(self):
        for path in self.files("zeek-*/dns.log*"):
            for ref, text in C.iter_raw_lines(path, self.base):
                r = self._json(text)
                if r is None:
                    continue
                t = C.parse_time(r.get("ts"))
                q = r.get("query")
                base, mlen, ent = dns_features(q)
                o, d = r.get("id.orig_h"), r.get("id.resp_h")
                self.events.append(event(
                    ts=C.iso(t), capture_ts=None, host=self.host, source="zeek", event_type="dns_query",
                    src_ip=ip_str(o), src_port=C.to_int(r.get("id.orig_p")), dst_ip=ip_str(d),
                    dst_port=C.to_int(r.get("id.resp_p")), proto=r.get("proto"), direction=direction(o, d),
                    dst_domain=q, dns_qtype=r.get("qtype_name"), dns_rcode=r.get("rcode_name"),
                    dns_base_domain=base, dns_label_max_len=mlen, dns_label_entropy=ent,
                    conn_uid=r.get("uid"), raw_ref=ref))
                for a in r.get("answers") or []:
                    if _ip(a) is not None:
                        self.dns_answers[ip_str(a)].append((t.timestamp(), q))
        for v in self.dns_answers.values():
            v.sort()

        for path in self.files("zeek-*/ssl.log*"):
            for ref, text in C.iter_raw_lines(path, self.base):
                r = self._json(text)
                if r is None:
                    continue
                t = C.parse_time(r.get("ts"))
                o, d = r.get("id.orig_h"), r.get("id.resp_h")
                fp = r.get("ja4") or r.get("ja3")
                self.sni_by_uid[r.get("uid")] = (r.get("server_name"), fp)
                self.events.append(event(
                    ts=C.iso(t), capture_ts=None, host=self.host, source="zeek", event_type="tls_hello",
                    src_ip=ip_str(o), src_port=C.to_int(r.get("id.orig_p")), dst_ip=ip_str(d),
                    dst_port=C.to_int(r.get("id.resp_p")), proto="tcp", direction=direction(o, d),
                    tls_sni=r.get("server_name"), tls_fp=fp, conn_uid=r.get("uid"), raw_ref=ref))

        for path in self.files("zeek-*/conn.log*"):
            for ref, text in C.iter_raw_lines(path, self.base):
                r = self._json(text)
                if r is None:
                    continue
                t = C.parse_time(r.get("ts"))
                o, d = r.get("id.orig_h"), r.get("id.resp_h")
                op, dp = C.to_int(r.get("id.orig_p")), C.to_int(r.get("id.resp_p"))
                dirn = direction(o, d, r.get("local_orig"), r.get("local_resp"))
                ob, rb = C.to_int(r.get("orig_bytes")), C.to_int(r.get("resp_bytes"))
                out_b, in_b = (rb, ob) if dirn == "in" else (ob, rb)
                dur = C.to_float(r.get("duration"))
                sni, fp = self.sni_by_uid.get(r.get("uid"), (None, None))
                e = event(
                    ts=C.iso(t), capture_ts=None, host=self.host, source="zeek", event_type="net_conn",
                    src_ip=ip_str(o), src_port=op, dst_ip=ip_str(d), dst_port=dp, proto=r.get("proto"),
                    direction=dirn, bytes_out=out_b, bytes_in=in_b, duration=dur,
                    conn_state=r.get("conn_state"), service=r.get("service"), conn_uid=r.get("uid"),
                    tls_sni=sni, tls_fp=fp, dst_domain=sni or self._domain_for(ip_str(d), t),
                    attribution="none", raw_ref=ref)
                self._attribute(e, t, dur)
                self.events.append(e)

    def _json(self, text):
        if text.startswith("#"):
            return None   # TSV header — Zeek must run with LogAscii::use_json=T
        try:
            return json.loads(text)
        except ValueError:
            return None

    def _domain_for(self, ip, t):
        lst = self.dns_answers.get(ip)
        if not lst or t is None:
            return None
        i = bisect.bisect_right(lst, (t.timestamp(), "￿"))
        return lst[i - 1][1] if i else None

    def _attribute(self, e, t, dur):
        """Full-tuple + time window against osquery socket snapshots -> id-match or nothing.

        Match requires proto, the local port, and the remote ip+port to agree, and — when the
        snapshot recorded a concrete (non-wildcard) local IP — the local IP too. Zeek's proto
        is lower-case (tcp/udp), matching the normalized socket proto. Window: conn start −5 s
        to conn end +65 s (osquery samples every 60 s). More than one distinct proc_key in the
        window is left `ambiguous`, never guessed.
        """
        if t is None:
            return
        proto = (e.get("proto") or "").lower()
        if e["direction"] == "in":
            key = (proto, e["dst_port"], e["src_ip"], e["src_port"])
            local_ip = e["dst_ip"]
        else:
            key = (proto, e["src_port"], e["dst_ip"], e["dst_port"])
            local_ip = e["src_ip"]
        cands = self.sock_index.get(key)
        if not cands:
            return
        lo, hi = t.timestamp() - ATTR_BEFORE, t.timestamp() + (dur or 0.0) + ATTR_AFTER
        hits = []
        for c in cands:
            ct, pk, pid, path, ref, snap_lip = c
            if not (lo <= ct <= hi) or not pk:
                continue
            # snapshot local IP must match unless it was a wildcard bind (0.0.0.0/::/None)
            if snap_lip and snap_lip not in ("0.0.0.0", "::") and local_ip and snap_lip != local_ip:
                continue
            hits.append(c)
        keys = {c[1] for c in hits}
        if len(keys) == 1:
            ct, pk, pid, path, ref, snap_lip = hits[0]
            info = self.proc_info.get(pk, {})
            e.update(proc_key=pk, pid=pid, process_path=path, proc_start=info.get("proc_start"),
                     attribution="id-match", attribution_ref=ref)
        elif len(keys) > 1:
            e["attribution"] = "ambiguous"

    # -------------------------------------------------- run
    def run(self):
        self.osquery()      # first: builds the socket index used for attribution
        self.eslogger()
        self.zeek()
        self.events.sort(key=lambda e: (e["ts"] or "", e["source"], e["raw_ref"]["file"], e["raw_ref"]["line"]))
        return self.events


def normalize_session(session_dir, out_dir, host=None):
    C.refuse_repo_path(out_dir)
    s = Session(session_dir, host)
    events = s.run()
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, s.name + ".jsonl")
    C.write_jsonl(out, events)
    counts = collections.Counter(e["event_type"] for e in events)
    attributed = sum(1 for e in events if e["event_type"] == "net_conn" and e["attribution"] == "id-match")
    conns = counts.get("net_conn", 0)
    manifest = {
        "normalizer": C.VERSION, "session": s.name, "host": s.host, "output": os.path.basename(out),
        "output_sha256": C.file_sha256(out), "events": len(events), "by_type": dict(counts),
        "net_conn_attributed": attributed,
        "net_conn_attribution_rate": round(attributed / conns, 3) if conns else None,
        "inputs": [{"file": os.path.relpath(p, s.base), "sha256": C.file_sha256(p)} for p in s.inputs],
    }
    with open(os.path.join(out_dir, s.name + ".manifest.json"), "w") as fh:
        json.dump(manifest, fh, indent=2)
    return manifest


def main(argv):
    import argparse
    ap = argparse.ArgumentParser(prog="dl normalize", description=__doc__.split("\n")[0])
    ap.add_argument("sessions", nargs="*", help="session dirs (default: every finished session in raw/)")
    ap.add_argument("--force", action="store_true", help="re-normalize sessions that already have output")
    ap.add_argument("--host", help="override host name from session.json")
    a = ap.parse_args(argv)
    vd = C.data_dir()
    out_dir = os.path.join(vd, "norm")
    active = None
    sp = os.path.join(vd, "run", "session")
    if os.path.exists(sp):
        active = os.path.abspath(open(sp).read().strip())
    sessions = a.sessions or sorted(d for d in glob.glob(os.path.join(vd, "raw", "*")) if os.path.isdir(d))
    for d in sessions:
        d = os.path.abspath(d)
        name = os.path.basename(d)
        if d == active:
            print("skip %s (collection still running)" % name)
            continue
        if not a.force and os.path.exists(os.path.join(out_dir, name + ".jsonl")):
            print("skip %s (already normalized; --force to redo)" % name)
            continue
        m = normalize_session(d, out_dir, a.host)
        print("%s: %d events %s  conn attribution %s" % (name, m["events"], m["by_type"], m["net_conn_attribution_rate"]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
