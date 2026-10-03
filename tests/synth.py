"""Synthetic raw sessions for tests. No real data, no network. Shapes mirror real tools
closely enough for the normalizer and rules; see docs/SCHEMA.md for field provenance."""
import datetime as _dt
import json
import os

EPOCH = _dt.datetime(2026, 10, 1, 12, 0, 0, tzinfo=_dt.timezone.utc)
HOST = "lab-mbp"


def t(sec):
    return EPOCH + _dt.timedelta(seconds=sec)


def epoch(sec):
    return (t(sec) - _dt.datetime(1970, 1, 1, tzinfo=_dt.timezone.utc)).total_seconds()


def start_str(sec):
    return t(sec).strftime("%Y-%m-%dT%H:%M:%S.000000Z")


class Writer:
    def __init__(self, session_dir):
        self.dir = session_dir
        self.zdir = os.path.join(session_dir, "zeek-en0")
        os.makedirs(self.zdir, exist_ok=True)
        self.osq = []
        meta = {"session": os.path.basename(session_dir), "host": HOST, "iface": "en0",
                "lo0": 0, "macos": "15.0", "started": start_str(0)}
        with open(os.path.join(session_dir, "session.json"), "w") as f:
            json.dump(meta, f)

    def zeek(self, name, rows):
        with open(os.path.join(self.zdir, name), "w") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")

    def conn(self, rows):
        self.zeek("conn.log", rows)

    def dns(self, rows):
        self.zeek("dns.log", rows)

    def osq_sample(self, sec, processes=None, sockets=None, launchd=None):
        cts = start_str(sec)
        def rec(tbl, rows):
            self.osq.append({"t": tbl, "capture_ts": cts, "rows": rows or []})
        rec("processes", processes)
        rec("process_open_sockets", sockets)
        rec("listening_ports", [])
        rec("launchd", launchd)
        rec("startup_items", [])

    def flush_osquery(self):
        with open(os.path.join(self.dir, "osquery-20261001T12.jsonl"), "w") as f:
            for r in self.osq:
                f.write(json.dumps(r) + "\n")

    def eslogger(self, events):
        with open(os.path.join(self.dir, "eslogger_exec.jsonl"), "w") as f:
            for e in events:
                f.write(json.dumps(e) + "\n")


def conn_row(sec, orig, orig_p, resp, resp_p, out_b, uid=None, proto="tcp", dur=0.2, state="SF"):
    return {"ts": epoch(sec), "uid": uid or ("C%d" % sec), "id.orig_h": orig, "id.orig_p": orig_p,
            "id.resp_h": resp, "id.resp_p": resp_p, "proto": proto, "duration": dur,
            "orig_bytes": out_b, "resp_bytes": 120, "conn_state": state}


def dns_row(sec, query, orig="192.168.1.50", answers=None):
    return {"ts": epoch(sec), "uid": "D%d" % sec, "id.orig_h": orig, "id.orig_p": 50000 + (sec % 1000),
            "id.resp_h": "192.168.1.1", "id.resp_p": 53, "proto": "udp", "query": query,
            "qtype_name": "A", "rcode_name": "NOERROR", "answers": answers or []}


def proc_row(pid, ppid, name, path, start_sec, threads=4, uid="501"):
    return {"pid": pid, "ppid": ppid, "name": name, "path": path,
            "start_time": int(epoch(start_sec)), "uid": uid, "threads": threads}


def sock_row(pid, lport, rip, rport, path, proto="6", state="ESTABLISHED"):
    return {"pid": pid, "family": 2, "protocol": proto, "local_address": "192.168.1.50",
            "local_port": lport, "remote_address": rip, "remote_port": rport, "state": state, "path": path}


def exec_row(sec, pid, ppid, path, signer="", team="", platform=False, args=None):
    return {"time": start_str(sec), "event": {"exec": {
        "target": {"audit_token": {"pid": pid, "euid": 501}, "ppid": ppid, "start_time": start_str(sec),
                   "executable": {"path": path}, "signing_id": signer, "team_id": team,
                   "is_platform_binary": platform, "cdhash": "ab%02d" % (pid % 100)},
        "args": args or [path]}}}
