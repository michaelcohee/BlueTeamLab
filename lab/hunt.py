"""Tier 2b — baseline + detections over normalized JSONL with the DuckDB CLI (offline).

  dl baseline [--until TS]          learn "normal" from events before TS (default: all)
  dl hunt [--since TS] [--rule R1]  run rules/*.sql on events at/after TS (default: after baseline)

Each rule is a SELECT over the views `hunt` (events in scope) and `baseline_*`.
Thresholds live in rules/params.json and are substituted as {{name}}.
Output: $VERTICALDATA/hits/hits-<UTC>.jsonl  (one hit per line, each citing raw_refs).
"""
import datetime as _dt
import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

from . import common as C

COLUMNS = {
    "ts": "TIMESTAMP", "capture_ts": "TIMESTAMP", "host": "VARCHAR", "source": "VARCHAR",
    "event_type": "VARCHAR", "proc_key": "VARCHAR", "pid": "BIGINT", "ppid": "BIGINT",
    "proc_start": "TIMESTAMP", "parent_proc_key": "VARCHAR", "process_path": "VARCHAR",
    "process_name": "VARCHAR", "user": "VARCHAR", "signer": "VARCHAR", "team_id": "VARCHAR",
    "is_platform_binary": "BOOLEAN", "cdhash": "VARCHAR", "sha256": "VARCHAR", "cmdline": "VARCHAR",
    "threads": "BIGINT", "src_ip": "VARCHAR", "src_port": "BIGINT", "dst_ip": "VARCHAR",
    "dst_port": "BIGINT", "proto": "VARCHAR", "direction": "VARCHAR", "bytes_out": "BIGINT",
    "bytes_in": "BIGINT", "duration": "DOUBLE", "conn_state": "VARCHAR", "service": "VARCHAR",
    "conn_uid": "VARCHAR", "dst_domain": "VARCHAR", "tls_sni": "VARCHAR", "tls_fp": "VARCHAR",
    "dns_qtype": "VARCHAR", "dns_rcode": "VARCHAR", "dns_base_domain": "VARCHAR",
    "dns_label_max_len": "BIGINT", "dns_label_entropy": "DOUBLE", "item_kind": "VARCHAR",
    "item_label": "VARCHAR", "item_path": "VARCHAR", "attribution": "VARCHAR",
    "attribution_ref": "STRUCT(file VARCHAR, line BIGINT, sha256 VARCHAR, \"row\" BIGINT)",
    "raw_ref": "STRUCT(file VARCHAR, line BIGINT, sha256 VARCHAR, \"row\" BIGINT)",
}

# Baseline tables: name -> (SELECT that builds it, empty schema when no baseline exists)
BASELINE = {
    "baseline_dst": (
        "SELECT DISTINCT host, dst_ip, dst_port FROM base "
        "WHERE event_type IN ('net_conn','socket_seen') AND dst_ip IS NOT NULL",
        "host VARCHAR, dst_ip VARCHAR, dst_port BIGINT"),
    "baseline_net_bin": (
        "SELECT DISTINCT host, process_path FROM base "
        "WHERE event_type IN ('net_conn','socket_seen') AND process_path IS NOT NULL "
        "AND direction NOT IN ('listen')",
        "host VARCHAR, process_path VARCHAR"),
    "baseline_exec_bin": (
        "SELECT DISTINCT host, process_path FROM base WHERE event_type = 'proc_exec' AND process_path IS NOT NULL",
        "host VARCHAR, process_path VARCHAR"),
    "baseline_persist": (
        "SELECT DISTINCT host, item_kind, item_label, item_path, process_path FROM base "
        "WHERE event_type = 'persistence_item'",
        "host VARCHAR, item_kind VARCHAR, item_label VARCHAR, item_path VARCHAR, process_path VARCHAR"),
    "baseline_bytes": (
        "SELECT host, coalesce(process_path, '(unattributed)') AS process_path, "
        "quantile_cont(h_out, 0.99) AS p99_out, count(*) AS hours FROM ("
        "  SELECT host, process_path, date_trunc('hour', ts) AS h, sum(bytes_out) AS h_out FROM base "
        "  WHERE event_type = 'net_conn' AND direction = 'out' GROUP BY ALL) GROUP BY ALL",
        "host VARCHAR, process_path VARCHAR, p99_out DOUBLE, hours BIGINT"),
    "baseline_dns_rate": (
        "SELECT host, dns_base_domain, max(n) AS max_per_min FROM ("
        "  SELECT host, dns_base_domain, date_trunc('minute', ts) m, count(*) n FROM base "
        "  WHERE event_type = 'dns_query' GROUP BY ALL) GROUP BY ALL",
        "host VARCHAR, dns_base_domain VARCHAR, max_per_min BIGINT"),
}


def duckdb_bin():
    exe = os.environ.get("DUCKDB") or shutil.which("duckdb")
    if not exe:
        raise SystemExit("duckdb CLI not found (brew install duckdb)")
    return exe


def run_sql(sql):
    p = subprocess.run([duckdb_bin(), "-batch", "-bail", "-noheader", "-list"], input=sql,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    if p.returncode != 0:
        raise SystemExit("duckdb failed:\n" + p.stderr + "\n--- SQL ---\n" + sql[-3000:])
    return p.stdout


def q(s):
    return "'" + str(s).replace("'", "''") + "'"


def events_view(norm_files):
    cols = ", ".join("%s: %s" % (q(k), q(v)) for k, v in COLUMNS.items())
    if not norm_files:
        return "CREATE VIEW events AS SELECT * FROM (SELECT %s) WHERE false;\n" % ", ".join(
            "NULL::%s AS %s" % (v, json.dumps(k)) for k, v in COLUMNS.items())
    files = "[" + ", ".join(q(f) for f in norm_files) + "]"
    return ("CREATE VIEW events AS SELECT * FROM read_json(%s, format='newline_delimited', "
            "columns={%s});\n" % (files, cols))


def norm_files(vd):
    return sorted(glob.glob(os.path.join(vd, "norm", "*.jsonl")))


def baseline_dir(vd):
    return os.path.join(vd, "baseline")


def load_params():
    with open(os.path.join(C.lab_root(), "rules", "params.json")) as fh:
        return json.load(fh)


def render(sql, params):
    def sub(m):
        k = m.group(1)
        if k not in params:
            raise SystemExit("rule uses unknown parameter {{%s}}" % k)
        return str(params[k])
    return re.sub(r"\{\{(\w+)\}\}", sub, sql)


# ---------------------------------------------------------------- baseline

def build_baseline(vd, until=None):
    C.refuse_repo_path(vd)
    files = norm_files(vd)
    if not files:
        raise SystemExit("no normalized data in %s/norm — run 'dl normalize' first" % vd)
    bd = baseline_dir(vd)
    os.makedirs(bd, exist_ok=True)
    cond = "ts < %s::TIMESTAMP" % q(until) if until else "true"
    sql = events_view(files) + "CREATE VIEW base AS SELECT * FROM events WHERE %s;\n" % cond
    for name, (select, _) in BASELINE.items():
        sql += "COPY (%s) TO %s (FORMAT JSON);\n" % (select, q(os.path.join(bd, name + ".json")))
    sql += "SELECT min(ts)::VARCHAR, max(ts)::VARCHAR, count(*) FROM base;\n"
    out = run_sql(sql).strip().splitlines()[-1].split("|")
    meta = {"built": C.iso(_dt.datetime.now(_dt.timezone.utc)), "until": until,
            "from_ts": out[0] or None, "to_ts": out[1] or None, "events": int(out[2]),
            "sources": [os.path.basename(f) for f in files]}
    with open(os.path.join(bd, "baseline.meta.json"), "w") as fh:
        json.dump(meta, fh, indent=2)
    return meta


def baseline_views(vd):
    bd = baseline_dir(vd)
    sql = ""
    for name, (_, schema) in BASELINE.items():
        p = os.path.join(bd, name + ".json")
        if os.path.exists(p) and os.path.getsize(p) > 0:
            cols = ", ".join("%s: %s" % (q(c.split()[0]), q(c.split(None, 1)[1])) for c in schema.split(", "))
            sql += "CREATE VIEW %s AS SELECT * FROM read_json(%s, format='newline_delimited', columns={%s});\n" % (
                name, q(p), cols)
        else:
            sql += "CREATE TABLE %s (%s);\n" % (name, schema)
    return sql


def baseline_meta(vd):
    p = os.path.join(baseline_dir(vd), "baseline.meta.json")
    if os.path.exists(p):
        with open(p) as fh:
            return json.load(fh)
    return None


# ---------------------------------------------------------------- hunt

RULE_HEADER = re.compile(r"^--\s*(\w+):\s*(.*)$")


def rule_files(only=None):
    files = sorted(glob.glob(os.path.join(C.lab_root(), "rules", "R*.sql")))
    if only:
        files = [f for f in files if os.path.basename(f).split("_")[0] in only]
    return files


def rule_meta(path):
    meta = {}
    with open(path) as fh:
        for line in fh:
            m = RULE_HEADER.match(line.rstrip())
            if m and m.group(1) in ("id", "name", "attack", "tactic", "sources"):
                meta[m.group(1)] = m.group(2).strip()
    return meta


def hunt(vd, since=None, only=None, include_loopback=False):
    C.refuse_repo_path(vd)
    files = norm_files(vd)
    bmeta = baseline_meta(vd)
    if since is None and bmeta and bmeta.get("until"):
        since = bmeta["until"]
    params = load_params()
    params["include_loopback"] = "true" if include_loopback else "false"
    tmp = tempfile.mkdtemp(prefix="dl-hunt-")
    sql = events_view(files) + baseline_views(vd)
    sql += "CREATE VIEW hunt AS SELECT * FROM events WHERE %s;\n" % (
        "ts >= %s::TIMESTAMP" % q(since) if since else "true")
    outs = []
    for rf in rule_files(only):
        meta = rule_meta(rf)
        with open(rf) as _fh:
            body = render(_fh.read(), params).strip().rstrip(";")
        out = os.path.join(tmp, meta["id"] + ".json")
        sql += "COPY (%s) TO %s (FORMAT JSON);\n" % (body, q(out))
        outs.append((meta, out))
    run_sql(sql)

    hits = []
    for meta, out in outs:
        if not os.path.exists(out):
            continue
        for row in C.read_jsonl(out):
            key = "|".join(str(row.get(k)) for k in ("rule_id", "host", "group_key", "first_ts"))
            hit = {
                "hit_id": hashlib.sha256(key.encode()).hexdigest()[:16],
                "rule_id": meta["id"], "rule_name": meta.get("name"), "attack": meta.get("attack"),
                "host": row.get("host"), "proc_key": row.get("proc_key"),
                "process_path": row.get("process_path"), "group_key": row.get("group_key"),
                "first_ts": row.get("first_ts"), "last_ts": row.get("last_ts"),
                "summary": row.get("summary"), "metrics": row.get("metrics") or {},
                "attribution": "id-match" if row.get("proc_key") else "none",
                "evidence": (row.get("evidence") or [])[: int(params.get("max_evidence", 20))],
                "hunt_since": since, "baseline": bmeta and {k: bmeta.get(k) for k in ("from_ts", "to_ts", "until")},
                "engine": "detection-lab " + C.VERSION,
            }
            hits.append(hit)
    shutil.rmtree(tmp, ignore_errors=True)
    hd = os.path.join(vd, "hits")
    os.makedirs(hd, exist_ok=True)
    stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = os.path.join(hd, "hits-%s.jsonl" % stamp)
    C.write_jsonl(path, hits)
    return path, hits, since, bmeta


def main_baseline(argv):
    import argparse
    ap = argparse.ArgumentParser(prog="dl baseline")
    ap.add_argument("--until", help="UTC time; events before it form the baseline (default: all)")
    a = ap.parse_args(argv)
    m = build_baseline(C.data_dir(), a.until)
    print("baseline: %(events)d events, %(from_ts)s → %(to_ts)s" % m)
    return 0


def main_hunt(argv):
    import argparse
    ap = argparse.ArgumentParser(prog="dl hunt")
    ap.add_argument("--since", help="UTC time; hunt events at/after it (default: baseline --until)")
    ap.add_argument("--rule", action="append", help="run only this rule id (repeatable)")
    ap.add_argument("--include-loopback", action="store_true",
                    help="also score 127.0.0.1 traffic (lab test sessions only)")
    a = ap.parse_args(argv)
    path, hits, since, bmeta = hunt(C.data_dir(), a.since, a.rule, a.include_loopback)
    if not bmeta:
        print("WARNING: no baseline — every destination/binary/item counts as first-seen")
    print("hunt since %s: %d hit(s) -> %s" % (since or "beginning", len(hits), path))
    for h in hits:
        print("  %s %-3s %s  %s" % (h["hit_id"], h["rule_id"], h["first_ts"], h["summary"]))
    return 0
