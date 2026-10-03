"""Shared helpers: data paths, raw-line reading with evidence references, time parsing.

Python 3.9 compatible, standard library only. Nothing here touches the network.
"""
import datetime as _dt
import gzip
import hashlib
import json
import os
import re

VERSION = "0.1.0"

# The common schema (docs/SCHEMA.md). Every normalized event has exactly these keys;
# unknown values are null, never guessed.
SCHEMA_FIELDS = [
    "ts", "capture_ts", "host", "source", "event_type",
    "proc_key", "pid", "ppid", "proc_start", "parent_proc_key",
    "process_path", "process_name", "user", "signer", "team_id", "is_platform_binary",
    "cdhash", "sha256", "cmdline", "threads",
    "src_ip", "src_port", "dst_ip", "dst_port", "proto", "direction",
    "bytes_out", "bytes_in", "duration", "conn_state", "service", "conn_uid",
    "dst_domain", "tls_sni", "tls_fp",
    "dns_qtype", "dns_rcode", "dns_base_domain", "dns_label_max_len", "dns_label_entropy",
    "item_kind", "item_label", "item_path",
    "attribution", "attribution_ref",
    "raw_ref",
]


def data_dir():
    return os.path.abspath(os.path.expanduser(os.environ.get("VERTICALDATA", "~/VerticalData")))


def lab_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def refuse_repo_path(path):
    """Refuse a path inside a git work tree (guardrail: raw logs / REAL Books stay out of git).

    Walks from the path up to the filesystem root; a `.git` dir OR file (worktrees/submodules
    use a `.git` file) at any level means the path is tracked somewhere, so we refuse it.
    """
    p = os.path.abspath(path)
    while True:
        if os.path.exists(os.path.join(p, ".git")):
            raise SystemExit("refusing: %s is inside the git repo at %s; keep raw data and REAL "
                             "Books outside any repo (set VERTICALDATA / --out elsewhere)" % (path, p))
        parent = os.path.dirname(p)
        if parent == p:
            return
        p = parent


class UnsafeRef(ValueError):
    """A raw_ref.file that escapes the data dir — refuse it rather than read an arbitrary file."""


def safe_join(base, rel):
    """Resolve `rel` (a raw_ref.file) under `base`, refusing absolute paths, traversal, and
    symlinks that escape. Returns the real path; raises UnsafeRef otherwise. A hits file can be
    attacker-shaped, so every raw_ref.file passes through here before it is opened."""
    if not isinstance(rel, str) or not rel or os.path.isabs(rel) or "\x00" in rel:
        raise UnsafeRef("bad raw_ref.file: %r" % (rel,))
    base_real = os.path.realpath(base)
    target = os.path.realpath(os.path.join(base_real, rel))
    if target != base_real and not target.startswith(base_real + os.sep):
        raise UnsafeRef("raw_ref.file escapes data dir: %r" % (rel,))
    return target


# ---------------------------------------------------------------- raw evidence

def open_text(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace", newline="")
    return open(path, "r", encoding="utf-8", errors="replace", newline="")


def logical_name(path):
    """raw_ref names the uncompressed file; lab.sh gzips files after a session ends."""
    return path[:-3] if path.endswith(".gz") else path


def physical_path(base, logical):
    """Find a raw file by its logical (uncompressed) name: NAME or NAME.gz.

    `logical` may come from an untrusted hits file, so it is resolved with safe_join and
    must stay under `base`; a traversing ref raises UnsafeRef rather than reading elsewhere.
    """
    p = safe_join(base, logical)
    if os.path.exists(p):
        return p
    if os.path.exists(p + ".gz"):
        return p + ".gz"
    return None


def line_sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def iter_raw_lines(path, rel_to):
    """Yield (raw_ref, text) per non-empty line. raw_ref = {file, line, sha256}.

    file is relative to the data dir (no user name in published samples), line is 1-based,
    sha256 covers the line without its trailing newline / carriage return.
    """
    rel = os.path.relpath(logical_name(path), rel_to)
    with open_text(path) as fh:
        for n, line in enumerate(fh, 1):
            text = line.rstrip("\n").rstrip("\r")
            if not text.strip():
                continue
            yield {"file": rel, "line": n, "sha256": line_sha256(text)}, text


def read_raw_line(base, ref):
    """Return (text, status) for a raw_ref. status: ok | missing | changed | unsafe."""
    try:
        p = physical_path(base, ref.get("file"))
    except UnsafeRef:
        return None, "unsafe"
    if p is None:
        return None, "missing"
    with open_text(p) as fh:
        for n, line in enumerate(fh, 1):
            if n == ref["line"]:
                text = line.rstrip("\n").rstrip("\r")
                return text, ("ok" if line_sha256(text) == ref["sha256"] else "changed")
    return None, "missing"


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------- time

_ISO = re.compile(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$")


def parse_time(value):
    """epoch number/string or ISO-8601 string -> aware UTC datetime, or None."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return _dt.datetime.fromtimestamp(float(value), _dt.timezone.utc)
    s = str(value).strip()
    try:
        return _dt.datetime.fromtimestamp(float(s), _dt.timezone.utc)
    except ValueError:
        pass
    m = _ISO.match(s)
    if not m:
        return None
    frac = (m.group(3) or "0")[:6].ljust(6, "0")
    base = _dt.datetime.strptime(m.group(1) + "T" + m.group(2), "%Y-%m-%dT%H:%M:%S")
    base = base.replace(microsecond=int(frac))
    tz = m.group(4)
    if tz and tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        hh, mm = int(tz[1:3]), int(tz[-2:])
        base = base - sign * _dt.timedelta(hours=hh, minutes=mm)
    return base.replace(tzinfo=_dt.timezone.utc)


def iso(dt):
    """UTC ISO-8601 with microseconds and Z. DuckDB reads it as TIMESTAMP."""
    if dt is None:
        return None
    return dt.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def compact(dt):
    """Second-precision start time used inside proc_key: 20261003T195201Z."""
    if dt is None:
        return None
    return dt.astimezone(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def proc_key(host, pid, start_dt):
    """host:pid:start. None when the start time is unknown — never key on pid alone."""
    if pid is None or start_dt is None:
        return None
    return "%s:%s:%s" % (host, int(pid), compact(start_dt))


def to_int(v):
    try:
        if v is None or v == "":
            return None
        return int(float(v))
    except (TypeError, ValueError):
        return None


def to_float(v):
    try:
        if v is None or v == "":
            return None
        return float(v)
    except (TypeError, ValueError):
        return None


def write_jsonl(path, rows):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, sort_keys=False, separators=(",", ":")) + "\n")
    os.replace(tmp, path)


def read_jsonl(path):
    with open_text(path) as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield json.loads(line)
