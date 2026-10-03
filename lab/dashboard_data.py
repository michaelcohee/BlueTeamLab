"""Read-only summaries for the optional local Streamlit dashboard.

This module deliberately has no collector or subprocess calls. Large raw logs are
measured by filesystem metadata; only small metadata, hit, and Book files are read.
"""

from collections import deque
import json
import os
from pathlib import Path
import shutil

from .vbook import Book, VBookError

GIB = 1024 ** 3
MIB = 1024 ** 2
MAX_HITS = 1000


def human_bytes(value):
    value = float(value or 0)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return ("%.0f" if unit == "B" else "%.1f") % value + " " + unit
        value /= 1024


def _json(path):
    try:
        with path.open(encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _lines(path, limit=20):
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            return list(deque((line.rstrip("\n") for line in fh), maxlen=limit))
    except OSError:
        return []


def _allocated(path):
    try:
        stat = path.lstat()
        return stat.st_blocks * 512 if hasattr(stat, "st_blocks") else stat.st_size
    except OSError:
        return 0


def _source_sizes(session):
    sizes = {"Zeek": 0, "eslogger": 0, "osquery": 0, "Other": 0}
    for folder, dirs, files in os.walk(session, followlinks=False):
        dirs[:] = [d for d in dirs if not (Path(folder) / d).is_symlink()]
        for name in files:
            path = Path(folder) / name
            if path.is_symlink():
                continue
            relative = path.relative_to(session)
            if relative.parts[0].startswith("zeek-") or name.startswith("zeek-"):
                source = "Zeek"
            elif name.startswith("eslogger"):
                source = "eslogger"
            elif name.startswith("osquery-") or name.startswith("osq."):
                source = "osquery"
            else:
                source = "Other"
            sizes[source] += _allocated(path)
    return sizes


def _active_session(root):
    run_file = root / "run" / "session"
    try:
        name = run_file.read_text(encoding="utf-8").strip()
        candidate = Path(name).resolve()
        raw = (root / "raw").resolve()
        if candidate.parent == raw and candidate.is_dir():
            return candidate.name
    except OSError:
        pass
    return None


def load_snapshot(root_string):
    """Summarize one data directory without reading telemetry payloads."""
    root = Path(root_string).expanduser().resolve()
    cap_gb = float(os.environ.get("LAB_CAP_GB", "3"))
    floor_gb = float(os.environ.get("LAB_FLOOR_GB", "4"))
    result = {"root": str(root), "exists": root.is_dir(), "cap_bytes": cap_gb * GIB,
              "floor_bytes": floor_gb * GIB, "sessions": [], "active": None,
              "used_bytes": 0, "free_bytes": None, "guard_lines": [],
              "baseline": None, "latest_hits": None, "books": []}
    if not root.is_dir():
        return result
    result["active"] = _active_session(root)
    result["guard_lines"] = _lines(root / "guard.log", 12)
    result["baseline"] = _json(root / "baseline" / "baseline.meta.json")
    try:
        result["free_bytes"] = shutil.disk_usage(root).free
    except OSError:
        pass
    for folder, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if not (Path(folder) / d).is_symlink()]
        result["used_bytes"] += _allocated(Path(folder))
        for name in files:
            path = Path(folder) / name
            if not path.is_symlink():
                result["used_bytes"] += _allocated(path)
    raw = root / "raw"
    if raw.is_dir():
        for session in sorted(raw.iterdir(), reverse=True):
            if not session.is_dir() or session.is_symlink():
                continue
            sources = _source_sizes(session)
            meta = _json(session / "session.json") or {}
            iface = meta.get("iface") or "en0"
            result["sessions"].append({"name": session.name,
                                       "active": session.name == result["active"],
                                       "stopped": (session / "stopped.json").is_file(),
                                       "limit_hit": (session / "LIMIT_HIT").exists(),
                                       "sources": sources, "bytes": sum(sources.values()),
                                       "meta": meta,
                                       "errors": {source: _lines(session / filename, 4)
                                                  for source, filename in (("Zeek", "zeek-%s.stderr" % iface),
                                                                           ("eslogger", "eslogger.stderr"),
                                                                           ("osquery", "osq.stderr"))}})
    hits_dir = root / "hits"
    if hits_dir.is_dir():
        files = sorted(hits_dir.glob("hits-*.jsonl"), reverse=True)
        if files:
            result["latest_hits"] = files[0].name
    books_dir = root / "books" / "auto"
    if books_dir.is_dir():
        result["books"] = [p.name for p in sorted(books_dir.glob("*.vbook"), reverse=True)
                           if p.is_file() and not p.is_symlink()][:100]
    return result


def load_hits(root_string, filename):
    root = Path(root_string).expanduser().resolve()
    path = root / "hits" / Path(filename).name
    if not filename.startswith("hits-") or not path.is_file() or path.is_symlink():
        return [], False
    hits = []
    try:
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                if len(hits) >= MAX_HITS:
                    return hits, True
                try:
                    hit = json.loads(line)
                except ValueError:
                    continue
                if isinstance(hit, dict):
                    hits.append(hit)
    except OSError:
        return [], False
    return hits, False


def load_book(root_string, filename):
    root = Path(root_string).expanduser().resolve()
    path = root / "books" / "auto" / Path(filename).name
    if not filename.endswith(".vbook") or not path.is_file() or path.is_symlink():
        raise VBookError("Book not found in the auto Book directory")
    return Book.load(path)
