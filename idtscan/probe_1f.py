#!/usr/bin/env python3
"""Safely analyze idtscan JSONL for x86 IDT vector 0x1f.

This tool consumes scanner output. It never invokes an interrupt, reads kernel memory,
loads a driver, or executes a command.
"""

import argparse
import json
import re
import sys


VECTOR = 0x1F
SEVERITY_RANK = {"info": 0, "medium": 1, "high": 2, "critical": 3}
CORE_WINDOWS_MODULES = {"nt", "ntoskrnl", "hal"}


def _vector_number(row):
    value = row.get("vector")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def _normalized_symbol(value):
    if not value:
        return None
    return re.sub(r"\+0x[0-9a-fA-F]+$", "", str(value).strip())


def _fingerprint(row):
    """Fields expected to remain meaningful across KASLR-enabled boots."""
    return {
        "present": bool(row.get("present")),
        "dpl": row.get("dpl"),
        "segment": row.get("segment"),
        "gate_type": row.get("gate_type"),
        "location": row.get("location"),
        "module": str(row.get("module") or "").lower() or None,
        "symbol": _normalized_symbol(row.get("symbol")),
    }


def _cpu(row):
    return str(row.get("cpu", "unknown"))


def analyze(rows, baseline_rows=None, parse_errors=None):
    parse_errors = list(parse_errors or [])
    entries = [r for r in rows if r.get("event_type") == "idt_entry" and _vector_number(r) == VECTOR]
    scan_gaps = [r for r in rows if r.get("event_type") == "scan_gap"]
    findings = []
    gaps = []

    for error in parse_errors:
        gaps.append({"code": "invalid_jsonl", "detail": error})
    for gap in scan_gaps:
        gaps.append({"code": gap.get("gap", "scanner_gap"), "detail": gap.get("detail", "scanner reported a gap")})
    if not entries:
        gaps.append({"code": "vector_1f_missing_from_output", "detail": "No IDT entry for vector 0x1f was present in the input."})

    seen = {}
    for entry in entries:
        cpu = _cpu(entry)
        seen[cpu] = seen.get(cpu, 0) + 1
        if not entry.get("present"):
            continue
        dpl = entry.get("dpl")
        if dpl == 3:
            findings.append({
                "severity": "critical", "code": "vector_1f_user_callable", "cpu": cpu,
                "detail": "Vector 0x1f is present with DPL 3 and is callable from user mode.",
            })
        location = entry.get("location")
        module = str(entry.get("module") or "").lower()
        if location == "unknown":
            findings.append({
                "severity": "critical", "code": "vector_1f_unknown_handler", "cpu": cpu,
                "detail": "Vector 0x1f points outside known kernel text and loaded modules.",
            })
        elif location == "module" and module not in CORE_WINDOWS_MODULES:
            findings.append({
                "severity": "high", "code": "vector_1f_noncore_module", "cpu": cpu,
                "detail": "Vector 0x1f resolves to non-core module %s." % (entry.get("module") or "unknown"),
            })

    for cpu, count in seen.items():
        if count > 1:
            gaps.append({"code": "duplicate_vector_1f", "cpu": cpu,
                         "detail": "Multiple vector 0x1f entries were emitted for the same CPU."})

    if baseline_rows is not None:
        baseline = [r for r in baseline_rows if r.get("event_type") == "idt_entry" and _vector_number(r) == VECTOR]
        current_by_cpu = {_cpu(r): r for r in entries}
        baseline_by_cpu = {_cpu(r): r for r in baseline}
        if not baseline:
            gaps.append({"code": "baseline_vector_1f_missing", "detail": "Baseline contains no vector 0x1f entry."})
        for cpu in sorted(set(current_by_cpu) | set(baseline_by_cpu)):
            if cpu not in current_by_cpu or cpu not in baseline_by_cpu:
                gaps.append({"code": "baseline_cpu_coverage_changed", "cpu": cpu,
                             "detail": "Vector 0x1f CPU coverage differs from the baseline."})
                continue
            before = _fingerprint(baseline_by_cpu[cpu])
            after = _fingerprint(current_by_cpu[cpu])
            if before != after:
                findings.append({
                    "severity": "high", "code": "vector_1f_semantic_change", "cpu": cpu,
                    "detail": "Vector 0x1f descriptor or handler identity changed from the baseline.",
                    "baseline": before, "current": after,
                })

    findings.sort(key=lambda f: (-SEVERITY_RANK[f["severity"]], f["code"], f.get("cpu", "")))
    status = "suspicious" if findings else ("inconclusive" if gaps else "clean")
    return {
        "tool": "idtscan-probe-1f", "vector": VECTOR, "vector_hex": "0x1f",
        "status": status, "entries_checked": len(entries), "findings": findings, "gaps": gaps,
    }


def read_jsonl(path):
    rows, errors = [], []
    stream = sys.stdin if path == "-" else open(path, "r", encoding="utf-8")
    try:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError("row is not a JSON object")
                rows.append(value)
            except (json.JSONDecodeError, ValueError) as exc:
                errors.append("%s:%d: %s" % (path, line_number, exc))
    finally:
        if stream is not sys.stdin:
            stream.close()
    return rows, errors


def main(argv=None):
    parser = argparse.ArgumentParser(description="Analyze idtscan JSONL for vector 0x1f without invoking it")
    parser.add_argument("input", help="current idtscan JSONL, or - for stdin")
    parser.add_argument("--baseline", help="optional known-good idtscan JSONL")
    parser.add_argument("--pretty", action="store_true", help="indent JSON output")
    args = parser.parse_args(argv)

    rows, errors = read_jsonl(args.input)
    baseline_rows = None
    if args.baseline:
        baseline_rows, baseline_errors = read_jsonl(args.baseline)
        errors.extend(baseline_errors)
    report = analyze(rows, baseline_rows, errors)
    print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=True))
    return {"clean": 0, "inconclusive": 1, "suspicious": 3}[report["status"]]


if __name__ == "__main__":
    sys.exit(main())
