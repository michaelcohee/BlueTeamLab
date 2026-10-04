"""Blueware — Cement CLI for the Daybreak defensive stream lab."""

import json
import os
import sys
import tempfile
import unittest

try:
    from cement import App, Controller, ex
except ImportError as exc:  # pragma: no cover - launcher reports the installation command
    raise SystemExit("Blueware requires Cement: python3 -m pip install -r requirements-cli.txt") from exc

from . import stream


VERSION = "0.1.0"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE_DIR = os.path.join(ROOT, "samples", "synthetic")
DEFAULT_BINARY = os.path.join(SAMPLE_DIR, "null_payload_carrier.bin")
DEFAULT_SOURCE = os.path.join(SAMPLE_DIR, "null_payload_carrier.c")
DEFAULT_CONTROL = os.path.join(SAMPLE_DIR, "school_control_ascii.bin")


def _dump(value, pretty=False):
    print(json.dumps(value, indent=2 if pretty else None, sort_keys=True))


def _reports_exit(reports):
    statuses = {report.get("status") for report in reports}
    return 3 if "suspicious" in statuses else (1 if "inconclusive" in statuses else 0)


def _emit_reports(reports, output_format, pretty=False, host=None):
    if output_format == "siem-json":
        for report in reports:
            _dump(stream.to_siem_event(report, host=host), pretty)
    elif output_format == "syslog":
        for report in reports:
            print(stream.to_syslog(stream.to_siem_event(report, host=host)))
    elif pretty:
        _dump(reports, True)
    else:
        for report in reports:
            _dump(report)


def _write_jsonl(rows, path):
    target = sys.stdout if path == "-" else open(path, "w", encoding="utf-8")
    try:
        for row in rows:
            target.write(json.dumps(row, sort_keys=True) + "\n")
    finally:
        if target is not sys.stdout:
            target.close()


def _read_json_value(path):
    source = sys.stdin if path == "-" else open(path, "r", encoding="utf-8")
    try:
        return json.load(source)
    finally:
        if source is not sys.stdin:
            source.close()


def _containment_plan(report):
    """Build a plan-only endpoint handoff from an explicitly eligible finding."""
    if not isinstance(report, dict):
        raise ValueError("analysis must be one JSON report object")
    findings = report.get("findings", [])
    if not isinstance(findings, list):
        raise ValueError("analysis findings must be a list")
    eligible = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        finding_type = finding.get("finding")
        classes = finding.get("reference_classes", [])
        if finding_type == "denylisted_whole_hash" or (
                finding_type == "known_content_inclusion" and "malicious" in classes):
            eligible.append({
                "rule_id": finding.get("rule_id"),
                "finding": finding_type,
                "reference_classes": classes,
            })
    authorized = (report.get("status") == "suspicious" and
                  report.get("containment") == "endpoint policy required" and
                  bool(eligible))
    plan = {
        "schema": "blueware-containment-plan/v1",
        "mode": "plan_only",
        "authorized": authorized,
        "requested_control": "tcp_cutoff" if authorized else None,
        "stream_id": report.get("stream_id"),
        "basis": eligible,
        "execution_performed": False,
        "simd_changed": False,
        "actions": [],
    }
    if authorized:
        plan["actions"] = [
            {"order": 1, "action": "preserve_evidence",
             "detail": "Retain the analysis JSON, source references, and hashes."},
            {"order": 2, "action": "validate_policy_basis",
             "detail": "Confirm the malicious reference or denylist provenance with an analyst."},
            {"order": 3, "action": "request_tcp_cutoff",
             "detail": ("Hand off to an authorized EDR or host firewall to block TCP traffic; "
                        "Blueware does not execute the block.")},
            {"order": 4, "action": "verify_and_record",
             "detail": ("Verify the TCP block, record the case decision and rollback, then assess "
                        "UDP, local IPC, and other transports separately.")},
        ]
    else:
        plan["reason"] = (
            "No explicit malicious-reference or denylisted-whole-hash finding authorizes "
            "an endpoint containment handoff."
        )
    return plan


class BaseController(Controller):
    class Meta:
        label = "base"
        description = (
            "Blueware — offline chunk integrity, GF(256) recovery, "
            "classified content matching, and payload-free SIEM output"
        )
        epilog = (
            "Evidence contract: exit 0=clean, 1=inconclusive gap, 2=tool/input error, "
            "3=suspicious. Parse JSON fields before taking policy action."
        )

    def _fail(self, message, code=2):
        print("blueware: %s" % message, file=sys.stderr)
        self.app.exit_code = code
        return code

    @ex(help="show application scope, version, and evidence boundaries")
    def about(self):
        _dump({
            "app": "Blueware",
            "version": VERSION,
            "framework": "Cement 3",
            "mode": "offline explicit-message analysis",
            "capabilities": [
                "chunk coverage and SHA-256 integrity",
                "single-erasure XOR teaching recovery",
                "GF(256) systematic 4+2 recovery",
                "classified canonical-content inclusion",
                "payload-free SIEM JSON and RFC 5424-style syslog",
            ],
            "boundaries": [
                "does not capture or reassemble live TCP",
                "does not decrypt SSH or TLS",
                "does not execute analyzed files",
                "does not execute containment; it can emit a plan-only endpoint handoff",
            ],
        }, True)
        return 0

    @ex(help="show reference-class and exit-code policy")
    def policy(self):
        _dump({
            "reference_classes": {
                "test": {"result": "school_control observation", "containment": "none"},
                "benign": {"result": "inclusion_only observation", "containment": "none"},
                "malicious": {"result": "suspicious finding", "containment": "endpoint policy required"},
            },
            "exit_codes": {
                "0": "complete or recovered; no suspicious finding",
                "1": "inconclusive evidence gap; parse JSON",
                "2": "usage, input, database, or tool error",
                "3": "suspicious finding",
            },
            "signature_schema": stream.SIGNATURE_SCHEMA,
            "legacy_policy": "version 1 databases are rejected and must be rebuilt",
        }, True)
        return 0

    @ex(
        help="analyze a JSONL message envelope",
        arguments=[
            (["input"], {"help": "JSONL path, or - for stdin"}),
            (["--denylist"], {"help": "file containing one SHA-256 per line"}),
            (["--signature-db"], {"help": "classified canonical signature database"}),
            (["--format"], {"choices": ("report", "siem-json", "syslog"), "default": "report"}),
            (["--host"], {"help": "host label for SIEM/syslog output"}),
            (["--pretty"], {"action": "store_true", "help": "pretty-print JSON"}),
        ],
    )
    def analyze(self):
        try:
            reports = stream.analyze(
                stream.read_jsonl(self.app.pargs.input),
                stream.load_denylist(self.app.pargs.denylist),
                stream.load_signature_db(self.app.pargs.signature_db),
            )
            _emit_reports(reports, self.app.pargs.format, self.app.pargs.pretty, self.app.pargs.host)
        except (OSError, ValueError) as exc:
            return self._fail(str(exc))
        self.app.exit_code = _reports_exit(reports)
        return self.app.exit_code

    @ex(
        label="containment-plan",
        help="build a non-executing endpoint handoff from an analysis report",
        arguments=[
            (["analysis"], {"help": "single Blueware report JSON path, or - for stdin"}),
            (["--pretty"], {"action": "store_true"}),
        ],
    )
    def containment_plan(self):
        try:
            report = _read_json_value(self.app.pargs.analysis)
            plan = _containment_plan(report)
            _dump(plan, self.app.pargs.pretty)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return self._fail(str(exc))
        self.app.exit_code = 0 if plan["authorized"] else 1
        return self.app.exit_code

    @ex(
        help="emit a harmless ordinary or XOR teaching stream",
        arguments=[
            (["--data-chunks"], {"type": int, "default": 5}),
            (["--drop"], {"type": int, "help": "data chunk index to omit"}),
            (["--parity"], {"action": "store_true", "help": "include XOR teaching parity"}),
            (["--output"], {"default": "-", "help": "JSONL output path (default: stdout)"}),
        ],
    )
    def simulate(self):
        total = self.app.pargs.data_chunks
        drop = self.app.pargs.drop
        if not 1 <= total <= 100:
            return self._fail("--data-chunks must be from 1 to 100")
        if drop is not None and not 0 <= drop < total:
            return self._fail("--drop must identify a data chunk")
        try:
            _write_jsonl(stream.make_simulation(total, drop, self.app.pargs.parity), self.app.pargs.output)
        except OSError as exc:
            return self._fail(str(exc))
        return 0

    @ex(
        label="simulate-rs",
        help="emit a harmless GF(256) 4+2 stream",
        arguments=[
            (["--drop"], {"type": int, "action": "append", "default": [],
                           "help": "share index 0..5 to omit; repeat up to twice"}),
            (["--matrix"], {"choices": ("daybreak-powers", "darkrock-custom"),
                             "default": "daybreak-powers"}),
            (["--output"], {"default": "-", "help": "JSONL output path (default: stdout)"}),
        ],
    )
    def simulate_rs(self):
        drops = self.app.pargs.drop
        if len(set(drops)) != len(drops) or len(drops) > 2 or any(not 0 <= value <= 5 for value in drops):
            return self._fail("--drop may identify up to two different share indices from 0 to 5")
        generator = (stream.RS_GENERATOR if self.app.pargs.matrix == "daybreak-powers"
                     else stream.DARKROCK_CUSTOM_GENERATOR)
        try:
            rows = stream.make_rs_simulation(drops, generator=generator, codec_name=self.app.pargs.matrix)
            _write_jsonl(rows, self.app.pargs.output)
        except (OSError, ValueError) as exc:
            return self._fail(str(exc))
        return 0

    @ex(
        help="wrap an inert file in the explicit message-envelope schema",
        arguments=[
            (["input"], {"help": "file to read without executing"}),
            (["--data-chunks"], {"type": int, "default": 8}),
            (["--drop"], {"type": int, "action": "append", "default": []}),
            (["--stream-id"], {"help": "optional stable stream identifier"}),
            (["--output"], {"default": "-", "help": "JSONL output path (default: stdout)"}),
        ],
    )
    def envelope(self):
        try:
            rows = stream.make_file_envelope(
                self.app.pargs.input, self.app.pargs.data_chunks,
                self.app.pargs.drop, self.app.pargs.stream_id)
            _write_jsonl(rows, self.app.pargs.output)
        except (OSError, ValueError) as exc:
            return self._fail(str(exc))
        return 0

    @ex(
        help="build a classified byte-stride canonical signature database",
        arguments=[
            (["references"], {"nargs": "+", "help": "authorized reference files"}),
            (["--output"], {"required": True}),
            (["--reference-class"], {"choices": stream.REFERENCE_CLASSES, "default": "test"}),
            (["--window-bytes"], {"type": int, "default": 32}),
            (["--min-match-bytes"], {"type": int, "default": 64}),
            (["--pretty"], {"action": "store_true"}),
        ],
    )
    def canonize(self):
        try:
            database = stream.build_signature_db(
                self.app.pargs.references,
                self.app.pargs.window_bytes,
                self.app.pargs.min_match_bytes,
                self.app.pargs.reference_class,
            )
            stream.write_signature_db(database, self.app.pargs.output)
        except (OSError, ValueError) as exc:
            return self._fail(str(exc))
        _dump({
            "output": self.app.pargs.output,
            "schema": database["schema"],
            "reference_class": self.app.pargs.reference_class,
            "references": len(database["references"]),
            "window_bytes": database["window_bytes"],
            "min_match_bytes": database["min_match_bytes"],
            "window_count": sum(item["window_count"] for item in database["references"]),
        }, self.app.pargs.pretty)
        return 0

    @ex(
        label="compare-matrices",
        help="compare the two defined GF(256) 4+2 matrices",
        arguments=[
            (["--input"], {"help": "inert file bytes; default is the school fixture"}),
            (["--pretty"], {"action": "store_true"}),
        ],
    )
    def compare_matrices(self):
        path = self.app.pargs.input or DEFAULT_BINARY
        try:
            with open(path, "rb") as fh:
                payload = fh.read()
            comparison = stream.compare_rs_generators(payload)
            comparison["input"] = os.path.basename(path)
            _dump(comparison, self.app.pargs.pretty)
        except (OSError, ValueError) as exc:
            return self._fail(str(exc))
        return 0

    @ex(
        label="inspect-control",
        help="statically verify the committed school fixture without executing it",
        arguments=[
            (["--binary"], {"default": DEFAULT_BINARY}),
            (["--source"], {"default": DEFAULT_SOURCE}),
            (["--control"], {"default": DEFAULT_CONTROL}),
            (["--pretty"], {"action": "store_true"}),
        ],
    )
    def inspect_control(self):
        try:
            with open(self.app.pargs.binary, "rb") as fh:
                binary = fh.read()
            with open(self.app.pargs.source, "rb") as fh:
                source = fh.read()
            with open(self.app.pargs.control, "rb") as fh:
                control = fh.read()
        except OSError as exc:
            return self._fail(str(exc))
        struct_offset, struct_size = 0x380, 184
        fixture = binary[struct_offset:struct_offset + struct_size]
        marker = b"MALWARE PAYLOAD CARRIER HERE"
        payload_marker = b"NULL PAYLOAD"
        marker_offset = binary.find(marker)
        result = {
            "execution_performed": False,
            "binary": {"name": os.path.basename(self.app.pargs.binary), "bytes": len(binary),
                       "sha256": stream.sha256(binary)},
            "source": {"name": os.path.basename(self.app.pargs.source), "bytes": len(source),
                       "sha256": stream.sha256(source)},
            "control": {"name": os.path.basename(self.app.pargs.control), "bytes": len(control),
                        "sha256": stream.sha256(control), "reference_class": "test"},
            "static_checks": {
                "mach_o_arm64_magic": binary[:8].hex() == "cffaedfe0c000001",
                "main_returns_zero_stub": binary[0x378:0x380].hex() == "00008052c0035fd6",
                "structure_offset": struct_offset,
                "structure_bytes": len(fixture),
                "version": int.from_bytes(fixture[:4], "little") if len(fixture) >= 8 else None,
                "slot_count": int.from_bytes(fixture[4:8], "little") if len(fixture) >= 8 else None,
                "all_callback_slots_null": len(fixture) == struct_size and not any(fixture[8:136]),
                "marker_offset": marker_offset,
                "payload_offset": binary.find(payload_marker),
                "control_matches_structure_tail": len(fixture) == struct_size and fixture[136:184] == control,
            },
        }
        _dump(result, self.app.pargs.pretty)
        checks = result["static_checks"]
        good = (len(control) == 48 and result["control"]["sha256"] ==
                "5e0910a520129f61f1d8ecd9eb76df39a6b16b56e74c05f193716ea4dfde2623" and
                all(value is True or key.endswith("offset") or key in ("structure_bytes", "version", "slot_count")
                    for key, value in checks.items()) and
                checks["version"] == 1 and checks["slot_count"] == 16 and
                checks["marker_offset"] == 0x408 and checks["payload_offset"] == 0x428)
        self.app.exit_code = 0 if good else 1
        return self.app.exit_code

    @ex(
        label="school-control",
        help="run the complete 48-byte school-control inclusion demonstration",
        arguments=[
            (["--binary"], {"default": DEFAULT_BINARY}),
            (["--control"], {"default": DEFAULT_CONTROL}),
            (["--drop"], {"type": int, "default": 7}),
            (["--output-envelope"], {"help": "optional JSONL evidence-envelope path"}),
            (["--output-signatures"], {"help": "optional signature-database path"}),
            (["--format"], {"choices": ("report", "siem-json", "syslog"), "default": "report"}),
            (["--host"], {"default": "school-lab", "help": "host label for SIEM/syslog output"}),
            (["--pretty"], {"action": "store_true"}),
        ],
    )
    def school_control(self):
        try:
            rows = stream.make_file_envelope(
                self.app.pargs.binary, data_chunks=8, drops=[self.app.pargs.drop],
                stream_id="binary-ascii-control")
            if self.app.pargs.output_envelope:
                _write_jsonl(rows, self.app.pargs.output_envelope)
            with tempfile.TemporaryDirectory() as directory:
                database_path = self.app.pargs.output_signatures or os.path.join(directory, "school-control.json")
                database = stream.build_signature_db(
                    [self.app.pargs.control], window_bytes=16, min_match_bytes=32,
                    reference_class="test")
                stream.write_signature_db(database, database_path)
                loaded = stream.load_signature_db(database_path)
                reports = stream.analyze(rows, signature_db=loaded)
            _emit_reports(reports, self.app.pargs.format, self.app.pargs.pretty, self.app.pargs.host)
        except (OSError, ValueError) as exc:
            return self._fail(str(exc))
        self.app.exit_code = _reports_exit(reports)
        return self.app.exit_code

    @ex(label="self-test", help="run the complete synthetic test suite")
    def self_test(self):
        suite = unittest.defaultTestLoader.discover(os.path.join(ROOT, "tests"), top_level_dir=ROOT)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        self.app.exit_code = 0 if result.wasSuccessful() else 1
        return self.app.exit_code


class BluewareApp(App):
    class Meta:
        label = "blueware"
        handlers = [BaseController]
        config_files = []
        config_dirs = []
        plugin_dirs = []
        exit_on_close = False


def main(argv=None):
    with BluewareApp(argv=list(argv) if argv is not None else None) as app:
        app.run()
        return app.exit_code


if __name__ == "__main__":
    sys.exit(main())
