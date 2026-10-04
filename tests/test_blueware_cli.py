import json
import os
import subprocess
import tempfile
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BLUEWARE = os.path.join(ROOT, "blueware")
SAMPLES = os.path.join(ROOT, "samples", "synthetic")


def run_blueware(*args):
    return subprocess.run(
        [BLUEWARE] + list(args), cwd=ROOT, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)


_BLUEWARE_PROBE = run_blueware("about")
_HAVE_CEMENT = not (
    _BLUEWARE_PROBE.returncode == 2 and
    "Cement is missing" in _BLUEWARE_PROBE.stderr
)


@unittest.skipUnless(_HAVE_CEMENT, "Cement not installed (requirements-cli.txt)")
class BluewareCliTests(unittest.TestCase):
    def test_help_exposes_complete_command_tree(self):
        result = run_blueware("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        for command in ("analyze", "canonize", "compare-matrices", "envelope",
                        "containment-plan", "inspect-control", "policy", "school-control",
                        "self-test", "simulate", "simulate-rs"):
            self.assertIn(command, result.stdout)

    def test_policy_keeps_test_and_benign_out_of_containment(self):
        result = run_blueware("policy")
        self.assertEqual(result.returncode, 0, result.stderr)
        policy = json.loads(result.stdout)
        self.assertEqual(policy["reference_classes"]["test"]["containment"], "none")
        self.assertEqual(policy["reference_classes"]["benign"]["containment"], "none")
        self.assertEqual(policy["reference_classes"]["malicious"]["containment"],
                         "endpoint policy required")

    def test_inspect_control_is_static_and_exact(self):
        result = run_blueware("inspect-control")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertFalse(report["execution_performed"])
        self.assertEqual(report["control"]["bytes"], 48)
        self.assertEqual(report["control"]["sha256"],
                         "5e0910a520129f61f1d8ecd9eb76df39a6b16b56e74c05f193716ea4dfde2623")
        self.assertTrue(report["static_checks"]["all_callback_slots_null"])
        self.assertEqual(report["static_checks"]["marker_offset"], 0x408)

    def test_school_control_is_inconclusive_event_without_containment(self):
        result = run_blueware("school-control", "--format", "siem-json")
        self.assertEqual(result.returncode, 1, result.stderr)
        event = json.loads(result.stdout)
        self.assertEqual(event["event.kind"], "event")
        self.assertEqual(event["host.name"], "school-lab")
        self.assertEqual(event["stream.status"], "inconclusive")
        self.assertEqual(event["containment"], "none")
        self.assertEqual(event["observations"][0]["disposition"], "school_control")
        self.assertEqual(event["stream.canonical_matches"][0]["matched_bytes"], 48)

    def test_rs_simulation_recovers_two_missing_shares(self):
        with tempfile.TemporaryDirectory() as directory:
            envelope = os.path.join(directory, "rs.jsonl")
            generated = run_blueware("simulate-rs", "--matrix", "darkrock-custom",
                                     "--drop", "0", "--drop", "5", "--output", envelope)
            self.assertEqual(generated.returncode, 0, generated.stderr)
            analyzed = run_blueware("analyze", envelope)
        self.assertEqual(analyzed.returncode, 0, analyzed.stderr)
        report = json.loads(analyzed.stdout)
        self.assertEqual(report["status"], "clean")
        self.assertEqual(report["manifest_verdict"], "verified")
        self.assertEqual(report["codec_formula"]["name"], "darkrock-custom")

    def test_explicit_malicious_reference_preserves_containment_path(self):
        with tempfile.TemporaryDirectory() as directory:
            database = os.path.join(directory, "malicious.json")
            envelope = os.path.join(directory, "partial.jsonl")
            control = os.path.join(SAMPLES, "school_control_ascii.bin")
            binary = os.path.join(SAMPLES, "null_payload_carrier.bin")
            made_db = run_blueware(
                "canonize", control, "--reference-class", "malicious",
                "--window-bytes", "16", "--min-match-bytes", "32", "--output", database)
            self.assertEqual(made_db.returncode, 0, made_db.stderr)
            made_envelope = run_blueware(
                "envelope", binary, "--data-chunks", "8", "--drop", "7",
                "--output", envelope)
            self.assertEqual(made_envelope.returncode, 0, made_envelope.stderr)
            analyzed = run_blueware("analyze", envelope, "--signature-db", database)
        self.assertEqual(analyzed.returncode, 3, analyzed.stderr)
        report = json.loads(analyzed.stdout)
        self.assertEqual(report["status"], "suspicious")
        self.assertEqual(report["containment"], "endpoint policy required")

    def test_version_one_database_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            envelope = os.path.join(directory, "stream.jsonl")
            database = os.path.join(directory, "v1.json")
            generated = run_blueware("simulate", "--output", envelope)
            self.assertEqual(generated.returncode, 0, generated.stderr)
            with open(database, "w", encoding="utf-8") as fh:
                json.dump({"schema": "daybreak-canonical-signatures/v1"}, fh)
            analyzed = run_blueware("analyze", envelope, "--signature-db", database)
        self.assertEqual(analyzed.returncode, 2)
        self.assertIn("unsupported schema", analyzed.stderr)

    def test_matrix_comparison_uses_fixture_by_default(self):
        result = run_blueware("compare-matrices")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["input"], "null_payload_carrier.bin")
        self.assertEqual(report["parity_comparison"]["different_bytes"], 339)
        self.assertTrue(all(item["all_rebuilds_exact"] for item in report["variants"]))

    def test_missing_input_is_tool_error(self):
        result = run_blueware("analyze", "/definitely/missing/blueware.jsonl")
        self.assertEqual(result.returncode, 2)
        self.assertIn("blueware:", result.stderr)

    def test_containment_plan_rejects_school_control(self):
        with tempfile.TemporaryDirectory() as directory:
            report_path = os.path.join(directory, "school.json")
            school = run_blueware("school-control")
            self.assertEqual(school.returncode, 1, school.stderr)
            report = json.loads(school.stdout)
            with open(report_path, "w", encoding="utf-8") as fh:
                json.dump(report, fh)
            planned = run_blueware("containment-plan", report_path)
        self.assertEqual(planned.returncode, 1, planned.stderr)
        plan = json.loads(planned.stdout)
        self.assertFalse(plan["authorized"])
        self.assertFalse(plan["execution_performed"])
        self.assertFalse(plan["simd_changed"])
        self.assertIsNone(plan["requested_control"])
        self.assertEqual(plan["actions"], [])

    def test_containment_plan_accepts_explicit_malicious_match_without_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            database = os.path.join(directory, "malicious.json")
            envelope = os.path.join(directory, "partial.jsonl")
            report_path = os.path.join(directory, "report.json")
            control = os.path.join(SAMPLES, "school_control_ascii.bin")
            binary = os.path.join(SAMPLES, "null_payload_carrier.bin")
            self.assertEqual(run_blueware(
                "canonize", control, "--reference-class", "malicious",
                "--window-bytes", "16", "--min-match-bytes", "32",
                "--output", database).returncode, 0)
            self.assertEqual(run_blueware(
                "envelope", binary, "--data-chunks", "8", "--drop", "7",
                "--output", envelope).returncode, 0)
            analyzed = run_blueware("analyze", envelope, "--signature-db", database)
            self.assertEqual(analyzed.returncode, 3, analyzed.stderr)
            with open(report_path, "w", encoding="utf-8") as fh:
                fh.write(analyzed.stdout)
            planned = run_blueware("containment-plan", report_path)
        self.assertEqual(planned.returncode, 0, planned.stderr)
        plan = json.loads(planned.stdout)
        self.assertTrue(plan["authorized"])
        self.assertFalse(plan["execution_performed"])
        self.assertFalse(plan["simd_changed"])
        self.assertEqual(plan["requested_control"], "tcp_cutoff")
        self.assertEqual(plan["basis"][0]["finding"], "known_content_inclusion")
        self.assertEqual(plan["actions"][2]["action"], "request_tcp_cutoff")


if __name__ == "__main__":
    unittest.main()
