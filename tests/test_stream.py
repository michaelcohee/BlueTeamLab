import base64
import json
import os
import tempfile
import unittest
from itertools import combinations

from lab import stream


class StreamAnalyzerTests(unittest.TestCase):
    def test_four_of_five_is_partial_and_unhashable(self):
        report = stream.analyze(stream.make_simulation(5, drop=4))[0]
        self.assertEqual(report["reconstruction"], "partial")
        self.assertEqual(report["coverage"], 0.8)
        self.assertEqual(report["missing_data_chunks"], [4])
        self.assertIsNone(report["whole_sha256"])
        self.assertEqual(report["manifest_verdict"], "not_computable")
        self.assertEqual(report["status"], "inconclusive")

    def test_out_of_order_complete_stream_verifies(self):
        rows = stream.make_simulation(5)
        report = stream.analyze([rows[0]] + list(reversed(rows[1:])))[0]
        self.assertEqual(report["reconstruction"], "complete")
        self.assertEqual(report["manifest_verdict"], "verified")
        self.assertEqual(report["confidence"], "full")
        self.assertEqual(report["status"], "clean")

    def test_single_missing_chunk_recovers_with_parity(self):
        report = stream.analyze(stream.make_simulation(4, drop=2, include_parity=True))[0]
        self.assertEqual(report["reconstruction"], "recovered")
        self.assertEqual(report["recovered_chunk"], 2)
        self.assertEqual(report["manifest_verdict"], "verified")
        self.assertEqual(report["status"], "clean")
        self.assertEqual(report["transport_chunks_received"], 4)
        self.assertEqual(report["transport_chunks_expected"], 5)
        self.assertEqual(report["transport_coverage"], 0.8)

    def test_bad_chunk_checksum_is_suspicious(self):
        rows = stream.make_simulation(2)
        rows[1]["sha256"] = "0" * 64
        report = stream.analyze(rows)[0]
        self.assertEqual(report["corrupt_indices"], [0])
        self.assertEqual(report["status"], "suspicious")
        self.assertIn("chunk_hash_mismatch", {finding["finding"] for finding in report["findings"]})

    def test_conflicting_duplicate_is_suspicious(self):
        rows = stream.make_simulation(2)
        conflict = dict(rows[1])
        payload = b"different"
        conflict["payload_b64"] = base64.b64encode(payload).decode("ascii")
        conflict["sha256"] = stream.sha256(payload)
        report = stream.analyze(rows + [conflict])[0]
        self.assertEqual(report["status"], "suspicious")
        self.assertIn("conflicting_chunk_evidence", {finding["finding"] for finding in report["findings"]})

    def test_complete_denylisted_hash_recommends_endpoint_policy(self):
        rows = stream.make_simulation(3)
        expected = rows[0]["whole_sha256"]
        report = stream.analyze(rows, {expected})[0]
        self.assertEqual(report["status"], "suspicious")
        self.assertEqual(report["containment"], "endpoint policy required")
        self.assertIn("denylisted_whole_hash", {finding["finding"] for finding in report["findings"]})

    def test_siem_and_syslog_outputs_contain_no_payload_bytes(self):
        report = stream.analyze(stream.make_simulation(5, drop=4))[0]
        event = stream.to_siem_event(report, host="school-lab")
        encoded = __import__("json").dumps(event)
        self.assertNotIn("payload_b64", encoded)
        self.assertEqual(event["stream.transport_coverage"], 0.8)
        line = stream.to_syslog(event)
        self.assertTrue(line.startswith("<132>1 "))
        self.assertIn("STREAM_INTEGRITY", line)

    def test_redtail_rs_recovers_every_two_share_loss_pattern(self):
        for first in range(6):
            for second in range(first + 1, 6):
                with self.subTest(drops=(first, second)):
                    report = stream.analyze(stream.make_rs_simulation([first, second]))[0]
                    self.assertEqual(report["manifest_verdict"], "verified")
                    self.assertEqual(report["confidence"], "full")
                    self.assertEqual(report["status"], "clean")
                    self.assertEqual(report["transport_chunks_received"], 4)
                    self.assertEqual(report["transport_chunks_expected"], 6)
                    self.assertFalse(report["codec_formula"]["zero_elimination"])
                    self.assertEqual(report["codec_formula"]["row_labels"],
                                     ["G0", "G1", "G2", "G3", "G4", "G5"])

    def test_rs_manifest_persists_and_validates_full_generator(self):
        rows = stream.make_rs_simulation([1, 4], generator=stream.DARKROCK_CUSTOM_GENERATOR,
                                         codec_name="darkrock-custom")
        formula = rows[0]["codec_formula"]
        self.assertEqual(formula["field_polynomial"], "0x11d")
        self.assertEqual(formula["generator_rows"][5], [1, 2, 3, 4])
        self.assertFalse(formula["zero_elimination"])
        self.assertEqual(len(formula["formula_sha256"]), 64)
        report = stream.analyze(rows)[0]
        self.assertEqual(report["manifest_verdict"], "verified")
        self.assertEqual(report["codec_formula"], formula)

    def test_rs_manifest_rejects_formula_change(self):
        rows = stream.make_rs_simulation()
        rows[0]["codec_formula"]["generator_rows"][5] = [0, 0, 0, 0]
        report = stream.analyze(rows)[0]
        self.assertEqual(report["status"], "inconclusive")
        self.assertIn("invalid_events", {gap["gap"] for gap in report["gaps"]})

    def test_rs_manifest_rejects_valid_matrix_with_stale_formula_hash(self):
        rows = stream.make_rs_simulation()
        rows[0]["codec_formula"]["generator_rows"] = [
            list(row) for row in stream.DARKROCK_CUSTOM_GENERATOR]
        report = stream.analyze(rows)[0]
        self.assertEqual(report["status"], "inconclusive")
        errors = [error for gap in report["gaps"] for error in gap.get("errors", [])]
        self.assertTrue(any("codec formula SHA-256" in error for error in errors))

    def test_known_rs_matrices_rebuild_all_loss_cases_exactly(self):
        payload = bytes(range(256)) * 2 + bytes(7)
        comparison = stream.compare_rs_generators(payload)
        self.assertFalse(comparison["zero_elimination"])
        self.assertGreater(comparison["parity_comparison"]["different_bytes"], 0)
        for variant in comparison["variants"]:
            self.assertTrue(variant["all_rebuilds_exact"])
            self.assertEqual(variant["one_share_loss_exact"], 6)
            self.assertEqual(variant["two_share_loss_exact"], 15)

    def test_redtail_rs_three_missing_shares_is_inconclusive(self):
        rows = stream.make_rs_simulation([0, 1])
        rows = [row for row in rows if not (row.get("kind") == "rs_share" and row.get("index") == 2)]
        report = stream.analyze(rows)[0]
        self.assertEqual(report["reconstruction"], "partial")
        self.assertEqual(report["manifest_verdict"], "not_computable")
        self.assertEqual(report["status"], "inconclusive")

    def test_redtail_rs_preserves_zero_bytes_at_tail_boundaries(self):
        for length in (1, 2, 3, 4, 5, 7, 8, 9, 255, 256, 257, 1023, 1024, 1025):
            payload = bytes((index * 17) & 255 for index in range(length))
            if length >= 5:
                payload = payload[:-5] + bytes(5)
            shares = stream.rs_encode_4_2(payload)
            self.assertTrue(all(len(share) == (length + 3) // 4 for share in shares))
            for missing in combinations(range(6), 2):
                observed = {index: share for index, share in enumerate(shares) if index not in missing}
                restored = b"".join(stream.rs_recover_4_2(observed))[:length]
                self.assertEqual(restored, payload, (length, missing))

    def test_partial_stream_matches_canonical_reference_without_whole_hash(self):
        rows = stream.make_simulation(5, drop=4)
        complete = stream.make_simulation(5)
        payload = b"".join(base64.b64decode(row["payload_b64"]) for row in complete if row["kind"] == "data")
        with tempfile.TemporaryDirectory() as directory:
            reference = os.path.join(directory, "known.bin")
            database_path = os.path.join(directory, "signatures.json")
            with open(reference, "wb") as fh:
                fh.write(payload)
            stream.write_signature_db(
                stream.build_signature_db([reference], reference_class="malicious"), database_path)
            report = stream.analyze(rows, signature_db=stream.load_signature_db(database_path))[0]
        self.assertIsNone(report["whole_sha256"])
        self.assertEqual(report["status"], "suspicious")
        self.assertEqual(report["canonical_matches"][0]["reference"], "known.bin")
        self.assertGreaterEqual(report["canonical_matches"][0]["matched_bytes"], 64)
        self.assertIn("known_content_inclusion", {item["finding"] for item in report["findings"]})
        self.assertEqual(report["canonical_matches"][0]["reference_class"], "malicious")
        self.assertEqual(report["containment"], "endpoint policy required")

    def test_binary_file_envelope_matches_reference_with_one_chunk_missing(self):
        payload = bytes(range(256)) * 8 + b"MALWARE PAYLOAD CARRIER HERE\0NULL PAYLOAD\0"
        with tempfile.TemporaryDirectory() as directory:
            reference = os.path.join(directory, "carrier.bin")
            database_path = os.path.join(directory, "signatures.json")
            with open(reference, "wb") as fh:
                fh.write(payload)
            rows = stream.make_file_envelope(reference, data_chunks=8, drops=[7])
            stream.write_signature_db(
                stream.build_signature_db([reference], reference_class="test"), database_path)
            report = stream.analyze(rows, signature_db=stream.load_signature_db(database_path))[0]
        self.assertEqual(report["manifest_verdict"], "not_computable")
        self.assertEqual(report["status"], "inconclusive")
        self.assertEqual(report["containment"], "none")
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["observations"][0]["observation"], "known_content_inclusion")
        self.assertEqual(report["observations"][0]["disposition"], "school_control")
        self.assertGreater(report["canonical_matches"][0]["matched_bytes"], 1000)

    def test_48_byte_school_control_is_observation_in_partial_binary(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        binary = os.path.join(root, "samples", "synthetic", "null_payload_carrier.bin")
        control = os.path.join(root, "samples", "synthetic", "school_control_ascii.bin")
        with open(control, "rb") as fh:
            self.assertEqual(stream.sha256(fh.read()),
                             "5e0910a520129f61f1d8ecd9eb76df39a6b16b56e74c05f193716ea4dfde2623")
        rows = stream.make_file_envelope(binary, data_chunks=8, drops=[7],
                                         stream_id="binary-ascii-control")
        with tempfile.TemporaryDirectory() as directory:
            database_path = os.path.join(directory, "school-control.json")
            database = stream.build_signature_db([control], window_bytes=16, min_match_bytes=32,
                                                 reference_class="test")
            stream.write_signature_db(database, database_path)
            report = stream.analyze(
                rows, signature_db=stream.load_signature_db(database_path))[0]
        self.assertEqual(report["transport_coverage"], 0.875)
        self.assertIsNone(report["whole_sha256"])
        self.assertEqual(report["manifest_verdict"], "not_computable")
        self.assertEqual(report["canonical_matches"][0]["matched_bytes"], 48)
        self.assertEqual(report["canonical_matches"][0]["observed_segment_offset"], 1032)
        self.assertEqual(report["canonical_matches"][0]["reference_class"], "test")
        self.assertEqual(report["status"], "inconclusive")
        self.assertEqual(report["containment"], "none")
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["observations"][0]["disposition"], "school_control")
        event = stream.to_siem_event(report, host="school-lab")
        self.assertEqual(event["event.kind"], "event")
        self.assertEqual(event["containment"], "none")
        self.assertEqual(event["findings"], [])
        self.assertEqual(event["observations"][0]["disposition"], "school_control")

    def test_benign_reference_is_inclusion_only(self):
        rows = stream.make_simulation(5)
        payload = b"".join(base64.b64decode(row["payload_b64"])
                           for row in rows if row["kind"] == "data")
        with tempfile.TemporaryDirectory() as directory:
            reference = os.path.join(directory, "benign.bin")
            database_path = os.path.join(directory, "benign.json")
            with open(reference, "wb") as fh:
                fh.write(payload)
            database = stream.build_signature_db([reference], reference_class="benign")
            stream.write_signature_db(database, database_path)
            report = stream.analyze(
                rows, signature_db=stream.load_signature_db(database_path))[0]
        self.assertEqual(report["status"], "clean")
        self.assertEqual(report["containment"], "none")
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["observations"][0]["disposition"], "inclusion_only")

    def test_repeated_zero_windows_are_not_specific_signatures(self):
        payload = bytes(4096)
        with tempfile.TemporaryDirectory() as directory:
            reference = os.path.join(directory, "zeros.bin")
            database_path = os.path.join(directory, "signatures.json")
            with open(reference, "wb") as fh:
                fh.write(payload)
            rows = stream.make_file_envelope(reference, data_chunks=8, drops=[7])
            stream.write_signature_db(stream.build_signature_db([reference]), database_path)
            report = stream.analyze(rows, signature_db=stream.load_signature_db(database_path))[0]
        self.assertEqual(report["canonical_matches"], [])
        self.assertEqual(report["status"], "inconclusive")


if __name__ == "__main__":
    unittest.main()
