import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("probe_1f", ROOT / "idtscan" / "probe_1f.py")
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


def entry(**changes):
    row = {
        "event_type": "idt_entry", "cpu": "all", "vector": 31, "present": True,
        "dpl": 0, "segment": "0x10", "gate_type": "interrupt",
        "location": "kernel-text", "module": None,
        "symbol": "asm_exc_spurious_interrupt", "handler": "0xffffffff81000000",
    }
    row.update(changes)
    return row


class ProbeTests(unittest.TestCase):
    def test_normal_core_handler_is_clean(self):
        self.assertEqual(PROBE.analyze([entry()])["status"], "clean")

    def test_user_callable_gate_is_suspicious(self):
        report = PROBE.analyze([entry(dpl=3)])
        self.assertEqual(report["status"], "suspicious")
        self.assertEqual(report["findings"][0]["code"], "vector_1f_user_callable")

    def test_unknown_handler_is_suspicious(self):
        report = PROBE.analyze([entry(location="unknown", symbol=None)])
        self.assertIn("vector_1f_unknown_handler", {f["code"] for f in report["findings"]})

    def test_scanner_gap_is_inconclusive(self):
        report = PROBE.analyze([entry(), {"event_type": "scan_gap", "gap": "kcore_unreadable", "detail": "denied"}])
        self.assertEqual(report["status"], "inconclusive")

    def test_kaslr_address_change_is_ignored(self):
        baseline = [entry(handler="0xffffffff81000000", symbol="handler+0x4")]
        current = [entry(handler="0xffffffff92000000", symbol="handler+0x18")]
        self.assertEqual(PROBE.analyze(current, baseline)["status"], "clean")

    def test_semantic_baseline_change_is_suspicious(self):
        report = PROBE.analyze([entry(symbol="different_handler")], [entry()])
        self.assertIn("vector_1f_semantic_change", {f["code"] for f in report["findings"]})


if __name__ == "__main__":
    unittest.main()
