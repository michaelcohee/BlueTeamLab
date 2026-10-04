#!/usr/bin/env python3
"""Generate harmless synthetic idtscan JSONL fixtures for vector 0x1f."""

import argparse
import json
import sys


SCENARIOS = {
    "normal": {"present": True, "dpl": 0, "location": "kernel-text", "module": None,
               "symbol": "asm_exc_spurious_interrupt", "handler": "0xffffffff81001234"},
    "absent": {"present": False, "dpl": 0, "location": "not-present", "module": None,
               "symbol": None, "handler": None},
    "user-callable": {"present": True, "dpl": 3, "location": "kernel-text", "module": None,
                      "symbol": "unexpected_gate", "handler": "0xffffffff81005678"},
    "unknown-handler": {"present": True, "dpl": 0, "location": "unknown", "module": None,
                        "symbol": None, "handler": "0xffff888000001000"},
    "alternate-core-handler": {"present": True, "dpl": 0, "location": "kernel-text", "module": None,
                               "symbol": "alternate_exception_stub", "handler": "0xffffffff82001234"},
}


def event(scenario, cpu="all"):
    row = {
        "ts": "2000-01-01T00:00:00.000000Z", "capture_ts": "2000-01-01T00:00:00.000000Z",
        "host": "synthetic-lab", "source": "idtscan-simulator", "scan_id": "synthetic",
        "scanner_version": "simulation-1", "event_type": "idt_entry", "cpu": cpu,
        "vector": 31, "vector_hex": "0x1f", "vector_name": "reserved", "reserved": True,
        "segment": "0x10", "ist": 0, "gate_type": "interrupt",
    }
    row.update(SCENARIOS[scenario])
    return row


def main(argv=None):
    parser = argparse.ArgumentParser(description="Emit synthetic vector 0x1f telemetry; performs no privileged action")
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), default="normal")
    parser.add_argument("--cpu", default="all")
    args = parser.parse_args(argv)
    print(json.dumps(event(args.scenario, args.cpu), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
