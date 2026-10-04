# Safe vector 0x1f inspection

The lab inspects telemetry and debugger output only. Do not execute `int 0x1f`, install a
test gate, patch an IDT, load an unsigned driver, or disable platform protections.

## Linux x86-64

1. Run `idtscan_linux.py` on the disposable Linux lab host and store its JSONL outside the
   repository.
2. Run `probe_1f.py current.jsonl --pretty`.
3. For a comparison, capture a known-good scan from the same kernel build and run
   `probe_1f.py current.jsonl --baseline known-good.jsonl --pretty`.
4. Preserve the kernel version, module list, scanner output, and any `scan_gap` rows with
   the case. A gap is inconclusive and must not be recorded as clean.

Raw handler addresses are deliberately excluded from baseline comparisons because KASLR
can move them between boots. The probe compares presence, DPL, segment, gate type,
resolved location, module, and normalized symbol.

## Windows x64

1. Create a kernel dump through the approved lab procedure and run `IdtScan.ps1` with
   `-DumpPath`, `-SaveKdLog`, and `-OutFile`.
2. Run `probe_1f.py` against the JSONL. Preserve the raw debugger transcript alongside it.
3. Treat duplicate CPU/vector rows, missing module ranges, incomplete CPU coverage, and
   missing CR0 values as scan gaps.
4. Review `!idt -a`, `lm`, and register output in the saved transcript. Do not invoke the
   vector or alter debugger memory.

## macOS

Apple silicon uses the Arm exception-vector model rather than an x86 IDT. Intel macOS has
no supported backend in this lab. Record the platform as unsupported; do not weaken SIP or
install a kernel extension for this check.

## Harmless detection exercise

Generate synthetic telemetry and pass it to the probe:

```sh
python3 idtscan/simulate_1f_events.py --scenario normal \
  | python3 idtscan/probe_1f.py - --pretty

python3 idtscan/simulate_1f_events.py --scenario user-callable \
  | python3 idtscan/probe_1f.py - --pretty
```

Expected exits are 0 for clean, 1 for inconclusive coverage, and 3 for suspicious output.
