# Blueware CLI

Blueware is the Cement-based command application for the defensive message-stream
lab. It provides the analyzer and SIEM-facing functions without starting the macOS
collectors or Streamlit dashboard.

## Install

Cement 3 requires Python 3.10 or newer. Install the pinned dependency in the project
virtual environment:

```zsh
cd "$HOME/BlueteamLab/detection-lab"
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-cli.txt
```

The `blueware` launcher automatically uses `.venv/bin/python` when it exists.

## Command tree

```text
blueware
├── about               scope, capabilities and boundaries
├── policy              reference classes and exit-code contract
├── analyze             analyze JSONL envelopes; report/SIEM/syslog output
├── containment-plan    create a plan-only endpoint-policy handoff
├── simulate            ordinary chunks and optional XOR teaching parity
├── simulate-rs         GF(256) 4+2 envelopes using either defined matrix
├── envelope            wrap inert file bytes without executing them
├── canonize            create a classified signature database
├── compare-matrices    compare both defined GF(256) matrices
├── inspect-control     statically verify the committed fixture
├── school-control      run the complete 48-byte S5 control demonstration
└── self-test           run all synthetic tests
```

Show Cement's generated help:

```zsh
./blueware --help
./blueware analyze --help
```

## One-command school demonstration

```zsh
./blueware school-control --format siem-json --pretty
```

Expected evidence:

- `event.kind: event`
- `stream.status: inconclusive`
- `stream.transport_coverage: 0.875`
- 48 matched bytes at offset `0x408`
- `disposition: school_control`
- `containment: none`
- no whole-file hash
- exit code `1`, meaning an evidence gap

Use `--host school-lab` or another neutral label for shareable SIEM output. The school
command defaults to `school-lab`.

## Static fixture inspection

```zsh
./blueware inspect-control --pretty
```

This reads bytes without executing the file and verifies the ARM64 Mach-O header, two-
instruction return-zero main stub, version, slot count, sixteen NULL callback slots,
marker offsets, exact 48-byte structure tail, and source/binary/control SHA-256 values.

## Matrix comparison

```zsh
./blueware compare-matrices --pretty
./blueware compare-matrices --input path/to/authorized.bin --pretty
```

The default input is the inert school fixture. The result includes formula definitions and
hashes, parity hashes and diffusion, and exact one-share/two-share recovery counts.

## GF(256) recovery pipeline

```zsh
./blueware simulate-rs \
  --matrix darkrock-custom \
  --drop 0 --drop 5 \
  --output /tmp/blueware-rs.jsonl

./blueware analyze /tmp/blueware-rs.jsonl --pretty
```

Expected status: `clean`, reconstruction: `recovered`, manifest: `verified`.

## Classified canonical references

School/test reference:

```zsh
./blueware canonize samples/synthetic/school_control_ascii.bin \
  --reference-class test \
  --window-bytes 16 \
  --min-match-bytes 32 \
  --output /tmp/school-control.json \
  --pretty
```

Authorized malicious-reference set:

```zsh
./blueware canonize authorized-reference.bin \
  --reference-class malicious \
  --output /secure/path/malicious-signatures.json
```

Reference class is mandatory in schema version 2; the CLI defaults to `test`. Version 1
databases fail closed and must be rebuilt.

## File envelope

```zsh
./blueware envelope samples/synthetic/null_payload_carrier.bin \
  --data-chunks 8 \
  --drop 7 \
  --stream-id school-demo \
  --output /tmp/school-demo.jsonl

./blueware analyze /tmp/school-demo.jsonl \
  --signature-db /tmp/school-control.json \
  --format siem-json \
  --host school-lab \
  --pretty
```

`analyze` accepts `-` as input for stdin. `simulate`, `simulate-rs`, and `envelope` accept
`--output -` for stdout.

## Output formats

```zsh
./blueware analyze stream.jsonl --format report --pretty
./blueware analyze stream.jsonl --format siem-json --host lab-host
./blueware analyze stream.jsonl --format syslog --host lab-host
```

Payload bytes are excluded from SIEM and syslog output.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | Complete/recovered with no suspicious finding |
| `1` | Inconclusive evidence gap; parse the JSON |
| `2` | Usage, input, database, or tooling error |
| `3` | Suspicious finding |

Automation must retain stdout on nonzero exit and route on `status`, `findings`,
`observations`, `gaps`, and `containment`. Exit code `1` is not an incident.

## Containment handoff

Blueware does not change endpoint state. It can convert one report into a reviewable plan:

```zsh
./blueware containment-plan analysis.json --pretty
```

The plan is authorized only when the report is suspicious and its basis includes an
explicitly malicious canonical reference or a denylisted whole-file hash. It records
`requested_control: tcp_cutoff`, `execution_performed: false`, and `simd_changed: false`, then
asks an authorized EDR or host firewall to block and verify TCP traffic. TCP cutoff does not
cover UDP, local IPC, or other transports. Test, benign, clean, and evidence-gap-only reports
produce no actions and exit `1`.

## Self-test

```zsh
./blueware self-test
```

The verified suite currently contains 77 tests, including eleven Cement CLI contract tests.

## Boundaries

Blueware:

- consumes explicit message envelopes;
- never executes the analyzed file;
- does not capture or reassemble live TCP;
- does not decrypt SSH or TLS;
- does not execute containment; `containment-plan` emits a plan-only endpoint handoff;
- emits an endpoint-policy recommendation only for a denylisted whole hash or explicitly
  malicious canonical reference.
