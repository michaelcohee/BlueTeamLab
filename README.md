# Blueware

Blueware is a school-lab Python stream scanner for partial-stream observation; it is not an
industry SIEM or a detection product. The surrounding offline, single-Mac lab collects local
network and process telemetry, hunts it with explainable SQL rules, and turns each hit into a
Vertical case notebook—automatically (Horizontal) and then by hand—so the two can be compared.

Built as a portfolio piece for SOC / detection-engineering work. Everything runs locally;
no component makes a network request or sends telemetry anywhere.

## What's here

```
collect/     macOS collectors (Zeek, osquery, eslogger) + disk guard — run on the Mac
lab/         the pipeline (Python 3.9+ stdlib; needs the duckdb CLI)
  normalize.py  raw logs      -> one common JSONL schema (docs/SCHEMA.md)
  hunt.py       baseline + rules/*.sql -> hits.jsonl
  horizontal.py a hit         -> an [AUTO] VERTICAL 1 case file
  bookdiff.py   [AUTO] book   vs a hand-traced book -> agreement score
  stream.py     explicit chunks -> coverage, reassembly, SHA-256 integrity verdict
  vbook.py      reader/writer for Vertical's format (byte-compatible)
rules/       R1–R6 as DuckDB SQL, one file each, with params.json
tests/       synthetic unit/integration suite (no real logs committed)
docs/        SCHEMA, TUNING, PLAYBOOK
dl           entry point:  ./dl <command>
blueware     Cement CLI for the message-stream analyzer and SIEM output
```

## Pipeline

```
Zeek / osquery / eslogger            (collect/, read-only, metadata only)
        │   raw/<session>/
        ▼
  dl normalize                       -> norm/<session>.jsonl   (proc_key, raw_ref on every event)
        │
  dl baseline --until <ts>           -> baseline/              (known dsts, binaries, persistence, p99)
        │
  dl hunt                            -> hits/hits-<ts>.jsonl   (each hit cites its raw lines)
        │
  dl trace <hit> --kind SIMULATION   -> books/auto/*.vbook     (Horizontal: untested/id-match only)
        │                                     │
   (hand trace in Vertical)  ── dl diff ──────┘               (agreement score + what the human upgraded)
```

## Quick start (after [Phase 0](PHASE0.md))

```zsh
export VERTICALDATA=~/VerticalData
collect/lab.sh dryrun 5          # 5-minute capture, prints per-source size
collect/lab.sh start --hours 24  # begin a bounded 24 h baseline capture
# … later …
collect/lab.sh stop
./dl normalize
./dl baseline --until 2026-10-04T12:00:00Z
./dl hunt
./dl trace <hit_id> --kind SIMULATION
```

## Partial-stream integrity demo

The school-lab stream analyzer demonstrates honest handling of incomplete message evidence.
Four of five ordinary chunks produce 80% coverage and no whole-file hash. A separate
RedTail-X-style 4+2 demonstration reconstructs a stripe from any four valid Reed–Solomon
shares. Partial ordinary streams can also be checked for continuous multi-byte inclusion
from an authorized canonical reference set.

### Blueware CLI

The dedicated Cement application runs the complete analyzer without the live collector or
dashboard:

```zsh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-cli.txt

./blueware --help
./blueware inspect-control --pretty
./blueware compare-matrices --pretty
./blueware school-control --format siem-json --pretty
```

The school-control command exits `1` because one chunk is deliberately missing. Its JSON
reports an evidence gap, an informational `school_control` observation, and no containment.
See [docs/BLUEWARE_CLI.md](docs/BLUEWARE_CLI.md) for the full command reference.

| Reference class or stream state | Reported result | Containment |
|---|---|---|
| `test` match | `school_control` observation | `none` |
| `benign` match | `inclusion_only` observation | `none` |
| `malicious` match | `suspicious` finding | endpoint policy required |
| Partial stream | `inconclusive`; coverage reported; whole hash unavailable | `none` unless a separately classified malicious reference matches |

Exit code `1` means evidence is incomplete. Callers must parse the JSON; it is not an alert or
a tooling failure. Version 1 signature databases lack a reference class and are rejected.

Blueware never changes endpoint state. For an analysis containing an explicitly malicious
reference or denylisted whole-file hash, `./blueware containment-plan analysis.json --pretty`
emits a reviewable `tcp_cutoff` request for an authorized EDR or host firewall. It does not
disable SIMD or execute the block. TCP cutoff does not cover UDP, local IPC, or other
transports. See [docs/CONTAINMENT_POLICY.md](docs/CONTAINMENT_POLICY.md).

```zsh
./dl stream simulate --data-chunks 5 --drop 4 > /tmp/four-of-five.jsonl
./dl stream analyze /tmp/four-of-five.jsonl --pretty

./dl stream simulate-rs --drop 0 --drop 5 > /tmp/redtail-rs.jsonl
./dl stream analyze /tmp/redtail-rs.jsonl --pretty

./dl stream compare-matrices --input samples/synthetic/null_payload_carrier.bin --pretty

./dl stream canonize reference.bin --reference-class test \
  --output /tmp/daybreak-signatures.json
./dl stream analyze /tmp/four-of-five.jsonl --signature-db /tmp/daybreak-signatures.json --pretty
```

A compiled, inert ARM64 Mach-O fixture is available under
[`samples/synthetic/`](samples/synthetic/README.md) for the canonical partial-stream
demonstration. It is never executed: `_main` returns `0`, its 16 callback slots are null, and
its exact 48-byte control has SHA-256
`5e0910a520129f61f1d8ecd9eb76df39a6b16b56e74c05f193716ea4dfde2623`.
Canonical references are explicitly classified as `test`, `benign`, or `malicious`; inclusion
alone never infers hostility.

For an approved EDR, syslog, or LogScale collector, emit payload-free normalized events with
`--format siem-json` or `--format syslog`. The analyzer writes to stdout and never sends data
or credentials itself.

See [docs/STREAM_ANALYZER.md](docs/STREAM_ANALYZER.md) for the event envelopes, recovery and
known-content rules, and the reason passive SIEM monitoring cannot hash plaintext inside
SSH/SCP or encrypted Canonizer records. See
[docs/FORMULA_ARRAY_AUDIT.md](docs/FORMULA_ARRAY_AUDIT.md) for the persisted `G0`–`G5`
codec rows, current matrix comparison, and the definition gaps that prevent a scientific
`C0`–`C5` control comparison today.

The publication-neutral project narrative, exact experiment results, claim ledger, launch
commands, limitations, and release checklist are in
[docs/DAYBREAK_BLUE_LAB_REPORT.md](docs/DAYBREAK_BLUE_LAB_REPORT.md).
The honest NIST CSF 2.0 mapping is in
[docs/NIST_CSF_MAPPING.md](docs/NIST_CSF_MAPPING.md); it describes a teaching lab, not
organizational compliance.

Project-owner artwork is preserved separately in
[docs/FUTURE_CONCEPT_ART.md](docs/FUTURE_CONCEPT_ART.md). It is concept art rather than an
implemented system or security claim.

## Local dashboard (optional)

The read-only Streamlit Observatory shows collection status, per-source disk use,
baseline metadata, hunt hits, and Horizontal draft Books. It does not start collectors,
run traces, or modify Vertical. The app binds to `127.0.0.1` and disables Streamlit
usage-stat collection.

```zsh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-ui.txt
export VERTICALDATA=~/VerticalData
.venv/bin/python -m streamlit run dashboard.py
```

Open the localhost URL printed by Streamlit. Stop it with Ctrl-C. The core `./dl`
commands do not require Streamlit.

## Design rules (non-negotiable)

- **proc_key = `host:pid:proc_start` is the only join key.** Never join on pid alone; if the
  start time is unknown the key is null and the event stays unattributed.
- **Zeek↔process attribution is `id-match`, never `confirmed`.** Zeek sees traffic, not
  processes; the tie to a process is a 5-tuple + time-window match against an osquery socket
  snapshot. A human confirms it, in Vertical, with live evidence (`lsof`).
- **Horizontal is honest by construction.** It may set link status only to `untested` or
  `id-match`; `confirmed`/`dropped` require a human basis and are rejected in code. Missing
  data becomes a `gap` node naming the manual step that closes it. No verdicts, no containment.
- **Raw logs and REAL case files never enter git.** `$VERTICALDATA` lives outside the repo;
  the pipeline refuses to write there if it detects a `.git` above it. Only rules, code,
  docs, and synthetic samples are published.
- **Rules are statistics, not ML.** Every hit is a SQL result you can read and re-derive, and
  it carries the raw lines behind it.

## Requirements

- macOS 13+ (eslogger), Zeek, osquery, the DuckDB CLI — see PHASE0.md.
- The core `./dl` collection, normalization, hunt, and case pipeline uses Python 3.9+
  standard-library code plus the DuckDB CLI; it requires no Python packages.
- Blueware is the exception: the optional `./blueware` application requires Python 3.10+
  and Cement from `requirements-cli.txt`. Its tests skip when Cement is unavailable.
- The optional local dashboard requires the packages in `requirements-ui.txt`.

## Status

Blueware, the pipeline, R1–R6, Horizontal, and the Book differ are built and covered by the
synthetic suite (`./dl test`). The collector is ready for local validation; no live capture or
baseline data is published with this repository. Horizontal output is verified to load in
the real Vertical CLI.
