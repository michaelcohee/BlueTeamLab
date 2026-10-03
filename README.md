# detection-lab

An offline, single-Mac blue-team pipeline: collect local network and process telemetry,
hunt it with explainable SQL rules, and turn each hit into a [Vertical](https://github.com/)
case notebook — automatically (Horizontal) and then by hand, so the two can be compared.

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
  vbook.py      reader/writer for Vertical's format (byte-compatible)
rules/       R1–R6 as DuckDB SQL, one file each, with params.json
tests/       23 tests on synthetic data (no real logs committed)
docs/        SCHEMA, TUNING, PLAYBOOK
dl           entry point:  ./dl <command>
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

## Quick start (after Phase 0 in PHASE0.md)

```zsh
export VERTICALDATA=~/VerticalData
collect/lab.sh dryrun 5          # 5-minute capture, prints per-source size
collect/lab.sh start             # begin the 24 h baseline capture
# … later …
collect/lab.sh stop
./dl normalize
./dl baseline --until 2026-10-04T12:00:00Z
./dl hunt
./dl trace <hit_id> --kind SIMULATION
```

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
- Python 3.9+ standard library only (no pip installs). The DuckDB CLI does the SQL.

## Status

Phase 0 ready to run on the Mac. Pipeline, rules, Horizontal, and the Book differ are built
and tested (`./dl test`). Horizontal output is verified to load in the real Vertical CLI.
