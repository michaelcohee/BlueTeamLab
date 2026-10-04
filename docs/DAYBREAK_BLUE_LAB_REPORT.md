# Daybreak Blue: Offline Detection and Stream Integrity Lab

**Document status:** publication-neutral technical report
**Release decision:** private portfolio or public repository, to be decided
**Last verified:** 2026-10-04
**Current automated test result:** 77 tests passing

## Abstract

Daybreak Blue is an offline defensive-security lab for collecting endpoint and network
metadata, normalizing it into an evidence-preserving schema, running explainable SQL
detections, and drafting case graphs for human review. A second lab track studies partial
message evidence: explicit chunk envelopes, 4+2 GF(256) reconstruction, known-content
inclusion, and the boundary between an observation and a containment decision.

The project is designed as a school and portfolio environment. It does not claim to be an
EDR, a production SIEM, a passive SSH decrypter, or a general malware classifier. Synthetic
tests validate the current code. A real five-minute macOS sizing capture and the proposed
24-hour capture have not yet been recorded as completed evidence.

## 1. Goals

The lab has five practical goals:

1. Collect useful macOS security metadata without uploading it to a service.
2. Preserve source attribution so every detection can be traced to raw evidence.
3. Express detections as readable SQL with documented thresholds and false positives.
4. Keep automated case drafts honest about uncertainty and require a human for confirmation.
5. Demonstrate exact and partial stream analysis without inventing missing bytes or
   treating a school control as malicious.

## 2. Current claim ledger

| Capability | State | Evidence boundary |
|---|---|---|
| Normalization, baselining, R1–R6 hunts | Implemented and synthetically tested | No completed live baseline is claimed |
| Process identity and network attribution | Implemented and tested | Attribution remains `id-match` until independently confirmed |
| Horizontal case drafting and Book comparison | Implemented and tested | Automated Books cannot claim `confirmed` or containment |
| Read-only Streamlit Observatory | Implemented and locally tested | It reads lab state and does not start collectors or containment |
| Collector health and 3 GiB disk guard | Implemented | Five-minute size report still required before a 24-hour run |
| Ordinary partial-stream analysis | Implemented and tested | Missing data prevents a whole-stream hash |
| GF(256) 4+2 reconstruction | Implemented and tested | Claims cover the two defined matrices and up to two lost shares |
| Classified known-content matching | Implemented and tested | Inclusion is not hostility; policy depends on reference class |
| Passive TCP sequence reassembly | Not implemented | Current experiments consume explicit message envelopes |
| SCP/SSH plaintext inspection | Not implemented | Requires authorized endpoint or post-decryption telemetry |
| Linux x86-64 IDT/GDT scanner | Implemented, live validation pending | Requires readable symbols and `/proc/kcore` |
| Windows x64 IDT parser | Experimental, unvalidated | GDT parsing remains incomplete |
| Apple-silicon IDT scanner | Not applicable | ARM64 uses exception vectors rather than x86 IDT/GDT |

## 3. Architecture

```text
Zeek + osquery + eslogger
          |
          | raw session files outside the repository
          v
     dl normalize
          |
          | common JSONL + raw_ref evidence pointers
          v
     dl baseline  ---> baseline datasets
          |
          v
       dl hunt    ---> R1-R6 hits with cited evidence
          |
          v
       dl trace   ---> [AUTO] case Book
          |                 |
          |                 v
          +-----------> dl diff <--- human Book

Explicit message envelopes
          |
          v
   dl stream analyze
          |
          +--> coverage and evidence gaps
          +--> XOR or GF(256) reconstruction when possible
          +--> manifest/share hash verification
          +--> classified known-content observations/findings
          +--> payload-free SIEM JSON or syslog
```

Core pipeline code uses Python's standard library and the DuckDB command-line client.
Streamlit is an optional local dashboard dependency. `blueware` is a separate Cement 3
command application for running the complete message-stream analyzer in a terminal.

## 4. Evidence and identity rules

### 4.1 Process identity

The only process join key is:

```text
proc_key = host:pid:proc_start
```

PID alone is insufficient because operating systems reuse PIDs. If start time is unknown,
the normalized event remains unattributed instead of guessing. Path-level rules may group
multiple process instances, but they set `proc_key` only when exactly one instance is
responsible and otherwise retain the member keys in metrics.

### 4.2 Network-to-process attribution

Zeek observes traffic and osquery observes socket ownership. A matching five-tuple and
time window is recorded as `id-match`, not `confirmed`. Direct live evidence such as a
matching `lsof` observation is required for a human upgrade.

### 4.3 Source traceability

Normalized events carry a `raw_ref` containing the source file, line, and source-line
SHA-256. Hits retain bounded lists of these references. Raw logs and REAL case files live
under `$VERTICALDATA`, outside the source repository.

### 4.4 Horizontal honesty rules

The automated tracer may emit only `untested` and `id-match` relationships. Code and tests
reject automated `confirmed` and `dropped` states. Unknown information becomes a `gap` node
that states what evidence would resolve it. Horizontal does not issue verdicts, execute
commands, or perform containment.

## 5. Collection layer

| Source | Evidence | Notes |
|---|---|---|
| Zeek | Connections, DNS, TLS and protocol metadata | JSON logs; no packet capture is retained |
| osquery | Processes, sockets, listening ports, launchd and startup items | Snapshot sampler with explicit query failure reporting |
| eslogger | Process execution events | macOS 13+; Terminal requires Full Disk Access |
| Manual tools | `ps`, `lsof`, `codesign`, `spctl`, hashes, persistence inspection | Used during human trace work |

Collector safety includes:

- startup preflight for required osquery tables and columns;
- a short eslogger permission probe;
- launch health checks for every required collector;
- hourly Zeek rotation and compression of completed logs;
- a 60-second guard interval by default;
- predictive stopping before a 3 GiB data cap or 4 GiB free-space floor;
- an optional timed stop using `collect/lab.sh start --hours N`;
- explicit `UNHEALTHY`, `LIMIT_HIT`, and `MAX_TIME_DONE` session markers.

The live sizing gate remains open: run the five-minute capture, inspect every source and
stderr file, and project the larger measured rate to 24 hours before starting a long run.

## 6. Normalized schema

Each JSONL record carries UTC event time, source, event type, host, raw process fields,
`proc_key`, network tuple fields, byte counts, DNS/TLS metadata, and `raw_ref`. Unknown
values are `null`; collection time is not fabricated from event time.

Important limits:

- Zeek byte counts are protocol metadata estimates rather than exact wire captures.
- Zeek cannot directly identify a process.
- osquery snapshots can miss short-lived sockets between samples.
- `capture_ts` remains null for sources that do not expose a trustworthy receipt time.
- DNS base-domain parsing is approximate and is not a full public-suffix implementation.

See [SCHEMA.md](SCHEMA.md) for the field-level contract.

## 7. Detection rules

The rules are deterministic SQL, not machine learning. Current defaults remain tuning
starting points until a real baseline is collected.

| Rule | Detection hypothesis | Current threshold | Expected false positives |
|---|---|---|---|
| R1 Shard fan-out | Similar-sized outbound chunks reach many new endpoints | 8 endpoints in 5 min, each at least 1 KiB, size CV below 0.15 | P2P, backup clients, CDNs, update systems |
| R2 Volume spike | One path sends far above its hourly baseline | More than 50 MiB and more than 3× baseline p99 | Sync, diagnostics, video calls, network backup |
| R3 Beaconing | Repeated connections have unusually regular intervals | At least 10 connections, mean interval at least 10 s, jitter below 0.10 | NTP, push keepalives, monitors, update checks |
| R4 DNS tunnel indicators | Queries are long, random-looking, or unusually frequent | Query over 50 chars; or label at least 20 chars with entropy at least 3.5; or over 100/min | CDN hashes, DKIM/SPF, security and telemetry services |
| R5 First-seen network binary | A new process path begins using the network | Absent from the network-binary baseline | Installs, updates, developer builds, Homebrew changes |
| R6 New persistence item | A launchd/startup item is absent from baseline | New tuple of kind, label, path and program | Application installs, helpers, OS updates |

R1 and R3 can group unattributed connections per host, which is weaker evidence. R2 is a
path-level analytic and may cover several process instances. R4 has no process attribution.
R5 is a triage trigger rather than proof of execution or ingress. R6 does not automatically
collect modern Background Task Management state; `sfltool dumpbtm` remains a manual step.

Threshold changes belong in [TUNING.md](TUNING.md) with the before/after value, dataset,
reason, and observed false-positive effect.

## 8. Case workflow

A normal investigation flow is:

1. Preserve the hit and its `raw_ref` evidence.
2. Resolve the process identity with PID, parent PID, start time, user and path.
3. Walk the parent chain and record uncertainty.
4. Inspect signing, Gatekeeper state, file hash and quarantine attributes.
5. Compare the live socket tuple with the attributed network event.
6. Check launchd, startup and Background Task Management persistence.
7. Record gaps before forming a verdict.
8. If action is authorized, preserve volatile evidence before terminating a process.
9. Record containment and its undo procedure in the human case.
10. Compare the human Book with the automated draft using `dl diff`.

The detailed manual procedure is in [PLAYBOOK.md](PLAYBOOK.md).

## 9. Local Observatory

The optional Streamlit interface displays:

- collector state and session health;
- data-cap consumption and per-source sizes;
- collector stderr and guard-log summaries;
- baseline metadata;
- detection hits;
- read-only Horizontal case drafts.

It binds to `127.0.0.1`, disables Streamlit usage statistics, and does not start collection,
run a trace, edit a Book, or perform containment.

## 10. Partial-stream integrity lab

### 10.1 Ordinary chunks

An explicit manifest declares the expected chunk count and optional whole SHA-256. Each
data event carries its index, payload, and chunk SHA-256. Four observed chunks from a
five-chunk stream produce 80% coverage and an `inconclusive` result. Unknown bytes are not
guessed and the whole-stream hash remains unavailable.

XOR parity is included as a teaching example for one missing chunk. It is not presented as
production erasure coding or authenticated transport.

### 10.2 GF(256) 4+2 reconstruction

The 4+2 experiment splits a payload into four systematic data shares and two parity shares.
Any four valid shares can reconstruct the original bytes for either tested matrix.

Every manifest persists and validates:

- GF(256) field polynomial `0x11d`;
- all six generator rows `G0` through `G5`;
- canonical formula SHA-256;
- six share SHA-256 values;
- original length and whole SHA-256;
- `zero_elimination: false`.

The first four rows are the identity matrix. The two defined variants are:

| Variant | G4 | G5 | Formula SHA-256 |
|---|---|---|---|
| `daybreak-powers` | `[1,1,1,1]` | `[1,2,4,8]` | `3e912b2fb1126e5ed09beaa2b4042167741087f1db80da64f8df2ca0d9198a36` |
| `darkrock-custom` | `[1,1,1,1]` | `[1,2,3,4]` | `c36eb872df7374faf4b049787d100dedfa2ac1a6649501b0f31ce1f446b05c4d` |

`G0` through `G5` are codec rows. They are separate from experimental `C0` through `C5`
control arms. SPF routing, entropy-based representation selection, witness escalation and
GF(256) share algebra are also separate mechanisms.

### 10.3 Rebuild experiment

Four inert inputs were compared. Every variant recovered all six single-share loss cases
and all fifteen double-share loss cases exactly.

| Input | Bytes | Input SHA-256 | Different parity bytes | Different parity bits | Recovery |
|---|---:|---|---:|---:|---|
| ARM64 Mach-O fixture | 16,936 | `8598bb3c7af0ded5dd012c5042259f150782f05b104bd82902821a907739cd20` | 339/8,468 | 1,273 | Both matrices: 6/6 and 15/15 |
| C source | 985 | `ddd261aa55143612cd0f2039006cb24974f4cbb10d024fce886d60db9a0012e5` | 247/494 | 998 | Both matrices: 6/6 and 15/15 |
| Extracted constant structure | 184 | `000ca5f3414ba1bc27dd59cad8586e0ced44175f2bcaff09e3e67c85200d01d5` | 40/92 | 206 | Both matrices: 6/6 and 15/15 |
| Padded ASCII school control | 48 | `5e0910a520129f61f1d8ecd9eb76df39a6b16b56e74c05f193716ea4dfde2623` | 12/24 | 54 | Both matrices: 6/6 and 15/15 |

The two variants share G4 and differ at G5. For the compact ASCII control, the shared half
of the parity is unchanged and the other half changes. The full Mach-O contains large
zero-filled regions, which explains its smaller parity delta. These results establish the
tested 4+2 recovery contract for the named inputs. They do not establish behavior for
other codes, more than two missing shares, corrupted manifests, or a live distributed node
set.

### 10.4 School-control known-content test

The committed [school control](../samples/synthetic/school_control_ascii.bin) is exactly 48
bytes:

```text
MALWARE PAYLOAD CARRIER HERE\0\0\0\0
NULL PAYLOAD\0\0\0\0
```

Static inspection of the ARM64 fixture showed `_main` returning zero, sixteen NULL callback
slots, and the control bytes in a constant structure. The fixture was not executed during
analysis.

S5 located all 48 control bytes at file offset `0x408` inside a deliberately incomplete
7-of-8 envelope:

| Field | Result |
|---|---|
| Transport coverage | 87.5% |
| Matched bytes | 48 |
| Reference class | `test` |
| Observation | `known_content_inclusion` |
| Disposition | `school_control` |
| Status | `inconclusive` |
| Containment | `none` |
| Whole-file SHA-256 | unavailable |

The match establishes inclusion of the reference bytes in observed plaintext message data.
It does not establish that the entire file was present, transferred, executed, or malicious.

### 10.5 Reference classification policy

Canonical-signature schema version 2 requires an explicit reference class:

| Reference class | S5 behavior | Containment field |
|---|---|---|
| `test` | Informational observation with `school_control` disposition | `none` |
| `benign` | Informational observation with `inclusion_only` disposition | `none` |
| `malicious` | High-severity finding and `suspicious` status | `endpoint policy required` |

The default for `canonize` is `test`. Version 1 databases must be rebuilt because they do
not contain a class. The current loader rejects them as unsupported; it does not infer a
class or preserve the former every-hit-is-hostile behavior. Rebuild rather than shim. A
reference match supplies evidence of inclusion; the stored policy class determines how
that evidence is handled.

## 11. Transport, SIEM and EDR boundaries

The stream analyzer reads explicit JSONL message envelopes. It currently does not capture
packets, track TCP sequence numbers, reorder segments, resolve retransmissions, or recover
plaintext from SSH/TLS.

SCP travels inside encrypted SSH. A passive sensor can observe endpoints, timing, byte
counts and protocol metadata but cannot compute the transferred plaintext hash. A deployable
defensive pattern is:

1. Network telemetry records the encrypted flow.
2. Endpoint telemetry records the `sshd`, `scp` or `sftp` process and destination write.
3. EDR hashes the completed file and evaluates an approved policy.
4. SIEM correlates the flow, process, path, hash verdict and later execution.
5. Endpoint policy performs any authorized block or quarantine action.

The analyzer can emit payload-free SIEM JSON or RFC 5424-style syslog. A school-control
match emits `event.kind: event`, an informational observation, and `containment: none`.
Incomplete evidence can still make event severity `warning` while remaining a non-alert.

### 11.1 Exit-status contract for automation

Callers must evaluate the structured result as well as the process exit status:

| Exit code | Meaning |
|---:|---|
| `0` | Every reported stream is complete/recovered and has no suspicious finding |
| `1` | At least one stream is inconclusive because evidence is incomplete or invalid |
| `2` | Usage, input, database, file or serialization error prevented normal analysis |
| `3` | At least one stream contains a suspicious finding |

Code `1` is an evidence-gap signal. It does not mean the analyzer crashed and must not be
translated into an incident. Integrations should retain and parse stdout even when the
process exits nonzero, then route on `stream.status`, `findings`, `observations`, `gaps` and
`containment`. Code `2`, missing output, or invalid JSON is the tooling-failure path.

## 12. Experimental IDT/GDT add-on

The `idtscan/` directory contains separate read-only experiments for x86-64 descriptor
integrity. The safe `0x1f` probe analyzes scanner JSONL and never invokes a CPU vector.

| Platform | Status |
|---|---|
| Linux x86-64 | Scanner built; live host validation pending |
| Windows x64 | Host checks and debugger transcript parser built; not validated; GDT parser incomplete |
| macOS Apple silicon | No x86 IDT/GDT backend; use native platform telemetry instead |
| macOS Intel | No backend implemented |

A present reserved vector is not automatically a rootkit finding. Handler ownership,
descriptor privilege, per-CPU consistency and a known-good semantic baseline are required.
KASLR address changes alone are ignored by the cross-platform probe.

See [idtscan/README.md](../idtscan/README.md) and
[SAFE_INSPECTION.md](../idtscan/SAFE_INSPECTION.md).

## 13. Reproducing the current results

### 13.1 Requirements

```zsh
brew install zeek duckdb jq
brew install --cask osquery
```

For live collection, grant the chosen Terminal application Full Disk Access, quit it, and
open it again. Create the external data directory:

```zsh
mkdir -p "$HOME/VerticalData"
chmod 700 "$HOME/VerticalData"
export VERTICALDATA="$HOME/VerticalData"
```

The standalone Blueware CLI requires Python 3.10+ and Cement 3.0.16:

```zsh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-cli.txt
./blueware --help
```

### 13.2 Automated suite

```zsh
cd "$HOME/BlueteamLab/detection-lab"
./dl test
```

Verified result on 2026-10-04: 77 tests passed.

### 13.3 Matrix comparison

```zsh
./dl stream compare-matrices \
  --input samples/synthetic/null_payload_carrier.bin \
  --pretty
```

The same experiment is available through Cement:

```zsh
./blueware compare-matrices --pretty
```

### 13.4 School-control inclusion

```zsh
./dl stream canonize samples/synthetic/school_control_ascii.bin \
  --reference-class test \
  --window-bytes 16 \
  --min-match-bytes 32 \
  --output /tmp/daybreak-school-control.json

./dl stream envelope samples/synthetic/null_payload_carrier.bin \
  --data-chunks 8 \
  --drop 7 \
  --stream-id binary-ascii-control \
  > /tmp/daybreak-school-control-partial.jsonl

./dl stream analyze /tmp/daybreak-school-control-partial.jsonl \
  --signature-db /tmp/daybreak-school-control.json \
  --pretty
```

The final command exits with code `1` because the evidence is incomplete. That exit code is
the expected gap signal, not an alert or test failure. Automation must parse the emitted
JSON instead of treating every nonzero exit as the same condition.

The complete sequence is also exposed as one command:

```zsh
./blueware school-control --format siem-json --pretty
```

### 13.5 Local dashboard

```zsh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-ui.txt
export VERTICALDATA="$HOME/VerticalData"
.venv/bin/python -m streamlit run dashboard.py
```

Open `http://127.0.0.1:8501` and stop the server with Ctrl-C.

### 13.6 Live sizing gate

```zsh
export VERTICALDATA="$HOME/VerticalData"
collect/lab.sh dryrun 5
```

Record uncompressed active and compressed stopped bytes for Zeek, eslogger and every
osquery source. Inspect stderr and guard state. Do not claim the 24-hour gate passed until
the projected raw plus normalized data fits below 3 GiB with headroom.

### 13.7 Timed collection and hunt

After the sizing gate passes:

```zsh
collect/lab.sh start --hours 24
collect/lab.sh status

# After the guard reaches the timer:
collect/lab.sh stop
./dl normalize
./dl baseline --until <UTC_TIMESTAMP>
./dl hunt --since <LATER_UTC_TIMESTAMP>
```

Baseline and hunt windows should be disjoint. Using the same events for both weakens the
evaluation and can leave no holdout events for hunting.

## 14. Test coverage

The 77-test suite currently covers:

- exact process-tuple attribution and multi-instance handling;
- path safety and repository boundary enforcement;
- R1–R6 fire/no-fire synthetic cases;
- baseline suppression and hit-to-Book flow;
- Book honesty, comparison and validation rules;
- safe IDT `0x1f` semantic-baseline analysis;
- ordinary incomplete streams, XOR recovery and hash failures;
- every one-share and two-share loss pattern for both GF(256) matrices;
- preservation of zero bytes and tail padding boundaries;
- formula persistence, validation and stale-hash rejection;
- classified malicious, benign and school-control S5 policy behavior;
- the exact 48-byte control match at `0x408` with no containment;
- payload-free SIEM and syslog serialization.
- the Cement command tree, exit codes, static control inspection, both policy branches,
  GF(256) recovery, and version 1 database rejection.

Synthetic tests demonstrate code behavior. They do not replace live validation of collector
permissions, operating-system table availability, real rule noise or cross-platform kernel
scanner output.

## 15. Known limitations and next work

1. Run and document the five-minute macOS capture with per-source byte counts.
2. Start a 24-hour capture only if the projection remains below the disk cap.
3. Create disjoint baseline and holdout periods, then measure R1–R6 false positives.
4. Add passive TCP sequence/retransmission reassembly only with an explicit capture and
   authorization model; keep encrypted application data opaque.
5. Add per-reference metadata management if one database must contain mixed classes created
   in a single command.
6. Validate Linux IDT/GDT output on an authorized x86-64 host.
7. Validate the Windows parser against an authorized live-kernel dump and implement GDT
   transcript parsing.
8. Add automated release scrubbing for hostnames, usernames and absolute paths.
9. Decide whether the experimental IDT add-on belongs in the same public repository.

Undefined `C2` through `C5` formulas remain undefined. They require versioned equations,
parameters and deterministic input schemas before a scientific comparison can be reported.

## 16. Publication checklist

Before publishing this report or repository:

- [ ] Decide the project name, license and third-party attribution language.
- [ ] Replace personal usernames, hostnames and absolute paths with neutral examples.
- [ ] Confirm that raw logs, REAL Books, tokens, dumps and kernel addresses are absent.
- [ ] Keep only synthetic samples whose source and behavior can be audited.
- [ ] Mark unvalidated Linux/Windows scanner work prominently.
- [ ] Add the measured five-minute size table only after the live run.
- [ ] Add real rule-tuning results only from a scrubbed dataset.
- [ ] Verify every command from a clean checkout.
- [ ] Review trademark and naming choices before calling any component compatible with an
      external project.

## 17. Repository map

```text
collect/                 macOS collector controller, sampler and disk guard
dashboard.py             read-only local Observatory
lab/normalize.py         raw telemetry to common JSONL
lab/hunt.py              baseline and SQL rule runner
lab/horizontal.py        automated draft case tracer
lab/bookdiff.py          automated-versus-human Book comparison
lab/stream.py            chunk, GF(256), canonical-content and SIEM logic
lab/blueware_cli.py      Cement command application for stream analysis
lab/vbook.py             case Book reader/writer
blueware                 dependency-aware CLI launcher
rules/R1...R6.sql        explainable detections
rules/params.json        tunable thresholds
samples/synthetic/       inert source-visible fixtures
idtscan/                 experimental cross-platform descriptor checks
tests/                   synthetic unit and integration tests
docs/                    schema, tuning, playbook and technical evidence
```

## 18. Supporting documents

- [Schema](SCHEMA.md)
- [Tuning log](TUNING.md)
- [Manual playbook](PLAYBOOK.md)
- [Stream analyzer](STREAM_ANALYZER.md)
- [Blueware Cement CLI](BLUEWARE_CLI.md)
- [Formula array audit](FORMULA_ARRAY_AUDIT.md)
- [RedTail-X evidence boundary](REDTAIL_X_EVIDENCE.md)
- [Archived original lab plan](LAB_PLAN.md)

---

Daybreak Blue reports what the available evidence supports. Missing data remains a gap,
automated correlation remains weaker than human confirmation, a byte match remains separate
from a malware verdict, and containment remains an explicit policy decision.
