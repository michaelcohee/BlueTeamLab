# Undercover Blueteamer Lab — Plan v1.0

Author: Claude (design) · Auditor: GPT · Owner: lab owner · Drafted 2026-10-03
Status: DRAFT for audit. Nothing in this plan changes Vertical's code yet.

> **Archived design draft.** This is the original v1.0 plan, kept for provenance.
> Decisions made since then live in `../../HANDOFF.md`; what was actually built and how it
> diverged (notably: V5 `vertical import` was **rejected** — the separate automated tracer
> "Horizontal" replaces it — and the §5/§8/§10 details were superseded by the audit
> follow-ups in `TUNING.md` and `SCHEMA.md`) is in `../README.md`. Read those for current state.


---

## 0. Goal

Build a single-Mac, offline blue-team lab that turns local network and process
telemetry into hunts, detections, and hand-built case files in **Vertical**
(the Offline SOC notebook), then publish the rules and write-ups as a portfolio.

**"Online" in this plan means:** Vertical gets fed real local TCP/IP and process
telemetry from this Mac. It does **not** mean internet access. No lab component
sends data off the machine. All collection is read-only.

### Success criteria

1. Collect one week of baseline telemetry within a 3 GB disk cap.
2. Six detections written, tested against emulated attacks, with false-positive notes.
3. At least three complete manual traces recorded as Vertical Books (two SIMULATION, one REAL if anything real turns up).
4. Public repo with rules, playbook, scrubbed sample data, and write-ups. No raw personal logs.
5. Skills map cleanly to SOC / detection-engineering job requirements (SC-200, BTL1 topics).

---

## 1. Architecture

Three tiers, all on the Mac. Vertical stays the analyst's notebook; it never
collects anything itself.

```
 ┌──────────────── Tier 1: COLLECT (read-only, separate from Vertical) ───────────────┐
 │ Zeek on en0 (metadata only) · osquery snapshots · eslogger (exec only)             │
 │ Unified log queries (log show) · manual Terminal captures (command catalog)        │
 └──────────────► ~/VerticalData/raw/YYYY-MM-DD/   (outside the repo, gzip-rotated)   │
                                   │
 ┌──────────────── Tier 2: NORMALIZE + HUNT ──────────────────────────────────────────┐
 │ normalize script → ~/VerticalData/norm/*.jsonl  (one common schema, §3)            │
 │ DuckDB (offline SQL) runs detections + ad-hoc hunts over the JSONL                 │
 │ Output: hits.jsonl  — each hit cites raw file + line + sha256                      │
 └────────────────────────────────────────────────────────────────────────────────────┘
                                   │  analyst decides a hit is worth tracing
 ┌──────────────── Tier 3: CASE (Vertical) ───────────────────────────────────────────┐
 │ New Book → paste/import evidence lines → trace PID/threads/parent chain →          │
 │ link states (assumed → id-match → confirmed/dropped) → containment record → close  │
 │ Qt viewer graph + hash-chained monitor journal                                     │
 └────────────────────────────────────────────────────────────────────────────────────┘
```

**Why DuckDB as the "SIEM query layer":** it is a single local binary, reads JSONL
directly, needs no server or network, and detections become plain SQL files that
are easy to review, version, and publish. (A `.duckdb` folder already exists in
the home directory, so it may already be installed.)

**Boundary rules (inherit Vertical's):**
- No component opens a listening port except loopback, and none makes outbound requests.
- Raw logs and REAL Books live in `~/VerticalData/` and are never committed.
- Vertical's binary stays free of shell execution, collection, and networking.

---

## 2. Data sources

| # | Source | What it records | How | Privilege | Volume |
|---|--------|-----------------|-----|-----------|--------|
| S1 | **Zeek** on `en0` | conn, dns, ssl, http, files metadata | `brew install zeek`; JSON output (`LogAscii::use_json=T`); **no pcap saved** | sudo (BPF) | Low for one laptop; measure day 1 |
| S2 | **osquery** | process ↔ socket ownership, listening ports, launchd items | scheduled queries: `processes`, `process_open_sockets`, `listening_ports`, `launchd` every 60 s; `--logger_rotate=true` with size/file caps | sudo for full visibility | Low |
| S3 | **eslogger** (built in, macOS 13+) | process executions with parent, path, signing info | `sudo eslogger exec` **only** — never all event types | root + Full Disk Access for the terminal app | Medium; exec-only keeps it small |
| S4 | **Unified log** | per-process log lines during a trace | `log show --last 10m --predicate 'processID == <pid>'` run by hand | user / sudo | On demand only |
| S5 | **Manual captures** | ps, lsof, threads, codesign, hashes, persistence | read-only command catalog (§7), output pasted into Vertical | mixed | On demand only |
| S6 | pf / LuLu logs (optional) | firewall allow/block decisions | export LuLu log or enable pflog | sudo | Low |

**Process attribution caveat:** Zeek sees traffic but not processes. Joining Zeek
connections to osquery socket snapshots by 5-tuple and time window is an
**approximate** match. In Vertical, that join is recorded as an `id-match` link,
never `confirmed`, until a second independent source (e.g. `lsof` at capture
time, eslogger exec record) agrees.

---

## 3. Common schema (normalized JSONL)

One JSON object per line. Unknown fields are `null`, never guessed.

| Field | Meaning |
|-------|---------|
| `ts` | Event time, UTC ISO-8601 |
| `capture_ts` | When the collector recorded it |
| `host` | Hostname |
| `source` | `zeek` · `osquery` · `eslogger` · `unifiedlog` · `manual` |
| `event_type` | `net_conn` · `dns_query` · `tls_hello` · `proc_exec` · `socket_snapshot` · `persistence_item` |
| `proc_key` | `host:pid:proc_start` — the only process identity used for joins |
| `pid`, `ppid`, `proc_start` | Raw values; `proc_start` may be null |
| `process_path`, `user`, `signer`, `team_id`, `sha256` | From eslogger / osquery / codesign |
| `src_ip`, `src_port`, `dst_ip`, `dst_port`, `proto`, `direction` | Network tuple |
| `bytes_out`, `bytes_in`, `duration` | From Zeek conn |
| `dst_domain`, `tls_sni` | From Zeek dns/ssl |
| `tls_fp` | JA4 / JA3 if the Zeek package is installed, else null |
| `raw_ref` | `{file, line, sha256}` of the raw source line — evidence chain into Vertical |

**Rule:** never join on `pid` alone. Joins use `proc_key`; if `proc_start` is
missing, the result is labelled `id-match` and carries a gap.

---

## 4. Disk budget (9.22 GB free at planning time)

Hard cap: **3 GB for all lab data**, leaving room for macOS swap and updates.

| Data | Retention | Notes |
|------|-----------|-------|
| Raw (Zeek, osquery, eslogger) | 7 days, gzip after 1 hour | Daily `du -sh ~/VerticalData/raw` for the first 3 days, then set real caps |
| Normalized JSONL | 30 days | Much smaller than raw |
| Hits | Keep | Tiny |
| Vertical Books + `.vertical-monitor` | Keep | Tiny; back up separately |

Before Phase 1: run `cargo clean` in DarkRock/ROS, clear Xcode DerivedData, and
check `~/Library/Caches`. Optional: put `~/VerticalData` on an external SSD.

---

## 5. Detections v1 (DuckDB SQL, one file per rule)

| ID | Name | Logic (summary) | ATT&CK |
|----|------|-----------------|--------|
| R1 | **Shard fan-out** | One `proc_key` sends to ≥ 8 never-before-seen destinations in 5 min with similar chunk sizes (coefficient of variation < 0.15) | T1030 Data Transfer Size Limits, T1041 |
| R2 | Outbound volume spike | Per-process `bytes_out` in 1 h > baseline p99 × 3 | T1048 Exfiltration Over Alternative Protocol |
| R3 | Beaconing | ≥ 10 connections to one destination with interval jitter < 10 % | T1071 Application Layer Protocol |
| R4 | DNS tunneling | Query names > 50 chars, or high-entropy labels, or > 100 queries/min to one domain | T1071.004 DNS |
| R5 | First-seen network binary | A `sha256` / `process_path` makes its first outbound connection since baseline | T1204, T1105 |
| R6 | New persistence item | New LaunchAgent / LaunchDaemon / login item since baseline | T1543.001, T1543.004 |

Example — R1 (draft; paths and thresholds to be tuned on real baseline):

```sql
-- rules/R1_shard_fanout.sql
WITH conns AS (
  SELECT proc_key, process_path, dst_ip, bytes_out, ts,
         time_bucket(INTERVAL 5 MINUTE, ts::TIMESTAMP) AS win
  FROM read_json_auto('/path/outside/repo/VerticalData/norm/net-*.jsonl')
  WHERE event_type = 'net_conn' AND direction = 'out'
    AND dst_ip NOT IN (SELECT dst_ip FROM read_json_auto('/path/outside/repo/VerticalData/baseline/dsts.jsonl'))
)
SELECT proc_key, process_path, win,
       count(DISTINCT dst_ip)                          AS new_dsts,
       sum(bytes_out)                                  AS total_out,
       stddev_pop(bytes_out) / nullif(avg(bytes_out),0) AS size_cv
FROM conns
GROUP BY ALL
HAVING new_dsts >= 8 AND size_cv < 0.15;
```

Every rule file carries a header: hypothesis, data sources, ATT&CK ID, expected
false positives, test that should fire it, test that should not.

---

## 6. Manual trace playbook (how a hit becomes a Vertical Book)

| Step | Action | Vertical node / link |
|------|--------|----------------------|
| 1 | **Trigger** — note the hit or the thing you noticed, with time | `event` |
| 2 | **Preserve** — paste the exact hit line(s) with `raw_ref` | `observation` (source = file + line + sha256) |
| 3 | **Identify** — `ps -o pid,ppid,lstart,user,comm -p <pid>`; build `proc_key` | `process` with ID `proc-<pid>-<YYYYMMDDTHHMMSS>` |
| 4 | **Threads** — `ps -M <pid>`; note thread count/state | `observation` under the process |
| 5 | **Parent chain** — walk `ppid` up to launchd; one process node per hop | `process` nodes + `spawned` links (`id-match` until start times agree) |
| 6 | **Binary** — `codesign -dvv`, `spctl --assess -vv`, `shasum -a 256` on the path | `observation`s; unsigned/ad-hoc signing → `note` flag |
| 7 | **Network** — `lsof -nP -i -a -p <pid>` at capture time | `observation`; link hit → process becomes `confirmed` only if tuple + proc_key agree (basis: "direct evidence") |
| 8 | **Persistence** — check LaunchAgents/Daemons, `sudo sfltool dumpbtm` | `observation` / `gap` |
| 9 | **Unknowns** — anything not yet proven | `gap` (what evidence would close it) |
| 10 | **Verdict** — benign / suspicious / malicious, with reason | `note` |
| 11 | **Contain (by hand)** — see below | `command` node |
| 12 | **Close** — run `vertical_verify`, export monitoring report | final `note` |

**Containment order (evidence first):**
1. `kill -STOP <pid>` — suspend; keeps memory and state for inspection.
2. Block network for that binary in LuLu (or a pf rule) instead of pulling Wi-Fi when possible.
3. Record hashes, then `kill -9 <pid>`.
4. Move the binary to `~/Quarantine/<case-id>/`, `chmod 000`, keep the original path in the node.
5. Disable its persistence item (move the plist into the same quarantine folder).
6. Write the **undo steps** in the `command` node text. A containment without an undo is incomplete.

---

## 7. Read-only command catalog (Workflow step 3)

All commands read state; none modify it. Containment commands are listed in §6,
not here.

| Purpose | Command | Notes |
|---------|---------|-------|
| Process list with start time | `ps -axo pid,ppid,lstart,user,comm` | `lstart` gives the start time for `proc_key` |
| Threads of a process | `ps -M <pid>` | macOS thread view |
| Open network sockets | `lsof -nP -i` / `lsof -nP -i -a -p <pid>` | `-nP` avoids DNS/port lookups |
| Listening ports | `lsof -nP -iTCP -sTCP:LISTEN` | |
| Live per-process traffic | `nettop -L 1 -P` | one sample, CSV-ish output |
| Process log lines | `log show --last 10m --predicate 'processID == <pid>'` | |
| Code signature | `codesign -dvv <path>` | Team ID, authority chain |
| Gatekeeper assessment | `spctl --assess -vv <path>` | |
| File hash | `shasum -a 256 <path>` | Hash ≠ verdict (see CASE_FORMAT) |
| Quarantine xattr | `xattr -l <path>` | Download origin hints |
| Persistence | `ls -la ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons`; `sudo sfltool dumpbtm` | |
| launchd job detail | `launchctl print gui/$(id -u)/<label>` | |

Each catalog entry should record macOS version tested, privilege, and output sample.

---

## 8. Vertical changes (proposed roadmap — needs lab-owner approval)

| # | Change | Why | Boundary impact |
|---|--------|-----|-----------------|
| V1 | Fix doc drift: CASE_FORMAT says XML and lists "anomaly"; code uses `VERTICAL 1` and six kinds | Docs must match code before audit | None |
| V2 | **`VERTICAL 2` format** with optional structured fields on nodes: `host`, `pid`, `proc_start`, `observed_at`, `capture_ts`, `sha256` | Lets the tool enforce "never merge on PID alone" | None |
| V3 | Link history: author, time, reason per status change | Promised in CASE_FORMAT, not implemented | None |
| V4 | New kinds: `anomaly`, `action` (containment) | Playbook steps 9 and 11 | None |
| V5 | **`vertical import`** — read one line from a user-named local file into an observation node (source = path, line, sha256, import time; text = exact line) | Removes copy-paste errors; keeps the evidence chain | **Changes the boundary:** workflow.md currently says transfer is manual. Still no collection, shell, or network — user-selected file read only, same as the planned file-hash action |
| V6 | Codec tests via `ctest` (round-trip, rejection cases) | Makes format changes safe | None |
| V7 | Small, frequent commits from here on | Shows progress on GitHub | None |

Recommendation: do V1, V6 first, then V2–V4, and decide V5 explicitly.

---

## 9. Adversary emulation (attack yourself, safely)

Rules: SIMULATION Books only; sinks must be machines you own; snapshot or back
up before each run; nothing leaves the Mac or your LAN.

| Test | Tool | Should fire |
|------|------|-------------|
| Shard spray | DarkRock RedTail-X 4+2 encodes a dummy file; send 6 shards to loopback ports or the local QEMU VM (`ROS-QEMU-active`, if it is a VM) | R1, maybe R2 |
| Beacon | Small loop curling a local HTTP server every 30 s ± 1 s | R3 |
| DNS tunnel | Long random subdomains against a local resolver / `dig @127.0.0.1` | R4 |
| New binary | Build and run an unsigned hello-world that connects to localhost | R5 |
| Persistence | Atomic Red Team macOS LaunchAgent test (T1543.001), then clean up | R6 |
| Shell/scripting | Atomic Red Team T1059.004 (Unix shell) | eslogger exec trail for a trace |

Record each run as: what was run, expected rule, fired yes/no, false positives,
tuning change.

---

## 10. Phases and exit criteria

| Phase | Work | Done when |
|-------|------|-----------|
| **0 · Prep** | Free disk; install Zeek, osquery, DuckDB; grant Full Disk Access to the terminal for eslogger; create `~/VerticalData/` | ≥ 9 GB free; each tool runs once |
| **1 · Collect** | Start S1–S3 with rotation; write collector start/stop script | 24 h of data, size measured |
| **2 · Normalize + baseline** | Normalizer to §3 schema; build baseline tables (known dsts, binaries, persistence) | 7 days baseline; schema validated |
| **3 · Detect** | Write R1–R6 as SQL with headers | Each rule runs clean on baseline (or FP noted) |
| **4 · Emulate** | Run §9 tests | Each rule has a fire / no-fire result |
| **5 · Trace** | Turn hits into Vertical Books using §6; apply V1/V6 (+ others if approved) | 3 complete Books; `vertical_verify` passes |
| **6 · Publish** | Public repo: rules, playbook, catalog, scrubbed samples, write-ups | GitHub profile pins it |

---

## 11. GPT audit checklist

1. Coverage gaps vs ATT&CK Exfiltration (TA0010) and Command and Control (TA0011).
2. False-positive risk and threshold sanity for R1–R6.
3. Missing schema fields; correctness of the `proc_key` join rule.
4. macOS accuracy: eslogger permissions, Zeek on Apple silicon, osquery table availability, `sfltool` on current macOS.
5. Whether V5 (`vertical import`) is consistent with Vertical's offline boundary.
6. Containment order — anything that destroys evidence too early.
7. Privacy: anything that could leak raw logs into the repo.

---

## 12. Open decisions for the lab owner

1. Approve V5 (`vertical import`) or keep transfer fully manual?
2. Run Zeek continuously, or only during hunt sessions (saves disk)?
3. External SSD for `~/VerticalData`, or stay on internal disk?
4. Publish as a new repo (e.g. `detection-lab`) with Vertical linked, or publish Vertical itself?

## 13. Limits

- Single host: no lateral movement, no domain controller, no real network sensor.
- Process attribution for network events is approximate (see §2).
- The monitor hash chain detects edits but is not tamper-proof (see MONITORING.md).
- Detections tuned on one person's laptop will not transfer unchanged to an enterprise.
