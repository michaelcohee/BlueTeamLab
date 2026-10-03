# Common event schema

One JSON object per line in `norm/<session>.jsonl`. Every normalized event has every key
below; a value the source did not provide is `null`, never guessed. Written by `lab/normalize.py`.

## Identity and provenance (on every event)

| Field | Source | Meaning |
|-------|--------|---------|
| `ts` | event | event time, UTC ISO-8601 (`...Z`) — DuckDB reads it as TIMESTAMP |
| `capture_ts` | collector | collector receipt time. Set for osquery samples (the sample time). **null** for Zeek and eslogger — their streams don't carry a cheap receipt time, so it is not faked to equal `ts`. |
| `host` | session.json | hostname; the prefix of every proc_key |
| `source` | — | `zeek` · `osquery` · `eslogger` |
| `event_type` | — | `net_conn` · `dns_query` · `tls_hello` · `proc_exec` · `proc_seen` · `socket_seen` · `listen_port` · `persistence_item` |
| `raw_ref` | — | `{file, line, sha256, row?}` — the exact raw line (relative path, 1-based line, sha256 of the line; `row` = index into an osquery sample's `rows`). This is the evidence chain into Vertical. |

## Process identity

| Field | Meaning |
|-------|---------|
| `proc_key` | **`host:pid:proc_start` — the only join key.** `null` when start time unknown. |
| `pid`, `ppid` | raw ids (not join keys on their own) |
| `proc_start` | process start time, UTC ISO-8601, or null |
| `parent_proc_key` | parent's proc_key when the parent was in the same snapshot |
| `process_path`, `process_name`, `user`, `threads` | from osquery `processes` / eslogger |
| `signer`, `team_id`, `is_platform_binary`, `cdhash` | from eslogger exec (code-signing) |
| `sha256` | binary hash — **null until a human runs `shasum`** (never auto-collected) |
| `cmdline` | exec args, clipped |

## Network (Zeek conn/dns/ssl, osquery sockets)

| Field | Meaning |
|-------|---------|
| `src_ip/src_port/dst_ip/dst_port/proto` | 5-tuple (IPv6-mapped IPv4 unwrapped) |
| `direction` | `out` · `in` · `lan` · `loopback` · `listen` · `multicast` · `other`, from RFC-1918/loopback/CGNAT classification |
| `bytes_out`, `bytes_in`, `duration`, `conn_state`, `service`, `conn_uid` | from Zeek conn (bytes are oriented to the local host) |
| `dst_domain` | SNI, else the most recent DNS answer that resolved to `dst_ip` before `ts` |
| `tls_sni`, `tls_fp` | from Zeek ssl (`tls_fp` = JA4/JA3 if that Zeek package is installed, else null) |
| `dns_qtype`, `dns_rcode`, `dns_base_domain`, `dns_label_max_len`, `dns_label_entropy` | DNS query + features for R4 |

## Persistence (osquery launchd/startup_items)

| Field | Meaning |
|-------|---------|
| `item_kind` | `launchd` · `startup_item:<type>` |
| `item_label`, `item_path` | job label, plist path |
| `process_path`, `cmdline` | program the item runs |

## Attribution (network events only)

| Field | Meaning |
|-------|---------|
| `attribution` | `none` · `id-match` · `ambiguous`. A Zeek connection becomes `id-match` only when exactly one osquery socket snapshot matches on the **full tuple** — protocol, local port, remote ip, remote port, and (when the snapshot bound a concrete local IP) the local IP — within the time window (−5 s … +duration+65 s, since osquery samples every 60 s). More than one distinct process in the window → `ambiguous`, never guessed. |
| `attribution_ref` | `raw_ref` of the osquery socket row that produced the match |

**Never** promote `id-match` to `confirmed` in code. That is a human judgment, recorded in
Vertical with live evidence (`lsof -nP -i -a -p <pid>` at capture time).

## Capture window (baseline vs hunt)

`dl baseline --until T` learns "normal" from events **before T**; `dl hunt --since T` scores
events **at/after T**. The first 24-hour capture is a size/noise **pilot**, not a validated
baseline — an hourly p99 (R2) or day/week rhythm needs more. Do not point `baseline --until`
at the end of your only capture: the default hunt window would then be empty (and `dl hunt`
now warns loudly when it is). Build the baseline from one period and hunt a **disjoint later /
holdout capture**.

## Direction and known approximations (documented, not bugs)

- `direction` prefers Zeek's `local_orig`/`local_resp`, which Zeek sets because `lab.sh` passes
  it the private/loopback/link-local/ULA nets as `Site::local_nets`. Your Mac's own **global
  IPv6** prefix is not in that list, so an outbound global-IPv6 connection can still read as
  `other`. Add your delegated prefix to `LOCAL_NETS` in `collect/lab.sh` to fix it on your host.
- `dns_base_domain` = last two labels; wrong for `co.uk`-style public suffixes. Encrypted DNS
  (DoH/DoT) is invisible to Zeek DNS, so R4 only sees cleartext DNS.
- Attribution misses connections shorter than the gap between osquery samples.
- Zeek on `en0` cannot see loopback traffic; emulation uses `lab.sh start --lo0` + `--include-loopback`.
- `proc_key` start time is second-precision (osquery's `start_time`); a same-second PID reuse
  could in principle collide. A process that started before collection may be unattributed
  until an osquery `processes` sample catches it.
- Zeek `orig_bytes`/`resp_bytes` are payload estimates, not exact wire bytes.
