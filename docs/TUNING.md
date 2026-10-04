# Tuning log

Thresholds live in `rules/params.json`. Change them there, never in the SQL. Record every
change here with the baseline it was measured against, so the portfolio shows the reasoning.

| Date | Param | Old | New | Why / evidence |
|------|-------|-----|-----|----------------|
| 2026-10-03 | (initial) | — | see params.json | First guesses from the plan; untuned. |

## Method
1. Build a baseline (`dl baseline --until <ts>`), then `dl hunt` over a quiet period.
2. Every hit on known-good activity is a false positive. Decide: raise a threshold, or
   allow-list the specific endpoint/binary (add to the baseline inputs), and note it here.
3. Re-run the fire/no-fire tests (`./dl test`) after any threshold change.

## Notes per rule
- R1 `r1_max_size_cv` 0.15 is strict; raise toward 0.3 if erasure-coded shards vary more.
- R2 `r2_min_bytes` 50 MB is the floor so small spikes stay quiet; the x3 multiplier needs a
  real p99, so R2 is only meaningful after the 7-day baseline.
- R3 expect NTP/update-checkers/push keepalives to fire first; allow-list them by endpoint.
- R4 CDN/anti-malware hashed labels are the usual FP; `dns_base_domain` is approximate and
  a last-two-label split is wrong for public suffixes such as `co.uk`. DNS events currently
  have no process attribution, so an R4 hit cannot identify the originating process.
- R5/R6 fire on every install/update; triage by signer/team_id and item owner, not by firing.

## Audit follow-ups (GPT, 2026-10-03) — validate against real data before publishing
- ATT&CK IDs in rule headers are **analytic hypotheses**, not verdicts. R1/R2 are limited
  TA0010 (Exfiltration) hypotheses; R3/R4 limited TA0011 (C2). None proves exfil or C2 — in
  particular T1048 (different protocol) vs T1041 (over existing C2) cannot be told apart from
  this telemetry. Say so in any write-up.
- R1: the planned "4+2 shard" emulation sends **6** endpoints, below the 8-endpoint threshold.
  Either raise the emulation to ≥8 endpoints or lower `r1_min_new_endpoints` for the test; the
  fixed 5-minute bucket can also split a real burst — consider a sliding window when tuning.
- R2: a path absent from baseline gets p99=0, so the floor alone fires. Require enough baseline
  hours before trusting the ×p99 test; it is a path-level analytic, now labelled as such, and
  reports process_instances + member_proc_keys instead of one arbitrary proc_key.
- R3: jitter is measured over the whole hunt period — use bounded windows + an endpoint/process
  allowlist; NTP, push, updaters and monitoring will match first.
- R4: use a public-suffix list for the base domain; require repeated behaviour before
  escalating; add a resolver or endpoint source that can attribute DNS activity to a
  `proc_key` before making any process claim.
- R5: triage trigger only; add signer/hash at hand-review, don't infer T1204/T1105 from network use.
- R6: classify LaunchAgent vs LaunchDaemon vs login item by plist location/owner; cover modern
  Login/Background Items with `sfltool dumpbtm` (manual).

## Containment note (from audit)
`kill -STOP` preserves state, but the later `kill -9` destroys volatile process evidence.
Capture process/socket/open-file (and any needed memory) state BEFORE the kill, and make the
order conditional on ongoing harm. Don't describe the sequence as universally evidence-preserving.
