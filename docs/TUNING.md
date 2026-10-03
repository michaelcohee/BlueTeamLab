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
- R4 CDN/anti-malware hashed labels are the usual FP; `dns_base_domain` is approximate.
- R5/R6 fire on every install/update; triage by signer/team_id and item owner, not by firing.
