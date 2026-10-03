-- id: R3
-- name: Beaconing
-- attack: T1071 Application Layer Protocol
-- tactic: TA0011 Command and Control
-- sources: zeek net_conn
-- hypothesis: very regular connection intervals to one endpoint suggest an automated check-in.
-- false positives: NTP, push-notification keepalives, update checkers, monitoring agents,
--   mail clients polling. Expect to allow-list some of these after the baseline review.
-- fires on: >= {{r3_min_conns}} connections to one endpoint, mean interval >= {{r3_min_interval_s}} s,
--   interval jitter (stddev / mean) < {{r3_max_jitter}}.
-- does not fire on: irregular browsing, or bursts with sub-{{r3_min_interval_s}} s spacing.
WITH c AS (
  SELECT host, coalesce(proc_key, host || ':unattributed') AS grp, proc_key, process_path,
         dst_ip, dst_port, ts, raw_ref,
         epoch(ts) - epoch(lag(ts) OVER (PARTITION BY host, coalesce(proc_key, ''), dst_ip, dst_port ORDER BY ts)) AS gap
  FROM hunt
  WHERE event_type = 'net_conn'
    AND (direction = 'out' OR ({{include_loopback}} AND direction = 'loopback'))
)
SELECT 'R3' AS rule_id, host, any_value(proc_key) AS proc_key, any_value(process_path) AS process_path,
       grp || '->' || dst_ip || ':' || dst_port AS group_key, min(ts) AS first_ts, max(ts) AS last_ts,
       printf('%d connections to %s:%d, mean interval %.1f s, jitter %.3f', count(*), dst_ip, dst_port,
              avg(gap), stddev_pop(gap) / nullif(avg(gap), 0)) AS summary,
       {'connections': count(*), 'mean_interval_s': avg(gap), 'jitter': stddev_pop(gap) / nullif(avg(gap), 0)} AS metrics,
       list(raw_ref ORDER BY ts) AS evidence
FROM c
GROUP BY host, grp, dst_ip, dst_port
HAVING count(*) >= {{r3_min_conns}}
   AND avg(gap) >= {{r3_min_interval_s}}
   AND stddev_pop(gap) / nullif(avg(gap), 0) < {{r3_max_jitter}}
