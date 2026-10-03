-- id: R2
-- name: Outbound volume spike
-- attack: T1048 Exfiltration Over Alternative Protocol
-- tactic: TA0010 Exfiltration
-- sources: zeek net_conn; baseline_bytes (hourly p99 per process_path)
-- hypothesis: a process sends far more in one hour than it ever did during baseline.
-- false positives: cloud sync after a large file change, OS/app updates uploading
--   diagnostics, video calls, Time Machine to a network disk.
-- fires on: hourly bytes_out > {{r2_multiplier}} x baseline p99 AND > {{r2_min_bytes}} bytes.
--   A process_path with no baseline row is compared against 0 (so only the floor applies).
-- does not fire on: the same volume below the floor, or within 3x of the process's p99.
-- note: this is a PATH-LEVEL analytic. One hour's bytes for a process_path may cover several
--   process instances; proc_key is set only when exactly one instance is responsible, else null
--   with every instance listed in metrics.member_proc_keys. A volume spike alone does not prove
--   T1048 (that needs an alternative protocol); treat the ATT&CK id as a hypothesis.
WITH h AS (
  SELECT host, coalesce(process_path, '(unattributed)') AS pp, date_trunc('hour', ts) AS hr,
         count(DISTINCT proc_key) FILTER (WHERE proc_key IS NOT NULL) AS n_keys,
         any_value(proc_key) FILTER (WHERE proc_key IS NOT NULL) AS one_key,
         list(DISTINCT proc_key) FILTER (WHERE proc_key IS NOT NULL) AS member_keys,
         sum(bytes_out) AS out_b, min(ts) AS first_ts, max(ts) AS last_ts,
         list(raw_ref ORDER BY bytes_out DESC) AS evidence
  FROM hunt
  WHERE event_type = 'net_conn' AND direction = 'out'
  GROUP BY ALL
)
SELECT 'R2' AS rule_id, h.host,
       CASE WHEN h.n_keys = 1 THEN h.one_key ELSE NULL END AS proc_key,
       nullif(h.pp, '(unattributed)') AS process_path,
       h.host || ':' || h.pp || ':' || h.hr AS group_key, h.first_ts, h.last_ts,
       printf('%s sent %d bytes in one hour; baseline p99 %d (%d process instance(s))',
              h.pp, h.out_b, coalesce(b.p99_out, 0)::BIGINT, h.n_keys) AS summary,
       {'bytes_out_hour': h.out_b, 'baseline_p99': coalesce(b.p99_out, 0), 'baseline_hours': coalesce(b.hours, 0),
        'process_instances': h.n_keys, 'member_proc_keys': h.member_keys} AS metrics,
       h.evidence
FROM h LEFT JOIN baseline_bytes b ON b.host = h.host AND b.process_path = h.pp
WHERE h.out_b > {{r2_min_bytes}} AND h.out_b > {{r2_multiplier}} * coalesce(b.p99_out, 0)
