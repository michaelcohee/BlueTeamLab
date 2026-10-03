-- id: R1
-- name: Shard fan-out
-- attack: T1030 Data Transfer Size Limits; T1041 Exfiltration Over C2 Channel
-- tactic: TA0010 Exfiltration
-- sources: zeek net_conn (process via id-match attribution when available)
-- hypothesis: one process sends similar-sized chunks to many never-before-seen
--   endpoints (ip:port) within a short window — the shape of erasure-coded or split uploads.
-- false positives: P2P/backup clients, software updaters using CDNs, browsers opening
--   many new CDN endpoints (sizes usually vary, so the CV test filters most).
-- fires on: >= {{r1_min_new_endpoints}} new endpoints in {{r1_window_min}} min, chunk-size CV < {{r1_max_size_cv}}.
-- does not fire on: the same volume to endpoints already in baseline_dst.
-- note: unattributed connections are grouped per host, which is weaker evidence.
WITH c AS (
  SELECT h.*, coalesce(h.proc_key, h.host || ':unattributed') AS grp,
         time_bucket(INTERVAL {{r1_window_min}} MINUTE, h.ts) AS win
  FROM hunt h
  WHERE h.event_type = 'net_conn'
    AND (h.direction = 'out' OR ({{include_loopback}} AND h.direction = 'loopback'))
    AND coalesce(h.bytes_out, 0) >= {{r1_min_bytes_each}}
    AND NOT EXISTS (SELECT 1 FROM baseline_dst b
                    WHERE b.host = h.host AND b.dst_ip = h.dst_ip AND b.dst_port = h.dst_port)
)
SELECT 'R1' AS rule_id, host, any_value(proc_key) AS proc_key, any_value(process_path) AS process_path,
       grp AS group_key, min(ts) AS first_ts, max(ts) AS last_ts,
       printf('%d new endpoints in %d min, %d bytes out, chunk-size CV %.3f (%s)',
              count(DISTINCT dst_ip || ':' || dst_port), {{r1_window_min}}, sum(bytes_out),
              coalesce(stddev_pop(bytes_out) / nullif(avg(bytes_out), 0), 0),
              coalesce(any_value(process_path), 'unattributed')) AS summary,
       {'new_endpoints': count(DISTINCT dst_ip || ':' || dst_port), 'bytes_out': sum(bytes_out),
        'size_cv': coalesce(stddev_pop(bytes_out) / nullif(avg(bytes_out), 0), 0)} AS metrics,
       list(raw_ref ORDER BY ts) AS evidence
FROM c
GROUP BY host, grp, win
HAVING count(DISTINCT dst_ip || ':' || dst_port) >= {{r1_min_new_endpoints}}
   AND coalesce(stddev_pop(bytes_out) / nullif(avg(bytes_out), 0), 0) < {{r1_max_size_cv}}
