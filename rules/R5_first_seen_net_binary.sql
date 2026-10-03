-- id: R5
-- name: First-seen network binary
-- attack: T1204 User Execution; T1105 Ingress Tool Transfer
-- tactic: TA0002 Execution / TA0011 Command and Control
-- sources: osquery socket_seen (direct process ownership), zeek net_conn (id-match)
-- hypothesis: a binary that never used the network during baseline starts talking out.
-- false positives: newly installed or updated apps (path changes on update), developer
--   builds, Homebrew upgrades. Review signer/team_id in the trace before escalating.
-- fires on: a process_path with an outbound socket or attributed connection that is not in
--   baseline_net_bin.
-- does not fire on: any binary already seen using the network during baseline.
-- note: a TRIAGE trigger, not a verdict. The planned SHA-256 criterion is absent by design
--   (hash is null until a human runs shasum), so do not infer T1204/T1105 from network use
--   alone. proc_key is set only when one instance is responsible, else null + member list.
SELECT 'R5' AS rule_id, h.host,
       CASE WHEN count(DISTINCT h.proc_key) FILTER (WHERE h.proc_key IS NOT NULL) = 1
            THEN any_value(h.proc_key) FILTER (WHERE h.proc_key IS NOT NULL) ELSE NULL END AS proc_key,
       h.process_path,
       h.host || ':' || h.process_path AS group_key, min(h.ts) AS first_ts, max(h.ts) AS last_ts,
       printf('first network use by %s: %d endpoint(s), first %s:%d', h.process_path,
              count(DISTINCT h.dst_ip || ':' || h.dst_port), arg_min(h.dst_ip, h.ts), arg_min(h.dst_port, h.ts)) AS summary,
       {'endpoints': count(DISTINCT h.dst_ip || ':' || h.dst_port), 'events': count(*),
        'process_instances': count(DISTINCT h.proc_key) FILTER (WHERE h.proc_key IS NOT NULL),
        'member_proc_keys': list(DISTINCT h.proc_key) FILTER (WHERE h.proc_key IS NOT NULL)} AS metrics,
       list(h.raw_ref ORDER BY h.ts) AS evidence
FROM hunt h
WHERE h.event_type IN ('socket_seen', 'net_conn')
  AND h.process_path IS NOT NULL
  AND (h.direction IN ('out', 'lan') OR ({{include_loopback}} AND h.direction = 'loopback'))
  AND NOT EXISTS (SELECT 1 FROM baseline_net_bin b WHERE b.host = h.host AND b.process_path = h.process_path)
GROUP BY h.host, h.process_path
