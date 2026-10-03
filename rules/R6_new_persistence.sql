-- id: R6
-- name: New persistence item
-- attack: T1543.001 Launch Agent; T1543.004 Launch Daemon; T1547.015 Login Items
-- tactic: TA0003 Persistence
-- sources: osquery launchd + startup_items (persistence_item)
-- hypothesis: a launchd job or login/startup item that did not exist during baseline.
-- false positives: app installs and updates (helpers, updaters), OS updates adding daemons.
--   Background Task Management (sfltool dumpbtm) is NOT collected; check it by hand.
-- fires on: any persistence_item whose (kind, label, plist path, program) is not in baseline_persist.
-- does not fire on: items unchanged since baseline.
SELECT 'R6' AS rule_id, h.host, NULL AS proc_key, h.process_path,
       h.host || ':' || h.item_kind || ':' || coalesce(h.item_label, '') || ':' || coalesce(h.item_path, '') AS group_key,
       min(h.ts) AS first_ts, max(h.ts) AS last_ts,
       printf('new %s item %s (%s) runs %s', h.item_kind, coalesce(h.item_label, '?'),
              coalesce(h.item_path, '?'), coalesce(h.process_path, '?')) AS summary,
       {'item_kind': h.item_kind, 'item_label': h.item_label, 'item_path': h.item_path} AS metrics,
       list(h.raw_ref ORDER BY h.ts) AS evidence
FROM hunt h
WHERE h.event_type = 'persistence_item'
  AND NOT EXISTS (SELECT 1 FROM baseline_persist b
                  WHERE b.host = h.host AND b.item_kind IS NOT DISTINCT FROM h.item_kind
                    AND b.item_label IS NOT DISTINCT FROM h.item_label
                    AND b.item_path IS NOT DISTINCT FROM h.item_path
                    AND b.process_path IS NOT DISTINCT FROM h.process_path)
GROUP BY h.host, h.item_kind, h.item_label, h.item_path, h.process_path
