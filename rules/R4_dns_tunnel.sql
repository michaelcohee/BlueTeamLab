-- id: R4
-- name: DNS tunneling indicators
-- attack: T1071.004 Application Layer Protocol: DNS
-- tactic: TA0011 Command and Control (also TA0010 when used for exfiltration)
-- sources: zeek dns_query (label length/entropy computed by the normalizer)
-- hypothesis: data carried in DNS shows up as long or random-looking subdomain labels,
--   or an unusual query rate to one base domain.
-- false positives: CDN and anti-malware lookups with hashed labels, DKIM/SPF records,
--   some telemetry SDKs. Base domain = last two labels (approximate for co.uk-style suffixes).
-- fires on: query length > {{r4_min_query_len}}, OR a label >= {{r4_min_label_len}} chars with entropy
--   >= {{r4_min_entropy}}, OR > {{r4_max_per_min}} queries/min to one base domain above its baseline max.
-- does not fire on: ordinary short hostnames at normal rates.
WITH q AS (
  SELECT *, date_trunc('minute', ts) AS m,
         length(dst_domain) > {{r4_min_query_len}} AS long_q,
         (dns_label_max_len >= {{r4_min_label_len}} AND dns_label_entropy >= {{r4_min_entropy}}) AS random_label
  FROM hunt WHERE event_type = 'dns_query' AND dst_domain IS NOT NULL
), per_min AS (
  SELECT host, dns_base_domain, m, count(*) AS n FROM q GROUP BY ALL
), flagged AS (
  SELECT q.*, coalesce(p.n, 0) AS n_min, coalesce(b.max_per_min, 0) AS base_max,
         (p.n > {{r4_max_per_min}} AND p.n > coalesce(b.max_per_min, 0)) AS high_rate
  FROM q
  LEFT JOIN per_min p USING (host, dns_base_domain, m)
  LEFT JOIN baseline_dns_rate b USING (host, dns_base_domain)
)
SELECT 'R4' AS rule_id, host, NULL AS proc_key, NULL AS process_path,
       host || ':' || dns_base_domain AS group_key, min(ts) AS first_ts, max(ts) AS last_ts,
       printf('%s: %d flagged queries (long %d, random-label %d, peak %d/min)', dns_base_domain, count(*),
              count(*) FILTER (WHERE long_q), count(*) FILTER (WHERE random_label), max(n_min)) AS summary,
       {'flagged_queries': count(*), 'long': count(*) FILTER (WHERE long_q),
        'random_label': count(*) FILTER (WHERE random_label), 'peak_per_min': max(n_min),
        'baseline_max_per_min': max(base_max), 'max_entropy': max(dns_label_entropy)} AS metrics,
       list(raw_ref ORDER BY ts) AS evidence
FROM flagged
WHERE long_q OR random_label OR high_rate
GROUP BY host, dns_base_domain
