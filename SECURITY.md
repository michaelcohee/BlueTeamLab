# Security and privacy policy

Blueware is a school-lab stream scanner and an offline detection-engineering exercise. It is
not an endpoint agent, production SIEM, malware verdict service, or automatic containment
system.

## Safe repository contents

Only source code, documentation, rules, tests, and synthetic fixtures belong in this
repository. Do not commit:

- raw or normalized telemetry;
- packet captures, memory dumps, crash reports, or real case books;
- hostnames, usernames, home-directory paths, internal addresses, or other personal data;
- API keys, credentials, private keys, certificates, or machine configuration profiles.

Runtime data belongs under `$VERTICALDATA`, outside every Git working tree. The collection
and case-writing paths reject destinations located inside a repository. `.gitignore` is a
backup control, not permission to skip review.

## Reporting a problem

For a public GitHub repository, use GitHub's private vulnerability-reporting feature. Include
the affected command, expected behavior, and a minimal synthetic reproduction. Do not attach
real telemetry or credentials.

## Analyzer policy boundary

- `test` references produce a `school_control` observation with no containment.
- `benign` references produce an `inclusion_only` observation with no containment.
- `malicious` references may produce a `suspicious` finding; any response is an endpoint
  policy decision outside this analyzer.
- incomplete evidence remains `inconclusive`; exit code `1` means the JSON must be inspected.

The committed Mach-O sample is a static, inert fixture and must never be executed as part of
a test. Version 1 signature databases are rejected because they do not carry a reference
class.

## Supported code

Security fixes target the current `main` branch. No production-support commitment is made.
