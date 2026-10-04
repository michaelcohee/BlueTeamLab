# NIST CSF 2.0 teaching-lab mapping

This document maps the repository's observable controls to the six functions in the
[NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework). It is a limited
portfolio mapping for a single-host school lab. It is not an assessment, certification, or
claim of organizational compliance.

| CSF 2.0 function | Evidence in this repository | Scope and gap |
|---|---|---|
| Govern | Policy split by reference class; raw-data and publication rules; documented analyzer limits | No organizational roles, legal review, supplier program, or enterprise risk process |
| Identify | Baseline of known destinations, binaries, persistence, and source manifests | One macOS host; no asset inventory beyond collected lab evidence |
| Protect | External data directory, path-safety checks, least-data collection, rotation, and 3 GB guard | No access-control system, identity provider, encryption management, or production hardening |
| Detect | Zeek, osquery, and eslogger normalization; R1–R6 SQL rules; partial-stream integrity and classified canonical inclusion | Approximate process/network attribution; no passive TCP sequence reassembly; no encrypted-payload visibility |
| Respond | Manual trace playbook, evidence-first guidance, reversible containment notes, SIEM-formatted output | Blueware does not contain endpoints or automate incident response |
| Recover | Reproducible synthetic tests, case comparison, and documented undo steps | No backup service, disaster-recovery plan, or measured recovery objective |

## Evidence rules that preserve the boundary

1. `proc_key = host:pid:proc_start` is the only process join key. A PID alone is never enough.
2. Automated Horizontal books can use only `untested` and `id-match`; they cannot claim
   confirmation, a verdict, or containment.
3. Partial streams report coverage and gaps. They do not receive a whole-stream hash until
   all bytes are present or the declared 4+2 recovery contract reconstructs them exactly.
4. Canonical inclusion is classified independently from stream completeness. A `test` or
   `benign` match cannot become a containment action.
5. Runtime telemetry and real cases stay outside Git.

## Publication evidence

The release review in [PUBLICATION_CHECKLIST.md](PUBLICATION_CHECKLIST.md) records the
repository-specific privacy, secrets, artifact, history, and test checks. NIST recommends
using the CSF to understand and improve cybersecurity risk management; this mapping makes
only the narrower claims supported by repository evidence.
