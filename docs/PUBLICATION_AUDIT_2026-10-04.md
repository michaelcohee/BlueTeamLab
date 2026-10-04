# Publication audit: 2026-10-04

This audit covers the Git repository rooted at `BlueteamLab/detection-lab`. The surrounding
`BlueteamLab` directory is not part of that repository.

## Result summary

| Check | Result |
|---|---|
| Runtime data boundary | `$HOME/VerticalData` is outside the repository and was empty at review time |
| JSON/event artifacts | `rules/params.json` is the only JSON-family file in the repository; no JSONL or NDJSON data is present |
| Telemetry and dumps | No logs, packet captures, memory dumps, crash dumps, local databases, or real case Books found |
| Current-tree privacy scan | No detected personal name, email, workstation path, shell identity, token, private key, credential assignment, or SSN pattern |
| Parent-directory scan | Handoff documents outside this repository contain personal names and absolute workstation paths; they are excluded from this repo |
| Git history content | Personal workstation paths were removed from every local commit by history rewrite |
| Git commit metadata | All 18 commits use the project owner's selected public author identity |
| Remote | `origin` is configured; its tracking ref remains on the pre-rewrite history until force-pushed |
| License | No license selected or committed |
| Synthetic binary | Intentional 16,936-byte ARM64 Mach-O, source committed beside it, static checks pass, never executed by tests |
| Automated verification | 77 tests pass; Python dependency check, compilation, shell syntax, and Git whitespace checks pass |

No secret or credential signature was found in the current tree or the scanned commit
contents. Pattern scanning reduces accidental exposure risk but cannot prove that arbitrary
prose contains no sensitive information.

## Controls added during review

- README opens with the school-lab scope and the observation/containment policy table.
- Runtime output, packet capture, dump, database, credential, and machine-local patterns are
  ignored by Git.
- Workstation-specific paths and owner names were removed from the current source tree.
- `SECURITY.md`, the NIST CSF 2.0 teaching-lab mapping, containment policy, and repeatable
  publication checklist were added.
- The collector now validates duration and interface inputs, uses `jq` for safe session JSON,
  and passes paths to privileged child shells as positional arguments instead of interpolating
  them into command strings.
- Blueware containment is a plan-only `tcp_cutoff` handoff. It cannot be authorized by test,
  benign, or evidence-gap-only results and never changes SIMD or endpoint state. The plan
  states that UDP, local IPC, and other transports require separate assessment.

## Claim review

The public documentation consistently states:

- `test` → `school_control`, containment `none`;
- `benign` → `inclusion_only`, containment `none`;
- `malicious` → `suspicious`, with an endpoint-policy handoff;
- incomplete ordinary streams → `inconclusive`, reported coverage, no whole-file hash;
- exit code `1` → an evidence gap that requires JSON inspection;
- signature database version 1 → rejected and rebuilt with a reference class;
- the static fixture has 16 null callback slots, a return-zero main stub, and the exact
  48-byte school control;
- passive TCP sequence reassembly and encrypted-payload visibility are not implemented.

## NIST posture

The repository supplies limited evidence across Govern, Identify, Protect, Detect, Respond,
and Recover. The exact evidence and gaps are listed in [NIST_CSF_MAPPING.md](NIST_CSF_MAPPING.md).
This is a teaching-lab mapping and does not establish SOC 2, NIST, product, or organizational
compliance.

## Gates before a public push

1. Choose a license.
2. Confirm the destination repository visibility.
3. Re-run [PUBLICATION_CHECKLIST.md](PUBLICATION_CHECKLIST.md) before pushing.

The commit email and personal workstation path were rewritten across the local history after
this audit. No remote update was performed as part of those rewrites.
