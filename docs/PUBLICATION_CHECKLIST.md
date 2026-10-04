# Public repository release checklist

Run this review from the repository root before every public push.

## Data boundary

- [ ] `$VERTICALDATA` resolves outside the repository.
- [ ] No raw telemetry, normalized events, packet captures, dumps, real Books, or local
  databases are tracked.
- [ ] Every committed binary is intentional, synthetic, source-visible, and documented.
- [ ] JSON files are configuration or synthetic fixtures; no exported event stream is present.

## Privacy and secrets

- [ ] Search the working tree and Git history for names, email addresses, home-directory
  paths, hostnames, internal addresses, credentials, private keys, and tokens.
- [ ] Review Git author name and email as public metadata.
- [ ] Confirm examples use placeholders or `$HOME`/`$VERTICALDATA`.
- [ ] Remove operating-system and editor metadata.

## Claim boundary

- [ ] README opens by calling Blueware a school-lab Python stream scanner.
- [ ] `test` maps to `school_control` and `containment: none`.
- [ ] `benign` maps to `inclusion_only` and `containment: none`.
- [ ] Only `malicious` can map to `suspicious` and endpoint policy.
- [ ] A partial stream stays `inconclusive`; coverage is reported and whole hash is absent.
- [ ] Exit code `1` is documented as an evidence gap, not an incident or tool failure.
- [ ] Version 1 signature databases are documented as rejected and must be rebuilt.
- [ ] No text claims passive TCP sequence reassembly or encrypted-payload visibility.
- [ ] Containment remains a plan-only endpoint handoff; no SIMD, kernel, process-kill, or
  firewall operation is executed by Blueware.

## Verification

```zsh
./dl test
./blueware self-test
.venv/bin/python -m pip check
git diff --check
git status --short
```

Review the exact staged set with `git diff --cached --stat` and
`git diff --cached --check` before committing.

## GitHub decisions

- [ ] Choose and add a license. No license means the default copyright rules apply.
- [ ] Decide whether the existing real Git author name and email are intended public
  attribution. If not, publish from sanitized history rather than pushing this history.
- [ ] Configure a remote only after the destination repository and visibility are confirmed.
- [ ] Enable private vulnerability reporting if the repository is public.
