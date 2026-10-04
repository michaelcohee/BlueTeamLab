# Containment policy boundary

Blueware does not execute containment. The `containment-plan` command creates a structured,
reviewable handoff to an authorized EDR or host-control policy.

## Authorization rule

A plan contains actions only when all three conditions hold:

1. `status` is `suspicious`;
2. `containment` is `endpoint policy required`; and
3. the finding is an explicitly `malicious` canonical-reference match or a denylisted
   whole-file SHA-256.

`test`, `benign`, clean, and evidence-gap-only reports cannot authorize the handoff. Stream
incompleteness by itself never authorizes containment.

## Plan steps

1. Preserve the analysis, source references, and hashes.
2. Have an analyst validate the malicious-reference or denylist provenance.
3. Ask an authorized EDR or host firewall for a TCP cutoff.
4. Verify the TCP block, record the decision and rollback, then assess UDP, local IPC, and
   other transports separately.

The plan always records `execution_performed: false`. It contains no process-kill, network,
firewall, driver, kernel, or CPU-feature command.

`requested_control: tcp_cutoff` names the requested policy outcome. It is not proof that a
block occurred, and it is not complete endpoint isolation. The receiving endpoint product
must report success or failure through its own audited control channel.

## SIMD is outside the control surface

SIMD is a family of CPU vector instructions, not an endpoint-isolation boundary. Blueware
does not attempt to disable SIMD and records `simd_changed: false`. A future containment
adapter must use documented endpoint controls, remain separate from analysis, require an
explicit malicious policy basis, and produce an auditable rollback path.
