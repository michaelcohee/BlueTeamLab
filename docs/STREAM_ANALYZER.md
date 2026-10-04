# Partial-stream integrity analyzer

This school-lab component demonstrates what a SIEM can and cannot conclude from chunked
data in transit. It consumes an explicit JSONL chunk envelope; it does not sniff arbitrary
traffic, decrypt SSH, execute transferred bytes, or block a process.

## Evidence model

Each data event declares `stream_id`, `kind=data`, `index`, `data_chunks`, `payload_b64`,
and the chunk's SHA-256. A manifest may declare the expected whole-stream SHA-256. An
optional XOR parity event carries the parity bytes and original chunk lengths.

The analyzer accepts chunks out of order and records duplicate, conflicting, corrupt, and
missing indices. Raw payload bytes are never printed. Results contain byte counts, coverage,
hashes, confidence, findings, and explicit evidence gaps.

## Four of five chunks

With four ordinary data chunks out of five, coverage is 80%, but the whole SHA-256 is
`null`: a cryptographic whole-file signature cannot be derived from unknown bytes. The
result is `inconclusive`, not clean.

```zsh
./dl stream simulate --data-chunks 5 --drop 4 > /tmp/four-of-five.jsonl
./dl stream analyze /tmp/four-of-five.jsonl --pretty
```

If a protocol deliberately sends four data chunks plus XOR parity, any one missing data
chunk can be recovered from the other three data chunks and parity:

```zsh
./dl stream simulate --data-chunks 4 --drop 2 --parity > /tmp/recoverable.jsonl
./dl stream analyze /tmp/recoverable.jsonl --pretty
```

XOR parity is an educational single-erasure example, not a substitute for authenticated
transport or production erasure coding.

## RedTail-X 4+2 shares

The RedTail-X paper describes four data shares plus two Reed–Solomon parity shares. Any
four valid shares can reconstruct one stripe. The lab now models that evidence directly:

```zsh
./dl stream simulate-rs --drop 0 --drop 5 > /tmp/redtail-rs.jsonl
./dl stream analyze /tmp/redtail-rs.jsonl --pretty
```

The manifest records `original_len`, `share_len`, the original SHA-256, six share
SHA-256 values, the GF(256) field polynomial, and all six generator rows. The rows are
named `G0` through `G5` to keep them distinct from experimental `C0` through `C5`
control arms. `zero_elimination` is explicitly `false`. The analyzer validates the matrix,
verifies the received shares, reconstructs missing data from any four valid shares,
truncates only the transport padding using `original_len`, and verifies the original hash.
With only three valid shares it reports `inconclusive`. It does not guess unknown bytes.

Compare the two generator matrices currently defined in the inspected sources:

```zsh
./dl stream compare-matrices --pretty
./dl stream compare-matrices --input samples/synthetic/null_payload_carrier.bin --pretty
```

The comparison tests all six one-share losses and all fifteen two-share losses. It reports
exact reconstruction counts, formula metadata, parity hashes, and parity byte/bit
differences. A finite-field erasure code does not have a useful floating-point
"sensitivity" score; rank, exact recovery, hashes, and diffusion are the meaningful
measurements here.

This is a message evidence model. Canonizer currently uses a `NEED`/`HAVE` bitmap and
retransmission rather than RedTail-X parity, so Canonizer events and RedTail-X share events
remain separate protocol types.

## Canonical known-content inclusion

A complete whole-file hash cannot be calculated from an ordinary stream with missing
bytes. A partial stream can still contain strong evidence from a known reference. Build a
canonical signature database from authorized reference files:

```zsh
./dl stream canonize reference-a.bin reference-b.bin \
  --reference-class malicious --output /tmp/daybreak-signatures.json
./dl stream analyze captured-messages.jsonl \
  --signature-db /tmp/daybreak-signatures.json --pretty
```

Every reference is explicitly classified. A match never supplies its own hostility:

| Reference class | Match result | Containment field |
|---|---|---|
| `test` | informational `known_content_inclusion`, `school_control` | `none` |
| `benign` | informational `known_content_inclusion`, `inclusion_only` | `none` |
| `malicious` | high-severity `known_content_inclusion`, `suspicious` status | `endpoint policy required` |

`canonize` defaults to `test`. Use `--reference-class malicious` only for an authorized
malicious reference set. The policy layer never infers hostility from matching bytes.
Version 1 databases did not carry a reference class and must be rebuilt with `canonize`.

The database stores a BLAKE2b-128 digest for every 32-byte window at one-byte stride, plus
the reference class, size, and whole SHA-256. It does not store the executable bytes. The analyzer
requires a continuous 64-byte aligned match by default. A one-byte match is never treated
as a signature because every arbitrary byte has only 256 possible values and would create
unusable false positives.

Windows that occur more than 64 times in the reference set remain stored for full byte
coverage but are excluded from alert scoring. This prevents long zero-filled executable
sections from creating a combinatorial match or a low-specificity alert.

An existing file can be wrapped into the explicit message schema without executing it:

```zsh
./dl stream envelope sample.bin --data-chunks 8 --drop 7 > /tmp/partial.jsonl
```

The byte-stride database is intentionally exhaustive and can be much larger than its
references. It is suitable for a small school-lab reference set. A production deployment
would use an indexed binary format, bounded reference policy, and controlled endpoint or
application telemetry.

## SCP and SSH boundary

SCP data is carried inside encrypted SSH. Canonizer's encrypted modes likewise seal record
payloads with AEAD or TLS. A passive network sensor can observe connection
metadata, timing, byte counts, endpoints, and SSH fingerprints, but cannot reconstruct the
transferred program or calculate its plaintext file hash.

The deployable defensive control is endpoint correlation:

1. Network sensor records the SSH flow.
2. Endpoint telemetry records `sshd`, `scp`, or `sftp` process activity and file writes.
3. EDR hashes the completed destination file and checks an approved or denied hash policy.
4. SIEM correlates the flow, process identity, file path, hash verdict, and execution event.
5. EDR performs quarantine or execution prevention. The SIEM records evidence and alerts.

This separation keeps the demo honest: the SIEM analyzes and correlates evidence; endpoint
policy performs containment.

## EDR, syslog, and LogScale

The analyzer can emit a normalized, payload-free SIEM event. It never connects to a remote
service or stores an ingest token:

```zsh
./dl stream analyze /tmp/four-of-five.jsonl --format siem-json
./dl stream analyze /tmp/four-of-five.jsonl --format syslog
```

`siem-json` is intended for a local file or JSON collector. `syslog` emits one RFC 5424-style
line using the `local0` facility. An administrator can route either output through the
organization's approved EDR or log collector. Falcon LogScale supports structured JSON
ingest and syslog through ingest listeners or the LogScale Collector; repository URL,
token, TLS, parser, and retention configuration belong in the collector, outside this code.

The event contains stream coverage, received and missing indices, reconstruction status,
whole-file SHA-256 when computable, rule identifiers, classified observations, evidence
gaps, and any explicit endpoint-policy recommendation. It never includes chunk payload
bytes.

## Exit codes

- `0`: complete or recovered, with no suspicious integrity finding.
- `1`: incomplete evidence or invalid rows; no whole-file conclusion.
- `2`: command usage, input, database, file, or serialization error.
- `3`: at least one suspicious integrity or explicitly malicious-content finding.

Exit code `1` is an evidence-gap signal, not an incident or analyzer crash. Automated
callers must retain and parse the JSON fields (`status`, `findings`, `observations`, `gaps`,
and `containment`) even when the exit status is nonzero. Version 1 signature databases are
rejected; rebuild them with `canonize` rather than assigning an inferred class.
- `3`: corrupt/conflicting evidence, manifest mismatch, or denylisted complete hash.
- `2`: command or input-file error.
