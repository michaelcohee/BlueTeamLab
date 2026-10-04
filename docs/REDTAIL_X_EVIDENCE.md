# RedTail-X evidence mapping

This note records the public design sources used by the school-lab stream analyzer. It
also prevents a name collision with the unrelated RedTail cryptomining malware family.

## Public Premise Works articles

1. [RedTail-X](https://premiseworks.blogspot.com/2026/09/redtail-x-variable-length-final-shares.html)
   defines variable-length final shares for a 4+2 Reed–Solomon stripe. Any four valid shares
   can reconstruct a stripe. Its in-memory manifest records `original_len`, `share_len`, an
   original-content hash, and six share hashes. The article states that its main benchmark
   did not evaluate a deployed network, persisted remote manifest format, or encryption.
2. [The House That Watches Back: Reconstructing The Greko](https://premiseworks.blogspot.com/2026/09/the-house-that-watches-back.html)
   separates transport evidence from event truth and requires explicit observation
   boundaries, declared blind spots, deterministic comparison, and post-response
   verification.
3. [What Is DevOps?](https://premiseworks.blogspot.com/2026/09/what-is-devops.html)
   describes the operating loop used here: observe, compare with expected state, execute a
   known procedure where authorized, verify, record, and escalate unknown conditions rather
   than guessing.

## Lab translation

- `simulate-rs` represents one 4+2 stripe as six explicit share messages plus a manifest.
- `analyze` accepts any four valid shares, reconstructs missing data, truncates to
  `original_len`, and verifies the whole SHA-256.
- Three valid shares remain inconclusive. The analyzer never invents missing bytes.
- `canonize` builds a known-content reference set from authorized files. Inclusion matches
  are evidence about observed plaintext message data, not proof that an entire file was
  transferred.
- Encrypted SCP, SSH, TLS, and AEAD record payloads require authorized endpoint or
  post-decryption telemetry. A passive SIEM cannot extract their plaintext hashes.
- SIEM output recommends endpoint policy only for a denylisted whole hash or an explicitly
  `malicious` canonical reference. `test` and `benign` inclusion matches remain
  informational. The analyzer itself does not execute, quarantine, or transmit content.

## Canonizer boundary

The read-only Canonizer inspection found a different recovery model. Canonizer uses
`NEED`/`HAVE` bitmaps and retransmission. Classic Python modes carry per-chunk hashes plus a
whole hash; streamed raw mode carries per-chunk hashes plus a root; encrypted lean and C++
TLS modes rely on authenticated encryption for record integrity. RedTail-X parity must not
be inferred from Canonizer traffic unless a producer explicitly emits the 4+2 share schema.
