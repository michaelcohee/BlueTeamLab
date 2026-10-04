# Synthetic binary fixture

`null_payload_carrier.bin` is a harmless ARM64 Mach-O executable compiled from
`null_payload_carrier.c`. It contains the exact marker strings:

```text
MALWARE PAYLOAD CARRIER HERE
NULL PAYLOAD
```

Its 16 callback slots are all null. It does not install a hook, open a socket, modify a
file, load a payload, or call a callback. The source is committed beside the binary so the
fixture can be audited and rebuilt.

`school_control_ascii.bin` is the exact 48-byte padded marker/payload region extracted from
the fixture. It is permanently classified as a school `test` reference. Its SHA-256 is:

```text
5e0910a520129f61f1d8ecd9eb76df39a6b16b56e74c05f193716ea4dfde2623
```

Current binary SHA-256:

```text
8598bb3c7af0ded5dd012c5042259f150782f05b104bd82902821a907739cd20
```

Rebuild and verify on Apple silicon macOS:

```zsh
clang -Os -Wall -Wextra -Werror \
  samples/synthetic/null_payload_carrier.c \
  -o samples/synthetic/null_payload_carrier.bin

strings -a samples/synthetic/null_payload_carrier.bin |
  grep -E 'MALWARE PAYLOAD CARRIER HERE|NULL PAYLOAD'
```

Run the partial-stream inclusion demonstration:

```zsh
./dl stream canonize samples/synthetic/school_control_ascii.bin \
  --reference-class test --window-bytes 16 --min-match-bytes 32 \
  --output /tmp/null-carrier-signatures.json
./dl stream envelope samples/synthetic/null_payload_carrier.bin \
  --data-chunks 8 --drop 7 --stream-id null-carrier-demo \
  > /tmp/null-carrier-partial.jsonl
./dl stream analyze /tmp/null-carrier-partial.jsonl \
  --signature-db /tmp/null-carrier-signatures.json --pretty
```

The expected result is a 48-byte `known_content_inclusion` observation at offset `0x408`.
It is a `school_control`, containment is `none`, and status is `inconclusive` because
chunk 7 was deliberately omitted and the whole-file hash remains unavailable.
