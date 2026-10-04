# Formula array audit

This note prevents four different mechanisms from being recorded as if they were one
polynomial formula.

## Persisted codec formulas

Every new `rs-4+2` lab manifest stores a `codec_formula` object containing:

- schema and formula name;
- GF(256) field polynomial `0x11d`;
- the complete six-row generator matrix, labeled `G0` through `G5`;
- a SHA-256 of the canonical formula definition;
- `zero_elimination: false`.

The analyzer rejects an absent, malformed, singular, or changed matrix. The first four
rows must remain systematic data rows, and every selection of four of the six rows must
be invertible. Original length controls removal of transport padding; byte values of zero
remain part of the protected input.

`G0` through `G5` are codec rows. They are not the experimental `C0` through `C5`
control arms.

## Current matrix comparison

Two explicit 4+2 matrices exist in the inspected lab sources:

| Variant | G4 | G5 | 1-share rebuilds | 2-share rebuilds |
|---|---|---|---:|---:|
| `daybreak-powers` | `[1,1,1,1]` | `[1,2,4,8]` | 6/6 exact | 15/15 exact |
| `darkrock-custom` | `[1,1,1,1]` | `[1,2,3,4]` | 6/6 exact | 15/15 exact |

Run the comparison against inert bytes with:

```zsh
./dl stream compare-matrices --input samples/synthetic/null_payload_carrier.bin --pretty
```

On the current 16,936-byte sample, the two formulas produce different parity hashes and
differ in 339 parity bytes / 1,273 parity bits. Both reconstruct every tested one-share
and two-share loss exactly. This establishes functional equivalence for the tested erasure
contract, not wire compatibility between their parity shares.

## Control array status

The requested experiment describes `C0` as a scientific control and `C1` as shortest-path
selection. Those labels are now reserved, but the current source does not define a common
equation or input/output schema for `C0` through `C5`:

| Arm | Current state | Runnable comparison |
|---|---|---|
| C0 | Requested scientific control; exact rebuild policy still needs a definition | No |
| C1 | Requested SPF arm; routing code can minimize summed path cost | No common rebuild dataset yet |
| C2 | No equation in the inspected source | No |
| C3 | No equation in the inspected source | No |
| C4 | No equation; witness escalation also lacks a fourth independent witness | No |
| C5 | No equation; witness escalation also lacks fourth and fifth independent witnesses | No |

The existing `control+k` witness ceiling is a separate decision experiment. Its `k_used`
manifest field records how many witnesses were reached; it does not persist a polynomial
or routing equation. C4 and C5 cannot be reported as independent witness experiments with
the current three-witness implementation.

## Separate measurements

- **Codec formula:** exact recovery, matrix rank, original/share hashes, parity diffusion,
  and rebuild cost.
- **Routing/SPF:** selected helpers, summed path cost, bottleneck bandwidth, byte-hops, and
  modeled repair latency. Routing chooses where shares come from; it does not change the
  share algebra.
- **Representation gate:** compression choice and exact decode. The inspected design uses
  a Shannon entropy threshold and a periodicity check; it does not define an entropy
  oscillation clamp as part of the RS formula.
- **Witness ceiling:** precision, coverage, abstention, wrong-decision rate, witness cost,
  and independence assumptions.

A valid C0-C5 comparison needs a versioned equation, parameters, and deterministic input
schema for each arm. Until those definitions exist, the lab reports each missing arm as
undefined instead of filling it with an inferred formula.
