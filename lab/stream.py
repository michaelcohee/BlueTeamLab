"""Chunk-aware, offline stream integrity analysis for defensive lab use.

The analyzer consumes an explicit JSONL envelope. It does not sniff traffic, decrypt SSH,
execute payloads, or perform containment. It reports whether a whole-stream hash is
computable and preserves missing/corrupt chunks as evidence gaps.
"""

import argparse
import base64
import binascii
import datetime as dt
import hashlib
import json
import os
import socket
import sys
from itertools import combinations


MAX_CHUNK_BYTES = 1024 * 1024
SIGNATURE_SCHEMA = "daybreak-canonical-signatures/v2"
SIGNATURE_HASH_BYTES = 16
MAX_SIGNATURE_WINDOW_OCCURRENCES = 64
REFERENCE_CLASSES = ("test", "benign", "malicious")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def _window_digest(data):
    """Compact strong fingerprint for one canonical content window."""
    return hashlib.blake2b(data, digest_size=SIGNATURE_HASH_BYTES).digest()


def build_signature_db(paths, window_bytes=32, min_match_bytes=64, reference_class="test"):
    """Build a byte-stride canonical set without storing executable content."""
    if not isinstance(window_bytes, int) or not 16 <= window_bytes <= 4096:
        raise ValueError("window_bytes must be an integer from 16 to 4096")
    if not isinstance(min_match_bytes, int) or min_match_bytes < window_bytes:
        raise ValueError("min_match_bytes must be at least window_bytes")
    if reference_class not in REFERENCE_CLASSES:
        raise ValueError("reference_class must be test, benign, or malicious")
    references = []
    for path in paths:
        with open(path, "rb") as fh:
            data = fh.read()
        if len(data) < window_bytes:
            raise ValueError("reference %s is smaller than window_bytes" % path)
        digests = bytearray()
        for offset in range(len(data) - window_bytes + 1):
            digests.extend(_window_digest(data[offset:offset + window_bytes]))
        references.append({
            "name": os.path.basename(path),
            "size": len(data),
            "sha256": sha256(data),
            "reference_class": reference_class,
            "window_count": len(data) - window_bytes + 1,
            "window_hashes_b64": base64.b64encode(bytes(digests)).decode("ascii"),
        })
    return {
        "schema": SIGNATURE_SCHEMA,
        "algorithm": "blake2b-128",
        "window_bytes": window_bytes,
        "reference_stride_bytes": 1,
        "min_match_bytes": min_match_bytes,
        "references": references,
    }


def write_signature_db(database, path):
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    temporary = path + ".tmp"
    with open(temporary, "w", encoding="utf-8") as fh:
        json.dump(database, fh, sort_keys=True, separators=(",", ":"))
        fh.write("\n")
    os.replace(temporary, path)


def load_signature_db(path):
    if not path:
        return None
    with open(path, encoding="utf-8") as fh:
        database = json.load(fh)
    if not isinstance(database, dict) or database.get("schema") != SIGNATURE_SCHEMA:
        raise ValueError("signature database has an unsupported schema")
    window = database.get("window_bytes")
    minimum = database.get("min_match_bytes")
    if not isinstance(window, int) or not 16 <= window <= 4096:
        raise ValueError("signature database has an invalid window size")
    if not isinstance(minimum, int) or minimum < window:
        raise ValueError("signature database has an invalid match threshold")
    references = database.get("references")
    if not isinstance(references, list) or not references:
        raise ValueError("signature database contains no references")
    for reference in references:
        if not isinstance(reference, dict) or not isinstance(reference.get("name"), str):
            raise ValueError("signature database contains an invalid reference")
        if reference.get("reference_class") not in REFERENCE_CLASSES:
            raise ValueError("signature database reference has no valid class")
        count = reference.get("window_count")
        try:
            packed = base64.b64decode(reference.get("window_hashes_b64", ""), validate=True)
        except (binascii.Error, ValueError):
            raise ValueError("signature database contains invalid window hashes")
        if not isinstance(count, int) or count < 1 or len(packed) != count * SIGNATURE_HASH_BYTES:
            raise ValueError("signature database window count does not match its hashes")
        reference["_packed_hashes"] = packed
    return database


def _contiguous_segments(chunks):
    """Join only adjacent message indices; never bridge an evidence gap."""
    segments = []
    start = previous = None
    parts = []
    for index in sorted(chunks):
        if previous is None or index == previous + 1:
            if start is None:
                start = index
            parts.append(chunks[index])
        else:
            segments.append((start, previous, b"".join(parts)))
            start, parts = index, [chunks[index]]
        previous = index
    if start is not None:
        segments.append((start, previous, b"".join(parts)))
    return segments


def match_canonical_content(chunks, database):
    """Find aligned runs of known content inside the observed message data."""
    if not database:
        return []
    window = database["window_bytes"]
    minimum = database["min_match_bytes"]
    occurrence_counts = {}
    for reference_index, reference in enumerate(database["references"]):
        packed = reference["_packed_hashes"]
        for offset in range(reference["window_count"]):
            begin = offset * SIGNATURE_HASH_BYTES
            digest = packed[begin:begin + SIGNATURE_HASH_BYTES]
            occurrence_counts[digest] = occurrence_counts.get(digest, 0) + 1
    lookup = {}
    for reference_index, reference in enumerate(database["references"]):
        packed = reference["_packed_hashes"]
        for offset in range(reference["window_count"]):
            begin = offset * SIGNATURE_HASH_BYTES
            digest = packed[begin:begin + SIGNATURE_HASH_BYTES]
            if occurrence_counts[digest] <= MAX_SIGNATURE_WINDOW_OCCURRENCES:
                lookup.setdefault(digest, []).append((reference_index, offset))

    best = {}
    for first_chunk, last_chunk, data in _contiguous_segments(chunks):
        if len(data) < window:
            continue
        pairs = {}
        for observed_offset in range(len(data) - window + 1):
            digest = _window_digest(data[observed_offset:observed_offset + window])
            for reference_index, reference_offset in lookup.get(digest, ()):
                key = (reference_index, observed_offset - reference_offset)
                pairs.setdefault(key, []).append((observed_offset, reference_offset))
        for (reference_index, _alignment), offsets in pairs.items():
            offsets.sort()
            run_start = run_previous = offsets[0]
            for pair in offsets[1:] + [(None, None)]:
                if pair[0] is not None and pair[0] == run_previous[0] + 1 and pair[1] == run_previous[1] + 1:
                    run_previous = pair
                    continue
                matched_bytes = run_previous[0] - run_start[0] + window
                if matched_bytes >= minimum:
                    reference = database["references"][reference_index]
                    candidate = {
                        "reference": reference["name"],
                        "reference_class": reference["reference_class"],
                        "reference_sha256": reference["sha256"],
                        "reference_size": reference["size"],
                        "matched_bytes": matched_bytes,
                        "reference_offset": run_start[1],
                        "observed_chunk_start": first_chunk,
                        "observed_chunk_end": last_chunk,
                        "observed_segment_offset": run_start[0],
                    }
                    prior = best.get(reference_index)
                    if prior is None or candidate["matched_bytes"] > prior["matched_bytes"]:
                        best[reference_index] = candidate
                run_start = run_previous = pair
                if pair[0] is None:
                    break
    return [best[index] for index in sorted(best)]


def _classify_canonical_matches(matches):
    """Turn reference matches into policy without inferring hostility from inclusion."""
    if not matches:
        return [], []
    classes = sorted(set(match["reference_class"] for match in matches))
    if "malicious" in classes:
        return [{
            "rule_id": "S5",
            "severity": "high",
            "finding": "known_content_inclusion",
            "reference_classes": classes,
            "detail": "Observed message data matches an explicitly malicious canonical reference.",
        }], []
    school_control = classes == ["test"]
    return [], [{
        "rule_id": "S5",
        "severity": "informational",
        "observation": "known_content_inclusion",
        "reference_classes": classes,
        "disposition": "school_control" if school_control else "inclusion_only",
        "detail": ("Observed message data matches a classified school control."
                   if school_control else
                   "Observed message data matches a classified benign reference."),
    }]


def xor_chunks(chunks):
    width = max((len(chunk) for chunk in chunks), default=0)
    output = bytearray(width)
    for chunk in chunks:
        for offset, value in enumerate(chunk):
            output[offset] ^= value
    return bytes(output)


def _decode_payload(row):
    encoded = row.get("payload_b64")
    if not isinstance(encoded, str):
        raise ValueError("payload_b64 must be a base64 string")
    try:
        payload = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("payload_b64 is not valid base64")
    if len(payload) > MAX_CHUNK_BYTES:
        raise ValueError("chunk exceeds %d byte safety limit" % MAX_CHUNK_BYTES)
    return payload


class StreamState:
    def __init__(self, stream_id):
        self.stream_id = stream_id
        self.data_chunks = None
        self.chunks = {}
        self.parity = None
        self.chunk_lengths = None
        self.expected_sha256 = None
        self.duplicates = []
        self.conflicts = []
        self.corrupt = []
        self.invalid = []

    def _set_total(self, value):
        if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 4096:
            self.invalid.append("data_chunks must be an integer from 1 to 4096")
            return False
        if self.data_chunks is not None and self.data_chunks != value:
            self.conflicts.append("data_chunks changed from %d to %d" % (self.data_chunks, value))
            return False
        self.data_chunks = value
        return True

    def add(self, row):
        if not self._set_total(row.get("data_chunks")):
            return
        kind = row.get("kind")
        if kind == "manifest":
            expected = row.get("whole_sha256")
            if expected is not None and (not isinstance(expected, str) or
                                         len(expected) != 64 or
                                         any(c not in "0123456789abcdefABCDEF" for c in expected)):
                self.invalid.append("manifest whole_sha256 is not a SHA-256 hex digest")
                return
            expected = expected.lower() if expected else None
            if self.expected_sha256 and expected and self.expected_sha256 != expected:
                self.conflicts.append("conflicting manifest hashes")
            elif expected:
                self.expected_sha256 = expected
            return
        if kind not in ("data", "xor_parity"):
            self.invalid.append("unsupported chunk kind %r" % kind)
            return
        try:
            payload = _decode_payload(row)
        except ValueError as exc:
            self.invalid.append(str(exc))
            return
        claimed = row.get("sha256")
        actual = sha256(payload)
        if claimed and str(claimed).lower() != actual:
            label = row.get("index") if kind == "data" else "parity"
            self.corrupt.append(label)
            return
        if kind == "xor_parity":
            lengths = row.get("chunk_lengths")
            if not isinstance(lengths, list) or len(lengths) != self.data_chunks or not all(
                    isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= MAX_CHUNK_BYTES for v in lengths):
                self.invalid.append("xor_parity requires one valid chunk_lengths entry per data chunk")
                return
            if self.parity is not None and (self.parity != payload or self.chunk_lengths != lengths):
                self.conflicts.append("conflicting XOR parity chunks")
            else:
                self.parity, self.chunk_lengths = payload, lengths
            return
        index = row.get("index")
        if not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < self.data_chunks:
            self.invalid.append("data chunk index is outside the declared range")
            return
        if index in self.chunks:
            if self.chunks[index] == payload:
                self.duplicates.append(index)
            else:
                self.conflicts.append("chunk %d arrived with different bytes" % index)
            return
        self.chunks[index] = payload

    def report(self, denylist=None, signature_db=None):
        denylist = denylist or set()
        expected = self.data_chunks or 0
        missing = [index for index in range(expected) if index not in self.chunks]
        recovered_index = None
        working = dict(self.chunks)
        if len(missing) == 1 and self.parity is not None and self.chunk_lengths is not None:
            candidate = xor_chunks([self.parity] + list(working.values()))
            recovered_index = missing[0]
            working[recovered_index] = candidate[:self.chunk_lengths[recovered_index]]
            missing = []
        complete = bool(expected) and not missing and len(working) == expected
        payload = b"".join(working[index] for index in range(expected)) if complete else None
        digest = sha256(payload) if payload is not None else None
        findings = []
        observations = []
        gaps = []
        if self.corrupt:
            findings.append({"rule_id": "S1", "severity": "high", "finding": "chunk_hash_mismatch",
                             "detail": "One or more chunks failed their declared SHA-256 checksum."})
        if self.conflicts:
            findings.append({"rule_id": "S2", "severity": "high", "finding": "conflicting_chunk_evidence",
                             "detail": "The same stream metadata or chunk index carried conflicting values."})
        canonical_matches = match_canonical_content(working if complete else self.chunks, signature_db)
        canonical_findings, canonical_observations = _classify_canonical_matches(canonical_matches)
        findings.extend(canonical_findings)
        observations.extend(canonical_observations)
        if digest and digest in denylist:
            findings.append({"rule_id": "S3", "severity": "critical", "finding": "denylisted_whole_hash",
                             "detail": "The complete reconstructed stream matches a supplied SHA-256 denylist."})
        hash_verdict = "not_provided"
        if self.expected_sha256:
            if digest is None:
                hash_verdict = "not_computable"
            elif digest == self.expected_sha256:
                hash_verdict = "verified"
            else:
                hash_verdict = "mismatch"
                findings.append({"rule_id": "S4", "severity": "high", "finding": "manifest_hash_mismatch",
                                 "detail": "The reconstructed stream does not match its declared whole SHA-256."})
        if missing:
            gaps.append({"gap": "missing_chunks", "detail": "Whole-stream hashing is impossible without all data chunks.",
                         "missing_indices": missing})
        if self.invalid:
            gaps.append({"gap": "invalid_events", "detail": "Some input rows could not be trusted.",
                         "errors": list(self.invalid)})
        status = "suspicious" if findings else ("inconclusive" if gaps else "clean")
        reconstruction = "recovered" if recovered_index is not None else ("complete" if complete else "partial")
        return {
            "stream_id": self.stream_id,
            "status": status,
            "reconstruction": reconstruction,
            "expected_data_chunks": expected,
            "received_data_chunks": sorted(self.chunks),
            "missing_data_chunks": missing,
            "recovered_chunk": recovered_index,
            "coverage": (len(self.chunks) / expected) if expected else 0.0,
            "parity_observed": self.parity is not None,
            "transport_chunks_received": len(self.chunks) + (1 if self.parity is not None else 0),
            "transport_chunks_expected": expected + (1 if self.parity is not None else 0),
            "transport_coverage": ((len(self.chunks) + (1 if self.parity is not None else 0)) /
                                   (expected + (1 if self.parity is not None else 0))) if expected else 0.0,
            "observed_bytes": sum(len(value) for value in self.chunks.values()),
            "reconstructed_bytes": len(payload) if payload is not None else None,
            "whole_sha256": digest,
            "manifest_sha256": self.expected_sha256,
            "manifest_verdict": hash_verdict,
            "duplicate_indices": sorted(set(self.duplicates)),
            "corrupt_indices": self.corrupt,
            "canonical_matches": canonical_matches,
            "findings": findings,
            "observations": observations,
            "gaps": gaps,
            "confidence": "full" if complete else "limited",
            "containment": "endpoint policy required" if any(
                f["finding"] in ("denylisted_whole_hash", "known_content_inclusion") for f in findings) else "none",
        }


def _gf_mul(a, b):
    """Multiply bytes in GF(2^8) with the Reed-Solomon polynomial 0x11d."""
    result = 0
    while b:
        if b & 1:
            result ^= a
        b >>= 1
        a <<= 1
        if a & 0x100:
            a ^= 0x11D
    return result


def _gf_pow(value, exponent):
    result = 1
    while exponent:
        if exponent & 1:
            result = _gf_mul(result, value)
        value = _gf_mul(value, value)
        exponent >>= 1
    return result


def _gf_inv(value):
    if not value:
        raise ValueError("singular Reed-Solomon matrix")
    return _gf_pow(value, 254)


RS_FIELD_POLYNOMIAL = 0x11D

# These are generator rows G0..G5.  They are deliberately not called C0..C5:
# C labels belong to the separate experimental control/witness arms.
RS_GENERATOR = (
    (1, 0, 0, 0),
    (0, 1, 0, 0),
    (0, 0, 1, 0),
    (0, 0, 0, 1),
    (1, 1, 1, 1),
    (1, 2, 4, 8),
)

DARKROCK_CUSTOM_GENERATOR = (
    (1, 0, 0, 0),
    (0, 1, 0, 0),
    (0, 0, 1, 0),
    (0, 0, 0, 1),
    (1, 1, 1, 1),
    (1, 2, 3, 4),
)


def _generator_manifest(name, generator):
    formula = {
        "schema": "daybreak-gf256-generator/v1",
        "name": name,
        "field_polynomial": "0x11d",
        "generator_rows": [list(row) for row in generator],
        "row_labels": ["G%d" % index for index in range(6)],
        "zero_elimination": False,
    }
    encoded = json.dumps(formula, sort_keys=True, separators=(",", ":")).encode("utf-8")
    formula["formula_sha256"] = sha256(encoded)
    return formula


def _validate_generator(generator):
    if (not isinstance(generator, (list, tuple)) or len(generator) != 6 or
            any(not isinstance(row, (list, tuple)) or len(row) != 4 for row in generator)):
        raise ValueError("GF(256) generator must contain six rows of four coefficients")
    normalized = []
    for row in generator:
        if any(not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 255
               for value in row):
            raise ValueError("GF(256) generator coefficients must be bytes")
        normalized.append(tuple(row))
    normalized = tuple(normalized)
    if normalized[:4] != RS_GENERATOR[:4]:
        raise ValueError("GF(256) 4+2 generator must use four systematic data rows")
    for selected in combinations(range(6), 4):
        _invert_matrix([normalized[index] for index in selected])
    return normalized


def _parse_generator_manifest(value):
    if not isinstance(value, dict):
        raise ValueError("manifest requires an explicit codec formula")
    if value.get("schema") != "daybreak-gf256-generator/v1":
        raise ValueError("unsupported codec formula schema")
    if str(value.get("field_polynomial", "")).lower() != "0x11d":
        raise ValueError("codec formula requires GF(256) polynomial 0x11d")
    if value.get("zero_elimination") is not False:
        raise ValueError("codec formula must preserve zero coefficients and zero bytes")
    generator = _validate_generator(value.get("generator_rows"))
    expected_labels = ["G%d" % index for index in range(6)]
    if value.get("row_labels") != expected_labels:
        raise ValueError("codec formula rows must be labeled G0 through G5")
    name = value.get("name")
    if not isinstance(name, str) or not name or len(name) > 100:
        raise ValueError("codec formula requires a short name")
    expected = _generator_manifest(name, generator)["formula_sha256"]
    if value.get("formula_sha256") != expected:
        raise ValueError("codec formula SHA-256 does not match its canonical definition")
    return name, generator


def _invert_matrix(matrix):
    size = len(matrix)
    work = [list(row) + [1 if i == j else 0 for j in range(size)]
            for i, row in enumerate(matrix)]
    for column in range(size):
        pivot = next((row for row in range(column, size) if work[row][column]), None)
        if pivot is None:
            raise ValueError("singular Reed-Solomon matrix")
        work[column], work[pivot] = work[pivot], work[column]
        factor = _gf_inv(work[column][column])
        work[column] = [_gf_mul(value, factor) for value in work[column]]
        for row in range(size):
            if row == column or not work[row][column]:
                continue
            factor = work[row][column]
            work[row] = [value ^ _gf_mul(factor, pivot_value)
                         for value, pivot_value in zip(work[row], work[column])]
    return [row[size:] for row in work]


def _matrix_shards(matrix, shards):
    width = len(shards[0])
    output = []
    for coefficients in matrix:
        target = bytearray(width)
        for coefficient, shard in zip(coefficients, shards):
            if coefficient == 1:
                for offset, value in enumerate(shard):
                    target[offset] ^= value
            elif coefficient:
                for offset, value in enumerate(shard):
                    target[offset] ^= _gf_mul(coefficient, value)
        output.append(bytes(target))
    return output


def rs_encode_4_2(payload, generator=RS_GENERATOR):
    generator = _validate_generator(generator)
    share_len = (len(payload) + 3) // 4
    padded = payload + bytes(share_len * 4 - len(payload))
    data = [padded[index * share_len:(index + 1) * share_len] for index in range(4)]
    parity = _matrix_shards(generator[4:], data)
    return data + parity


def rs_recover_4_2(shares, generator=RS_GENERATOR):
    if len(shares) < 4:
        return None
    generator = _validate_generator(generator)
    selected = sorted(shares)[:4]
    width = len(shares[selected[0]])
    if any(len(shares[index]) != width for index in selected):
        raise ValueError("Reed-Solomon shares have different lengths")
    inverse = _invert_matrix([generator[index] for index in selected])
    return _matrix_shards(inverse, [shares[index] for index in selected])


def compare_rs_generators(payload):
    """Compare defined 4+2 matrices by exact recovery and parity diffusion."""
    if not payload:
        raise ValueError("comparison input is empty")
    variants = (
        ("daybreak-powers", RS_GENERATOR),
        ("darkrock-custom", DARKROCK_CUSTOM_GENERATOR),
    )
    encoded = {}
    results = []
    for name, generator in variants:
        shares = rs_encode_4_2(payload, generator)
        encoded[name] = shares
        one_loss = two_loss = 0
        for missing_count in (1, 2):
            for missing in combinations(range(6), missing_count):
                observed = {index: share for index, share in enumerate(shares) if index not in missing}
                restored = b"".join(rs_recover_4_2(observed, generator))[:len(payload)]
                if restored == payload:
                    if missing_count == 1:
                        one_loss += 1
                    else:
                        two_loss += 1
        parity = b"".join(shares[4:])
        results.append({
            "formula": _generator_manifest(name, generator),
            "input_bytes": len(payload),
            "input_sha256": sha256(payload),
            "parity_sha256": sha256(parity),
            "one_share_loss_exact": one_loss,
            "one_share_loss_cases": 6,
            "two_share_loss_exact": two_loss,
            "two_share_loss_cases": 15,
            "all_rebuilds_exact": one_loss == 6 and two_loss == 15,
        })
    left = b"".join(encoded[variants[0][0]][4:])
    right = b"".join(encoded[variants[1][0]][4:])
    byte_differences = sum(a != b for a, b in zip(left, right))
    bit_differences = sum(bin(a ^ b).count("1") for a, b in zip(left, right))
    return {
        "schema": "daybreak-gf256-comparison/v1",
        "interpretation": "G0-G5 are codec generator rows; C0-C5 control arms are a separate experiment",
        "zero_elimination": False,
        "variants": results,
        "parity_comparison": {
            "bytes_compared": len(left),
            "different_bytes": byte_differences,
            "different_bits": bit_differences,
        },
    }


class RSStreamState:
    """One RedTail-X-style 4+2 stripe represented as explicit message events."""
    def __init__(self, stream_id):
        self.stream_id = stream_id
        self.original_len = None
        self.share_len = None
        self.expected_sha256 = None
        self.share_hashes = None
        self.codec_name = None
        self.generator = None
        self.shares = {}
        self.duplicates = []
        self.conflicts = []
        self.corrupt = []
        self.invalid = []

    def add(self, row):
        if row.get("coding") != "rs-4+2":
            self.conflicts.append("stream coding changed")
            return
        if row.get("kind") == "manifest":
            original_len, share_len = row.get("original_len"), row.get("share_len")
            hashes = row.get("share_sha256")
            expected = row.get("whole_sha256")
            valid_hash = lambda value: isinstance(value, str) and len(value) == 64 and all(
                char in "0123456789abcdefABCDEF" for char in value)
            if (not isinstance(original_len, int) or isinstance(original_len, bool) or original_len < 1 or
                    not isinstance(share_len, int) or isinstance(share_len, bool) or share_len < 1 or
                    share_len != (original_len + 3) // 4):
                self.invalid.append("manifest has invalid RedTail-X original_len/share_len")
                return
            if not valid_hash(expected) or not isinstance(hashes, list) or len(hashes) != 6 or not all(
                    valid_hash(value) for value in hashes):
                self.invalid.append("manifest requires one whole hash and six valid share hashes")
                return
            try:
                codec_name, generator = _parse_generator_manifest(row.get("codec_formula"))
            except ValueError as exc:
                self.invalid.append(str(exc))
                return
            values = (original_len, share_len, expected.lower(), [value.lower() for value in hashes],
                      codec_name, generator)
            prior = (self.original_len, self.share_len, self.expected_sha256, self.share_hashes,
                     self.codec_name, self.generator)
            if self.original_len is not None and prior != values:
                self.conflicts.append("conflicting RedTail-X manifests")
            else:
                (self.original_len, self.share_len, self.expected_sha256, self.share_hashes,
                 self.codec_name, self.generator) = values
            return
        if row.get("kind") != "rs_share":
            self.invalid.append("unsupported RedTail-X event kind %r" % row.get("kind"))
            return
        index = row.get("index")
        if not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < 6:
            self.invalid.append("Reed-Solomon share index must be from 0 to 5")
            return
        try:
            payload = _decode_payload(row)
        except ValueError as exc:
            self.invalid.append(str(exc))
            return
        if self.share_len is not None and len(payload) != self.share_len:
            self.corrupt.append(index)
            return
        claimed = row.get("sha256")
        actual = sha256(payload)
        if claimed and str(claimed).lower() != actual:
            self.corrupt.append(index)
            return
        if self.share_hashes is not None and self.share_hashes[index] != actual:
            self.corrupt.append(index)
            return
        if index in self.shares:
            if self.shares[index] == payload:
                self.duplicates.append(index)
            else:
                self.conflicts.append("share %d arrived with different bytes" % index)
            return
        self.shares[index] = payload

    def report(self, denylist=None, signature_db=None):
        denylist = denylist or set()
        findings, gaps = [], []
        data = None
        if self.original_len is not None and len(self.shares) >= 4:
            try:
                data = rs_recover_4_2(self.shares, self.generator)
            except ValueError as exc:
                self.conflicts.append(str(exc))
        payload = b"".join(data)[:self.original_len] if data is not None else None
        digest = sha256(payload) if payload is not None else None
        verdict = "not_computable" if self.expected_sha256 and digest is None else "not_provided"
        if digest is not None and self.expected_sha256:
            verdict = "verified" if digest == self.expected_sha256 else "mismatch"
        if self.corrupt:
            findings.append({"rule_id": "S1", "severity": "high", "finding": "chunk_hash_mismatch",
                             "detail": "One or more shares failed the manifest SHA-256."})
        if self.conflicts:
            findings.append({"rule_id": "S2", "severity": "high", "finding": "conflicting_chunk_evidence",
                             "detail": "The same stream metadata or share index carried conflicting values."})
        if digest and digest in denylist:
            findings.append({"rule_id": "S3", "severity": "critical", "finding": "denylisted_whole_hash",
                             "detail": "The reconstructed stream matches a supplied SHA-256 denylist."})
        if verdict == "mismatch":
            findings.append({"rule_id": "S4", "severity": "high", "finding": "manifest_hash_mismatch",
                             "detail": "Four available shares reconstructed bytes that do not match the manifest."})
        match_chunks = {index: shard for index, shard in enumerate(data)} if data is not None else {
            index: shard for index, shard in self.shares.items() if index < 4}
        canonical_matches = match_canonical_content(match_chunks, signature_db)
        observations = []
        canonical_findings, canonical_observations = _classify_canonical_matches(canonical_matches)
        findings.extend(canonical_findings)
        observations.extend(canonical_observations)
        missing_shares = [index for index in range(6) if index not in self.shares]
        missing_data = [index for index in range(4) if index not in self.shares]
        if payload is None:
            gaps.append({"gap": "insufficient_rs_shares",
                         "detail": "RedTail-X 4+2 requires any four valid shares for reconstruction.",
                         "missing_indices": missing_shares})
        if self.invalid:
            gaps.append({"gap": "invalid_events", "detail": "Some input rows could not be trusted.",
                         "errors": list(self.invalid)})
        status = "suspicious" if findings else ("inconclusive" if gaps else "clean")
        recovered = payload is not None and bool(missing_data)
        return {
            "stream_id": self.stream_id,
            "coding": "rs-4+2",
            "codec_formula": _generator_manifest(self.codec_name, self.generator) if self.generator else None,
            "status": status,
            "reconstruction": "recovered" if recovered else ("complete" if payload is not None else "partial"),
            "expected_data_chunks": 4,
            "received_data_chunks": sorted(index for index in self.shares if index < 4),
            "missing_data_chunks": missing_data if payload is None else [],
            "recovered_chunks": missing_data if recovered else [],
            "received_share_indices": sorted(self.shares),
            "missing_share_indices": missing_shares,
            "coverage": len([index for index in self.shares if index < 4]) / 4,
            "parity_observed": any(index >= 4 for index in self.shares),
            "transport_chunks_received": len(self.shares),
            "transport_chunks_expected": 6,
            "transport_coverage": len(self.shares) / 6,
            "observed_bytes": sum(len(value) for value in self.shares.values()),
            "reconstructed_bytes": len(payload) if payload is not None else None,
            "whole_sha256": digest,
            "manifest_sha256": self.expected_sha256,
            "manifest_verdict": verdict,
            "duplicate_indices": sorted(set(self.duplicates)),
            "corrupt_indices": sorted(set(self.corrupt)),
            "canonical_matches": canonical_matches,
            "findings": findings,
            "observations": observations,
            "gaps": gaps,
            "confidence": "full" if verdict == "verified" else "limited",
            "containment": "endpoint policy required" if any(
                item["finding"] in ("denylisted_whole_hash", "known_content_inclusion") for item in findings) else "none",
        }


def analyze(rows, denylist=None, signature_db=None):
    states = {}
    global_errors = []
    for number, row in enumerate(rows, 1):
        if not isinstance(row, dict):
            global_errors.append("row %d is not an object" % number)
            continue
        stream_id = row.get("stream_id")
        if not isinstance(stream_id, str) or not stream_id or len(stream_id) > 200:
            global_errors.append("row %d has no valid stream_id" % number)
            continue
        coding = row.get("coding")
        wanted = RSStreamState if coding == "rs-4+2" else StreamState
        if stream_id not in states:
            states[stream_id] = wanted(stream_id)
        elif not isinstance(states[stream_id], wanted):
            states[stream_id].conflicts.append("stream coding changed")
            continue
        states[stream_id].add(row)
    reports = [states[key].report(denylist, signature_db) for key in sorted(states)]
    if global_errors:
        reports.append({"stream_id": None, "status": "inconclusive", "reconstruction": "none",
                        "findings": [], "gaps": [{"gap": "invalid_rows", "errors": global_errors}],
                        "confidence": "limited"})
    return reports


def read_jsonl(path):
    stream = sys.stdin if path == "-" else open(path, encoding="utf-8")
    try:
        for number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except ValueError as exc:
                yield {"stream_id": "input-errors", "kind": "invalid", "data_chunks": 1,
                       "_error": "%s:%d: %s" % (path, number, exc)}
    finally:
        if stream is not sys.stdin:
            stream.close()


def load_denylist(path):
    if not path:
        return set()
    values = set()
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            value = line.split("#", 1)[0].strip().lower()
            if value:
                if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                    raise ValueError("denylist contains a non-SHA-256 value")
                values.add(value)
    return values


def to_siem_event(report, host=None):
    """Normalized JSON suitable for a file/syslog collector or LogScale JSON ingest."""
    severities = {finding.get("severity") for finding in report.get("findings", [])}
    severity = "critical" if "critical" in severities else ("high" if "high" in severities else
               ("warning" if report.get("status") == "inconclusive" else "informational"))
    evidence = report.get("findings", []) + report.get("observations", [])
    return {
        "@timestamp": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "event.kind": "alert" if report.get("status") == "suspicious" else "event",
        "event.category": "network",
        "event.type": "info",
        "event.module": "daybreak_stream",
        "event.dataset": "daybreak.stream_integrity",
        "event.severity": severity,
        "host.name": host or socket.gethostname(),
        "observer.product": "Detection Lab",
        "stream.id": report.get("stream_id"),
        "stream.status": report.get("status"),
        "stream.reconstruction": report.get("reconstruction"),
        "stream.coverage": report.get("coverage"),
        "stream.transport_coverage": report.get("transport_coverage"),
        "stream.received_indices": report.get("received_data_chunks", []),
        "stream.missing_indices": report.get("missing_data_chunks", []),
        "stream.recovered_index": report.get("recovered_chunk"),
        "stream.recovered_indices": report.get("recovered_chunks", []),
        "stream.coding": report.get("coding", "uncoded-or-xor"),
        "stream.manifest_verdict": report.get("manifest_verdict"),
        "stream.canonical_matches": report.get("canonical_matches", []),
        "file.hash.sha256": report.get("whole_sha256"),
        "rule.ids": [item.get("rule_id") for item in evidence],
        "findings": report.get("findings", []),
        "observations": report.get("observations", []),
        "gaps": report.get("gaps", []),
        "containment": report.get("containment", "none"),
    }


def _syslog_escape(value):
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def to_syslog(event):
    """RFC 5424-style local0 line; emission only, with no network side effect."""
    severity = event.get("event.severity")
    syslog_severity = {"critical": 2, "high": 3, "warning": 4}.get(severity, 6)
    priority = 16 * 8 + syslog_severity  # local0 facility
    structured = '[daybreak@32473 stream_id="%s" status="%s" reconstruction="%s" coverage="%s"]' % (
        _syslog_escape(event.get("stream.id") or "unknown"),
        _syslog_escape(event.get("stream.status") or "unknown"),
        _syslog_escape(event.get("stream.reconstruction") or "unknown"),
        _syslog_escape(event.get("stream.transport_coverage")),
    )
    message = json.dumps(event, sort_keys=True, separators=(",", ":"))
    return "<%d>1 %s %s daybreak-siem - STREAM_INTEGRITY %s %s" % (
        priority, event["@timestamp"], event["host.name"], structured, message)


def make_simulation(data_chunks=5, drop=None, include_parity=False, stream_id="school-demo"):
    payload = (b"Authorized school lab stream. This is synthetic evidence for defensive analysis only. "
               b"The whole-file hash is available only after complete reconstruction.")
    width = (len(payload) + data_chunks - 1) // data_chunks
    chunks = [payload[index * width:(index + 1) * width] for index in range(data_chunks)]
    rows = [{"stream_id": stream_id, "kind": "manifest", "data_chunks": data_chunks,
             "whole_sha256": sha256(payload)}]
    for index, chunk in enumerate(chunks):
        if index == drop:
            continue
        rows.append({"stream_id": stream_id, "kind": "data", "index": index, "data_chunks": data_chunks,
                     "payload_b64": base64.b64encode(chunk).decode("ascii"), "sha256": sha256(chunk)})
    if include_parity:
        parity = xor_chunks(chunks)
        rows.append({"stream_id": stream_id, "kind": "xor_parity", "data_chunks": data_chunks,
                     "payload_b64": base64.b64encode(parity).decode("ascii"), "sha256": sha256(parity),
                     "chunk_lengths": [len(chunk) for chunk in chunks]})
    return rows


def make_file_envelope(path, data_chunks=8, drops=None, stream_id=None):
    """Wrap an existing file as explicit lab messages without executing it."""
    with open(path, "rb") as fh:
        payload = fh.read()
    if not payload:
        raise ValueError("input file is empty")
    if not 1 <= data_chunks <= 4096:
        raise ValueError("data_chunks must be from 1 to 4096")
    width = (len(payload) + data_chunks - 1) // data_chunks
    chunks = [payload[offset:offset + width] for offset in range(0, len(payload), width)]
    data_chunks = len(chunks)
    drops = set(drops or [])
    if any(index < 0 or index >= data_chunks for index in drops):
        raise ValueError("drop index is outside the generated chunk range")
    identifier = stream_id or "file-" + sha256(payload)[:16]
    rows = [{"stream_id": identifier, "kind": "manifest", "data_chunks": data_chunks,
             "whole_sha256": sha256(payload), "file_name": os.path.basename(path)}]
    for index, chunk in enumerate(chunks):
        if index in drops:
            continue
        rows.append({"stream_id": identifier, "kind": "data", "index": index,
                     "data_chunks": data_chunks, "payload_b64": base64.b64encode(chunk).decode("ascii"),
                     "sha256": sha256(chunk)})
    return rows


def make_rs_simulation(drops=None, stream_id="school-rs-demo", generator=RS_GENERATOR,
                       codec_name="daybreak-powers"):
    payload = (b"Authorized RedTail-X school lab stripe. Four data shares plus two parity shares "
               b"permit reconstruction from any four valid shares. No executable content is used.")
    generator = _validate_generator(generator)
    shares = rs_encode_4_2(payload, generator)
    drops = set(drops or [])
    rows = [{
        "stream_id": stream_id,
        "kind": "manifest",
        "coding": "rs-4+2",
        "original_len": len(payload),
        "share_len": len(shares[0]),
        "whole_sha256": sha256(payload),
        "share_sha256": [sha256(share) for share in shares],
        "codec_formula": _generator_manifest(codec_name, generator),
    }]
    for index, share in enumerate(shares):
        if index in drops:
            continue
        rows.append({"stream_id": stream_id, "kind": "rs_share", "coding": "rs-4+2", "index": index,
                     "payload_b64": base64.b64encode(share).decode("ascii"), "sha256": sha256(share)})
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser(prog="dl stream", description="Analyze explicit chunk envelopes offline")
    commands = parser.add_subparsers(dest="command", required=True)
    analyze_parser = commands.add_parser("analyze", help="analyze chunk JSONL")
    analyze_parser.add_argument("input", help="JSONL file, or - for stdin")
    analyze_parser.add_argument("--denylist", help="file containing one SHA-256 digest per line")
    analyze_parser.add_argument("--signature-db", help="canonical content signature database")
    analyze_parser.add_argument("--pretty", action="store_true")
    analyze_parser.add_argument("--format", choices=("report", "siem-json", "syslog"), default="report",
                                help="stdout format; no network connection is made")
    simulate_parser = commands.add_parser("simulate", help="emit harmless synthetic chunk JSONL")
    simulate_parser.add_argument("--data-chunks", type=int, default=5)
    simulate_parser.add_argument("--drop", type=int)
    simulate_parser.add_argument("--parity", action="store_true")
    envelope_parser = commands.add_parser("envelope", help="wrap a file as explicit lab message chunks")
    envelope_parser.add_argument("input")
    envelope_parser.add_argument("--data-chunks", type=int, default=8)
    envelope_parser.add_argument("--drop", type=int, action="append", default=[])
    envelope_parser.add_argument("--stream-id")
    rs_parser = commands.add_parser("simulate-rs", help="emit a harmless RedTail-X 4+2 stripe")
    rs_parser.add_argument("--drop", type=int, action="append", default=[],
                           help="share index 0..5 to omit; repeat to omit two")
    compare_parser = commands.add_parser(
        "compare-matrices", help="compare the defined GF(256) 4+2 generator matrices")
    compare_parser.add_argument("--input", help="optional file to read as inert comparison bytes")
    compare_parser.add_argument("--pretty", action="store_true")
    canonize_parser = commands.add_parser("canonize", help="build known-content signatures from references")
    canonize_parser.add_argument("references", nargs="+")
    canonize_parser.add_argument("--output", required=True)
    canonize_parser.add_argument("--window-bytes", type=int, default=32)
    canonize_parser.add_argument("--min-match-bytes", type=int, default=64)
    canonize_parser.add_argument("--reference-class", choices=REFERENCE_CLASSES, default="test",
                                 help="policy class for these references (default: test)")
    args = parser.parse_args(argv)
    if args.command == "simulate":
        if not 1 <= args.data_chunks <= 100:
            parser.error("--data-chunks must be from 1 to 100")
        if args.drop is not None and not 0 <= args.drop < args.data_chunks:
            parser.error("--drop must identify a data chunk")
        for row in make_simulation(args.data_chunks, args.drop, args.parity):
            print(json.dumps(row, sort_keys=True))
        return 0
    if args.command == "simulate-rs":
        if len(set(args.drop)) != len(args.drop) or len(args.drop) > 2 or any(
                index < 0 or index > 5 for index in args.drop):
            parser.error("--drop may identify up to two different share indices from 0 to 5")
        for row in make_rs_simulation(args.drop):
            print(json.dumps(row, sort_keys=True))
        return 0
    if args.command == "compare-matrices":
        try:
            if args.input:
                with open(args.input, "rb") as fh:
                    payload = fh.read()
            else:
                payload = (b"Authorized formula comparison input. Exact bytes, including zero bytes, "
                           b"must survive every supported one-share and two-share loss.\0\0")
            comparison = compare_rs_generators(payload)
        except (OSError, ValueError) as exc:
            print("dl stream: %s" % exc, file=sys.stderr)
            return 2
        print(json.dumps(comparison, indent=2 if args.pretty else None, sort_keys=True))
        return 0
    if args.command == "envelope":
        try:
            rows = make_file_envelope(args.input, args.data_chunks, args.drop, args.stream_id)
        except (OSError, ValueError) as exc:
            print("dl stream: %s" % exc, file=sys.stderr)
            return 2
        for row in rows:
            print(json.dumps(row, sort_keys=True))
        return 0
    if args.command == "canonize":
        try:
            database = build_signature_db(args.references, args.window_bytes, args.min_match_bytes,
                                          args.reference_class)
            write_signature_db(database, args.output)
        except (OSError, ValueError) as exc:
            print("dl stream: %s" % exc, file=sys.stderr)
            return 2
        summary = {"output": args.output, "references": len(database["references"]),
                   "reference_class": args.reference_class,
                   "window_bytes": database["window_bytes"],
                   "min_match_bytes": database["min_match_bytes"],
                   "window_count": sum(item["window_count"] for item in database["references"])}
        print(json.dumps(summary, sort_keys=True))
        return 0
    try:
        reports = analyze(read_jsonl(args.input), load_denylist(args.denylist),
                          load_signature_db(args.signature_db))
    except (OSError, ValueError) as exc:
        print("dl stream: %s" % exc, file=sys.stderr)
        return 2
    if args.format == "siem-json":
        for report in reports:
            print(json.dumps(to_siem_event(report), indent=2 if args.pretty else None, sort_keys=True))
    elif args.format == "syslog":
        for report in reports:
            print(to_syslog(to_siem_event(report)))
    elif args.pretty:
        print(json.dumps(reports, indent=2, sort_keys=True))
    else:
        for report in reports:
            print(json.dumps(report, sort_keys=True))
    statuses = {report["status"] for report in reports}
    return 3 if "suspicious" in statuses else (1 if "inconclusive" in statuses else 0)


if __name__ == "__main__":
    sys.exit(main())
