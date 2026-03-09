# DETERMINISM_RULES.md — Adapter Determinism Rules

**Version:** 1.0  
**Phase:** 0

---

## Purpose

Aletheia's core guarantee is that the same input always produces the same canonical record. This document specifies exactly how adapters must achieve this. Violating any rule here breaks reproducibility and undermines the integrity model.

---

## Rule 1 — Deterministic Input Hashing

**Rule:** Hash the raw input bytes with SHA256 before any decoding or parsing. Store this hash as `input_hash` in the result.

**Why:** If the input is modified after hashing, the hash will not match. The hash must be computed from the bytes as received, not from any parsed representation.

**Implementation:** `hash_raw_bytes(raw)` in `aletheia/adapters/base.py`.

**No exception:** The hash is always computed even when the input is rejected.

---

## Rule 2 — Deterministic Unicode Normalisation

**Rule:** All human-readable string fields are NFC-normalised before comparison, storage, or hashing. Use `normalise_unicode()` from `aletheia/adapters/determinism.py`.

**Why:** Unicode has multiple valid encodings for visually identical strings. `café` (precomposed) and `cafe` + combining accent (decomposed) are different byte sequences but the same string. NFC normalisation collapses these to a canonical form.

**Security:** This also prevents unicode confusion attacks where visually identical strings with different byte representations bypass string comparisons.

**Exception:** Device IDs, model version strings, and other externally-assigned identifiers are preserved exactly as provided — they are not normalised.

---

## Rule 3 — Deterministic Field Normalisation

**Rule:** Field name normalisation (for mapping profiles) uses `normalise_field_name()`: NFC → strip → lowercase → replace non-alnum/underscore → collapse underscores.

**Why:** External systems use inconsistent naming conventions. Normalisation must be deterministic so the same field name always maps to the same canonical name.

---

## Rule 4 — Deterministic Timestamp Policy

**Rule:** All timestamps are converted to ISO8601 UTC with Z suffix and second precision: `YYYY-MM-DDTHH:MM:SSZ`.

| Input form | Output | Ambiguous? |
|---|---|---|
| Unix epoch int/float | ISO8601 UTC Z | No |
| ISO8601 with Z suffix | Preserved | No |
| ISO8601 with +00:00 | Converted to Z | No |
| ISO8601 without timezone | UTC assumed, LOSS_OF_AUTHENTICITY recorded | Yes |
| Unparseable | `None`, loss recorded | — |

**Fallback:** If no timestamp is present in the source, no timestamp is invented. `time_wall` is omitted from the canonical event. The Spine assigns its own wall clock timestamp on append.

**Subsecond precision:** Dropped. Record LOSS_OF_PRECISION if subsecond data was present.

**Implementation:** `parse_timestamp()` in `aletheia/adapters/determinism.py`.

---

## Rule 5 — Deterministic Event Ordering

**Rule:** Events emitted from a single `adapt()` call are returned in the order they were produced. No sorting, no deduplication, no reordering.

**Why:** Order is provenance. Changing the order changes the meaning of the record.

**Streaming:** Within a `StreamBatch`, items are processed in arrival order. Late items are flagged but not reordered.

---

## Rule 6 — Deterministic Failure Outcomes

**Rule:** A rejection is never silently swallowed. Every parse failure, validation failure, or policy violation produces a `RejectionRecord` or `LossRecord` with a specific type and detail string.

**Rule:** The same malformed input always produces the same rejection type. Failure outcomes are not random or dependent on runtime state.

**Rule:** In STRICT mode (file adapter), the first failure stops processing and returns REJECTED. The failure reason is always the first error encountered, not a summary.

---

## Rule 7 — Deterministic Hashing for Content Integrity

**Rule:** When content hashing is enabled (e.g. AI audit adapter `hash_content=True`), hashes are computed as SHA256 of the UTF-8 encoded content string.

**Rule:** Batch hashes (streaming) are computed as SHA256 over the concatenation of item input hashes in arrival order.

**Why:** This makes batch integrity checkable without storing every item's content.

---

## Rule 8 — No Invented Data

**Rule:** An adapter never adds data to a payload that was not present in the source input.

**Permitted:** Fallback values declared in a profile (these are explicit, not invented).  
**Permitted:** Type coercion of a present value (e.g. "42" → 42).  
**Not permitted:** Defaulting a missing required field to a plausible value.  
**Not permitted:** Inferring a causal link that is not asserted by the source.

---

## Rule 9 — NaN and Infinity Prohibition

**Rule:** NaN and Infinity are never permitted in any payload field. Python's `json.loads` accepts bare `NaN` and `Infinity` as a non-standard extension; adapters must scan for and reject these after parsing.

**Implementation:** `_find_nan_inf()` in `json_adapter.py`.

---

## Rule 10 — Adapter Isolation

**Rule:** Each `adapt()` call is independent. An adapter holds no state between calls that could affect output determinism. Caches (e.g. profile cache) are read-only after initialisation.
