# REJECTION_TAXONOMY.md — Rejection Taxonomy

**Version:** 1.0  
**Phase:** 0

---

## Purpose

A rejection means an adapter could not produce a usable canonical event from the input (or from part of the input in MIXED mode). Every rejection must use one of these types. The set is closed.

---

## MALFORMED

The input violates the format the adapter expects.

**Examples:**
- JSON that is not syntactically valid.
- A field that must be a string contains an integer.
- A timestamp that cannot be parsed by any supported format.
- NaN or Infinity in a numeric field.
- Bytes that are not valid UTF-8.

---

## UNVERIFIABLE

The input contains a claim that cannot be checked given available information.

**Examples:**
- An event claims `AUTHENTICATED_SOURCE` but carries no credential, signature, or token.
- A record references an external ID that would require a network call to verify (and the adapter operates offline-only).

**Note:** UNVERIFIABLE is not the same as false. It means the claim cannot be checked, not that it is wrong.

---

## INCOMPLETE

Required information is missing.

**Examples:**
- A sensor reading record lacks a `device_id` field.
- A required profile field has no value and no fallback.
- An AI inference request has no `model` field.
- The `event_type` field is absent.

---

## INCONSISTENT

The input contains self-contradictory information.

**Examples:**
- `start_time` is after `end_time`.
- A state change record shows `from_state == to_state` when the system declares these must differ.
- A record claims GOOD quality for a measurement that is marked as from a failed sensor in the same payload.

---

## UNSUPPORTED

The adapter cannot handle this input type.

**Examples:**
- The JSON adapter received a Protocol Buffers binary payload.
- The file adapter received a ZIP archive rather than a line-delimited file.
- The OT adapter received a record_type it has no handler for and has no UNKNOWN_RECORD fallback configured.

**Note:** UNSUPPORTED is distinct from MALFORMED. MALFORMED means the adapter understands the format but the content is broken. UNSUPPORTED means the adapter does not handle this format or type at all.

---

## HOSTILE

The input appears designed to exploit or overload the adapter.

**Examples:**
- An array with 100,000 items (MAX_EVENTS_PER_INPUT exceeded).
- A nested JSON structure 50 levels deep (MAX_PAYLOAD_DEPTH exceeded).
- An input of 11 MiB (MAX_INPUT_BYTES exceeded).
- A string field containing 50,000 characters (MAX_STRING_FIELD_LEN exceeded without truncation being appropriate).
- A ZIP file with a 1 TB decompressed payload (detected by ZipGuard).
