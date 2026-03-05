# Spine v1 Specification

## Core Guarantees
- Append-only ledger
- Deterministic canonical JSON canonicalization
- SHA-256 hash chaining
- Sealed window commits
- SCAR event generation on abnormal shutdown
- Segment-aware verification

## Event Schema (Minimal)
{
  "event_id": "uuid",
  "timestamp_wall": "ISO8601",
  "timestamp_mono": "int_ns",
  "event_type": "string",
  "payload": {},
  "prev_hash": "hex",
  "hash": "hex"
}

## Window Rules
- Events grouped by window_id
- On seal:
  - Compute window_root_hash
  - Emit WINDOW_SEALED event
- No mutation allowed post-seal

## SCAR Events
Generated on:
- Dirty shutdown
- Ledger truncation
- Gap detection
