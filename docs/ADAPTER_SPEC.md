# ADAPTER_SPEC.md — Universal Adapter Contract

**Version:** 1.0  
**Phase:** 0 (Canonical Contract and Determinism Rules)

---

## Purpose

This document defines the universal adapter contract for the Aletheia ingestion boundary. Every adapter — present and future — must conform to this contract. No adapter may introduce behaviour not described here.

The contract exists because the adapter layer is where untrusted external data meets the Spine. The Spine is append-only and tamper-evident. Data that enters corrupted, ambiguous, or silently lossy corrupts the integrity record permanently. The adapter layer is the last point at which these problems can be caught and reported cleanly.

---

## Architecture Position

```
External World → [Adapter Layer] → [Ingest Gate] → [Spine Ledger]
```

- The Adapter Layer translates external data into canonical events.
- The Ingest Gate enforces admissibility (schema, size, rate).
- The Spine stores the tamper-evident record.

**No external data reaches the Spine without passing through both the adapter layer and the ingest gate.**

---

## Adapter Contract

An adapter is a Python class that:

1. Inherits from `AdapterBase` (`aletheia/adapters/base.py`).
2. Sets `NAME` (stable identifier), `VERSION` (semver string), `DEFAULT_TRUST`.
3. Implements `adapt(raw: bytes, *, profile=None) -> AdapterResult`.
4. Never raises exceptions from `adapt()` — all errors become rejections.
5. Never mutates the `raw` argument.
6. Always hashes `raw` before any processing (via `_start_result()`).
7. Always returns an `AdapterResult` — never `None`.

---

## Canonical Event Schema

Every event emitted by an adapter has this structure:

| Field | Type | Required | Description |
|---|---|---|---|
| `source` | string 1–64 | Yes | Stable origin identifier |
| `event_type` | string 1–64 | Yes | Uppercase underscore event type |
| `payload` | object | Yes | JSON-safe dict. No NaN or Infinity |
| `time_wall` | string | No | ISO8601 UTC, Z suffix, second precision |
| `adapter_meta` | object | Yes | Adapter identity and provenance |

`adapter_meta` fields:

| Field | Required | Description |
|---|---|---|
| `adapter_name` | Yes | Stable adapter identifier |
| `adapter_version` | Yes | Semver string |
| `trust_level` | Yes | One of TRUST_LEVELS |
| `input_hash` | Yes | SHA256 hex of raw input bytes |
| `losses` | Yes | List of LossRecord dicts (may be empty) |
| `warnings` | Yes | List of strings (may be empty) |

---

## Adapter Result Schema

`AdapterResult` has these fields:

| Field | Description |
|---|---|
| `adapter_name` | Adapter name |
| `adapter_version` | Adapter version |
| `trust_level` | Source trust classification |
| `status` | ACCEPTED / ACCEPTED_WITH_LOSS / REJECTED / UNSUPPORTED |
| `input_hash` | SHA256 of raw input |
| `canonical_events` | List of CanonicalEvent |
| `losses` | List of LossRecord |
| `rejections` | List of RejectionRecord |
| `warnings` | List of strings |
| `raw_ref` | Optional raw retention record |

Status is computed, not set:

- REJECTED: rejections present AND no canonical events.
- ACCEPTED_WITH_LOSS: events present AND losses (or partial rejections) present.
- ACCEPTED: events present, no losses, no rejections.
- UNSUPPORTED: no events and no rejections.

---

## Adapter Statuses

| Status | Meaning |
|---|---|
| `ACCEPTED` | All events translated cleanly. No loss. |
| `ACCEPTED_WITH_LOSS` | Events produced but information was degraded during translation. Losses documented. |
| `REJECTED` | No usable events could be produced from this input. |
| `UNSUPPORTED` | This adapter cannot handle this input type. |

---

## Invariants

These must hold for every adapter on every input:

1. `input_hash` is always a 64-character lowercase hex SHA256 string.
2. `input_hash` is computed from the raw bytes before any decoding or parsing.
3. The same `raw` input always produces the same `input_hash` (SHA256 is deterministic).
4. `status` is always one of the four values above — never a custom string.
5. `losses` and `rejections` are always lists — never `None`.
6. An adapter that ACCEPTED an event never silently discards information without a LossRecord.
7. An adapter never invents data not present in the source input.
8. An adapter never produces NaN or Infinity in any payload field.
9. String fields in payloads longer than 4096 chars are truncated with LOSS_OF_PRECISION.
10. An adapter that cannot produce a clean result returns REJECTED, not a best-effort partial.

---

## Downstream Treatment of Lossy Events

Events with `ACCEPTED_WITH_LOSS` status reach the Spine. Downstream consumers should:

- Check `adapter_meta.losses` before treating payload fields as authoritative.
- Treat LOSS_OF_CAUSAL_LINKAGE as "this event cannot be chained without external verification".
- Treat LOSS_OF_AUTHENTICITY as "source origin is not verified — treat as UNAUTHENTICATED_SOURCE".
- Use Veritas claim pins to link events to external verification when loss makes a claim uncertain.
