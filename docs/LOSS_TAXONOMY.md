# LOSS_TAXONOMY.md — Information Loss Taxonomy

**Version:** 1.0  
**Phase:** 0

---

## Purpose

When an adapter translates external data into a canonical Aletheia event, information can be degraded in specific, classifiable ways. This taxonomy defines every class of loss. No adapter may invent a loss type not in this taxonomy. The set is closed.

---

## LOSS_OF_PRECISION

Information was present but reduced in fidelity during translation.

**Examples:**
- Timestamp with microsecond precision truncated to second precision.
- A floating-point value coerced to two decimal places.
- A string field longer than 4096 characters truncated.
- Source coordinates at 8 decimal places stored at 6.

**Downstream implication:** The payload field exists and is directionally correct, but exact reconstruction of the original value is not possible from the canonical record alone. Use the raw_ref for full fidelity if retention mode is FULL.

---

## LOSS_OF_STRUCTURE

Structural organisation of the source was flattened or discarded.

**Examples:**
- A nested JSON object with three levels mapped to a flat dict.
- Unknown fields preserved under a single `_unknown` key.
- A multi-paragraph text field stored as a single concatenated string.
- An ordered list structure collapsed to an unordered set.

**Downstream implication:** The data is present but the original organisation is not recoverable from the canonical record. Cross-field relationships from the source structure may be lost.

---

## LOSS_OF_COMPLETENESS

Part of the source data was absent or could not be translated.

**Examples:**
- An optional field was absent and had no fallback.
- A tool invocation had 600 individual calls; only the first 50 were recorded.
- A prompt response was truncated because it exceeded the content limit.
- A file was partially readable and only the first 1000 lines were ingested.

**Downstream implication:** The canonical record does not represent the full source. The `field` in the LossRecord indicates what is missing.

---

## LOSS_OF_CAUSAL_LINKAGE

A causal relationship that should connect this event to another event could not be established.

**Examples:**
- An inference response has no `request_id` to link it to the triggering request.
- A tool invocation chain is missing the initial request that started the chain.
- A state change has no `from_state` — the previous state is unknown.
- A reasoning step has no `chain_id` — it cannot be grouped into its parent chain.

**Downstream implication:** This event cannot be causally chained to its context without external verification. Claims about causality must be verified via Veritas claim pins before being asserted as WITNESSED.

---

## LOSS_OF_AUTHENTICITY

The origin, authorship, or verification status of data could not be confirmed.

**Examples:**
- A timestamp had no timezone; UTC was assumed.
- A source claimed to be `AUTHENTICATED_SOURCE` but no credential was present to verify.
- A sensor reports BAD quality — the measurement may not reflect physical reality.
- A timestamp is more than 300 seconds old — it may not reflect when the event occurred.
- An HMAC signature was absent from a webhook that declared itself signed.

**Downstream implication:** The data is included, but its authenticity cannot be asserted. Downstream systems must treat this event as `UNAUTHENTICATED_SOURCE` regardless of what the source declared.
