# RETENTION_POLICY.md — Raw Data Retention Policy

**Version:** 1.0  
**Phase:** 8

---

## Purpose

Adapters receive raw external data. Before translating it, they hash it. After translating it, they may retain some or all of the original. This document defines what is retained, how, and what must always be recorded.

---

## Invariant: The Hash Is Always Stored

Regardless of retention mode, the SHA256 of the raw input bytes is always recorded in `AdapterResult.input_hash` and in the `raw_ref.input_hash` field.

This is non-negotiable. It makes the following statement possible: "this canonical event was produced from an input with this hash." Without the hash, provenance cannot be established.

---

## Retention Modes

### FULL

The complete raw input bytes are decoded and stored in the `raw_ref.content` field.

**When to use:** Forensic deployments where every byte of every input must be recoverable. High storage cost.

**Privacy implication:** If the raw input contains PII or confidential data, FULL mode stores it. Choose REDACTED or HASHED for sensitive sources.

---

### HASHED

Only the hash is stored. Content is not retained.

**When to use:** Default for most deployments. Provides input integrity verification without storing content.

**Limitation:** The original content cannot be recovered from the hash. If a dispute arises about what the input contained, the raw bytes must be sourced externally and hashed to verify.

---

### REDACTED

Content is stored with sensitive fields replaced. The redaction is explicitly recorded.

**When to use:** Sources that mix PII and non-sensitive operational data. Audit logs that contain user identifiers but where the event structure itself is important.

**Rules:**
- `raw_ref.redaction_note` must describe what was redacted and why.
- Redaction is recorded as LOSS_OF_COMPLETENESS.
- The hash in `raw_ref.input_hash` is the hash of the **original** bytes, not the redacted version.

---

### EXTERNAL_REF

A URI pointer to where the raw input is stored externally.

**When to use:** When the raw input is already stored in an external system (object store, document management) and duplicating it would be wasteful.

**Rules:**
- `raw_ref.external_ref` must be a valid URI pointing to the raw input.
- Aletheia cannot verify that the external reference remains accessible.
- LOSS_OF_AUTHENTICITY is recorded — future verification of the content depends on the external system's integrity.

---

## Omission

If an adapter produces no `raw_ref` at all (not supported in built-in adapters, but possible in custom adapters), this must be explicitly noted in the adapter documentation. Silent omission is not permitted.

---

## Redaction Recording

When redaction occurs, the `raw_ref` must record:

```json
{
  "retention_mode": "REDACTED",
  "input_hash": "<hash of original bytes>",
  "byte_length": 1234,
  "redaction_note": "Fields 'user_id' and 'email' redacted under GDPR Art. 5(1)(c)"
}
```

And the `AdapterResult.losses` must include:

```json
{
  "loss_type": "LOSS_OF_COMPLETENESS",
  "field": "raw_ref",
  "detail": "Raw content partially redacted. See raw_ref.redaction_note."
}
```
