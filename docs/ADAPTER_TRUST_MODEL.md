# ADAPTER_TRUST_MODEL.md — Adapter Trust Boundary and Authenticity Model

**Version:** 1.0  
**Phase:** 1

---

## Purpose

Trust classification answers one question: how confident are we that this event came from who it claims to come from?

Every canonical event carries a `trust_level` from the adapter that produced it. This trust level is metadata — it does not block ingestion. Its purpose is to make authenticity limits visible to downstream consumers so they can set their confidence in claims accordingly.

---

## Trust Classifications

### AUTHENTICATED_SOURCE

The adapter has verified the origin of this event through a cryptographic mechanism.

**Conditions that justify this level:**
- HMAC-SHA256 signature verified against a known shared secret.
- mTLS client certificate verified against a trusted CA.
- JWT with verified signature and valid claims.
- RFC 3161 timestamp authority token verified.

**Adapter responsibility:** The adapter must have performed the verification itself, within the `adapt()` call. Claiming AUTHENTICATED_SOURCE because the source *says* it is authenticated is not permitted — that is UNAUTHENTICATED_SOURCE.

---

### OBSERVED_SOURCE

The adapter observed data from a source it has a stable, persistent connection to, but has not cryptographically verified the source identity.

**Conditions that justify this level:**
- Data received from a persistent MQTT subscription to a known broker.
- Events received from a named OT device on a physically isolated network.
- Data from a database connection with known credentials (the credentials authenticate the connection, not the data content).

**Distinction from AUTHENTICATED_SOURCE:** The connection is trusted but individual messages are not signed.

---

### UNAUTHENTICATED_SOURCE

The adapter has no basis to assert anything about the source identity.

**Conditions that require this level:**
- Any HTTP webhook without signature verification.
- A file uploaded to the system without any provenance chain.
- JSON data parsed from a string with no declared origin.
- Any source that claims to be authenticated but carries no verifiable credential.

**Default:** All adapters default to UNAUTHENTICATED_SOURCE unless they have an explicit mechanism to set a higher level.

---

### AMBIGUOUS_SOURCE

The adapter has conflicting or self-contradictory evidence about the source.

**Conditions that require this level:**
- A record claims to be from `AUTHENTICATED_SOURCE` but the signature verification failed.
- Two fields in the same record attribute the event to different sources.
- A webhook payload carries a signature that does not match any known key.

**Note:** AMBIGUOUS_SOURCE is not the same as UNAUTHENTICATED_SOURCE. AMBIGUOUS_SOURCE means the evidence is contradictory. UNAUTHENTICATED_SOURCE means there is no evidence either way.

---

## When Authenticity Claims Are Valid

An adapter may set `AUTHENTICATED_SOURCE` only when ALL of the following are true:

1. A cryptographic mechanism was applied within the current `adapt()` call.
2. The mechanism used a key or certificate not provided by the source itself.
3. The verification succeeded without error.
4. The mechanism is one of: HMAC-SHA256, RSA/ECDSA signature, mTLS, JWT (RS256/ES256), RFC 3161.

---

## When Ambiguity Must Be Reported

An adapter must set `AMBIGUOUS_SOURCE` when:

1. A credential is present but cannot be verified against a known key.
2. A signature is present but does not match.
3. Conflicting source identity claims exist within the same record.

In all these cases, the adapter must also record LOSS_OF_AUTHENTICITY.

---

## How Unverifiable Origin Is Handled

An adapter that cannot verify origin does not reject the event. It:

1. Sets `trust_level = UNAUTHENTICATED_SOURCE`.
2. Proceeds with translation.
3. Does NOT record a loss (absence of verification is the default state, not a degradation).

Downstream consumers are responsible for deciding what level of trust is required for their use case.

---

## How Downstream Modules Treat Lossy Events

| Loss type | Downstream implication |
|---|---|
| LOSS_OF_AUTHENTICITY | Treat as UNAUTHENTICATED_SOURCE regardless of declared trust_level |
| LOSS_OF_CAUSAL_LINKAGE | Do not assert causal claims without external verification via Veritas pins |
| LOSS_OF_COMPLETENESS | The field is absent — do not infer its value |
| LOSS_OF_PRECISION | The field exists but may not be exact |
| LOSS_OF_STRUCTURE | Structural relationships are not recoverable from the payload alone |

---

## Adapter Identity Schema

See `schemas/adapter_identity.schema.json` for the full schema.

Key fields tracked per adapter:

| Field | Description |
|---|---|
| `adapter_name` | Stable identifier. Never changes between versions. |
| `adapter_version` | Semver string. Tracked for drift detection. |
| `trust_level` | Default trust level for events from this adapter. |
| `signing_capability` | Whether this adapter can verify signatures (true/false). |
