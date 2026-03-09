"""
aletheia.adapters.taxonomy — Loss and Rejection taxonomy constants

Phase 0: Loss taxonomy
Phase 0: Rejection taxonomy
Phase 1: Trust level taxonomy

These are the only values any adapter may use. The set is closed.
No adapter may invent a loss or rejection type not in this module.
"""
from __future__ import annotations

# ── Loss types (Phase 0) ──────────────────────────────────────────────────────
LOSS_OF_PRECISION       = "LOSS_OF_PRECISION"
LOSS_OF_STRUCTURE       = "LOSS_OF_STRUCTURE"
LOSS_OF_COMPLETENESS    = "LOSS_OF_COMPLETENESS"
LOSS_OF_CAUSAL_LINKAGE  = "LOSS_OF_CAUSAL_LINKAGE"
LOSS_OF_AUTHENTICITY    = "LOSS_OF_AUTHENTICITY"

LOSS_TYPES = frozenset({
    LOSS_OF_PRECISION,
    LOSS_OF_STRUCTURE,
    LOSS_OF_COMPLETENESS,
    LOSS_OF_CAUSAL_LINKAGE,
    LOSS_OF_AUTHENTICITY,
})

# ── Rejection types (Phase 0) ─────────────────────────────────────────────────
REJECT_MALFORMED     = "MALFORMED"
REJECT_UNVERIFIABLE  = "UNVERIFIABLE"
REJECT_INCOMPLETE    = "INCOMPLETE"
REJECT_INCONSISTENT  = "INCONSISTENT"
REJECT_UNSUPPORTED   = "UNSUPPORTED"
REJECT_HOSTILE       = "HOSTILE"

REJECTION_TYPES = frozenset({
    REJECT_MALFORMED,
    REJECT_UNVERIFIABLE,
    REJECT_INCOMPLETE,
    REJECT_INCONSISTENT,
    REJECT_UNSUPPORTED,
    REJECT_HOSTILE,
})

# ── Adapter status (Phase 0) ──────────────────────────────────────────────────
STATUS_ACCEPTED           = "ACCEPTED"
STATUS_ACCEPTED_WITH_LOSS = "ACCEPTED_WITH_LOSS"
STATUS_REJECTED           = "REJECTED"
STATUS_UNSUPPORTED        = "UNSUPPORTED"

ADAPTER_STATUSES = frozenset({
    STATUS_ACCEPTED,
    STATUS_ACCEPTED_WITH_LOSS,
    STATUS_REJECTED,
    STATUS_UNSUPPORTED,
})

# ── Trust levels (Phase 1) ────────────────────────────────────────────────────
TRUST_AUTHENTICATED   = "AUTHENTICATED_SOURCE"
TRUST_OBSERVED        = "OBSERVED_SOURCE"
TRUST_UNAUTHENTICATED = "UNAUTHENTICATED_SOURCE"
TRUST_AMBIGUOUS       = "AMBIGUOUS_SOURCE"

TRUST_LEVELS = frozenset({
    TRUST_AUTHENTICATED,
    TRUST_OBSERVED,
    TRUST_UNAUTHENTICATED,
    TRUST_AMBIGUOUS,
})

# ── Retention modes (Phase 8) ─────────────────────────────────────────────────
RETAIN_FULL         = "FULL"
RETAIN_HASHED       = "HASHED"
RETAIN_REDACTED     = "REDACTED"
RETAIN_EXTERNAL_REF = "EXTERNAL_REF"

RETENTION_MODES = frozenset({
    RETAIN_FULL,
    RETAIN_HASHED,
    RETAIN_REDACTED,
    RETAIN_EXTERNAL_REF,
})
