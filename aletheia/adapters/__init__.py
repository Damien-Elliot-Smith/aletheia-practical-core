"""
aletheia.adapters — Universal Adapter Layer

Phase 0–11: Deterministic, provenance-preserving ingestion boundary.

Architecture:
  External World → Adapter Layer → Ingest Gate → Spine Ledger

No external data reaches the Spine without passing through the adapter
layer and the ingest gate.

Importing this package registers all built-in adapters.

Quick start:
    from aletheia.adapters import run_adapter

    report = run_adapter(gate, "json_adapter", raw_bytes)
    # report.events_accepted — number of events written to Spine
    # report.adapter_result.status — ACCEPTED / ACCEPTED_WITH_LOSS / REJECTED
    # report.adapter_result.losses — list of LossRecord
"""
from __future__ import annotations

# Register all built-in adapters on package import
import aletheia.adapters.json_adapter        # noqa: F401
import aletheia.adapters.file_adapter        # noqa: F401
import aletheia.adapters.ai_audit_adapter    # noqa: F401
import aletheia.adapters.ai_audit_causal     # noqa: F401
import aletheia.adapters.ot_adapter          # noqa: F401

from aletheia.adapters.base import (
    AdapterBase, AdapterResult, CanonicalEvent,
    LossRecord, RejectionRecord,
    hash_raw_bytes, build_raw_ref,
)
from aletheia.adapters.taxonomy import (
    # Loss types
    LOSS_OF_PRECISION, LOSS_OF_STRUCTURE, LOSS_OF_COMPLETENESS,
    LOSS_OF_CAUSAL_LINKAGE, LOSS_OF_AUTHENTICITY,
    # Rejection types
    REJECT_MALFORMED, REJECT_UNVERIFIABLE, REJECT_INCOMPLETE,
    REJECT_INCONSISTENT, REJECT_UNSUPPORTED, REJECT_HOSTILE,
    # Statuses
    STATUS_ACCEPTED, STATUS_ACCEPTED_WITH_LOSS, STATUS_REJECTED, STATUS_UNSUPPORTED,
    # Trust levels
    TRUST_AUTHENTICATED, TRUST_OBSERVED, TRUST_UNAUTHENTICATED, TRUST_AMBIGUOUS,
)
from aletheia.adapters.registry import get_adapter, list_adapters, register
from aletheia.adapters.runner import AdapterRunner, RunnerReport


def run_adapter(gate, adapter_name: str, raw: bytes, profile=None) -> RunnerReport:
    """
    Convenience function: run a named adapter against raw bytes via gate.

    Args:
        gate:         An IngestGate instance (already connected to a SpineLedger).
        adapter_name: Name of a registered adapter (e.g. "json_adapter").
        raw:          Raw input bytes.
        profile:      Optional loaded profile dict (from profiles.load_profile()).

    Returns:
        RunnerReport with full adapter result and all gate decisions.
    """
    runner = AdapterRunner(gate)
    return runner.run(adapter_name, raw, profile=profile)


__all__ = [
    "run_adapter",
    "AdapterBase", "AdapterResult", "CanonicalEvent",
    "LossRecord", "RejectionRecord",
    "hash_raw_bytes", "build_raw_ref",
    "LOSS_OF_PRECISION", "LOSS_OF_STRUCTURE", "LOSS_OF_COMPLETENESS",
    "LOSS_OF_CAUSAL_LINKAGE", "LOSS_OF_AUTHENTICITY",
    "REJECT_MALFORMED", "REJECT_UNVERIFIABLE", "REJECT_INCOMPLETE",
    "REJECT_INCONSISTENT", "REJECT_UNSUPPORTED", "REJECT_HOSTILE",
    "STATUS_ACCEPTED", "STATUS_ACCEPTED_WITH_LOSS", "STATUS_REJECTED", "STATUS_UNSUPPORTED",
    "TRUST_AUTHENTICATED", "TRUST_OBSERVED", "TRUST_UNAUTHENTICATED", "TRUST_AMBIGUOUS",
    "get_adapter", "list_adapters", "register",
    "AdapterRunner", "RunnerReport",
]
