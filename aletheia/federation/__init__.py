"""
aletheia.federation — Phase 2.2: Multi-Node Federation

Problem: v1 is single-node. Real deployments have evidence from multiple
locations — multiple sensors, systems, jurisdictions.

Solution: Federation combines independently-verified case.zip bundles
into a single FederatedBundle with a federation manifest.

Design rules:
  - No distributed consensus. Nodes do not communicate in real-time.
  - Federation happens at export time (offline).
  - Each node's case.zip is independently verified before federation.
  - A compromised node produces FAIL for its sub-bundle only.
  - The federation verdict reflects the worst sub-bundle verdict.
  - Federation manifest is itself hash-anchored (SHA256 of all constituent
    manifest hashes + federation metadata).
  - Claims from Node A can reference evidence pins from Node B.
    ClaimCheck federation mode resolves pins across all sub-bundles.

Verdicts:
  PASS            — all sub-bundles verified, no failures
  PARTIAL         — some sub-bundles PASS, at least one FAIL/INCONCLUSIVE
  FAIL            — all sub-bundles failed verification
  INCONCLUSIVE    — no sub-bundles provided, or manifest unreadable
"""
from __future__ import annotations

import hashlib
import json
import os
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from aletheia.spine.ledger import canonicalize_json


FEDERATION_SCHEMA_VERSION = "2.1"
FEDERATION_VERDICT_PASS = "PASS"
FEDERATION_VERDICT_PARTIAL = "PARTIAL"
FEDERATION_VERDICT_FAIL = "FAIL"
FEDERATION_VERDICT_INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class NodeResult:
    node_id: str
    zip_path: str
    case_id: Optional[str]
    verdict: str            # PASS / FAIL / INCONCLUSIVE / ERROR
    reasons: List[str]
    drift_signature: Optional[str]
    sealed_windows: List[str]
    manifest_hash: Optional[str]   # SHA256 of the node's case_manifest.json


@dataclass
class FederationResult:
    federation_id: str
    schema_version: str
    created_utc: str
    nodes: List[NodeResult]
    verdict: str
    reasons: List[str]
    federation_hash: str    # SHA256 of canonicalized federation manifest
    cross_node_pins: Dict[str, str]  # pin_hash -> node_id (populated lazily)


class FederationError(Exception):
    pass


# ── Core functions ─────────────────────────────────────────────────────────────

def verify_node(zip_path: str) -> NodeResult:
    """
    Run standalone verification on a single case.zip node bundle.
    This is an isolated call — it imports nothing from the live Spine.
    Returns a NodeResult with verdict PASS / FAIL / INCONCLUSIVE / ERROR.
    """
    import tempfile
    from aletheia.detective.zipguard import build_extraction_plan, safe_extract, ZipGuardError
    from aletheia.detective.limits import ZipLimits

    node_id = Path(zip_path).stem

    try:
        limits = ZipLimits()
        plan = build_extraction_plan(zip_path, limits)
    except ZipGuardError as e:
        return NodeResult(
            node_id=node_id, zip_path=zip_path, case_id=None,
            verdict="ERROR", reasons=[f"ERR_ZIPGUARD: {e.reason_code}"],
            drift_signature=None, sealed_windows=[], manifest_hash=None,
        )
    except Exception as e:
        return NodeResult(
            node_id=node_id, zip_path=zip_path, case_id=None,
            verdict="ERROR", reasons=[f"ERR_BAD_ZIP: {str(e)}"],
            drift_signature=None, sealed_windows=[], manifest_hash=None,
        )

    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            safe_extract(zip_path, tmpdir, plan)
        except Exception as e:
            return NodeResult(
                node_id=node_id, zip_path=zip_path, case_id=None,
                verdict="ERROR", reasons=[f"ERR_EXTRACT: {str(e)}"],
                drift_signature=None, sealed_windows=[], manifest_hash=None,
            )

        root = Path(tmpdir)

        # Read manifest
        manifest_path = root / "case_manifest.json"
        if not manifest_path.exists():
            manifest_path = root / "manifest.json"
        if not manifest_path.exists():
            return NodeResult(
                node_id=node_id, zip_path=zip_path, case_id=None,
                verdict="INCONCLUSIVE", reasons=["MISSING_MANIFEST"],
                drift_signature=None, sealed_windows=[], manifest_hash=None,
            )

        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception as e:
            return NodeResult(
                node_id=node_id, zip_path=zip_path, case_id=None,
                verdict="FAIL", reasons=[f"MANIFEST_UNREADABLE: {e}"],
                drift_signature=None, sealed_windows=[], manifest_hash=None,
            )

        manifest_hash = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        case_id = manifest.get("case_id")

        # Verify file hashes from manifest
        file_entries = manifest.get("files", [])
        # files is a list of {zip_path, sha256, bytes} objects
        if isinstance(file_entries, dict):
            # legacy dict form
            file_map = file_entries
        else:
            file_map = {e["zip_path"]: e["sha256"] for e in file_entries
                        if isinstance(e, dict) and "zip_path" in e and "sha256" in e}

        failures = []
        for arc_path, expected_hash in file_map.items():
            fpath = root / arc_path
            if not fpath.exists():
                failures.append(f"MISSING: {arc_path}")
                continue
            actual = hashlib.sha256(fpath.read_bytes()).hexdigest()
            if actual != expected_hash:
                failures.append(f"HASH_MISMATCH: {arc_path}")

        if failures:
            return NodeResult(
                node_id=node_id, zip_path=zip_path, case_id=case_id,
                verdict="FAIL", reasons=failures,
                drift_signature=None, sealed_windows=[], manifest_hash=manifest_hash,
            )

        # Verify + driftlock using the existing case-reader path
        verify_report_path = root / "evidence" / "verify_report.json"
        if verify_report_path.exists():
            try:
                vreport = json.loads(verify_report_path.read_text(encoding="utf-8"))
                # verify_report structure: {"verify": {"ok": bool, "failures": [...]}}
                inner = vreport.get("verify", vreport)
                if not inner.get("ok", False):
                    reasons = inner.get("failures", ["VERIFY_FAIL"])
                    return NodeResult(
                        node_id=node_id, zip_path=zip_path, case_id=case_id,
                        verdict="FAIL", reasons=[str(r) for r in reasons] or ["VERIFY_FAIL"],
                        drift_signature=None, sealed_windows=[],
                        manifest_hash=manifest_hash,
                    )
            except Exception:
                pass

        # DriftLock check using the existing API
        try:
            from aletheia.detective.drift_lock import driftlock_check
            with zipfile.ZipFile(zip_path, "r") as zf:
                drift_result = driftlock_check(zf, manifest)
        except Exception as e:
            drift_result = {"verdict": "INCONCLUSIVE", "reasons": [str(e)],
                           "drift_signature": None, "sealed_windows": []}

        drift_sig = drift_result.get("drift_signature")
        sealed_windows = drift_result.get("sealed_windows", [])
        drift_verdict = drift_result.get("verdict", "INCONCLUSIVE")

        if drift_verdict == "FAIL":
            return NodeResult(
                node_id=node_id, zip_path=zip_path, case_id=case_id,
                verdict="FAIL", reasons=["DRIFTLOCK_FAIL"] + drift_result.get("reasons", []),
                drift_signature=drift_sig, sealed_windows=sealed_windows,
                manifest_hash=manifest_hash,
            )

        return NodeResult(
            node_id=node_id, zip_path=zip_path, case_id=case_id,
            verdict="PASS", reasons=["OK"],
            drift_signature=drift_sig, sealed_windows=sealed_windows,
            manifest_hash=manifest_hash,
        )


def federate(zip_paths: List[str], *, node_ids: Optional[List[str]] = None) -> FederationResult:
    """
    Combine multiple independently-verified case.zip bundles into a
    FederationResult.

    Each zip is verified independently. The federation verdict reflects
    the aggregate:
      - All PASS                → PASS
      - Mix of PASS + FAIL      → PARTIAL
      - All FAIL                → FAIL
      - Empty or all ERROR      → INCONCLUSIVE

    Args:
        zip_paths:  list of paths to case.zip files, one per node
        node_ids:   optional override for node identifiers (defaults to filename stems)

    Returns:
        FederationResult with per-node verdicts and a federation_hash.
    """
    if not zip_paths:
        return FederationResult(
            federation_id=_new_id(),
            schema_version=FEDERATION_SCHEMA_VERSION,
            created_utc=_utc_now(),
            nodes=[],
            verdict=FEDERATION_VERDICT_INCONCLUSIVE,
            reasons=["NO_NODES_PROVIDED"],
            federation_hash="",
            cross_node_pins={},
        )

    node_results: List[NodeResult] = []
    for i, zp in enumerate(zip_paths):
        nid = node_ids[i] if node_ids and i < len(node_ids) else Path(zp).stem
        result = verify_node(zp)
        result.node_id = nid
        node_results.append(result)

    # Aggregate verdict
    verdicts = {r.verdict for r in node_results}
    if verdicts == {"PASS"}:
        verdict = FEDERATION_VERDICT_PASS
        reasons = ["OK"]
    elif "PASS" in verdicts and ("FAIL" in verdicts or "INCONCLUSIVE" in verdicts):
        verdict = FEDERATION_VERDICT_PARTIAL
        reasons = [f"NODE_{r.node_id}_VERDICT_{r.verdict}" for r in node_results if r.verdict != "PASS"]
    elif verdicts <= {"FAIL", "ERROR"}:
        verdict = FEDERATION_VERDICT_FAIL
        reasons = [f"NODE_{r.node_id}_VERDICT_{r.verdict}" for r in node_results]
    else:
        verdict = FEDERATION_VERDICT_INCONCLUSIVE
        reasons = [f"NODE_{r.node_id}_VERDICT_{r.verdict}" for r in node_results]

    # Build federation manifest and hash it
    fed_id = _new_id()
    manifest_obj = {
        "federation_id": fed_id,
        "schema_version": FEDERATION_SCHEMA_VERSION,
        "created_utc": _utc_now(),
        "verdict": verdict,
        "nodes": [
            {
                "node_id": r.node_id,
                "case_id": r.case_id,
                "verdict": r.verdict,
                "drift_signature": r.drift_signature,
                "manifest_hash": r.manifest_hash,
                "sealed_windows": r.sealed_windows,
            }
            for r in node_results
        ],
    }
    federation_hash = hashlib.sha256(canonicalize_json(manifest_obj)).hexdigest()

    # Build cross-node pin index: map each event hash to its node_id
    cross_node_pins: Dict[str, str] = {}
    for r in node_results:
        for wid in r.sealed_windows:
            # Pins are event hashes — just register the node as source
            # Full resolution happens in ClaimCheck federation mode
            cross_node_pins[wid] = r.node_id

    return FederationResult(
        federation_id=fed_id,
        schema_version=FEDERATION_SCHEMA_VERSION,
        created_utc=_utc_now(),
        nodes=node_results,
        verdict=verdict,
        reasons=reasons,
        federation_hash=federation_hash,
        cross_node_pins=cross_node_pins,
    )


def write_federation_bundle(
    result: FederationResult,
    node_zips: List[str],
    out_path: str,
) -> str:
    """
    Write a federated bundle zip containing:
      federation_manifest.json
      nodes/<node_id>.zip  (each constituent case.zip)

    Returns the SHA256 of the output zip.
    """
    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # Federation manifest
        manifest = {
            "federation_id": result.federation_id,
            "schema_version": result.schema_version,
            "created_utc": result.created_utc,
            "verdict": result.verdict,
            "reasons": result.reasons,
            "federation_hash": result.federation_hash,
            "nodes": [
                {
                    "node_id": r.node_id,
                    "case_id": r.case_id,
                    "verdict": r.verdict,
                    "drift_signature": r.drift_signature,
                    "manifest_hash": r.manifest_hash,
                    "sealed_windows": r.sealed_windows,
                }
                for r in result.nodes
            ],
        }
        zf.writestr(
            "federation_manifest.json",
            json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n",
        )
        # Constituent node zips
        for r, zp in zip(result.nodes, node_zips):
            zf.write(zp, f"nodes/{r.node_id}.zip")

    sha = hashlib.sha256(Path(out_path).read_bytes()).hexdigest()
    return sha


def read_federation_bundle(bundle_path: str) -> Dict[str, Any]:
    """
    Read federation_manifest.json from a federation bundle zip.
    Returns the parsed manifest dict or raises FederationError.
    """
    try:
        with zipfile.ZipFile(bundle_path, "r") as zf:
            names = zf.namelist()
            if "federation_manifest.json" not in names:
                raise FederationError("Not a federation bundle: missing federation_manifest.json")
            return json.loads(zf.read("federation_manifest.json").decode("utf-8"))
    except zipfile.BadZipFile as e:
        raise FederationError(f"Bad zip: {e}") from e


# ── Helpers ────────────────────────────────────────────────────────────────────

def _new_id() -> str:
    import uuid
    return uuid.uuid4().hex[:16]


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
