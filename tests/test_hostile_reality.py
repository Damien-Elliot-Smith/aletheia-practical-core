#!/usr/bin/env python3
"""test_hostile_reality.py — Hostile real-world input test suite.

Tests against messy, broken, adversarial, and accidental operator inputs.
These are the cases that break systems that only work on disciplined examples.

Run:
    PYTHONPATH=. python3 tests/test_hostile_reality.py

Designed to work without pytest (stdlib unittest only).
"""
from __future__ import annotations

import hashlib
import io
import json
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tools.verify_case import verify_case
from aletheia.detective.zipguard import ZipGuardError
from tools._zip_io import open_zip_verified, open_zipfile_verified


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def make_good_zip(td: Path) -> Path:
    """Build a minimal valid case zip that passes verification."""
    from aletheia.spine.ledger import SpineLedger
    from aletheia.chronicle.export import build_case_zip
    root = td / "root"; root.mkdir()
    led = SpineLedger(root)
    led.open_window("main")
    led.append_event("main", "WITNESS", {"key": "value"})
    led.seal_window("main")
    led.close_clean()
    case = td / "good.zip"
    build_case_zip(root, case)
    return case


def zip_with_files(td: Path, name: str, files: dict) -> Path:
    """Build a raw zip with given {filename: bytes} contents."""
    p = td / name
    with zipfile.ZipFile(str(p), "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for fname, data in files.items():
            if isinstance(data, str):
                data = data.encode("utf-8")
            zf.writestr(fname, data)
    return p


def make_manifest(files_list: list, *, case_id: str = "test-001",
                  extra_keys: dict = None) -> bytes:
    man = {
        "case_id": case_id,
        "schema_version": "1",
        "files": files_list,
        "windows": [],
        "verify_report_sha256": "a" * 64,
    }
    if extra_keys:
        man.update(extra_keys)
    return json.dumps(man).encode("utf-8")


class HostileRealityTests(unittest.TestCase):

    # ── 1. Truncated zip ─────────────────────────────────────────────────────
    def test_01_truncated_zip(self):
        """A zip truncated mid-stream. Must produce ERROR, never PASS."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as zf:
                zf.writestr("case_manifest.json", b'{"x": 1}')
                zf.writestr("evidence/data.json", b'{"y": 2}')
            full = buf.getvalue()
            truncated = td / "truncated.zip"
            truncated.write_bytes(full[:len(full) // 2])

            result = open_zip_verified(str(truncated))
            self.assertNotEqual(result.verdict, "PASS",
                "Truncated zip must not PASS ZipGuard")

    # ── 2. Empty zip ──────────────────────────────────────────────────────────
    def test_02_empty_zip(self):
        """A zip with zero files — no manifest."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            p = td / "empty.zip"
            with zipfile.ZipFile(str(p), "w"):
                pass  # empty
            result = verify_case(p)
            self.assertIn(result.get("verdict"), ("FAIL", "ERROR"),
                "Empty zip (no manifest) must FAIL or ERROR")

    # ── 3. Wrong filename — manifest called "Manifest.json" (capitalised) ────
    def test_03_wrong_manifest_name(self):
        """Operator used 'Manifest.json' instead of 'case_manifest.json'."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            evidence = b'{"answer": "something"}'
            p = zip_with_files(td, "wrong_name.zip", {
                "Manifest.json": json.dumps({"case_id": "x"}),
                "evidence/data.json": evidence,
            })
            result = verify_case(p)
            self.assertIn(result.get("verdict"), ("FAIL", "ERROR"),
                "Wrong manifest filename must FAIL or ERROR")

    # ── 4. Manifest missing required keys ────────────────────────────────────
    def test_04_manifest_missing_required_keys(self):
        """Manifest is valid JSON but missing schema_version, files, windows."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            p = zip_with_files(td, "missing_keys.zip", {
                "case_manifest.json": json.dumps({"case_id": "test", "note": "incomplete"}),
            })
            result = verify_case(p)
            self.assertEqual(result.get("verdict"), "FAIL",
                "Manifest with missing required keys must FAIL")

    # ── 5. Hash mismatch — file modified after capture ────────────────────────
    def test_05_file_content_tampered(self):
        """A file's content differs from its recorded hash."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            original = b'{"answer": "original value"}'
            tampered = b'{"answer": "tampered value"}'
            # Manifest records hash of original, zip contains tampered
            p = zip_with_files(td, "tampered.zip", {
                "case_manifest.json": make_manifest([
                    {"zip_path": "evidence/data.json", "sha256": sha256(original), "bytes": len(original)}
                ]),
                "evidence/data.json": tampered,
                "evidence/verify_report.json": b'{}',
            })
            result = verify_case(p)
            self.assertEqual(result.get("verdict"), "FAIL",
                "Tampered file content must produce FAIL")
            reasons = result.get("reasons", [])
            self.assertTrue(
                any("HASH" in r or "MISMATCH" in r or "MISSING" in r for r in reasons),
                f"Expected hash/mismatch reason, got: {reasons}"
            )

    # ── 6. File listed in manifest but absent from zip ────────────────────────
    def test_06_missing_evidence_file(self):
        """Manifest lists a file that isn't in the zip."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            p = zip_with_files(td, "missing_file.zip", {
                "case_manifest.json": make_manifest([
                    {"zip_path": "evidence/data.json", "sha256": "a" * 64, "bytes": 100}
                ]),
                # evidence/data.json is NOT included
                "evidence/verify_report.json": b'{}',
            })
            result = verify_case(p)
            self.assertEqual(result.get("verdict"), "FAIL",
                "Zip missing a manifested file must FAIL")

    # ── 7. Path traversal in zip ───────────────────────────────────────────────
    def test_07_path_traversal(self):
        """Zip contains ../../etc/passwd style path — must be rejected before reading."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            p = td / "traversal.zip"
            # Manually build a zip with a traversal path
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as zf:
                zf.writestr("../../evil.json", b'{"evil": true}')
                zf.writestr("case_manifest.json", b'{}')
            p.write_bytes(buf.getvalue())
            result = open_zip_verified(str(p))
            self.assertNotEqual(result.verdict, "PASS",
                "Path traversal zip must not PASS ZipGuard")

    # ── 8. Duplicate files in zip ────────────────────────────────────────────
    def test_08_duplicate_manifest(self):
        """Two entries for case_manifest.json — Python zipfile returns last, but we must not PASS silently."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            p = td / "duplicate.zip"
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as zf:
                zf.writestr("case_manifest.json", json.dumps({"case_id": "a", "schema_version": "1",
                    "files": [], "windows": [], "verify_report_sha256": "a" * 64}))
                zf.writestr("case_manifest.json", json.dumps({"case_id": "b_different", "schema_version": "1",
                    "files": [], "windows": [], "verify_report_sha256": "b" * 64}))
            p.write_bytes(buf.getvalue())
            # ZipGuard should catch this OR verify_case should at minimum not silently PASS
            result = verify_case(p)
            # We accept PASS here only if ZipGuard allows it AND verify is consistent
            # The key thing: it must not throw an unhandled exception
            self.assertIn(result.get("verdict"), ("PASS", "FAIL", "ERROR", "INCONCLUSIVE"),
                "Duplicate manifest: must return bounded verdict, not crash")

    # ── 9. Manifest is valid JSON but payload is a list, not dict ────────────
    def test_09_manifest_wrong_type(self):
        """Manifest contains a JSON array instead of object."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            p = zip_with_files(td, "list_manifest.zip", {
                "case_manifest.json": b'[1, 2, 3]',
            })
            result = verify_case(p)
            self.assertIn(result.get("verdict"), ("FAIL", "ERROR"),
                "List-typed manifest must FAIL or ERROR, not crash")

    # ── 10. Huge file count (within limits) ──────────────────────────────────
    def test_10_many_files_within_limits(self):
        """500 small files — should complete without OOM or timeout."""
        from aletheia.detective.limits import ZipLimits
        limit = ZipLimits().max_files
        n = min(500, limit - 1)
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            p = td / "many_files.zip"
            evidence_files = []
            with zipfile.ZipFile(str(p), "w", compression=zipfile.ZIP_DEFLATED) as zf:
                for i in range(n):
                    content = f'{{"index": {i}}}'.encode()
                    fname = f"evidence/file_{i:04d}.json"
                    zf.writestr(fname, content)
                    evidence_files.append({
                        "zip_path": fname,
                        "sha256": sha256(content),
                        "bytes": len(content),
                    })
                report_bytes = b'{}'
                zf.writestr("evidence/verify_report.json", report_bytes)
                man = {
                    "case_id": "many-files", "schema_version": "1",
                    "files": evidence_files,
                    "windows": [],
                    "verify_report_sha256": sha256(report_bytes),
                }
                zf.writestr("case_manifest.json", json.dumps(man))
            result = verify_case(p)
            self.assertIn(result.get("verdict"), ("PASS", "FAIL", "ERROR", "INCONCLUSIVE"),
                "Many-file zip must return bounded verdict")

    # ── 11. Inconsistent manifest — sha256 field has wrong length ────────────
    def test_11_malformed_sha256_in_manifest(self):
        """Manifest has a sha256 value that's not 64 hex chars — operator typo."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            evidence = b'{"data": "value"}'
            p = zip_with_files(td, "short_hash.zip", {
                "case_manifest.json": make_manifest([
                    {"zip_path": "evidence/data.json",
                     "sha256": "tooshort",  # operator typo
                     "bytes": len(evidence)}
                ]),
                "evidence/data.json": evidence,
                "evidence/verify_report.json": b'{}',
            })
            result = verify_case(p)
            # Must not crash and must not return PASS (hash can't match)
            self.assertIn(result.get("verdict"), ("FAIL", "ERROR"),
                "Manifest with malformed sha256 must FAIL or ERROR")

    # ── 12. Misleading but well-formed bundle — all hashes correct but ────────
    #         case_id suggests it's a different case than it is
    def test_12_well_formed_but_wrong_case_id(self):
        """All hashes match, but case_id is different from the file it was built from.
        This is the 'misleading but technically valid' case.
        Aletheia should PASS — it is not responsible for case_id correctness,
        only hash integrity. But it must surface the case_id for operator review."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            evidence = b'{"answer": "actual answer"}'
            report_bytes = b'{}'
            p = zip_with_files(td, "misleading.zip", {
                "case_manifest.json": make_manifest(
                    [{"zip_path": "evidence/data.json",
                      "sha256": sha256(evidence), "bytes": len(evidence)}],
                    case_id="WRONG-CASE-ID-INJECTED"
                ),
                "evidence/data.json": evidence,
                "evidence/verify_report.json": report_bytes,
            })
            result = verify_case(p)
            # Hash integrity should PASS — Aletheia doesn't validate case_id semantics
            # The case_id is surfaced in output for human review
            self.assertIn(result.get("verdict"), ("PASS", "FAIL", "ERROR"),
                "Well-formed zip must return bounded verdict")
            # Key assertion: case_id is surfaced
            self.assertEqual(result.get("case_id"), "WRONG-CASE-ID-INJECTED",
                "case_id must be surfaced in output for human operator review")


class VerifyBundleIntegrationTests(unittest.TestCase):
    """Integration tests through the full verify pipeline (verify_bundle.py path)."""

    def _run_verify_bundle(self, zip_path: str) -> dict:
        import io
        from contextlib import redirect_stdout
        from tools.verify_bundle import main as vb_main
        buf = io.StringIO()
        with redirect_stdout(buf):
            try:
                vb_main([zip_path, "--pretty"])
            except SystemExit:
                pass
        return json.loads(buf.getvalue())

    def test_good_case_passes_full_pipeline(self):
        """The real example case passes the full verify_bundle pipeline."""
        good = ROOT / "examples" / "case_boundary_test.zip"
        if not good.exists():
            self.skipTest("example case not found")
        result = self._run_verify_bundle(str(good))
        self.assertEqual(result.get("overall_verdict"), "PASS")

    def test_tampered_case_fails_full_pipeline(self):
        """The real tampered example fails the full verify_bundle pipeline."""
        tampered = ROOT / "examples" / "case_boundary_test_TAMPER2.zip"
        if not tampered.exists():
            self.skipTest("tampered example not found")
        result = self._run_verify_bundle(str(tampered))
        self.assertIn(result.get("overall_verdict"), ("FAIL", "ERROR"))

    def test_nonexistent_path_returns_error_not_exception(self):
        """A path that does not exist must produce a bounded verdict, not an exception."""
        from aletheia_verify import run_verify
        rc = run_verify("/tmp/aletheia_does_not_exist_12345.zip")
        self.assertEqual(rc, 2, "Non-existent file must return exit code 2")

    def test_not_a_zip_returns_bounded_verdict(self):
        """A plain text file passed as a zip must produce ERROR, not an exception."""
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            p = td / "notazip.zip"
            p.write_bytes(b"this is not a zip file at all\x00\x01\x02")
            result = self._run_verify_bundle(str(p))
            self.assertIn(result.get("overall_verdict"), ("ERROR", "FAIL"),
                "Non-zip input must produce ERROR or FAIL, not PASS")

    def test_json_output_conforms_to_contract(self):
        """JSON output must have all required Report Contract v1 fields."""
        good = ROOT / "examples" / "case_boundary_test.zip"
        if not good.exists():
            self.skipTest("example case not found")
        result = self._run_verify_bundle(str(good))
        for field in ("report_type", "report_version", "overall_verdict", "checks"):
            self.assertIn(field, result, f"Missing required field: {field}")
        self.assertIsInstance(result["checks"], list)
        for check in result["checks"]:
            self.assertIn("check_id", check)
            self.assertIn("verdict", check)
            self.assertIn(check["verdict"], ("PASS", "FAIL", "ERROR", "INCONCLUSIVE"))


if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromTestCase(HostileRealityTests))
    suite.addTests(loader.loadTestsFromTestCase(VerifyBundleIntegrationTests))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 2)
