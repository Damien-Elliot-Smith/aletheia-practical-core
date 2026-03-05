Step 17 — Release Hardening
==========================

Goal
----
Make the project reproducible for outsiders with a single command that:
- validates the manifest
- runs the calibration pack + red-team pack + drift detector (if present)
- produces a full snapshot zip + .sha256
- emits a machine-readable release_report_*.json

How to run (Termux)
-------------------
From the core folder:

  cd /storage/emulated/0/Provenance/core/Aletheia_v1_Practical_Core
  chmod +x tools/release.sh 2>/dev/null || true
  PYTHONPATH="." bash tools/release.sh --version v1_18 --out-dir /storage/emulated/0/Download

Outputs
-------
In the output directory, you get:
- Provenance_FULL_SNAPSHOT_<version>.zip
- Provenance_FULL_SNAPSHOT_<version>.zip.sha256
- release_report_<version>.json
- optional: _release_calibration_report.json / _release_redteam_report.json / _release_drift_report.json

Notes
-----
- The zip's internal timestamps are whatever zipfile writes; integrity is the SHA256 of the produced zip.
- Excluded by default: dist/, sessions/, __pycache__/, .pytest_cache/
