Calibration Pack v1 (Known-Answer Suite)
=======================================

This pack is intentionally small and stdlib-only.
It tests deterministic behavior of:
  - tools/structure_question.py
  - tools/validate_structured_answer.py
  - tools/make_envelope.py + tools/validate_envelope.py
  - tools/verify_case.py (optional, if demo zips exist)

The runner computes output SHA256 and compares against expected SHA256.
