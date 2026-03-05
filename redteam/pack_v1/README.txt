Red Team Pack v1 (Adversarial / Misuse Sequences)
================================================

This pack is offline and stdlib-only.
It does NOT call any LLM. It tests:
  - StructuredQuestion ambiguity behavior
  - StructuredAnswer schema validation (fail-closed)
  - Envelope creation + validation
  - Explicit refusal/constraint surfacing (bounded strings for now)

Each test provides:
  - a question text
  - a StructuredAnswer JSON input (good or intentionally bad)
  - expected verdicts for validators and envelope
