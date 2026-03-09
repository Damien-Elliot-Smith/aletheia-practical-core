# Aletheia Core

Deterministic provenance and integrity verification engine.

Aletheia answers one question with a bounded verdict: **has this evidence bundle been tampered with since capture?**

Verdict is always one of: `PASS` / `FAIL` / `ERROR` / `INCONCLUSIVE`. No exceptions, no silent failures.

---

## Quick start

```bash
git clone https://github.com/Damien-Elliot-Smith/aletheia-practical-core
cd aletheia-practical-core
pip install -e .
python tools/validate_repo.py
```

That runs the full validation sequence: selfcheck → 228 core tests → 461 adversarial tests → example verification. If it exits 0, the engine is intact on your machine.
Current validated count: 228 core tests + 461 adversarial tests = 689 total.


---

## Verify a bundle

```bash
# Human-readable report
python aletheia.py verify examples/case_boundary_test.zip

# Machine-readable JSON
python aletheia.py verify examples/case_boundary_test.zip --json

# Stdlib-only (no other files needed beyond the verifier itself)
PYTHONPATH=. python tools/verify_case.py examples/case_boundary_test.zip
```

Expected outputs for the three included example bundles:

| Bundle | Expected verdict |
|---|---|
| `case_boundary_test.zip` | `PASS` |
| `case_boundary_test_TAMPER2.zip` | `FAIL` |
| `case_boundary_test_TAMPER.zip` | `ERROR` |

---

## Self-check

```bash
python aletheia_selfcheck.py
```

Verifies all core modules are importable and internally consistent. Exit 0 = engine is intact.

---

## Run tests

```bash
# Core suite (228 tests, stdlib only)
python -m unittest discover -s tests -p "test_*.py"

# Adversarial suite (461 tests)
python -m unittest discover -s tests_adversarial -p "test_*.py"

# Everything at once
python tools/validate_repo.py
```

---

## What Aletheia verifies

- Zip structure is safe (no path traversal, no symlinks, no zip bombs)
- Every file matches its recorded hash
- The hash chain is unbroken and correctly sequenced
- The bundle has not been modified since capture

## What Aletheia does not verify

- Whether the original content was true or accurate
- Whether the operator who captured it was honest
- Whether the capturing machine was compromised
- Whether all relevant evidence was captured
- Legal chain of custody before ingestion

---

## Guarantees

- **Deterministic outputs**: the same input always produces the same verdict
- **Tamper detection**: any modification to a sealed bundle is detected
- **Bounded verdicts**: `PASS` / `FAIL` / `ERROR` / `INCONCLUSIVE` — no surprises
- **Fail closed**: ambiguous or malformed input produces `ERROR`, never `PASS`
- **Zero dependencies**: stdlib only; runs on any Python 3.10+ installation

---

## Project structure

```
aletheia/          Core engine modules
  adapters/        Universal adapter layer (JSON, file, AI audit, OT, streaming)
  claims/          Closed finite-state claims model
  chronicle/       Case bundle export
  detective/       Deterministic drift-locked sieve + ZipGuard
  ingest/          Bounded ingest gate
  spine/           Append-only hash-chained ledger
  siren/           Degrade-and-MAYDAY state machine
  veritas/         Epistemic session layer

tools/             CLI tools and utilities
  verify_case.py   Core verifier (stdlib only)
  verify_bundle.py Bundle verifier (full report)
  validate_repo.py One-command repository validation
  release_build.py Deterministic release builder

tests/             Core test suite (228 tests)
tests_adversarial/ Adversarial and scenario tests (461 tests)
examples/          Sample bundles (PASS / FAIL / ERROR)
docs/              Full specification documents
schemas/           JSON schemas
profiles/          Adapter mapping profiles
```

---

## Release

```bash
python tools/release_build.py
```

Cleans artifacts, runs validation, builds a deterministic zip with SHA256 in `dist/`.
