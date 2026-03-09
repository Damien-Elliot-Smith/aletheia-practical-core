Aletheia Practical Core

Deterministic provenance and verification system for evidence bundles.

Aletheia is designed for forensic-grade verification of event evidence. It produces bounded, deterministic verdicts and creates tamper-evident evidence bundles that can be independently verified.

The system avoids hidden assumptions, silent failure modes, and probabilistic interpretation.

---

## Core Principles

**Deterministic behaviour**  

Given the same inputs, the system always produces the same outputs.

**Bounded verdicts**  

All verification returns one of four outcomes:

PASS / FAIL / ERROR / INCONCLUSIVE

**Fail closed**  

Malformed or ambiguous inputs never produce a PASS.

**Zero dependencies**  

Core system runs on the Python standard library only.

**Tamper-evident storage**  

All evidence records are hash-linked.

---

## Key Capabilities

### Evidence bundles

Evidence bundles contain:

- evidence files  

- a manifest  

- hashes for each file  

- structural metadata  

Bundles can be independently verified without trusting the original system.

---

### Deterministic verification

The verification engine checks:

- bundle structure  

- manifest integrity  

- file hashes  

- schema conformance  

- deterministic verdict rules  

Verification produces a structured report.

---

### Bounded ingest gate

Incoming records pass through a strict ingest gate enforcing:

- maximum payload size  

- maximum nesting depth  

- deterministic canonicalisation  

- schema validation  

- UTF-8 enforcement  

This prevents hostile or malformed inputs from corrupting the ledger.

---

### Spine ledger

The spine is an append-only hash-chained ledger.

Each entry includes:

- event type  

- timestamp  

- payload  

- previous hash  

Tampering with past records invalidates the chain.

---

### Drift-locked verification

Evidence bundles are verified with a deterministic rule set.

Rules cannot silently change between runs.

---

## Adapter Framework

Adapters allow external systems to feed events into Aletheia.

Adapters convert external records into canonical Aletheia events.

Supported adapters include:

- JSON event streams  

- file log ingestion  

- OT / sensor telemetry  

- AI audit event capture  

Adapter results record:

- accepted events  

- rejected records  

- loss information  

- canonical transformations  

---

## Loss Accounting

Aletheia never hides degraded information.

Loss events explicitly record:

- missing fields  

- ambiguous timestamps  

- truncated content  

- structural uncertainty  

Auditors can see exactly what information was lost during ingestion.

---

## Project Structure

aletheia/ adapters/        Universal adapter layer (JSON, file, AI audit, OT) claims/          Closed finite-state claims model chronicle/       Case bundle export detective/       Deterministic drift-locked sieve + ZipGuard ingest/          Bounded ingest gate spine/           Append-only hash-chained ledger siren/           Degrade-and-MAYDAY state machine veritas/         Epistemic session layer

tools/ verify_case.py       Core verifier (stdlib only) verify_bundle.py     Bundle verifier (full report) validate_repo.py     One-command repository validation release_build.py     Deterministic release builder

tests/ Core deterministic test suite (228 tests)

tests_adversarial/ Adversarial and scenario tests (461 tests)

examples/ Sample bundles (PASS / FAIL / ERROR)

docs/ Full specification documents

schemas/ JSON schemas

profiles/ Adapter mapping profiles

---

## Running the system

Install locally:

pip install -e .

Run repository validation:

python tools/validate_repo.py

This runs:

selfcheck → core tests → adversarial tests → example verification

If it exits successfully, the repository is validated.

---

## Test Coverage

Current validated counts:

228 core deterministic tests 461 adversarial scenario tests 689 total tests

Coverage includes:

- hostile zip files  

- malformed manifests  

- corrupted hashes  

- path traversal attempts  

- payload boundary violations  

- ingestion failure modes  

---

## Example verification

Verify a clean bundle:

python tools/verify_case.py examples/case_boundary_test.zip

Verify a tampered bundle:

python tools/verify_case.py examples/case_boundary_test_TAMPER2.zip

Expected results:

clean bundle → PASS tampered bundle → FAIL

---

## Release

Create a deterministic release archive:

python tools/release_build.py

This performs:

- validation  

- artifact cleanup  

- deterministic zip creation  

- release manifest generation  

---

## Security Model

Aletheia assumes:

- inputs may be hostile  

- bundles may be tampered  

- verification may run offline  

- results must be reproducible  

Therefore the system enforces:

- bounded inputs  

- deterministic processing  

- explicit failure states  

- append-only evidence recording  

---

## License

Apache License 2.0

---

## Status

Practical Core v1 Deterministic provenance system Full adversarial validation suite Adapter framework integrated Repository validation tooling active

---

## Purpose

Aletheia provides a minimal deterministic foundation for evidence provenance systems where verification must remain reproducible, inspectable, and resistant to hidden manipulation.

Once you paste this:

1. Delete everything in the conflict editor

2. Paste this

3. Click Mark as resolved

4. Click Commit merge

5. Then Merge pull requests 