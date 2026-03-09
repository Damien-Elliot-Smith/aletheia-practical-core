# Changelog

## v1.0.0 — 2026-03-09

### Core engine
- Spine: append-only, hash-chained event ledger with POSIX-correct atomic writes
- Siren: degrade-and-MAYDAY state machine (NORMAL → DEGRADED → SUMMARIES_ONLY → HALT)
- Ingest: bounded rejection ring, surge detection, rate gate
- ZipGuard: hostile zip filter (path traversal, symlinks, bombs, size limits)
- Detective: deterministic drift-locked sieve with canonical JSON hashing
- Claims FSM: closed finite-state model (OPEN → WITNESSED → DERIVED → REFUTED → SUPERSEDED → INCONCLUSIVE → RETRACTED)
- Chronicle: case bundle export (sealed, hash-manifest, replay-verifiable)
- Veritas: epistemic session layer with claim pinning

### Adapter layer (Universal Ingest Boundary)
- Closed loss taxonomy: LOSS_OF_PRECISION, LOSS_OF_STRUCTURE, LOSS_OF_COMPLETENESS, LOSS_OF_CAUSAL_LINKAGE, LOSS_OF_AUTHENTICITY
- Closed rejection taxonomy: MALFORMED, UNVERIFIABLE, INCOMPLETE, INCONSISTENT, UNSUPPORTED, HOSTILE
- JSON adapter (Phase 3): NaN/Inf scan, depth guard, profile mode
- File adapter (Phase 4): STRICT/MIXED modes, line-level provenance
- AI audit adapter (Phase 5A): inference_request/response, tool invocations, moderation, session bounds
- AI causal adapter (Phase 5B): tool call linkage, reasoning chain reconstruction, override tracking, moderation lineage
- OT adapter (Phase 6): sensor readings, state changes, commands, alarms, maintenance; ISA-95 quality codes
- Mapping profiles (Phase 7): field translation via JSON config, no invented certainty
- Streaming layer (Phase 9): bounded buffer with backpressure, batch hashing, webhook HMAC verification
- Adapter selfcheck (Phase 10): known-answer tests, version fingerprinting

### Test coverage
- 257 core tests (stdlib unittest, no dependencies)
- 461 adversarial scenario tests
- 718 total

### Repository structure
- `pyproject.toml`: installable via `pip install -e .`
- `tools/validate_repo.py`: single-command validation
- `tools/release_build.py`: deterministic release zip with SHA256
- `examples/`: three case bundles (PASS / FAIL / ERROR) for cold-start verification
- `tests/`: core test suite
- `tests_adversarial/`: adversarial and legacy phase tests
- Docs: ADAPTER_SPEC, DETERMINISM_RULES, LOSS_TAXONOMY, REJECTION_TAXONOMY, ADAPTER_TRUST_MODEL, PROFILE_SPEC, RETENTION_POLICY, THREAT_MODEL, SECURITY, ARCHITECTURE, SPINE_SPEC, SIREN_SPEC, CLAIMS, VERITAS

### Known limitations
- RFC 3161 timestamp authority: interface defined, live TSA submission not yet implemented
- Multi-node federation: module stubs present, full implementation is Phase 2 roadmap
- REST API: module stub present, full implementation is Phase 2 roadmap
