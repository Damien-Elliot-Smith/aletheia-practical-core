# Security Posture (Deployable v1)

## Design stance
- Deterministic, auditable, append-only.
- "Fail closed" on integrity: prefer **INCONCLUSIVE** over invented certainty.

## File integrity
- Each event is hashed over a canonical JSON encoding.
- Each sealed window records a root hash over the event hash chain.
- `case_manifest.json` lists hashes/sizes for all included files.
- `tools/verify_case.py` verifies the case without importing the codebase.

## Custody and access
- Reading/exporting evidence should be treated as a custody event (future expansion).
- Today: verification guarantees integrity of the exported artifact, not who accessed it.

## Keys and signing
- Optional signing of sealed windows is not enabled in Deployable v1.
- If/when added, keys must be managed outside the repo (env/keystore/HSM).

## Operational guidance
- Always seal windows before exporting cases used for audit or decisions.
- Treat SCAR (dirty shutdown) as an integrity boundary.
- If ingest rejects surge, expect Siren to escalate and halt/limit capture rather than pretending everything is fine.

## What to do when verification fails
- Stop using the case for decisions.
- Re-export from the original root if available.
- If the root is suspect, collect a fresh copy and treat the incident as potential evidence compromise.
