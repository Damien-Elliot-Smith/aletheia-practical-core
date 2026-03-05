# Aletheia Detective v1 (Implemented)

## What it does (now)
- Read-only bridge to Spine via EQI
- Verifies Spine before reasoning
- Only uses evidence from **SEALED** windows (no parallel truths)
- Enforces drift lock via schema validation:
  - Closed line types
  - Mandatory pins for WITNESS_FACT and ELIMINATION
  - Reason codes required on every line
- Deterministic "Logic Sieve" evaluates structured hypotheses against pinned witnesses
- Scar policy: if scars exist, emits INCONCLUSIVE_SCAR line and never assumes continuity beyond sealed windows

## Minimal witness model (v1)
Witness events are Spine events with:
- event_type = "WITNESS"
- payload contains either:
  - direct witness fields: {"entity","key","value"} OR
  - nested under ingest sanitization: payload.payload = {"entity","key","value"}

## Usage
Create hypotheses, then:
Detective(root_dir).evaluate(hypotheses)
Returns a drift-locked logic map (list of dict lines).
