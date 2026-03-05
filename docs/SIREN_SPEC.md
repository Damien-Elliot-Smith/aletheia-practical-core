# Siren v1 (Implemented)

## What it does now
- Persists a 4-state degrade ladder
- Emits Spine events:
  - MAYDAY on every transition
  - MAYDAY_HEARTBEAT periodically while degraded
- Stores state at: spine/siren_state.json
- Never silently resets to NORMAL after restart

## States
NORMAL → DEGRADED_CAPTURE → SUMMARIES_ONLY → HALT (and RECOVERED to NORMAL)

## Reason codes (minimal)
DISK_PRESSURE, VERIFY_FAIL, INTEGRITY_COMPROMISE, MANUAL, RECOVERED, HEARTBEAT
