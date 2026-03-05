# Veritas (Phase 2a)

Veritas is a **deterministic session shell** (no LLM).
It lets a human propose claims, link evidence pins, and evolve claim status through validated transitions.

## Run

```bash
python ag.py init --root ./demo_root
python veritas.py --root ./demo_root
```

## Notes
- `claim-list` and `claim-show` use ClaimEQI, which is **sealed-window only**. Use `seal` in the REPL.
- Veritas writes `SESSION_START`/`SESSION_END` events into Spine window `sessions`.
