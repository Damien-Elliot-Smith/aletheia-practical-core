# Claims (Epistemic layer)

Claims live in the Spine window `claims` as append-only `CLAIM` events.

## Quick demo

```bash
python ag.py init --root ./demo_root
python ag.py claim-propose --root ./demo_root --claim-id c1 --type EMPIRICAL --text "sensor temp is stable" --seal
python ag.py claim-show --root ./demo_root --claim-id c1 --window claims
```
