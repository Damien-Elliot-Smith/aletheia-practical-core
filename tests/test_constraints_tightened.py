import tempfile, zipfile, json
from pathlib import Path
from aletheia.spine.ledger import SpineLedger
from aletheia.constraints.registry import ConstraintRegistry, ConstraintEQI
from aletheia.chronicle.export import build_case_zip

def test_get_active_ignores_deprecate_as_head_and_deprecates_prev():
    with tempfile.TemporaryDirectory() as td:
        root=Path(td); led=SpineLedger(root)
        reg=ConstraintRegistry(led, window_id="constants")
        r1=reg.publish("x","1.0",{"a":1})
        # deprecate the published constraint
        reg.deprecate("x","1.0", previous_hash=r1.constraint_hash)
        led.seal_window("constants"); led.close_clean()
        eqi=ConstraintEQI(root, window_id="constants")
        assert eqi.get_active("x") is None

def test_get_active_detects_fork_and_returns_none():
    with tempfile.TemporaryDirectory() as td:
        root=Path(td); led=SpineLedger(root)
        reg=ConstraintRegistry(led, window_id="constants")
        # two independent publishes (fork)
        reg.publish("y","1.0",{"a":1})
        reg.publish("y","1.1",{"a":2})
        led.seal_window("constants"); led.close_clean()
        eqi=ConstraintEQI(root, window_id="constants")
        assert eqi.get_active("y") is None

def test_chronicle_snapshot_records_forks():
    with tempfile.TemporaryDirectory() as td:
        root=Path(td); led=SpineLedger(root)
        reg=ConstraintRegistry(led, window_id="constants")
        reg.publish("z","1.0",{"a":1})
        reg.publish("z","1.1",{"a":2})
        led.seal_window("constants")
        led.open_window("w1"); led.append_event("w1","WITNESS",{"a":1}); led.seal_window("w1")
        led.close_clean()
        out=root/"case.zip"
        build_case_zip(root,out)
        with zipfile.ZipFile(out,"r") as zf:
            snap=json.loads(zf.read("evidence/constraints_registry_snapshot.json").decode("utf-8"))
        assert "forks" in snap
        assert "z" in snap["forks"]
