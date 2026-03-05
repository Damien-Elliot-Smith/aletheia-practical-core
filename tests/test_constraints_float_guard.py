import tempfile
from pathlib import Path
from aletheia.spine.ledger import SpineLedger
from aletheia.constraints.registry import ConstraintRegistry

def test_publish_allows_floats_in_rule():
    with tempfile.TemporaryDirectory() as td:
        root=Path(td); led=SpineLedger(root)
        reg=ConstraintRegistry(led, window_id="constants")
        # floats should be accepted
        reg.publish("temp.constraints","1.0",{"temp":{"min":0,"max":100,"roc_max_per_s":1.0}})
        led.seal_window("constants")
        led.close_clean()
