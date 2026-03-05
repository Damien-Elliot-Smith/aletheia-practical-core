from aletheia.detective.canon import canonical_json_bytes

def test_canonical_json_stable_ordering():
    a = canonical_json_bytes({"b": 1, "a": 2})
    b = canonical_json_bytes({"a": 2, "b": 1})
    assert a == b
