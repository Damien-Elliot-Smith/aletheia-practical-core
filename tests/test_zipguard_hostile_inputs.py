import io
import os
import zipfile
import pytest

from aletheia.detective.zipguard import build_extraction_plan, ZipGuardError
from aletheia.detective.limits import ZipLimits
from aletheia.detective import reasons as R


def _make_zip(path, members):
    # members: list of (name, data_bytes, zipinfo_customizer | None)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data, customize in members:
            zi = zipfile.ZipInfo(filename=name)
            if customize:
                customize(zi)
            zf.writestr(zi, data)


def test_bad_zip(tmp_path):
    p = tmp_path / "bad.zip"
    p.write_bytes(b"not a zip")
    with pytest.raises(ZipGuardError) as e:
        build_extraction_plan(str(p), ZipLimits())
    assert e.value.reason_code == R.ERR_BAD_ZIP


def test_path_traversal(tmp_path):
    p = tmp_path / "trav.zip"
    _make_zip(str(p), [("../evil.txt", b"x", None)])
    with pytest.raises(ZipGuardError) as e:
        build_extraction_plan(str(p), ZipLimits())
    assert e.value.reason_code == R.ERR_PATH_TRAVERSAL


def test_absolute_path(tmp_path):
    p = tmp_path / "abs.zip"
    _make_zip(str(p), [("/tmp/evil.txt", b"x", None)])
    with pytest.raises(ZipGuardError) as e:
        build_extraction_plan(str(p), ZipLimits())
    assert e.value.reason_code == R.ERR_PATH_TRAVERSAL


def test_symlink_rejected(tmp_path):
    p = tmp_path / "sym.zip"
    def mark_symlink(zi):
        # set unix mode to symlink
        zi.create_system = 3
        zi.external_attr = (0o120777 << 16)  # symlink
    _make_zip(str(p), [("link", b"target", mark_symlink)])
    with pytest.raises(ZipGuardError) as e:
        build_extraction_plan(str(p), ZipLimits())
    assert e.value.reason_code == R.ERR_SYMLINK


def test_file_count_limit(tmp_path):
    p = tmp_path / "many.zip"
    limits = ZipLimits(max_files=3)
    members = [(f"f{i}.txt", b"x", None) for i in range(4)]
    _make_zip(str(p), members)
    with pytest.raises(ZipGuardError) as e:
        build_extraction_plan(str(p), limits)
    assert e.value.reason_code == R.ERR_FILE_COUNT_LIMIT


def test_total_size_limit(tmp_path):
    p = tmp_path / "big.zip"
    limits = ZipLimits(max_total_uncompressed=10)
    members = [("a.bin", b"123456", None), ("b.bin", b"123456", None)]
    _make_zip(str(p), members)
    with pytest.raises(ZipGuardError) as e:
        build_extraction_plan(str(p), limits)
    assert e.value.reason_code == R.ERR_SIZE_LIMIT


def test_single_file_limit(tmp_path):
    p = tmp_path / "onebig.zip"
    limits = ZipLimits(max_single_file=5)
    members = [("a.bin", b"123456", None)]
    _make_zip(str(p), members)
    with pytest.raises(ZipGuardError) as e:
        build_extraction_plan(str(p), limits)
    assert e.value.reason_code == R.ERR_SINGLE_FILE_SIZE_LIMIT


# --- Path collisions and non-canonical names --------------------------------
# Two entries that extract to the same file let a bundle carry content the
# verifier never looked at. Names must be canonical, and names that collide
# after case/Unicode folding are rejected so the result does not depend on
# the filesystem the bundle is verified on.

def _plan_error(tmp_path, names):
    p = tmp_path / "c.zip"
    _make_zip(str(p), [(n, b"x", None) for n in names])
    with pytest.raises(ZipGuardError) as e:
        build_extraction_plan(str(p), ZipLimits())
    return e.value.reason_code


@pytest.mark.parametrize("names", [
    ["a//b.txt", "a/b.txt"],
    ["a/./b.txt", "a/b.txt"],
    ["a//b.txt"],
    ["./a.txt"],
])
def test_non_canonical_paths_rejected(tmp_path, names):
    assert _plan_error(tmp_path, names) == R.ERR_BAD_PATH


def test_non_canonical_directory_entry_rejected(tmp_path):
    assert _plan_error(tmp_path, ["a//", "a/b.txt"]) == R.ERR_BAD_PATH


def test_traversal_hidden_in_middle_rejected(tmp_path):
    assert _plan_error(tmp_path, ["a/../b.txt"]) == R.ERR_PATH_TRAVERSAL


@pytest.mark.parametrize("names", [
    ["A.txt", "a.txt"],
    ["docs/README.md", "DOCS/readme.md"],
    ["café.txt", "café.txt"],  # NFC vs NFD
])
def test_case_and_unicode_collisions_rejected(tmp_path, names):
    assert _plan_error(tmp_path, names) == R.ERR_PATH_COLLISION


@pytest.mark.parametrize("names", [
    ["a", "a/b.txt"],
    ["A", "a/b.txt"],
    ["a/", "A"],
])
def test_file_directory_collisions_rejected(tmp_path, names):
    assert _plan_error(tmp_path, names) == R.ERR_PATH_COLLISION


def test_distinct_canonical_paths_accepted(tmp_path):
    p = tmp_path / "ok.zip"
    _make_zip(str(p), [("a/", b"", None), ("a/b.txt", b"1", None), ("a/c.txt", b"2", None), ("b.txt", b"3", None)])
    plans = build_extraction_plan(str(p), ZipLimits())
    assert [x.rel_path for x in plans] == ["a/b.txt", "a/c.txt", "b.txt"]


def test_safe_extract_never_overwrites(tmp_path):
    from aletheia.detective.zipguard import ZipMemberPlan, safe_extract
    p = tmp_path / "ok.zip"
    _make_zip(str(p), [("a.txt", b"first", None), ("b.txt", b"second", None)])
    # A hand-built plan that maps two entries onto one file must fail, not overwrite.
    plans = [ZipMemberPlan("a.txt", "x.txt", 5), ZipMemberPlan("b.txt", "x.txt", 6)]
    out = tmp_path / "out"
    with pytest.raises(FileExistsError):
        safe_extract(str(p), str(out), plans)
    assert (out / "x.txt").read_bytes() == b"first"


def test_verify_case_rejects_colliding_entries(tmp_path):
    from tools.verify_case import verify_case
    p = tmp_path / "case.zip"
    _make_zip(str(p), [("case_manifest.json", b"{}", None), ("evidence//a.json", b"{}", None), ("evidence/a.json", b"{}", None)])
    result = verify_case(p)
    assert result["verdict"] != "PASS"
    assert R.ERR_BAD_PATH in str(result)
