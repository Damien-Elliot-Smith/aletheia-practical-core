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
