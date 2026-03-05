# Provenance (Aletheia Practical Core)

Deterministic provenance and verification system for evidence bundles.

## Quickstart

Run the verification demo:

export PYTHONPATH="$PWD"

python tools/ui_verify.py examples/case_boundary_test.zip
python tools/ui_verify.py examples/case_boundary_test_TAMPER.zip
python tools/ui_verify.py examples/case_boundary_test_TAMPER2.zip

Expected results:

case_boundary_test.zip -> PASS  
case_boundary_test_TAMPER.zip -> ERROR (corrupt zip)  
case_boundary_test_TAMPER2.zip -> FAIL (hash mismatch)

## Compile sanity check

export PYTHONPATH="$PWD"

python -m py_compile \
tools/_zip_write.py \
tools/verify_bundle.py \
tools/ui_verify.py \
aletheia/chronicle/export.py \
aletheia/detective/__init__.py
