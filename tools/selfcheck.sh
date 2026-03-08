#!/bin/sh
# selfcheck.sh — Aletheia engine self-check
# Works on: Termux (Android), Linux, macOS
# No hardcoded paths. Run from any directory.
set -e

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
export PYTHONPATH="$ROOT_DIR"

# Detect python binary (Termux uses 'python', others may use 'python3')
if command -v python3 > /dev/null 2>&1; then
    PY=python3
elif command -v python > /dev/null 2>&1; then
    PY=python
else
    echo "[selfcheck] ERROR: python not found. Install python first."
    exit 1
fi

echo "[selfcheck] ROOT=$ROOT_DIR"
echo "[selfcheck] Python=$($PY --version 2>&1)"

# 1. Engine module check
echo "[selfcheck] Checking engine modules..."
$PY "$ROOT_DIR/aletheia_selfcheck.py"
if [ $? -ne 0 ]; then
    echo "[selfcheck] FAIL: engine module check failed"
    exit 2
fi

# 2. Verify known-good example
echo "[selfcheck] Verifying known-good example..."
$PY "$ROOT_DIR/aletheia.py" verify "$ROOT_DIR/examples/case_boundary_test.zip" --json | \
    $PY -c "import sys,json; r=json.load(sys.stdin); v=r.get('overall_verdict'); print('[selfcheck] good case verdict:', v); sys.exit(0 if v=='PASS' else 2)"
if [ $? -ne 0 ]; then
    echo "[selfcheck] FAIL: good example did not PASS"
    exit 2
fi

# 3. Verify tampered example detects tampering
echo "[selfcheck] Verifying tampered example is caught..."
TAMPER_VERDICT=$($PY "$ROOT_DIR/aletheia.py" verify "$ROOT_DIR/examples/case_boundary_test_TAMPER2.zip" --json | \
    $PY -c "import sys,json; r=json.load(sys.stdin); print(r.get('overall_verdict','ERROR'))")
if [ "$TAMPER_VERDICT" = "FAIL" ] || [ "$TAMPER_VERDICT" = "ERROR" ]; then
    echo "[selfcheck] tampered case verdict: $TAMPER_VERDICT (correct)"
else
    echo "[selfcheck] FAIL: tampered example gave unexpected verdict: $TAMPER_VERDICT"
    exit 2
fi

echo ""
echo "[selfcheck] ALL OK — Aletheia is working correctly on this device."
echo "Try: $PY aletheia.py demo"
