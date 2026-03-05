#!/data/data/com.termux/files/usr/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
export PYTHONPATH="$ROOT_DIR"

echo "[selfcheck] ROOT_DIR=$ROOT_DIR"

python -m aletheia.detective --help >/dev/null

# Phase B1 gate: ban raw zipfile.ZipFile usage outside allowed modules
echo "[selfcheck] zip IO gate (no raw zipfile.ZipFile outside ZipGuard/_zip_io/_zip_write; tests exempt)..."
BAD="$(grep -RIn "zipfile\.ZipFile(" . \
  --exclude-dir=__pycache__ \
  --exclude="*.pyc" \
  | grep -v "aletheia/detective/zipguard.py" \
  | grep -v "tools/_zip_io.py" \
  | grep -v "tools/_zip_write.py" \
  | grep -v "^\./tests/" || true)"
if [ -n "$BAD" ]; then
  echo "[selfcheck] FAIL: raw zipfile.ZipFile usage found (must route through tools/_zip_io.py or tools/_zip_write.py):"
  echo "$BAD"
  exit 2
fi


CASES="/storage/emulated/0/Aletheia/cases"
GOOD="$CASES/case_boundary_test.zip"
BAD1="$CASES/case_boundary_test_TAMPER.zip"
BAD2="$CASES/case_boundary_test_TAMPER2.zip"

for f in "$GOOD" "$BAD1" "$BAD2"; do
  if [ ! -f "$f" ]; then
    echo "[selfcheck] ERROR: missing required demo case: $f"
    exit 2
  fi
done

echo "[selfcheck] verify GOOD (expect PASS): $GOOD"
python -m aletheia.detective verify "$GOOD" --pretty | grep -q '"verdict": "PASS"'

echo "[selfcheck] verify BAD1 (expect ERROR): $BAD1"
OUT1="$(python -m aletheia.detective verify "$BAD1" --pretty || true)"
echo "$OUT1" | grep -q '"status": "ERROR"'

echo "[selfcheck] verify BAD2 (expect FAIL): $BAD2"
OUT2="$(python -m aletheia.detective verify "$BAD2" --pretty || true)"
echo "$OUT2" | grep -q '"verdict": "FAIL"'

echo "[selfcheck] OK"
