#!/usr/bin/env bash
set -euo pipefail

# Release hardening wrapper (Step 17)
# Usage:
#   PYTHONPATH="." bash tools/release.sh --version v1_18 --out-dir /storage/emulated/0/Download
# Defaults:
#   --version local
#   --out-dir ./dist

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

VERSION="local"
OUT_DIR="$ROOT_DIR/dist"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2;;
    --out-dir) OUT_DIR="$2"; shift 2;;
    *) echo "Unknown arg: $1" >&2; exit 2;;
  esac
done

mkdir -p "$OUT_DIR"

PYTHONPATH="$ROOT_DIR" python "$ROOT_DIR/tools/release_pack.py"   --core-dir "$ROOT_DIR"   --version "$VERSION"   --out-dir "$OUT_DIR"
