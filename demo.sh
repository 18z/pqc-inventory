#!/usr/bin/env bash
# Equivalent to `make demo` when GNU make is unavailable.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
if [[ ! -x .venv/bin/python ]]; then
  python3 -m venv .venv
fi
.venv/bin/pip install -e ".[dev]" -q
OUT="${OUT:-$ROOT/out}"
.venv/bin/python -m pqc_inventory scan samples/vulnerable-app --out "$OUT"
echo ""
echo "Report: $OUT/report.md"
echo "Inventory: $OUT/inventory.json"
echo "CBOM: $OUT/cbom.cdx.json"
