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
.venv/bin/python -m pqc_inventory scan samples/vulnerable-app --out "$OUT" --fail-on never
echo ""
echo "Report: $OUT/report.md"
echo "Inventory: $OUT/inventory.json"
echo "CBOM: $OUT/cbom.cdx.json"
echo "SARIF: $OUT/results.sarif"
echo ""
echo "Note: SAFE (NIST PQC) findings appear in inventory/report/CBOM;"
echo "      they are omitted from SARIF alerts (like competitor SAFE tracking)."
if command -v python3 >/dev/null; then
  python3 - <<'PY' "$OUT"
import json, sys
from pathlib import Path
out = Path(sys.argv[1])
inv = json.loads((out / "inventory.json").read_text())
by = inv["summary"]["by_risk"]
print(f"by_risk: {by}")
safe = [f for f in inv["findings"] if f["quantum_risk"] == "safe"]
print(f"SAFE findings in inventory: {len(safe)}")
sarif = json.loads((out / "results.sarif").read_text())
print(f"SARIF alerts: {len(sarif['runs'][0]['results'])} (SAFE excluded)")
PY
fi
