# Using pqc-inventory from an AI agent

Defensive static crypto inventory. Inventory and prioritize only.
Do not add attack, exploit, or auto-migration features.

## When to run

The user wants a cryptographic asset list, quantum-risk flags, a priority report, or a CycloneDX CBOM from source code and dependency manifests.

## Command

```bash
python3 -m pip install -e ".[dev]"
python3 -m pqc_inventory scan <repo-or-dir> --out ./out
```

Always pass `--out`. Read results from files, not from stdout.

## Outputs

| File | Use |
|------|-----|
| `out/inventory.json` | Machine-readable findings. Prefer this. |
| `out/report.md` | Human priority report and next steps |
| `out/cbom.cdx.json` | CycloneDX 1.6-oriented CBOM |
| `out/results.sarif` | SARIF 2.1.0 for GitHub code scanning |

Each finding includes `file`, `line`, `family`, `quantum_risk`, `priority_score`, `owner`, `data_lifetime_years`.

## Rules

- Scope is source + dependency manifests only. Do not claim runtime, binary, or full-estate coverage.
- CBOM may include `pqc-inventory:ref:*` planning references (EO 14412 / CNSA / NIST IR 8547). Never claim the scan certifies compliance.
- `results.sarif` is SARIF 2.1.0; only non-suppressed, non-`safe` findings become alerts. SAFE (NIST PQC / already-migrated) stays in inventory/CBOM/report. Upload with `github/codeql-action/upload-sarif@v3`; workflow needs `security-events: write`. Still static-only / not certification.
  Drop-in Action:
  ```yaml
  - uses: 18z/pqc-inventory/.github/actions/scan@main
    with:
      path: .
      out: out
      fail-on: high
  - uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: ${{ steps.<id>.outputs.sarif-file }}
  ```
  Or CLI:
  ```yaml
  - run: pqc-inventory scan . --out out --fail-on never
  - uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: out/results.sarif
  ```
- Never invent `data_lifetime_years` or sensitivity. Leave unknown unless the user sets an override.
- Overrides: `--set-lifetime 'path:line=15'`, `--set-exposure`, `--set-owner`, or a line comment `# pqc-inventory: lifetime=15 exposure=public_key owner=team`.
- Hash/checksum noise: default `--hash-policy downrank`. Use `drop` to omit, `keep` to keep.
- Exit codes: `0` ok, `1` over `--fail-on` / `--fail-score`, `2` bad path or args. `safe` never trips `--fail-on`.
- CI that must not fail on demo highs: `--fail-on never`.
- Baseline (known findings): `--write-baseline PATH` after a scan; `--baseline PATH` to suppress known fingerprints for fail-on / fail-score (primary report list is new-only). Fingerprint = `sha256(rule_id|file|normalize_whitespace(snippet))`, line-insensitive. Bad/missing baseline → exit 2.
- Do not rewrite crypto, rotate keys, or "fix" findings unless the user explicitly asks.

## Suggested agent loop

1. Scan the target with `--out`.
2. Summarize HIGH items by `priority_score`, not raw HIGH count.
3. Ask the user to fill owner / lifetime for the top items if those fields are empty.
4. Point them at `report.md` and `cbom.cdx.json`.
