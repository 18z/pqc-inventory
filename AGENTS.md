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

Each finding includes `file`, `line`, `family`, `quantum_risk`, `priority_score`, `owner`, `data_lifetime_years`.

## Rules

- Scope is source + dependency manifests only. Do not claim runtime, binary, or full-estate coverage.
- CBOM may include `pqc-inventory:ref:*` planning references (EO 14412 / CNSA / NIST IR 8547). Never claim the scan certifies compliance.
- Never invent `data_lifetime_years` or sensitivity. Leave unknown unless the user sets an override.
- Overrides: `--set-lifetime 'path:line=15'`, `--set-exposure`, `--set-owner`, or a line comment `# pqc-inventory: lifetime=15 exposure=public_key owner=team`.
- Hash/checksum noise: default `--hash-policy downrank`. Use `drop` to omit, `keep` to keep.
- Exit codes: `0` ok, `1` over `--fail-on` / `--fail-score`, `2` bad path or args.
- CI that must not fail on demo highs: `--fail-on never`.
- Do not rewrite crypto, rotate keys, or "fix" findings unless the user explicitly asks.

## Suggested agent loop

1. Scan the target with `--out`.
2. Summarize HIGH items by `priority_score`, not raw HIGH count.
3. Ask the user to fill owner / lifetime for the top items if those fields are empty.
4. Point them at `report.md` and `cbom.cdx.json`.
