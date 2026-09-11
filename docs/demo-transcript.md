# Demo transcript — SAFE PQC + SARIF omission

Captured 2026-09-11 from `./demo.sh` against `samples/vulnerable-app`
(includes intentional NIST PQC strings in `python_app/pqc_migrated.py` and
`js_app/pqc_migrated.js`). SAFE alias pairs (ML-KEM↔Kyber, etc.) on the same
asset are merged so inventory is not double-counted.

```text
$ ./demo.sh
Scanned 7 file(s); 42 merged finding(s) (raw hits: 57; suppressed: 3).
  high=19 medium=9 low=2 info=3 safe=9
Wrote: out/inventory.json
Wrote: out/report.md
Wrote: out/cbom.cdx.json
Wrote: out/results.sarif

by_risk: {'high': 19, 'medium': 9, 'low': 2, 'info': 3, 'safe': 9}
SAFE findings in inventory: 9
SARIF alerts: 30 (SAFE excluded)
```

## What to look for

| Artifact | SAFE (ML-KEM / ML-DSA / SLH-DSA / PQC) |
|----------|----------------------------------------|
| `inventory.json` | Present (`quantum_risk: "safe"`); alias pairs merged per asset |
| `report.md` | Listed under prioritized findings as `[SAFE]` |
| `cbom.cdx.json` | Components with high `nistQuantumSecurityLevel` |
| `results.sarif` | **Absent** from `runs[].results` (not an alert) |

`--fail-on high` (or even `--fail-on info`) does **not** fail solely because of SAFE hits.

## Drop-in CI

```yaml
- uses: 18z/pqc-inventory/.github/actions/scan@main
  with:
    path: .
    out: out
    fail-on: high
```

See `.github/workflows/pqc-inventory.example.yml`.
