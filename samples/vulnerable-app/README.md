# Sample vulnerable-app (demo only)

Intentionally uses RSA / ECDSA / EdDSA / TLS wrappers so `pqc-inventory` can
produce non-empty findings. **Do not use as production crypto guidance.**

## Sample overrides (Cut B)

In-file annotations (see `python_app/crypto_demo.py` and `js_app/crypto_demo.js`):

```
# pqc-inventory-file: owner=sample-python-team
# pqc-inventory: lifetime=15 exposure=public_key owner=payments
// pqc-inventory: lifetime=10 exposure=trust_boundary owner=auth
```

CLI / JSON example: `pqc-overrides.example.json` (optional; annotations already spread scores).

Unoverridden findings keep `data_lifetime_years: null` — the scanner never invents lifetime or sensitivity.
