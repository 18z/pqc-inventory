# pqc-inventory

**防禦性**靜態掃描 CLI：盤點目錄中常見密碼學函式庫 / API 使用，標示量子風險，並產出優先級報告（Markdown + JSON + CycloneDX CBOM）。

> **Scope:** **static analysis of source code + dependency manifests only** — not runtime, binaries, network traffic, or a complete coverage guarantee.

> **範圍聲明（defensive-only）**：本工具只做盤點與風險標記。  
> **不做**：攻擊工具、exploit、金鑰破解、自動遷移 / 重加密引擎。

## Non-claims（明確非目標）

| Non-claim | Meaning |
|-----------|---------|
| **No migration engine** | Does not rewrite crypto, rotate keys, or re-encrypt data |
| **No guessed data lifetime / sensitivity** | `data_lifetime_years` and sensitivity stay empty/unknown unless you set an **explicit override** |
| **Static code + deps only** | Source + dependency manifests; not runtime, binaries, or network traffic |
| **No attack tooling** | Inventory and risk flags only |

## 做什麼

對目標路徑做啟發式 regex 掃描（Python、JS/TS 原始碼 + 常見 manifest），找出：

| 類型 | 範例 |
|------|------|
| Python | `cryptography`、PyCryptodome、`hashlib`、`ssl`、`rsa`、`ecdsa` |
| JS/TS | Node `crypto`、`node-forge`、`jose`、WebCrypto、RSA/ECDSA/ECDH |
| Manifest | `requirements.txt`、`pyproject.toml`、`package.json` 相關依賴 |

每個 finding 包含：演算法/API 家族、檔案:行號、`quantum_risk`（high/medium/low/info）、`owner` / `data_lifetime_years`、priority score 與說明。

### Denoise / merge

同一檔案+行號（或重疊 snippet / 相關 family cluster）若命中多條規則，會合併成單一 finding（列出合併的 `rule_ids` / `families`，並保留 children），避免「全部 priority 1」洗版。

### Priority score（非「全 HIGH = rank 1」）

```
priority_score = risk_points + lifetime_points + exposure_points
```

| 成分 | 說明 |
|------|------|
| **risk_points** | high=100, medium=40, low=15, info=5 |
| **lifetime_points** | **explicit override only** for the field value; scoring uses `min(50, round(years*2))` when set; **null/unknown → 20** (conservative mid + unknown penalty). Scanner never invents years. |
| **exposure_points** | trust_boundary(TLS/JWT)=30, public_key=22, library_import=12, symmetric=6, hash_local=2, other=8 — auto-classified unless overridden |

報告依 `priority_score` 降序；即使 lifetime 仍為 null，也可靠 exposure 區分兩個 HIGH（例如 JWT/TLS trust boundary 高於本地 hash helper）。`priority` 欄位為排序後的顯示名次（1 = 最急）。

## Cut B — lifetime / exposure overrides

Unoverridden findings keep `data_lifetime_years: null` and auto exposure. **Never invent** lifetime or sensitivity.

### In-file annotations

Place on the line **immediately above** a crypto hit (or as a trailing comment on the same line):

```python
# pqc-inventory-file: owner=platform-team          # file-wide owner default
# pqc-inventory: lifetime=15 exposure=public_key owner=payments
private_key = rsa.generate_private_key(...)
```

```javascript
// pqc-inventory: lifetime=10 exposure=trust_boundary owner=auth
const alg = 'RS256';
```

Keys: `lifetime` / `data_lifetime_years` / `years`, `exposure`, `owner`.  
Exposure classes: `trust_boundary`, `public_key`, `library_import`, `symmetric`, `hash_local`, `other`.

### CLI overrides

```bash
pqc-inventory scan PATH --out ./out \
  --set-lifetime 'python_app/crypto_demo.py:14=15' \
  --set-exposure 'js_app/crypto_demo.js:23=trust_boundary' \
  --set-owner 'python_app/crypto_demo.py=payments' \
  --overrides samples/vulnerable-app/pqc-overrides.example.json
```

`--set-*` uses `FILE[:LINE]=VALUE`. CLI line-specific beats JSON beats in-file annotations.

Overrides appear in `inventory.json` (`overrides_applied`, non-null `data_lifetime_years`) and `report.md` so priority scores spread.

## Cut A — hash / checksum suppression

Local SHA/hash helpers clutter priority lists. Default policy **downranks** them:

| `--hash-policy` | Behavior |
|-----------------|----------|
| `downrank` (**default**) | Cap score, mark `suppressed=true`, sort below non-suppressed |
| `drop` | Omit hash/checksum noise from merged findings |
| `keep` | No suppression |

## Cut C — exit codes & CI

| Exit | Meaning |
|------|---------|
| **0** | Scan ok / under threshold |
| **1** | Findings exceeded `--fail-on` or `--fail-score` |
| **2** | Usage / path / overrides parse error |

```bash
# Default: never fail on findings
pqc-inventory scan PATH --out ./out

# CI: non-zero if any HIGH (or worse) non-suppressed finding
pqc-inventory scan PATH --out ./out --fail-on high

# Or fail when any priority_score >= 140
pqc-inventory scan PATH --out ./out --fail-score 140
```

`--fail-on` choices: `never` (default), `high`, `medium`, `low`, `info` (level or worse).  
Minimal workflow: [`.github/workflows/pqc-inventory.yml`](.github/workflows/pqc-inventory.yml).

## 量子風險指引

| 等級 | 含義 |
|------|------|
| **high** | RSA、古典 ECDSA/ECDH/EdDSA（長期信任）、finite-field DH — Shor 演算法可破 |
| **medium** | TLS / crypto wrapper 語意不清、未見明確 PQC |
| **low** | AES / ChaCha — Grover 約使有效金鑰長度減半；實務上偏好 256-bit |
| **info** | SHA-2/3 完整性雜湊 — 一般可接受；避免 MD5/SHA-1 |

## 如何使用

```bash
cd /workspace/a3-pqc-inventory
python3 -m pip install -e ".[dev]"
python3 -m pqc_inventory scan samples/vulnerable-app --out ./out
# 或 console script：
# pqc-inventory scan samples/vulnerable-app --out ./out
```

`--out` 目錄會寫入：

- `out/inventory.json` — 機器可讀盤點（含 merge 後 findings + priority_score + overrides）
- `out/report.md` — 優先級報告 + 合規/密碼學負責人下一步建議
- `out/cbom.cdx.json` — CycloneDX 1.6–oriented Crypto BOM（CBOM）子集（stdlib JSON，無重型依賴）

可選：`--no-merge` 關閉 denoise（輸出原始 per-rule hits，不建議）。

## Demo

```bash
cd /workspace/a3-pqc-inventory
make demo          # 需要 GNU make
# 或（無 make 時）：
./demo.sh
# 或手動：
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pqc_inventory scan samples/vulnerable-app --out ./out
```

會掃描 `samples/vulnerable-app/`（刻意使用 RSA/ECDSA 等 + sample overrides），並列印報告路徑。

## 測試

```bash
make test
# 或
python3 -m pytest -q
```

## 限制與非目標（limitations / non-goals）

- **啟發式 / regex**：非完整 AST；可能有 false positive / negative。
- **僅靜態原始碼 + dependency manifests** — 不解析執行期、編譯後二進位、網路流量；**不保證完整覆蓋**。
- **不實作** PQC 遷移、金鑰輪替、或任何攻擊/破解能力。
- **不猜測** data lifetime / sensitivity — 僅接受明確 override。
- **不取代**正式密碼學審查或 SBOM / SCA 工具；作為 crypto-agility 盤點輸入。

## 授權

MIT。僅供防禦性資產盤點與合規規劃。
