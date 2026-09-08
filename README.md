![pqc-inventory](docs/logo.png)

# pqc-inventory

給其他 AI agent：見 [AGENTS.md](AGENTS.md)。


把專案裡「用了哪些密碼演算法」掃出來，排出該先處理哪個，並產出報告。

適合：合規／密碼盤點、PQC 遷移**開工前**的清單。  
不是遷移引擎，也不會猜資料要保密幾年。

## 30 秒試跑

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pqc_inventory scan samples/vulnerable-app --out ./out
```

打開這三個檔：

| 檔案 | 給誰看 |
|------|--------|
| `out/report.md` | 人：優先序＋下一步 |
| `out/inventory.json` | 程式：每筆命中的細節 |
| `out/cbom.cdx.json` | 機器可讀的密碼清單（CycloneDX CBOM） |

## 它看什麼

只看**原始碼與依賴清單**（Python / JS / `requirements.txt`、`package.json` 等）。

不看執行期、二進位、網路流量。掃不完整個環境，也不保證沒漏。

## 風險怎麼排

分數 = 演算法風險 + 資料壽命 + 暴露面。

- 你沒標壽命，欄位就維持 unknown，工具**不會猜**。
- 本地 hash／checksum 預設降權，比較不會洗版。

自己標壽命（選用）：

```bash
pqc-inventory scan PATH --out ./out \
  --set-lifetime 'app/crypto.py:14=15' \
  --set-owner 'app/crypto.py=payments'
```

或在程式上一行寫：

```python
# pqc-inventory: lifetime=15 exposure=public_key owner=payments
```

## CI（選用）

有 HIGH 就失敗：

```bash
pqc-inventory scan PATH --out ./out --fail-on high
```

| 結束碼 | 意思 |
|--------|------|
| 0 | 通過 |
| 1 | 超過門檻 |
| 2 | 路徑或參數錯誤 |

範例 workflow：`.github/workflows/pqc-inventory.yml`

## 不做的事

- 不改程式、不輪替金鑰、不自動換成 PQC
- 不猜資料壽命或敏感度
- 不做攻擊、破解、exploit

## 測試

```bash
.venv/bin/python -m pytest -q
```

MIT。僅供防禦性盤點。
