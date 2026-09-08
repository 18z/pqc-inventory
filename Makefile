.PHONY: demo test install clean venv

PYTHON ?= /workspace/a3-pqc-inventory/.venv/bin/python
PIP    ?= /workspace/a3-pqc-inventory/.venv/bin/pip
OUT    ?= /workspace/a3-pqc-inventory/out
SAMPLE ?= samples/vulnerable-app
VENV   ?= .venv

venv:
	python3 -m venv $(VENV)

install: venv
	$(PIP) install -e ".[dev]" -q

demo: install
	$(PYTHON) -m pqc_inventory scan $(SAMPLE) --out $(OUT)
	@echo ""
	@echo "Report: $(OUT)/report.md"
	@echo "Inventory: $(OUT)/inventory.json"
	@echo "CBOM: $(OUT)/cbom.cdx.json"

test: install
	$(PYTHON) -m pytest -q

clean:
	rm -rf $(OUT) .pytest_cache $$(find . -type d -name __pycache__ 2>/dev/null) *.egg-info build dist
