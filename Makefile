PYTHON ?= python3
VENV ?= .venv
BIN := $(VENV)/bin
SENTINEL := $(BIN)/sentinel
PYTHON_FILES := $(shell find sentinel -type f -name '*.py')
POLICY_FILES := $(shell find policies sentinel/policies sentinel/scanner/rules -type f 2>/dev/null)

.PHONY: install demo gateway sandbox dashboard scan benchmark load-benchmark verify clean

install: $(SENTINEL)

$(SENTINEL): pyproject.toml README.md $(PYTHON_FILES) $(POLICY_FILES)
	$(PYTHON) -m venv $(VENV)
	$(BIN)/python -m pip install --disable-pip-version-check -e .

demo: install
	$(SENTINEL) demo

gateway: install
	$(SENTINEL) gateway --policy policies/default-strict.yaml

sandbox: install
	$(SENTINEL) sandbox

dashboard:
	cd dashboard && npm ci --no-audit --no-fund && npm run dev

scan: install
	$(SENTINEL) scan sentinel --format sarif --output sentinel.sarif

benchmark: install
	$(BIN)/python -m benchmarks.run_benchmark

load-benchmark: install
	$(BIN)/python -m benchmarks.load_gateway --target http://127.0.0.1:8000

verify: install
	$(SENTINEL) verify

clean:
	rm -rf $(VENV) dashboard/node_modules dashboard/dist reports/demo-report.md benchmarks/results/latest.json build dist
