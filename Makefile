PY ?= .venv/bin/python
DATA ?= data/sample/events.log
INPUT ?= $(DATA)
OUT ?= out
INPUT_DIR ?= data/input

.PHONY: setup sample run analyze demo score eval bench check serve test clean graph-up graph-down

setup:
	python3.11 -m venv .venv && .venv/bin/pip install -r requirements.txt

sample:
	$(PY) tools/gen_scenarios.py --start 2026-10-01T00:00:00Z --days 2 --seed 7 --events 20000 --cef-ratio 0.1

# Dev sample -> workspace out/sample (scored against ground truth)
run:
	$(PY) -m forgetrace run --input $(INPUT) --out $(OUT)/sample $(if $(GRAPH),--graph,)

# Your own logs: every log file in data/input/ -> workspace out/input
analyze:
	$(PY) -m forgetrace run --input $(INPUT_DIR) --out $(OUT)/input

# 5-event walkthrough file -> workspace out/demo (shown on the dashboard's Demo page)
demo:
	$(PY) -m forgetrace run --input data/demo/demo_events.log --out $(OUT)/demo

score:
	$(PY) tools/score.py --gt data/sample/ground_truth.json --out $(OUT)/sample

# Phase 2 evaluation: make eval DS=d0 EXP=E0 [GT=... RUN=...] -> metrics/<DS>/<EXP>.json
DS ?= d0
EXP ?= dev
GT ?= data/sample/ground_truth.json
RUN ?= $(OUT)/sample
eval:
	$(PY) -m forgetrace eval --gt $(GT) --run $(RUN) --dataset $(DS) --experiment $(EXP)

# Throughput + peak RSS of one run: make bench DATA=<file> BENCH=bench/<name>.json
BENCH ?= bench/latest.json
bench:
	$(PY) tools/bench.py --input $(DATA) --out $(OUT)/bench --report $(BENCH)

# Neo4j graph store (docs/wp/GR-1.md): make graph-up, then `make run GRAPH=1` or `forgetrace run --graph`
graph-up:
	docker compose -f deploy/neo4j/docker-compose.yml up -d
graph-down:
	docker compose -f deploy/neo4j/docker-compose.yml down

check:
	$(PY) -m ruff check forgetrace tools tests
	$(PY) -m pytest -q

serve:
	$(PY) -m forgetrace serve --out $(OUT)

test:
	$(PY) -m pytest -q

clean:
	rm -rf $(OUT)
