PY ?= .venv/bin/python
INPUT ?= data/sample/events.log
OUT ?= out
INPUT_DIR ?= data/input

.PHONY: setup sample run analyze score serve test clean

setup:
	python3.11 -m venv .venv && .venv/bin/pip install -r requirements.txt

sample:
	$(PY) tools/gen_scenarios.py --start 2026-10-01T00:00:00Z --days 2 --seed 7 --events 20000 --cef-ratio 0.1

# Dev sample -> workspace out/sample (scored against ground truth)
run:
	$(PY) -m forgetrace run --input $(INPUT) --out $(OUT)/sample

# Your own logs: every log file in data/input/ -> workspace out/input
analyze:
	$(PY) -m forgetrace run --input $(INPUT_DIR) --out $(OUT)/input

score:
	$(PY) tools/score.py --gt data/sample/ground_truth.json --out $(OUT)/sample

serve:
	$(PY) -m forgetrace serve --out $(OUT)

test:
	$(PY) -m pytest -q

clean:
	rm -rf $(OUT)
