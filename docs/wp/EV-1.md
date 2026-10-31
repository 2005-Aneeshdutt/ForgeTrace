# EV-1 — Evaluation harness v2 (Must, 1 d, owner A)

**Responsibility.** One tool, `forgetrace eval`, that scores any run directory against any GroundTruth file and writes `metrics/<dataset>/<experiment>.json` with every PHASE2 metric, bootstrap CIs, multi-seed summaries and provenance (config hash, git SHA).

**Inputs.** GroundTruth (EV-0) files; run directories produced by `forgetrace run` (DuckDB `detections`, `event_labels`, `alert_groups`, `incident_cache`, `events`, `run_stats.json`); optional `bench/<run>.json`.

**Outputs.**
- `forgetrace/eval/runview.py`: loads a run directory into an in-memory `RunView` (detections, labels, incidents, event host/time for the locators that need it). Metrics never touch DuckDB, so they are unit-testable on toys.
- `forgetrace/eval/metrics.py`: pure metric functions (step, attack, incident, event, ML score, ranking, reach hit@k, bootstrap).
- `forgetrace/eval/schema.py`: Pydantic `MetricsFile` (the metrics JSON schema).
- `forgetrace/eval/cli.py`: `python -m forgetrace eval --gt G --run R [--gt G2 --run R2 …] --dataset D --experiment E` (several pairs = several seeds); `make eval DS= EXP=`.

**Dependencies.** EV-0.

**Failure modes.** A metric with an empty denominator must print N/A with a reason, never 0 or 100. ML score metrics need detections with scores and are N/A for rule-only runs where every score is the rule prior. Reach hit@k needs the truncation backtest (CO-4): N/A until then. p95 path latency is measured in-process on the API handler (no HTTP stack), and is labelled that way. time_to_first_incident = wall time in batch mode until SC-4.

**Tests.** `tests/test_eval_metrics.py`: every metric on a toy ground truth with a hand-computed answer; bootstrap CI contains the point estimate and is reproducible with a fixed seed; the CLI writes a schema-valid file for the dev sample whose headline numbers equal `tools/score.py`'s.

**Acceptance criteria (from PHASE2.md).** "Eval harness v2 with every metric above, bootstrap CIs, time splits, metrics JSON schema." Plan doc: "Each metric unit-tested on a toy ground truth with a hand-computed answer; forgetrace eval writes metrics/<ds>/<exp>.json".
