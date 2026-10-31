# WORKLOG

Start: 2026-10-31 14:13 IST. Deadline: 16:43 IST. Implementation finished about 14:50 (≈ 37 min used); no step overran its time box.

## Step log
| Time (IST) | Step | Outcome |
|---|---|---|
| 14:13–14:24 | Inspection | Dossier read in full (22 sections). Missing sources and dataset findings recorded in docs/DECISIONS.md D-01..D-07. |
| 14:24–14:26 | 1 Scaffold | venv (Python 3.11), pinned requirements, Cytoscape 3.30.2 vendored, Makefile, docs. |
| 14:26–14:28 | 2 Data generation | `tools/gen_scenarios.py`: A1, A2, D1; deterministic (identical SHA-256 across runs); 10% CEF; tags off by default. |
| 14:28–14:30 | 3 Ingestion | JSON/CEF/FortiGate parsers, field_map.yaml, Parquet, parse_errors, evidence verify. 20,129 lines, 0 errors, 0.64 s. |
| 14:30–14:34 | 4 Detection | 12 YAML rules (R001–R011 + R010), match/threshold/followed_by/baseline, label priority + also_matched. |
| 14:34–14:38 | 5 Correlation | §12 formula, entity index, degree penalty, top-K, union-find, ≥ 2-tactic gate; A1, A2 found; D1 abstained. |
| 14:38–14:39 | 6 Reachability | §14 compromised set, observed/configured/inferred edges, max-product search, disable_account simulation. |
| 14:39–14:42 | 7 API + UI | FastAPI endpoints, strict CSP, dashboard verified in headless Chrome. |
| 14:42–14:45 | 8 Scoring + tests | tools/score.py; 54 tests pass. |
| 14:45–14:47 | Hardening | Independent run on edr_events.json and a 50 MB firex slice: added process-tree `link` to R010, fixed FortiGate timestamps, evidence computed only for kept edges. |
| 14:47–14:50 | 9 Docs + final validation | make sample/run/score/test/serve all pass. |

## Follow-up (2026-10-31 ~15:00–15:25 IST): UI and input workflow
- Rebuilt the dashboard as a multi-page console: overview, incidents, detections, data sources, rules and evaluation pages, plus an evidence drawer, deep links and themes. Checked in headless Chrome in dark and light mode.
- Added the `data/input/` drop folder, `make analyze`, raw-body uploads, background runs with progress, per-workspace results and new endpoints (`/workspaces`, `/overview`, `/detections`, `/metrics`, `/inputs`, `/runs`).
- Tests: 56 pass, including a live upload → analyse → evidence → delete cycle and path-traversal rejection.

## Follow-up: Pipeline demo page
- Added `data/demo/demo_events.log` (5 events), `make demo`, `GET /walkthrough`, and an 8-step "Pipeline demo" page showing ingest → normalise/store → detect → aggregate → correlate → graph → path → risk/reach/evidence on real stored output. Every step was checked in headless Chrome. 57 tests pass.

## Phase 2 (docs/PHASE2.md) — 2026-10-31 evening

| WP | Done | Acceptance criterion | Status | Evidence |
|---|---|---|---|---|
| STEP 0 | PHASE2.md saved; STATE.md; bench harness; 10 GB baseline | prompt saved verbatim and committed; state + gaps written; 10 GB measured | PASS (py-spy replaced by cProfile: needs root on macOS) | `e6d64a3`, docs/STATE.md, bench/baseline.json |
| EV-0 | Pydantic models + Arrow schemas; pipeline emits detector/score/reasons, p_malicious/contributions, dataset | "Freeze interfaces … tests for round-trip" | PASS | tests/test_models.py (7 tests) |
| EV-1 | `forgetrace eval`, metrics schema, bootstrap, multi-seed | "every metric unit-tested on a toy ground truth with a hand-computed answer; writes metrics/<ds>/<exp>.json" | PASS (reach hit@k and time-to-first-incident reported N/A until CO-4/SC-4) | tests/test_eval_metrics.py (12 tests); dev sample equals tools/score.py |
| EV-2 | 20-seed D0 suite | "Seeds 1–10 tuning, 11–20 test; byte-identical regeneration" | PASS | tests/test_suite.py; data/d0/suite.json |

## Metrics (make score, seed 7)
Step recall 100% (11/11) · parent label 100% · sub-technique 81.8% (R008 emits T1021, ground truth T1021.001/.002) · attacks in order 2/2 · false-alarm share 0/2 · run 1.14 s · peak RSS 231.5 MiB.
The generator, ground truth and rules share an author, so these numbers are optimistic (see README "How to read these numbers").

## Requirements not met / reduced scope
- Source files named in the brief are absent: `docs/ForgeTrace_Dossier.pdf` (used the root PDF), `docs/PRD_Kill_Chain_Attack_Path.pdf`, `tools/edr_log_generator.py`; dossier §23–25 do not exist (D-01..D-04). The benign generator was reimplemented instead of imported.
- Manifest ground truth could not be used for evaluation: it describes firex-30G + a Windows stream that are not present (D-05).
- The primary path uses the brief's time/tactic ordering; the dossier DP is shown as `strongest_chain` and drops weakly linked steps (D-30).
- Only disable_account is simulated (D-34). The network factor in reachability is not modelled.

## Open risks
- Overfitting: rules and data come from the same author; R009's rarity condition misses C2 destinations shared by many hosts (seen in edr_events.json).
- Precision at scale is untested: the 13 incidents on edr_events.json (Execution+Persistence) have no ground truth to judge them against.
- Single-process ingest at ~12.6 MB/s/core would need ~8 min for the ~4.8 GB of text in firex-10G (estimate from the 50 MB measurement, not a measured run).
- `config/assets.yaml` is generated alongside the sample; for real data it must be authored.

## Next Phase (explicitly deferred)
- Parallel byte-range ingestion (dossier §11 worker pool).
- Full-tier ingestion and processing (firex-10G / firex-30G).
- Top-k alternative attack paths.
- Bounded connectors (dossier §12 step 5).
- Privacy controls (dossier §15).
- LLM-generated reports.
- Docker deployment.
- Live mode.
- Also: RDP/SMB sub-technique rules, firewall rule pack, STIX-built technique table, `sequence` rules, truncation backtest (§9), `/report` and `/metrics`.
