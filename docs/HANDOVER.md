# Phase 2 handover

## Update 2026-11-01 (supersedes the status tables below where they differ)

Direction set by the owners and mentor:
- **Accuracy metrics are paused.** There is no ground truth for the provided firex-10G/50G files; results are checked by **manual verification**, so every output carries a human-verifiable explanation.
- **Real-time is the target.** Logs arrive continuously (e.g. 2 GB per 5 min) and accumulate to TBs. The system links what arrives now to what came days ago through a growing **Neo4j knowledge graph**.
- **Nothing dataset-specific is hardcoded.** A new unseen dataset is the final checkpoint.

Built since the first handover (all committed; `make check` = 162 tests):

| Area | Entry point | Notes |
|---|---|---|
| Unseen formats | `forgetrace/ingest/parsers.py`, `config/field_aliases.yaml`, `config/site.yaml` | JSON/CEF/syslog/kv/CSV auto-detected; aliases, timestamps, message patterns in config (D-79, D-80) |
| Router / blind spots | `forgetrace/rules/router.py` → `run_plan.json` | rules disabled when their fields are absent (D-81) |
| Scale | `forgetrace/ingest/ingest.py`, `reports/scale.md` | 9-worker ingest; firex-10G 194 s, firex-50G ≈ 22 min / 6.0 GB (D-57..D-78) |
| FortiGate rules | `config/rules/firewall.yml` | 17 behaviour-only rules (no vendor verdicts) |
| Graph store | `forgetrace/graph/`, `make graph-up` | Neo4j hybrid with Parquet; campaigns = long-range links (D-62..D-70) |
| **Live engine** | `forgetrace live --watch … --out … --graph` | micro-batches, bucketed long-window rules, persistent knowledge base, accumulating graph, hot/cold tiers (D-82..D-85, docs/wp/LIVE.md) |
| **Explanations** | `GET /explain/{alert,incident,campaign}/{id}` | condition in English, observed numbers, verified raw lines, sed/grep steps, benign look-alikes (D-86) |
| **AI summary** | `?llm=true`, needs `OPENROUTER_API_KEY` | restates facts only; pseudonymised, validated, cached, capped (D-87) |
| **ML detectors** | `forgetrace/ml/`, `config/ml.yml` | behaviour model (Isolation Forest + per-entity baselines + SHAP reasons) and graph link model; fusion `p_malicious`; models corroborate rules, never form an incident alone; live retrains on stored history (D-89..D-93) |
| **UI** | Live page, Knowledge graph page | timeline graph per incident/campaign, entity explorer, explanation panel, deep link `#/graph/explain:<kind>:<id>` |

To set up on a new machine:
1. `make setup`, then `make graph-up` (Docker), then `make serve`.
2. Start live analysis with `python -m forgetrace live --watch data/input --out out/live --graph`.
3. For the AI summary, `export OPENROUTER_API_KEY=…` before `make serve`.

For a new dataset:
1. Drop the files into the watched folder.
2. Check `run_plan.json` for the formats seen, the rules that are disabled, and the learned site values.
3. Add aliases or message patterns in `config/field_aliases.yaml` if fields are missing.
4. Set `config/site.yaml` if home countries or the time zone are known.

Still open, from the PHASE2 plan:
- ML-4 (GNN encoder) and ML-5 (provenance model); ML-1..ML-3 and FU-2 (label-free form) are done
- calibrated fusion (FU-1/FU-2 learned form), which needs labels
- learned correlation (CO-1..CO-3) and predictive reach (CO-4)
- vectorised parser (SC-2)
- memory governor and Prometheus metrics (SC-5)
- tus upload (UP-1)
- React UI rewrite (UI-1..UI-4); the vanilla console now has the live and graph views
- LANL/AIT adapters, which are blocked on data

## Original handover — 2026-10-31, 21:45 IST

This file is for whoever continues Phase 2. Read it alongside `docs/PHASE2.md`, the authoritative plan. **Read PHASE2.md fully before writing code.** It defines the non-negotiable rules, the frozen interfaces, the work packages (WPs), the execution protocol and the milestones. This file covers what is already done, what is in progress and what comes next.

## 1. Read these first, in this order

1. `docs/PHASE2.md`: the plan, saved verbatim. Re-read it at the start of every session.
2. `CLAUDE.md`: the working rules: never modify the datasets, stream files and never load one whole, no vendor tags in detection, no hard-coded entities, render as text only.
3. `docs/STATE.md`: what each module does, its interface, the Phase 1 metrics, the gaps against PHASE2, and 10 conflicts between PHASE2 and the code or environment. **Read §5 (conflicts).**
4. `docs/DECISIONS.md`: one line per decision. Phase 2 entries start at D-47.
5. `WORKLOG.md`: the Phase 2 table with pass/fail evidence per WP.
6. `docs/wp/*.md`: the plan for each WP (EV-0, EV-1, EV-2, SC-1 so far).
7. `docs/DATASETS.md`: dataset status and licences.

Protocol for every WP (PHASE2 "EXECUTION PROTOCOL"):
1. Write `docs/wp/<ID>.md`.
2. Implement with tests in the same commit.
3. Run `make check`.
4. Run `make eval` on the affected datasets, and record before/after numbers in `docs/DECISIONS.md`.
5. Mark the acceptance criteria pass/fail in `WORKLOG.md`.
6. Commit as `<ID>: <summary>`.

Stop and ask the project owner only when PHASE2 says to, or at a milestone.

## 2. Environment

Machine:
- macOS on Apple Silicon: 10 CPUs, 16 GB RAM.
- **About 17 GiB free disk.**
- Python 3.11 venv at `.venv`.
- Node 20 and npm 10 are available, for the UI WPs.

Commands:
- `make check`: ruff plus pytest. 79 tests pass.
- `make run DATA=<file>`: runs the pipeline into `out/sample`.
- `make eval DS= EXP= [GT= RUN=]`: writes `metrics/<DS>/<EXP>.json`.
- `make bench DATA= BENCH=`: benchmarks one run.
- `make demo`, `make serve`.

Packages:
- Installed in Phase 2 (all on the PHASE2 pre-approved list): numpy, psutil, py-spy, hypothesis, ruff.
- Not installed yet: scikit-learn, shap, optuna, pandas, torch, torch_geometric, sse-starlette, import-linter, mypy. All are pre-approved, so install each when its WP needs it.
- `requirements.txt` still lists only the Phase 1 stack. Add packages to it as you install them.

Commits:
- Two-person team. Commit as yourself.
- Do not add AI co-author trailers; the owners asked for that.

## 3. What PHASE2 asks for vs. what is done

### STEP 0 (context and inspection)

| Item | Status | Where |
|---|---|---|
| 0.1 Save the prompt verbatim and commit | Done | `docs/PHASE2.md` (commit e6d64a3) |
| 0.2 Read the repo | Done | — |
| 0.3 Write STATE.md (modules, interfaces, metrics, gaps, conflicts) | Done | `docs/STATE.md`. §6 "10 GB baseline" is still pending; see §4 below |
| 0.4 10 GB benchmark plus profiler | **Partly done** | See §4 below |
| 0.5 Summary and blockers posted to the owner | Done | Blockers repeated in §6 below |

### Work packages

| WP | Priority | Status | Evidence / notes |
|---|---|---|---|
| **EV-0** Freeze the interfaces | Must | **DONE** | `forgetrace/models.py`: Event (+dataset), Reason, Detection (+detector, score, reasons), AlertGroup (+p_malicious, contributions), RunPlan, each with an Arrow schema. `forgetrace/eval/groundtruth.py`: GroundTruth / Attack / Step / LineRef / AuthEdge, plus a converter from the Phase 1 format. The pipeline now writes these columns. Tests: `tests/test_models.py`. Decisions D-47..D-50. |
| **EV-1** Evaluation harness v2 | Must | **DONE** | `forgetrace/eval/{runview,metrics,schema,cli}.py`; `python -m forgetrace eval` / `make eval`. Computes every PHASE2 metric, bootstrap 95% CIs over attacks and incidents, multi-seed pooling, and writes config hash plus git SHA. Each metric is tested on a hand-computed toy (`tests/test_eval_metrics.py`). On the dev sample its output matches `tools/score.py` exactly. Next-step hit@k (needs CO-4) and time-to-first-incident (needs SC-4) are reported as N/A. Decisions D-52, D-53. |
| **EV-2** D0 suite (20 seeds) | Must | **DONE** | `tools/gen_suite.py` generates `data/d0/seed_NN/` (gitignored; regenerate with `python tools/gen_suite.py`, about 70 s). The sha256 per seed is in `data/d0/suite.json`. Seeds 1–10 are tuning and 11–20 are test. What varies: victims, targets, counts, gaps, step order, benign mix and CEF ratio. A3 deliberately uses techniques with no rule. Decoys D2 and D3 deliberately cross rule thresholds. Test: `tests/test_suite.py`. Decisions D-55, D-56. |
| **E0** Baseline on D0–D3 | Must | **NEXT, partly unblocked** | D0 can run now: `python tools/run_suite.py --experiment E0 --split tuning` then `--split test`. This writes `metrics/d0/E0_tuning.json` and `E0_test.json`. D1 and D3 wait for the datasets. |
| DS-1 LANL adapter | Must | Blocked | Needs the owner's download path (registration required). |
| DS-2 AIT-LDS v2 adapter | Must | Blocked | Needs download approval plus disk space (each scenario is 17–30 GB). |
| DS-3 OpTC / DS-4 EVTX | Should / Could | Not started | DS-3 needs disk space. |
| RT-1 errors.csv | Must | Not started | Can start as soon as D0 E0_tuning exists. |
| RT-2 tuning loop, Optuna, coverage | Must | Not started | Note STATE.md §5.4: "R009 periodicity CV" and "θ_incident" do not exist yet and must be added before they can be tuned. A3's techniques (T1069.002, T1560.001, T1567.002) have no rule, which is the coverage-expansion target. |
| ML-1..ML-5 | Must / Should / Could | Not started | — |
| FU-1 router, FU-2 fusion | Must | Not started | The `RunPlan` model already exists. `AlertGroup.p_malicious` is null today. |
| CO-1..CO-4 | Should / Must (CO-4) | Not started | STATE.md §5.5: top-k paths and the bounded connector do not exist yet, although PHASE2 treats them as present. |
| **SC-1** Benchmark matrix | Must | **Plan written, not run** | `docs/wp/SC-1.md` lists the profile findings. |
| SC-2..SC-5 | Must / Should | Not started | See the profile findings in §4. |
| UP-1 tus upload | Must | Not started | — |
| UI-1..UI-4 | Must / Should | Not started | No `ui/` app yet. The Phase 1 vanilla-JS UI is in `forgetrace/api/static`. STATE.md §5.10: keep the strict CSP. |
| LLM-1 | Should | Not started | CLAUDE.md still says "No LLM anywhere"; update it when this WP starts (STATE.md §5.8). |
| FIN | Must | Not started | — |

Milestone M1 = EV-0..E0 + SC-1..3. Stop and report to the owner at M1.

## 4. The 10 GB baseline (STEP 0.4): in progress, finish it

- Input: `data/bench/firex_style_10g.log`. It is 10.23 GB with 15.3M lines, made by `tools/gen_bulk.py` (gitignored; regenerate with `python tools/gen_bulk.py --out data/bench/firex_style_10g.log --size-gb 10`, about 6 min).
- The run uses the frozen baseline code in a git worktree pinned at `e6d64a3`. The command:
  `tools/bench.py --input data/bench/firex_style_10g.log --out out/bench10 --report bench/baseline.json`
- Observed so far, from timestamps rather than final numbers:
  - Started 21:19:01.
  - Ingest finished about 21:34:30, roughly 15.5 min, about 11 MB/s on one worker. Other CPU work ran on the machine during ingest, so treat this speed as a lower bound.
  - Detection was still running at 21:45, more than 10 min in.
- **If `bench/baseline.json` exists when you start**, commit it and fill in STATE.md §6.
- **If the run died** (the agent session that started it may be gone), re-run it from a checkout of `e6d64a3` with nothing else running.
- Profile (cProfile on a 150 MB slice; py-spy needs root on macOS):
  1. **The rule engine's threshold-window merge is quadratic per group key** ([forgetrace/rules/engine.py `_run_rule`](../forgetrace/rules/engine.py), the `evs[: i + 1]` rescan and the `m not in cur` list check). This alone made 19M `timestamp()` calls on 150 MB. It is the most likely reason the 10 GB detection is slow. Fix it with a two-pointer window; the output must stay identical, so pin it with a test before changing anything.
  2. Per-line Python normalisation dominates ingest; that is SC-2's target.
  3. `_evidence_ids` in correlation, and the row-by-row `INSERT` of detections in `_write`.

## 5. Recommended next steps (in order)

1. Finish or re-run the 10 GB baseline; commit `bench/baseline.json` and STATE.md §6.
2. **E0 on D0**: run the two `tools/run_suite.py` commands above and commit `metrics/d0/E0_*.json`.
   - Expect lower recall than the dev sample (A3 has no rules) and false alerts from D2/D3. That is the honest baseline; do not tune before freezing it.
   - Record in DECISIONS that `E0_test` is the frozen held-out row.
3. **RT-1**: generate `errors.csv` from `metrics/d0/E0_tuning.json`. The per-step results under `runs[].metrics.attacks` give found, predicted and detectors per step, which makes it straightforward. Assign one root cause per row.
4. **SC-1 → SC-2 → SC-3** (owner B), in parallel with RT-2 (owner A).
   - Fix the quadratic window first; it is a correctness-neutral speed fix.
5. **DS-1 / DS-2** as soon as the owner provides the data.
6. Then follow the order in PHASE2 "WORK PACKAGES" and the cut order if time is short.

## 6. Open blockers and decisions waiting on the owner

1. **LANL** (D1): needs the owner's local download path.
2. **AIT-LDS v2** (D3): approval to download from Zenodo, plus disk space.
3. **Disk:** about 17 GiB free. The 50 GB tier, AIT and OpTC cannot be stored as things stand.
4. **py-spy:** needs `sudo` on macOS. cProfile is used meanwhile.
5. **Decision:** D0 is JSON/CEF, but the provided `firex-10G.log` is FortiGate key=value. Should the suite gain a FortiGate variant? (STATE.md §5.1)
6. **Decision:** move the API under `/api/*` (PHASE2 and the UI plan use it) and keep the root routes as aliases? (STATE.md §5.6)
7. Checkpoint 2 date: it sets the cut line (plan §12).

## 7. Files added in Phase 2 so far

```
docs/PHASE2.md  docs/STATE.md  docs/HANDOVER.md  docs/DATASETS.md  docs/wp/{EV-0,EV-1,EV-2,SC-1}.md
forgetrace/models.py  forgetrace/eval/{__init__,__main__,groundtruth,runview,metrics,schema,cli}.py
tools/{bench,gen_bulk,gen_suite,run_suite}.py  data/d0/suite.json  ruff.toml
tests/{test_models,test_eval_metrics,test_suite}.py
```

Modified:
- `forgetrace/{__main__,pipeline}.py`, `forgetrace/ingest/ingest.py`, `forgetrace/rules/engine.py` and `forgetrace/correlate/correlate.py`: the interface columns.
- `tests/test_e2e.py`: the ground-truth isolation test is narrowed to `eval/` and `datasets/`, and a new test checks the pipeline never imports `forgetrace.eval`.
- `Makefile`, `.gitignore`, `docs/DECISIONS.md`, `WORKLOG.md`.
