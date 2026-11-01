# ForgeTrace — handover

Status as of **2026-11-01**, `main` (all pushed). This replaces the earlier handover; older versions are in git history.

This document is for whoever continues the work. Part A covers what the system is and how to run it. Part B covers what is done, Part C what is left and Part D the risks and traps.

---

## Part A — Orientation

### What ForgeTrace is

An offline security-log investigation engine (hackathon project for CyberForge by Mitigata; two-person team, Dishan-D and Aneesh dutt). In order, it:
1. ingests logs in any format: JSON, CEF, syslog, key=value (FortiGate) or CSV;
2. detects with YAML rules plus two unsupervised ML models, labelling every detection with an ATT&CK technique;
3. links detections into incidents and attack paths, and estimates reachable critical assets;
4. in **live mode**, keeps enriching a persistent knowledge base and a **Neo4j graph** as logs arrive;
5. gives every alert, incident and campaign a **human-verifiable explanation**: the condition, the observed numbers, SHA-256-verified raw lines and how to check by hand.

### Direction set by the owners and mentor (these override `docs/PHASE2.md` where they conflict)

1. **Accuracy metrics are paused.** The provided firex-10G/50G files have no ground truth. Results are checked by **manual verification**, so explanations must let a person confirm or reject each finding.
2. **Real-time and graph first.** Logs arrive continuously (e.g. 2 GB per 5 min) and accumulate to TBs. Something arriving now must be linked to related activity from days ago. The graph DB was the mentor's suggestion.
3. **Nothing dataset-specific in code.** The **final hackathon checkpoint is a new, unseen dataset**, so adapting to it must take config edits only.
4. **ML wherever it helps.** Rules alone were not enough; behaviour analysis must be in the loop.
5. Don't spend time on performance metric runs unless asked.

### Read these, in this order

1. `CLAUDE.md`: working rules (non-negotiable; summarised in Part D).
2. `README.md`: the "How to run" section.
3. `docs/DECISIONS.md`: one line per decision, D-01 to D-93. Phase 2 starts at D-47; the ML layer is D-89 to D-93.
4. `WORKLOG.md`: per-package status with evidence.
5. `docs/wp/LIVE.md`, `GR-1.md`, `GR-2.md`, `SC-4.md`: designs for live mode, the graph and streaming.
6. `docs/PHASE2.md`: the original plan. Still the reference for interfaces and protocol, but see the direction changes above.
7. The dossier PDF (`ForgeTrace — Research & Implementation Dossier-2.pdf`): the architectural authority for §10–14.

### Environment

- MacBook M2 Pro: 10 cores (6P+4E), 16 GB RAM. Python 3.11 venv in `.venv`.
- Docker Desktop runs Neo4j. **Set Docker's memory to about 4 GB**: at 8 GB, macOS swapped 17 GB during the 50 GB run.
- **Disk is about 97% full (16 GiB free).** Delete old `out/` workspaces before large runs; a 50 GB run writes roughly 10 GB of Parquet.
- Data lives in `data/input/` (git-ignored, read-only evidence):
  - `firex-50G.log` (32.7 GB)
  - `firex_logs/firex-10G.log`
  - `edr_events.json`
- Git:
  - Commit as yourself.
  - **No AI co-author trailers** (owner request).
  - Remote: `https://github.com/2005-Aneeshdutt/ForgeTrace`.
  - `AGENTS.md` is untracked and not ours; leave it out of commits.

### Run it

```bash
make setup && make graph-up          # venv + Neo4j (Docker, localhost, neo4j / forgetrace-dev)
make check                           # ruff + 162 tests, about 1.5 min
make sample && make run && make serve   # dev sample end to end -> http://127.0.0.1:8000
make live GRAPH=1 RESET=1            # live mode on data/input/ -> out/live (drop RESET=1 to resume)
.venv/bin/python -m forgetrace run --input <files> --out out/<name> --graph   # batch on anything
```

CLI subcommands:
- `run`: ingest and analyse.
- `analyse`: re-analyse an already-ingested workspace without re-ingesting.
- `stream`: analyse a growing file in batches.
- `live`: follow folders and enrich the knowledge base and graph.
- `serve`: dashboard and API.

Optional: `export OPENROUTER_API_KEY=…` enables the AI summary button. Without it, everything works offline.

### Architecture in one picture

```
logs ─► ingest (parallel byte ranges, 9 workers) ─► Parquet (event_id = file_id<<48 | byte_offset)
          │ syntax detect + config/field_map.yaml / field_aliases.yaml / site.yaml
          ▼
       router (capability profile → rules enabled/disabled = blind spots, run_plan.json)
          ▼
       detect: YAML rules (DuckDB SQL)  +  ML: behaviour model (UEBA) + graph link model
          ▼
       aggregate → correlate (§12 edge score, top-K, ≥2-tactic gate, ≥1 rule) → fusion p_malicious
          ▼
       reach (§14) → incidents.json / DuckDB ─► FastAPI + vanilla-JS dashboard
          └─► Neo4j: entities, alerts, LEADS_TO / RELATED edges, campaigns, live incidents
Live mode: micro-batches (batch + 60-min lookback), bucketed long-window state, kb_* tables,
           hot/cold Parquet tiers, live_snapshot.duckdb for the API, graph sync per batch.
```

### Code map

| Area | Files |
|---|---|
| Ingest / parsing | `forgetrace/ingest/{ingest,parsers}.py`, `config/field_map.yaml`, `config/field_aliases.yaml`, `config/site.yaml` |
| Rules | `forgetrace/rules/{engine,router}.py`, `config/rules/*.yml` (Windows/EDR R001–R011, FortiGate F001–F017), `config/attack.yml` |
| ML | `forgetrace/ml/{ueba,link,fusion,rows}.py`, `config/ml.yml` |
| Correlation / reach | `forgetrace/correlate/correlate.py`, `forgetrace/reach/reach.py`, `config/correlation.yml`, `config/assets.yaml` (generated for the sample) |
| Pipeline | `forgetrace/pipeline.py` (batch), `forgetrace/stream.py`, `forgetrace/live/{engine,graph_sync}.py`, `config/live.yml` |
| Graph | `forgetrace/graph/{loader,campaigns,queries}.py`, `config/graph.yml`, `deploy/neo4j/docker-compose.yml` |
| Explanations / LLM | `forgetrace/report/{explain,llm}.py`, `tools/llm/openrouter.py`, `config/explain.yml`, `config/llm.yml` |
| API / UI | `forgetrace/api/app.py`, `frontend/` (React source), built into `forgetrace/api/static` (previously vanilla JS + Cytoscape, strict CSP) |
| Evaluation (paused) | `forgetrace/eval/`, `tools/score.py`, `tools/gen_scenarios.py`, `tools/gen_suite.py`, `tools/run_suite.py` |

---

## Part B — What is done

All of this is committed. 162 tests pass (`make check`).

| Area | What exists | Evidence |
|---|---|---|
| Phase 1 | Ingest, rules, correlation, attack path, reach, API, dashboard, scorer | `tests/test_e2e.py`, `test_correlation.py`; dev sample: step recall 11/11, attacks in order 2/2, 0 false-alarm incidents |
| Frozen interfaces (EV-0) | Pydantic models + Arrow schemas: Event, Detection (`detector`, `score`, `reasons`), AlertGroup (`p_malicious`, `contributions`), RunPlan | `forgetrace/models.py`, `tests/test_models.py` |
| Eval harness (EV-1) and D0 suite (EV-2) | All PHASE2 metrics with bootstrap CIs; 20-seed synthetic suite | `forgetrace/eval/`, `tests/test_eval_metrics.py`, `test_suite.py` (built, but E0 has not been run; paused) |
| Scale | Parallel byte-range ingest; linear-time threshold windows; indexed correlation; bounded incident records | firex-10G (6.5 GB) 194 s; **firex-50G (32.7 GB, 62M events) about 22 min, 6.0 GB peak RSS**; `reports/scale.md`, `bench/*.json` |
| FortiGate behaviour rules | F001–F017: scans, brute force, VPN anomalies, night logins from abroad, admin changes, exfil volume, etc. Never reads vendor verdict fields. | `config/rules/firewall.yml`, `tests/test_rules_firewall.py` |
| Unseen formats (final checkpoint) | Per-line syntax detection; alias mapping; timestamp candidates; message patterns; `source_type` rules; learned site values (home countries) | `tests/test_generic_parsing.py`, `tests/test_unseen_e2e.py` |
| Router / blind spots (FU-1) | Rules are disabled when their fields are missing. `run_plan.json` lists formats, fill rates, disabled rules, site values and ML features. | `forgetrace/rules/router.py` |
| Graph store (GR-1/GR-2) | Neo4j hybrid with Parquet: Entity/Alert nodes, LEADS_TO and RELATED (long-range) edges, Campaign nodes, live incidents | `tests/test_graph.py`; firex-10G graph load about 10 s |
| Live engine | Micro-batches, bucketed long-window rule state, first-seen state, persistent `kb_alerts`/`kb_edges`, graph sync, hot/cold tiers, read-only snapshot for the API | `tests/test_live.py`: live equals batch for rules, idempotent re-runs, appended data handled |
| Explanations | `/explain/{alert,incident,campaign}/{id}`: condition in English, observed values, verified raw lines, `sed`/`grep` checks, benign look-alikes, data-quality notes | `tests/test_explain_llm.py` |
| LLM narrative (optional) | OpenRouter (`google/gemini-2.5-flash-lite`): pseudonymised (HMAC), validated (rejects invented ids or numbers), cached, spend caps ($1.50 lifetime / $0.25 per run) | `forgetrace/report/llm.py`; key only from `OPENROUTER_API_KEY` |
| **ML layer (newest)** | **Behaviour model**: Isolation Forest per entity type over hourly windows, compared with each entity's own baseline, SHAP reasons, evidence lines. **Graph link model**: new out-of-pattern logons/admin connections, Adamic-Adar peer reach, clustering filter, one flag per hop. **Fusion**: noisy-OR `p_malicious`. **Live**: stored windows and edges, growth-triggered retraining, 6-h warm-up. Models corroborate: an incident needs at least one rule, and rules are never absorbed by model flags. | `tests/test_ml.py` (8 tests); D-89..D-93 |
| UI | Overview, Incidents, Detections, Data sources, Rules, Evaluation, Pipeline demo, **Live**, **Knowledge graph** (timeline layout, entity explorer, deep links), explanation panel with rule/model badge, fused p and AI-summary button | `forgetrace/api/static/` |
| Docs | README "How to run", DECISIONS to D-93, WORKLOG, `reports/scale.md` | — |

Dev-sample result with ML on: 2 incidents. Attack A1 is reconstructed in order, with the behaviour model flagging the brute force and the exfiltration and the link model flagging the jdsouza → SRV-FILE-01 hop. In live mode the models flag the same A1 entities after warm-up.

---

## Part C — What is left

Roughly in priority order for the hackathon. P0 = needed for the final checkpoint; P1 = strongly recommended; P2 = from the PHASE2 plan, optional under the new direction.

### P0 — before the final checkpoint

1. **Dry-run the unseen-dataset workflow.** Pick a log type we have not used (e.g. a public Linux auth/syslog sample, Windows EVTX exported as JSON, or Zeek/Suricata JSON). Then:
   1. run `forgetrace run` on it;
   2. read `run_plan.json`;
   3. fix gaps **only** in `config/field_aliases.yaml`, `config/site.yaml` and `config/rules/`;
   4. write down every config edit as a checklist for the event.

   This is the most important rehearsal.
2. **Measure the ML stage on firex-10G**, once, as a sanity check of time and memory (the 50 GB pipeline was measured before ML existed). The stage time is `ml_s` in the run's stage timings. If it is slow, look at the per-entity window SQL and SHAP on the flagged rows.
3. **Manually review a sample of model flags** on firex-10G with the explanation panel, and tune `ueba.alerts_per_day` / `min_score_percentile` in `config/ml.yml`. The budget of 10 per entity type per day is a guess.
4. **Rehearse the demo offline:**
   1. `make graph-up`, `make serve`;
   2. run live mode on a folder while copying a large file into it;
   3. show the Live page, then the Knowledge graph, then an explanation;
   4. show the AI summary from cache.

   The venue may be offline, so warm the LLM cache in advance.

### P1 — quality and robustness

5. **Persist live models.** Live mode keeps fitted models in memory, so a restart refits from `kb_ml_windows`. This is fine, but the first batch after a restart is slower. Pickle the models to `out/<ws>/ml_models/` with the feature-set hash.
6. **Timestamp clamp on firex** (D-61, D-74): 69% of firex-10G events share one pinned timestamp. This inflates R001/F002 groups and limits what time-based models can learn on that file. The firex-10G file is also binary beyond about 4.8 GB (D-06). Decide whether to report this as a data-quality finding (the explanation's `data_quality` list already flags it) or to tune the affected rules.
7. **Live alert filtering:** `/live/alerts` returns the latest 50; add filters by detector, tactic and entity.
8. **Neo4j growth to TB-scale history.** Raw events never go to Neo4j, only aggregated relationships and alerts, which is fine. But there is no TTL or compaction yet for very old Batch markers or RELATED edges. Add a periodic cleanup job if the demo runs for days.
9. **Memory governor and `/metrics` (SC-5)**: bounded queues; drop workers when RSS > 7 GB; Prometheus text endpoint.

### P2 — PHASE2 items not done (decide whether they still matter)

| PHASE2 item | Status | Note |
|---|---|---|
| E0 / RT-1 / RT-2 (baseline, error analysis, Optuna tuning) | Not done | Paused: no ground truth for the real data. The D0 synthetic suite and harness are ready if wanted (`tools/run_suite.py`). |
| firex 30G ground truth | Waiting on the owner | Only the 30G manifest has ground truth (seed 2); the 30G logs are not here (D-05, D-66). The adapter exists (`tests/test_firex_gt.py`). |
| DS-1..DS-4 (LANL, AIT-LDS, OpTC, EVTX) | Not done | Blocked on downloads and disk space. |
| ML-4 (GNN encoder), ML-5 (provenance model) | Not done | Likely unnecessary; the PHASE2 cut order drops them first. |
| FU-2 learned / calibrated fusion | Not done | Needs labels; the noisy-OR fallback is implemented. |
| CO-1..CO-3 learned edge weights / transitions | Not done | Need labelled attacks. The hand formula is in `config/correlation.yml`. |
| CO-4 predictive reach with link probabilities | Not done | The link model's peer-reach could feed "likely next hop". |
| SC-2 vectorised parser | Not done | Ingest is already parallel (50 GB in about 8 min of ingest); only needed if ingest becomes the bottleneck. |
| UP-1 resumable (tus) upload | Not done | Live mode watching a folder covers "data arrives continuously"; the dashboard has simple uploads. |
| UI-1..UI-4 React rewrite | Not done | The vanilla console has every needed view. Low value for the checkpoint. |
| FIN: ablation report, final 50 GB run | Not done | `reports/ablation.md` does not exist. |

---

## Part D — Rules, risks and traps

**Non-negotiable rules** (from `CLAUDE.md`, enforced by tests where possible):
- Never modify the datasets. Stream files line by line; never read a log whole.
- `event_id = (file_id << 48) | byte_offset`. Every derived row carries raw event ids.
- Detection never reads vendor verdicts (`threat.*`, `rule.*`, `labels.*`, `event.kind`, `event.severity`, FortiGate attack/virus/severity fields). `tests/test_vendor_ban.py` enforces this.
- No LLM in detect/label/link/score/decide. The LLM only restates verified facts.
- No hard-coded hosts, users, IPs, domains or countries. Use `config/`.
- Ground truth is read only by `tools/score.py` / `forgetrace/eval`.
- Render log-derived strings as text (`textContent`), never as HTML.
- Every threshold or architectural decision is recorded as one line in `docs/DECISIONS.md`.

**Known traps:**
- **Spawn workers + stdin scripts.** Ingest uses a spawn ProcessPool, so any ad-hoc script that ingests must be run from a file with `if __name__ == "__main__":`. A script piped into `python -` dies with `BrokenProcessPool`.
- **Old live workspaces** built before the ML columns lack `p_malicious`/`reasons`. The API now tolerates this. Running the live engine on the workspace adds the columns; `--reset` rebuilds it with ML.
- **Live vs batch ML results differ by design.** Live models learn from history only. Tests compare rule output; don't "fix" ML to match batch.
- **Clearing a big Neo4j workspace** must be batched (`clear_workspace`), or Neo4j runs out of transaction memory.
- **DuckDB holds one writer.** The live engine publishes `live_snapshot.duckdb` for the API to read; don't point the API at the live engine's working database.
- **Disk space.** The machine is at 97%.

**Open decisions for the owners:**
1. Whether to obtain the firex-30G logs, to make the manifest ground truth usable.
2. Whether any PHASE2 P2 item is still expected by the judges (React UI, tus upload, ablation report).
3. Which unseen-format sample to rehearse with (P0 item 1).
