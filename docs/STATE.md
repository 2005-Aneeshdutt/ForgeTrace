# ForgeTrace — state at the start of Phase 2 (2026-10-31)

Written for STEP 0.3 of docs/PHASE2.md. Baseline commit: `e6d64a3`. Everything below was read from the code or measured; nothing is estimated unless it says so.

## 1. What exists, per module

| Module | What it does | Interface (as of now) |
|---|---|---|
| `forgetrace/ingest/parsers.py` | Sniffs a line (ECS JSON / CEF / FortiGate key=value), parses it, normalises into the envelope via `config/field_map.yaml` | `parse_line(bytes) -> dict`; `sniff`, `parse_json`, `parse_cef`, `parse_kv`, `normalise(raw, fmt)` |
| `forgetrace/ingest/ingest.py` | Single-process `readline` loop; envelope rows buffered to Arrow and written as zstd Parquet every 200k rows; per-line SHA-256 digest; `parse_errors.parquet`; `files.json` manifest with whole-file SHA-256 | `ingest(inputs, out, batch_rows=200_000, progress=None) -> manifest`; `make_event_id(file_id, off)` = `(file_id << 48) \| off`; 40-column `SCHEMA` |
| `forgetrace/ingest/evidence.py` | Seeks to the byte offset, re-reads the raw line and checks its digest | `get_raw(event_id, out, con) -> dict` |
| `forgetrace/store.py` | DuckDB file per workspace, `memory_limit=4GB`, views `events` / `parse_errors` over Parquet | `connect(out)`, `create_views(con, out)` |
| `forgetrace/rules/engine.py` | YAML rules (Pydantic `Rule`) compiled to DuckDB SQL; types `match`, `threshold` (+`followed_by` with optional `link`), `baseline` first-seen; label priority → `event_labels`; subset duplicates → `duplicate_of` | `load_rules()`, `detect(con, rules)`; tables `detections`, `event_labels`, `rules` |
| `config/rules/*.yml` | 12 rules R001, R001c, R002–R011 | fields: id, technique, tactic, severity, confidence, label_priority, type, filter, … |
| `forgetrace/correlate/correlate.py` | Aggregation (15 min gap) → groups; entity index; candidate edges scored `clip(0.45L+0.20T+0.20P+0.10R−0.25F)`; θ_edge 0.45, top-K 3; union-find; ≥ 2-tactic gate; primary path by time/tactic; dossier DP kept as `strongest_chain` | `correlate(con) -> {groups, candidate_edges, edges, incidents, abstained}` |
| `forgetrace/reach/reach.py` | Compromised set, observed/fixture/inferred edges, max-product search (H = 4), `disable_account` simulation, candidate ranking | `reachability(con, incident, gid, remove_accounts)`, `simulate(...)`, `candidate_actions(...)` |
| `forgetrace/pipeline.py` | ingest → detect → correlate → reach/cache → persist; writes `incidents.json`, `run_stats.json` (stage seconds, ru_maxrss, config hash) | `run(inputs, out, progress=None) -> stats`; CLI `python -m forgetrace run --input --out` |
| `forgetrace/api/app.py` | FastAPI, strict CSP, workspaces `demo` / `sample` / `input`, raw-body uploads, one background run at a time | `/health /incidents /incidents/{id}[/path,/reach,/reachability,/simulate] /events/{id}/raw /alerts /rules /workspaces /overview /detections /metrics /inputs /runs /runs/current /walkthrough` (no `/api` prefix) |
| `forgetrace/api/static/` | Vanilla-JS console (no build step): Pipeline demo, Overview, Incidents (Cytoscape graph), Detections, Data sources, Rules, Evaluation | served at `/` |
| `tools/gen_scenarios.py` | Deterministic in-memory generator: benign SimEDR JSON + 10% CEF, attacks A1 (6 steps), A2 (5 steps), decoy D1; writes ground truth and `config/assets.yaml` | `--seed --days --events --cef-ratio --out-dir` |
| `tools/gen_bulk.py` (new, STEP 0) | Same event shapes, one day per chunk, bounded memory; for scale benchmarks only (no GT) | `--out --size-gb --events-per-day --seed` |
| `tools/score.py` | The only reader of ground truth; step recall, parent/sub label accuracy, path order, false-alarm share, runtime, RSS | `--gt --out` |
| `tools/bench.py` (new, STEP 0) | Runs `forgetrace run` in a child process with psutil 1 s RSS sampling over the process tree; MB/s per stage | `--input --out --report` |
| `tests/` | 57 tests: ingest/evidence round trip, vendor-field ban (static), per-rule positive/negative, dossier correlation worked example, reach, e2e, upload workflow, demo walkthrough | `make test` |

## 2. Current metrics (make run + make score, dev sample seed 7, 14.1 MB, 20,129 lines)

| Metric | Value | PRD target |
|---|---|---|
| Step recall | 11/11 = 100% | > 90% |
| Label accuracy, parent | 11/11 = 100% | > 85% |
| Label accuracy, exact sub-technique | 9/11 = 81.8% (R008 emits T1021 for T1021.001/.002) | > 85% |
| Attacks in order | 2/2 | all |
| False-alarm incidents | 0/2 (decoy D1 rejected) | < 10% |
| Wall time | 1.23 s | < 1 h |
| Peak RSS (ru_maxrss) | 233 MiB | < 8 GB |

These are in-sample numbers: the same author wrote the generator, the ground truth and the rules, and there is one seed and no held-out split. They are not evidence of generalisation, and there are no confidence intervals. With 11 steps, one miss moves recall by 9 points.

## 3. Scale baseline (STEP 0.4)

See `bench/baseline.json` and §6 below (filled in after the 10 GB run).

## 4. Gaps against docs/PHASE2.md

| Area | Required by PHASE2 | Today |
|---|---|---|
| Interfaces (EV-0) | Pydantic `Event`, `Detection` (+detector, score, reasons[]), `AlertGroup` (+p_malicious, contributions), `RunPlan`, `GroundTruth` | Plain dicts/DuckDB tables; detections have no `detector`/`score`/`reasons`; GT uses `decoy`, `event_ids`, `line_nos`, no `t_start/t_end/hosts/users/is_decoy/name` |
| Evaluation (EV-1) | `forgetrace eval`, metrics JSON, Kendall τ, purity, ARI, nodes-to-inspect, per-detector P/R/F1, AUC-PR, Recall@B, NDCG@10, bootstrap CIs, seeds, splits | `tools/score.py` with 7 headline metrics, no CIs, single seed |
| D0 suite (EV-2) | 20 seeds, varied mixes, ordering, decoys incl. typo failures and benign admin account creation | One seed; one decoy (D1); generator is in-memory and writes `config/assets.yaml` as a side effect |
| Datasets DS-1..4 | LANL, AIT-LDS v2, OpTC, EVTX adapters under `forgetrace/datasets/<name>/` | None; one combined field map, no per-dataset mapping |
| Rule tuning (RT-1/2) | errors.csv with root cause, Optuna | None; Optuna not installed |
| ML (ML-1..5) | DuckDB features, UEBA (rarity + IsolationForest + SHAP), auth-graph link prediction, GNN | None. R008 is the only behavioural element (first-seen pair after a 6 h warm-up) |
| Router + fusion (FU-1/2) | Capability profile, `requires:` per detector, RunPlan, calibrated LR fusion | None |
| Correlation (CO-1..4) | Learned weights, learned transitions, p_malicious node weights, predictive reach | Hand weights; no top-k alternative paths; no bounded connector |
| Scale (SC-1..5) | Byte-range workers, vectorised parser, lazy digests, sorted/dict Parquet, micro-batches, memory governor, `/api/metrics` Prometheus | Single process; per-line Python parse + per-line SHA-256; `/metrics` returns run_stats JSON, not Prometheus |
| Upload (UP-1) | tus resumable upload, watermark ingest, SSE | Single raw-body POST, ingest after upload completes, polling |
| UI (UI-1..4) | React/Vite/shadcn app in `ui/`, typed client from `docs/openapi.json` | Vanilla JS in `forgetrace/api/static`; no `ui/`; no committed OpenAPI file |
| LLM-1 | OpenRouter narrative, ledger, cache | None (Phase 1 forbade any LLM) |
| Make targets | `check`, `run DATA=`, `eval DS= EXP=`, `bench`, `serve`, `ui`, `demo` | `setup sample run analyze demo score serve test clean`; `run` takes `INPUT=`, not `DATA=` |
| Determinism test | byte-identical incident JSON for same input + config | Not tested; `run_stats.json` has timestamps (incidents.json does not) |
| Metrics provenance | config hash + git SHA in every metrics file | config hash + `CODE_VERSION` string; no git SHA |
| Import contract | only `forgetrace/report` and `tools/llm` may import an HTTP client | Not enforced (no import-linter) |

## 5. Conflicts between PHASE2.md and the code or environment

1. **"firex scenario suite" vs firex data.** PHASE2 calls D0 the "firex scenario suite" from `tools/gen_scenarios.py`. That generator emits SimEDR JSON + CEF. The real `firex-10G.log` (now at `data/input/firex-10G.log`, 6.5 GB) is FortiGate key=value text, and is binary after ~4.8 GB (D-06). D0 as specified therefore does not test the format of the only firex file we have. Proposal: D0 = generator suite (as written); add the FortiGate format to the generator as a variant so the judges' format is covered.
2. **50 GB tier vs disk.** The data volume has 27 GiB free (460 GiB disk, 94% used). A 50 GB file plus its Parquet cannot be stored. The 10 GB tier fits. E6 / FIN / SC-1's 50 GB column are blocked until space is freed or an external disk is used.
3. **firex-30G is absent.** The manifest describes `firex-30G.log` + `firex-30G.win.jsonl`; neither is present (D-05), so the judges-style ground truth cannot be scored.
4. **Optuna parameters that do not exist.** "R009 periodicity CV" — R009 is count + bytes + rarity, with no periodicity term. "θ_incident" — the Phase 1 gate is ≥ 2 distinct tactics (D-31); there is no incident score threshold. Both must be added before they can be tuned.
5. **"Kept as is: top-k temporal path search, bounded connector."** Neither exists in Phase 1 (deferred in WORKLOG). The plan treats them as present.
6. **API prefix.** PHASE2 and the plan use `/api/*`; Phase 1 serves at the root. Proposal: mount the existing router under `/api` and keep root aliases until the old UI is retired.
7. **Peak RSS definition.** PHASE2 wants psutil 1 s sampling over all processes; Phase 1 reports ru_maxrss of one process. `tools/bench.py` reports both. On the dev sample they differ (117 MB sampled vs 231 MB ru_maxrss) because 1 s sampling misses short peaks in a 2 s run.
8. **Phase 1 rule "no LLM anywhere".** CLAUDE.md says "No LLM anywhere"; PHASE2 allows an LLM only in `forgetrace/report` and `tools/llm`, off the decision path. CLAUDE.md must be updated when LLM-1 starts.
9. **CLAUDE.md dependency list** is the Phase 1 stack; PHASE2 widens it. CLAUDE.md should point to PHASE2's list.
10. **UI stack.** Phase 1 UI is build-free vanilla JS with a strict CSP (`script-src 'self'`). The React/Vite app must keep that CSP (no inline scripts or styles in the built bundle), which rules out some shadcn defaults (inline style attributes on Radix popovers need `style-src 'unsafe-inline'` or nonce handling).

## 6. Scale baseline (10 GB, single worker)

In progress at handover (see docs/HANDOVER.md §4). Observed from timestamps: ingest of 10.23 GB / 15.3M lines took ≈ 15.5 min (≈ 11 MB/s, one worker, other load on the machine); detection was still running after 10+ min. Final numbers go in `bench/baseline.json`.
