# FORGETRACE PHASE 2 — MASTER IMPLEMENTATION PROMPT
You are the lead engineer on ForgeTrace, a hackathon entry (Mitigata "Kill Chain and Attack Path Analysis"). 
Phase 1 already exists in this repo: streaming ingest → Parquet/DuckDB, YAML rules mapped to MITRE ATT&CK,
scored-edge correlation into incidents and paths, reachability + containment simulation, FastAPI + a basic page.
Phase 2 (this prompt) adds rigorous evaluation on industry datasets, rule tuning, research-backed ML detection,
a deterministic router + calibrated fusion, learned correlation, 50 GB scale, live upload, and an industry-grade UI.
The goal is a measurable ablation story: each experiment adds one component and must beat the previous one on held-out data.

## STEP 0 — Save context and inspect (do this first, no feature code)
1. Save this entire prompt verbatim to docs/PHASE2.md and commit it. Reread it at the start of every session.
2. Read the repo, CLAUDE.md, WORKLOG.md, docs/DECISIONS.md, docs/ (PRD + dossier if present), config/, tests/.
3. Write docs/STATE.md: what exists per module, its interfaces, current metrics (run  make run  +  make score  on the
   dev sample), the gaps against this prompt, and anything in this prompt that conflicts with the code.
4. Measure first: run the current pipeline on a 10 GB generated file and record MB/s per stage and peak RSS in
   bench/baseline.json. Use py-spy on one worker to find the hot path.
5. Post a short summary and the list of blockers (datasets I must download, credentials, decisions). Then continue
   with work that is not blocked.

## NON-NEGOTIABLE RULES
•  Never load a whole log file into memory. Stream byte ranges. Peak RSS must stay < 8 GB (target < 6 GB). DuckDB memory_limit=4GB with spill.
•  event_id = (file_id << 48) | byte_offset is the evidence pointer. Every detection, edge, path step and reach result carries raw event_ids.
•  Never use vendor pre-tags for detection: threat., rule., labels.*, event.kind, event.severity. A CI test enforces this.
•  No LLM in detection, labelling, linking, scoring, routing or any decision. Only forgetrace/report and tools/llm may import an HTTP client (import-linter contract).
•  ATT&CK labels for every detector (rules AND ML) come from deterministic tables in config, never learned, never LLM.
•  No hostname/user/IP/domain literals in detection code or rules (CI test). Use config.
•  No train/test leakage: detectors train only on the baseline period; labels used only for evaluation and for fitting fusion/correlation weights on TUNING splits; TEST splits are run once per frozen config.
•  No mock or hard-coded data in the UI bundle (CI check greps ui/src for fixture JSON). Every number on screen comes from the API.
•  Render log-derived strings as text, never HTML. Defensive scope only.
•  Deterministic: same input + config = byte-identical incident JSON (test). Every metrics file records config hash + git SHA.
•  Ask before adding dependencies beyond: duckdb, pyarrow, orjson, numpy, pandas (eval only), scikit-learn, shap, optuna,
  networkx, torch, torch_geometric, fastapi, uvicorn, sse-starlette, pydantic v2, pyyaml, jinja2, structlog, psutil,
  python-evtx, pytest, hypothesis, ruff, mypy, import-linter, py-spy. UI: React, Vite, TypeScript, Tailwind, Radix/shadcn,
  TanStack Router + Table, Recharts, Cytoscape.js + cytoscape-fcose, tus-js-client.
•  Keep make targets working: make check | make run DATA= | make eval DS= EXP= | make bench | make serve | make ui | make demo.

## FROZEN INTERFACES (define in WP EV-0 before parallel work; change only via docs/DECISIONS.md)
•  Event: existing canonical envelope (+ source_event_id, dataset, file_id, line_no).
•  Detection: + detector ("rule:<id>" | "m1_ueba" | "m2_authgraph" | "m3_prov"), score (float), reasons[] ({feature, value, baseline, contribution, text}), technique_id, tactic, member_event_ids.
•  AlertGroup: + p_malicious (float|null), contributions {feature: value}.
•  RunPlan: {dataset, capability_profile {field: fill_rate}, enabled[], disabled[{detector, missing}], blind_spots[]}.
•  GroundTruth (all datasets): [{attack_id, name, is_decoy, steps:[{order, technique, tactic, event_ids|line_refs|edges, t_start, t_end, hosts, users}]}].
•  metrics/<dataset>/<experiment>.json (schema in WP EV-1). OpenAPI spec generated from FastAPI and committed at docs/openapi.json.

## DATASETS (adapters: forgetrace/datasets/<name>/adapter.py with iter_events(path)->Iterator[Event] streaming, ground_truth(path)->GroundTruth; mappings in config/field_map/<name>.yaml; each ships a 1,000-line fixture + round-trip test)
•  D0 firex scenario suite (PRIMARY, scored like the judges): tools/gen_scenarios.py, 20 seeds. Seeds 1–10 = tuning, 11–20 = test.
  Vary benign mix, attack step ordering, gaps, CEF ratio; include decoys (benign admin account creation/group add, typo login failures).
•  D1 LANL Comprehensive Multi-Source Cyber-Security Events (csr.lanl.gov/data/cyber1): auth/proc/flows/dns + redteam.txt
  (time,user@domain,src,dst). CC0, registration required → ASK ME for the local path; do not scrape. Days 1–20 baseline/tuning, 21–58 test.
  Published baselines to report beside ours: Euler (NDSS) AUC 0.991, AP 0.052, precision 0.0054; UltraLMD++ (arXiv 2504.13527) AP 0.0088, Rec@10 0.179 (stricter setup).
•  D2 DARPA OpTC (github.com/FiveDirections/OpTC-data), eCAR JSON, public domain. SHOULD-have. Subset: benign days + 3 red-team days for
  all ground-truth hosts + 100 random benign hosts. Ground truth from OpTCRedTeamGroundTruth.pdf (see OpenRouter use #3; human review required).
  Baselines: UltraLMD++ AUC 0.991 AP 0.151; Argus AP 0.024 (lateral movement).
•  D3 AIT Log Data Set v2 (zenodo.org/records/5789064), line-level labels. Tuning: fox, harrison. Test: russellmitchell, santos.
  Parse auth, audit, apache access/error, dns. Download via Zenodo directly (ask me if the network blocks it).
•  S1 label corpus (COULD): OTRF Security-Datasets + EVTX-ATTACK-SAMPLES via python-evtx → per-technique label accuracy only. Use locally, do not redistribute.
Write docs/DATASETS.md: version, size, subset taken, licence, adapter coverage (which canonical fields each provides).

## METRICS (forgetrace eval; every metric unit-tested on a toy ground truth with hand-computed answers)
Step level: step_recall (step found if ≥1 detection member event intersects step events; fallback same host ±60 s);
label_acc_exact and label_acc_parent (found steps only).
Attack level: ordered_path_rate (found steps in primary path in GT order, Kendall τ=1); mean Kendall τ; step_coverage_in_one_incident.
Incident level: false_alert_rate (incidents with zero GT overlap ÷ incidents; decoys = negatives); purity; ARI over detections; nodes_to_inspect (mean nodes per incident and malicious share).
Event level: precision/recall/F1 per detector and per technique.
Score level (ML): AUC-PR (average precision), Recall@B for B=10/50/100 alerts per day, alerts_per_day at 90% recall. Do not headline ROC-AUC.
Reach: next_step_hit@3 and @5 via truncation backtest, vs criticality-only and fixture-only baselines.
System: wall time per stage, MB/s, peak RSS (psutil 1 s sampling over all processes), p95 incident-path latency, time_to_first_incident.
Ranking: NDCG@10 of incident list.
Hygiene: time-based splits; bootstrap 95% CIs (1,000 resamples over attacks/incidents); mean ± sd over seeds; config hash + git SHA in output.
PRD targets to show on every report: step recall >90%, label acc >85%, all paths ordered, false alerts <10%, <1 h, <8 GB, <500 ms.

## EXPERIMENT LADDER (each row = frozen config; keep a component only if it passes its gate on HELD-OUT data; otherwise record a negative result and continue from the previous kept row)
E0 rules baseline (current) on D0–D3 → gate: metrics with CIs for every dataset.
E1 tuned rules → gate: beats E0 held-out; no literal entities.
E2 + M1 behavioural baselines → gate: recall and AUC-PR up, false_alert_rate not worse.
E3 + M2 auth-graph model → gate: LANL AP/Recall@B reported next to Euler/UltraLMD++; fused recall up without false alerts up.
E4 + router + calibrated fusion → gate: fusion beats max-score fusion, else ship max-score.
E5 + correlation upgrades C1–C4 → gate: purity, ordered paths, hit@k improve.
E6 best config on full 50 GB tier + live upload → gate: <1 h, <8 GB, p95 <500 ms.
Output: reports/ablation.md + metrics files; the UI Experiments page renders the same files.

## WORK PACKAGES (owner A = data/eval/detection/ML, B = scale/upload/correlation/UI; do them in the order given; Must before Should before Could)
EV-0 [Must,0.5d] Freeze interfaces above as Pydantic models + Parquet schemas; tests for round-trip.
EV-1 [Must,1d] Eval harness v2 with every metric above, bootstrap CIs, time splits, metrics JSON schema.
EV-2 [Must,0.5d] D0 suite: 20 seeds, variants, decoys; byte-identical regeneration test.
DS-1 [Must,1d] LANL adapter (auth first; then proc/flows/dns) + redteam→GroundTruth (user→host edges with time).
DS-2 [Must,1.5d] AIT-LDS v2 adapter + line-label GroundTruth.
DS-3 [Should,1.5d] OpTC subset adapter + GT from PDF (LLM draft + mandatory human review checklist in docs/DATASETS.md).
DS-4 [Could,0.5d] S1 EVTX label corpus.
E0  [Must,0.5d] Run baseline on D0–D3; freeze metrics/*/E0.json.
RT-1 [Must,0.5d] errors.csv: one row per missed step / wrong label / wrong order / false-alert incident / over-merge, with ONE root cause:
     parse-mapping gap | rule never fires | rule fires on benign | wrong technique | found-not-linked | benign linked | order wrong.
RT-2 [Must,1.5d] Tuning loop: fix largest bucket, re-run, log before/after in docs/DECISIONS.md. Then Optuna TPE (≤8 params: R001 count,
     R009 periodicity CV, R011 bytes floor, aggregation gap, θ_edge, θ_incident, τ, degree-penalty weight), objective
     0.4·step_recall + 0.2·label_acc + 0.2·ordered_paths − 0.2·false_alert_rate s.t. false_alert_rate ≤ 0.10, 100 trials on tuning only.
     Coverage expansion: for each GT technique without a rule, adapt one Sigma rule (keep author, DRL 1.1 attribution shown in UI) or write YAML with
     positive+negative fixtures. Reject any change that helps one dataset's tuning split but costs ≥2 points on another's. → E1.
ML-1 [Must,1d] DuckDB feature builder over Parquet (no Python loops over events), user-hour and host-hour windows, ~15 features:
     distinct dst hosts; first-seen user→host pairs; failed/total auth ratio; logon-type mix; off-hours vs entity's own hours;
     process-name rarity on host; parent→child pair rarity; distinct external dsts; external-dst fleet rarity; bytes-out z vs own history;
     beacon periodicity (CV of inter-arrival); new privileged-group membership. Must run on 50 GB within the 4 GB DuckDB limit.
ML-2 [Must,1d] M1 UEBA: rarity scorer −log P(value|entity history) with Laplace smoothing for categorical features;
     IsolationForest per entity type with peer-group normalisation (peer groups from config/assets.yaml regex);
     threshold = per-type percentile chosen on tuning for a fixed alert budget; SHAP TreeExplainer top-3 reasons rendered as text
     ("bytes out 38× this host's p99; destination seen on 1 host fleet-wide"); deterministic reason→technique table in config
     (first-seen admin logon→T1021, external bytes spike→T1041, rare Office→script child→T1059, periodic low-byte external→T1071.001).
     Emits Detection rows with member_event_ids. Report AUC-PR, Recall@B. → E2.
ML-3 [Must,1d] M2a auth-graph link prediction: hourly snapshot graphs of successful logons (user/host→host); edge anomaly =
     1 − P(edge) from historical frequency + Adamic–Adar on the long-term graph + first-seen flag; UltraLMD++ post-filter: keep an
     anomalous edge only if a neighbouring edge in the window is also anomalous. Report LANL AUC, AP, Rec@B next to published numbers.
ML-4 [Should,1.5d] M2b Euler-style GCN encoder + GRU over snapshots (PyTorch Geometric, MPS on Apple Silicon, CPU fallback),
     trained on baseline days only. Keep only if it beats M2a test AP; else report as negative finding. → E3.
     Note: Euler reports precision ~0.5% standalone, so M2 feeds fusion/correlation, never the analyst queue directly.
ML-5 [Could,1.5d] M3 Velox-style provenance edge-type predictor (linear encoder + small MLP; error = anomaly) on OpTC process events.
FU-1 [Must,0.5d] Router: per-source capability profile from ingest stats (field fill rates, category volumes); each detector declares
     requires: in config (e.g., R002 needs outcome+src_ip ≥90%; M2 needs auth_success from ≥50 hosts); RunPlan stored per run and served at
     /api/runs/{id}/plan. Test plans for D0, LANL auth-only, and a CEF-only fixture.
FU-2 [Must,1d] Fusion per AlertGroup: features = max rule severity×confidence, M1 percentile, M2 percentile, # independent detectors agreeing,
     target criticality, entity-degree penalty; L2 logistic regression fit on tuning; isotonic calibration on a held-out part of tuning;
     fallback noisy-OR of per-detector precision (from D0 tuning) when a dataset has no tuning labels. Output p_malicious + contributions
     (coef×value). Groups enter incidents if p_malicious ≥ θ_p or linked to one that is; others stay in unlinked-alerts queue.
     Reliability diagram in reports/. Ablation rows: rules; +M1 max; +M1+M2 max; +M1+M2 fusion. → E4.
CO-1 [Should,1d] Learned edge weights: logistic regression on candidate edges labelled "consecutive steps of same attack" (D0+D3 tuning),
     same features as the current hand formula so learned weights replace config values one-for-one; publish the weight table.
CO-2 [Should,0.5d] Learned tactic/technique transitions: first-order Markov matrix, Dirichlet prior = current hand matrix, counts from tuning attacks.
CO-3 [Should,0.5d] Use p_malicious as node weight in top-k path search and abstention.
CO-4 [Must,1d] Predictive reachability: add M2's predicted link probability for the next window as a "likely next hop" weight; rank reachable
     assets by criticality × reach × P(link); keep the fixed disclaimer text; truncation backtest hit@3/@5 on D0, D1, D2 vs both baselines. → E5.
SC-1 [Must,0.5d] Benchmark matrix: workers 1/2/4/8 × parser (current, pyarrow.json.read_json with explicit schema, DuckDB read_json with explicit columns) × 1/10/50 GB.
SC-2 [Must,1.5d] Vectorised parser: per byte range, line starts via numpy flatnonzero(buf==10); classify by first byte ({=JSON, C/<=CEF);
     parse JSON lines in one Arrow call with explicit schema of needed fields only; CEF minority stays Python. Exact offsets preserved
     (property test: random event_id seeks return identical lines). Target ≥3× current and ≥150 MB/s on 8 workers.
SC-3 [Must,0.5d] Lazy line digests (per-range SHA-256 always; line digest only for detection members); Parquet sorted by ts, dictionary
     encoding for host/user/process, zstd 1–3, 128k-row groups.
SC-4 [Should,1.5d] Pipelined micro-batches: watermark of closed time partitions; detect/correlate closed ranges while ingest continues;
     correlation refresh every 30 s; measure time_to_first_incident.
SC-5 [Must,0.5d] Memory governor (bounded queues; drop worker count if RSS >7 GB) + /api/metrics (Prometheus text) + bench/<run>.json; Count-Min/HLL only if DuckDB group-bys spill excessively.
UP-1 [Must,1.5d] Resumable upload via tus protocol (tus-js-client in UI; server = small FastAPI implementation of tus core: POST create,
     HEAD offset, PATCH with Upload-Offset, 64 MB chunks) writing data/uploads/<job>/source.log; committed offset = ingest watermark;
     incremental SHA-256; SSE /api/jobs/{id}/events at 1 s; "register local path" and "replay finished job (labelled replay)" options.
     Test: kill the connection mid-upload, it resumes; ingest progresses during upload.
UI-1 [Must,1d] New app in ui/ based on satnaing/shadcn-admin (MIT; remove Clerk): sidebar, ⌘K palette, dark/light, TanStack Router;
     typed API client generated from docs/openapi.json; Overview page (KPI tiles, incidents by tactic, throughput) from /api/metrics and /api/incidents;
     empty-database state; FastAPI serves ui/dist so the demo runs offline.
UI-2 [Must,2d] Incidents table (risk, ATT&CK tactic strip à la ATT&CK Navigator, merged-alert count, p_malicious, first/last seen) and
     Incident workspace: left timeline with time histogram (Timesketch pattern); centre Cytoscape graph with typed node icons and path highlight
     (BloodHound CE pattern), dashed = inferred; right drawer: raw line + verified badge, edge score breakdown, ML reasons; tabs: alternative paths,
     reachability + containment simulator (fixed disclaimer), orchestrator plan, report. p95 path latency <500 ms.
UI-3 [Must,1d] Jobs page: upload; live panels (pipeline bar uploaded→ingested→detected→correlated; MB/s and events/s sparklines; RSS vs 8 GB line;
     CPU; DuckDB spill; detections by tactic; first-incident time; run card with config hash/git SHA/manifest digest). Final values must equal bench/<run>.json.
UI-4 [Should,1d] Experiments (ablation tables with CIs per dataset, config diff between runs), Detections explorer (by detector/technique/entity,
     unlinked queue), Rules (YAML editor, fixture results, reload, Sigma author attribution).
LLM-1 [Should,0.5d] OpenRouter integration (below).
FIN [Must,1d] Final ablation on TEST splits, 50 GB live run with metrics, reports/ablation.md, README results table, two offline rehearsals.
Cut order if short on time: DS-4, ML-5, UI-4, SC-4, CO-1, CO-2, CO-3, ML-4, DS-3.

## OPENROUTER (≈ USD 2.80 total; the product must work fully with it OFF; never on the detection path)
•  Key from env OPENROUTER_API_KEY only; never committed. Module tools/llm/openrouter.py + forgetrace/report/llm.py only.
•  Model: cheapest reliable JSON-mode model at build time (check openrouter.ai/models; Aug 2026 candidates: google/gemini-2.5-flash-lite ≈ $0.10/$0.40 per M,
  deepseek v4 flash ≈ $0.05/$0.16 per M). Record the slug and price in docs/DECISIONS.md.
•  Spend ledger data/llm_ledger.jsonl with hard caps: lifetime $1.50, per run $0.25, max_tokens 1200, max 2 attempts per item. Refuse calls past caps.
•  Cache every response keyed by (input hash, prompt version, model). Demo uses cache only (venue is offline).
Allowed uses, in priority order:
 1. Incident narrative (B-2): input = deterministic template facts, pseudonymised (HMAC tokens for users/hosts/IPs); temperature 0; JSON schema
    {summary ≤120 words, steps[{order, text ≤40 words, event_ids[], technique_id}], uncertainties[]}; reject if any event_id/technique_id is not in the
    incident, any step lacks a citation, any number or token is not in the payload. Rejected → template only. UI label: "AI-written summary of verified evidence".
 2. Orchestrator explanation: one cached sentence explaining a RunPlan from its JSON. Never changes the plan.
 3. Dev-time only: draft OpTC GroundTruth JSON from the red-team PDF text; output saved as DRAFT, a human reviews every row before use; log cost.
Expected total < $0.30. A unit test asserts no raw user/email/IP pattern ever appears in an outgoing payload.

## EXECUTION PROTOCOL (every work package)
1. Plan: write docs/wp/<ID>.md (responsibility, inputs, outputs, dependencies, failure modes, tests, acceptance criteria copied from this prompt).
   Do not wait for approval unless the WP changes a frozen interface or adds a dependency.
2. Implement in small commits with tests in the same commit; typed code; a "why this exists" header citing the method (paper/source) on every non-trivial algorithm.
3. Run make check; run make eval on affected datasets; record before/after in docs/DECISIONS.md.
4. Mark each acceptance criterion pass/fail with evidence in WORKLOG.md (done, metrics, open risks, next). Commit "<ID>: <summary>".
5. If a criterion cannot pass, add an xfail test with the reason, log it, continue.
Stop and ask me ONLY when: you need a dataset path or credential; a frozen interface must change; a new dependency is needed;
a result contradicts this prompt's assumptions in a way that changes the plan; or at each milestone below.
Context hygiene: one WP per session if context grows; resume with "Reread docs/PHASE2.md, docs/STATE.md, WORKLOG.md and continue with the next unfinished WP."

## MILESTONES (stop and report at each: criterion table pass/fail with evidence, metrics with CIs, risks, next)
M1 after EV-0..E0 + SC-1..3: baseline metrics on D0, D1, D3 and the scale benchmark table.
M2 after RT-2 + ML-1..3 + FU-1/2 + CO-4 + SC-5 + UP-1 + UI-1..3: E1–E5 (Must parts) with ablation table; 10 GB live upload working.
M3 after Should items + FIN: final ablation on test splits, 50 GB run, README, rehearsed demo.

## FINAL DELIVERABLES
reports/ablation.md (rows E0–E6 × datasets × PRD metrics with CIs, including negative results); reports/scale.md (benchmark matrix, 50 GB run);
docs/DATASETS.md; docs/DECISIONS.md; docs/openapi.json; README with one-command start (make demo), results table, licences/attributions
(MITRE ATT&CK terms, Sigma DRL authors, shadcn-admin MIT, Cytoscape MIT, dataset citations: Kent 2015 LANL, DARPA OpTC, AIT-LDS, Euler, UltraLMD++).

Start with STEP 0.
