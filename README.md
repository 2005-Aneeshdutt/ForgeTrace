# ForgeTrace

ForgeTrace is a local, deterministic, offline investigation engine. It streams security logs (any format: JSON, CEF, syslog, key=value, CSV) into Parquet, runs YAML detection rules in DuckDB, and labels each detection with an ATT&CK technique and tactic. It links detections into incidents using a transparent edge score, reconstructs the attack path, and estimates which critical assets are reachable next. In **live mode** it consumes logs as they arrive and keeps enriching a **Neo4j knowledge graph**, so an event arriving now is linked to related activity seen days ago. Every alert, incident and campaign comes with a **human-verifiable explanation**: the rule's condition in plain English, the observed numbers, the exact raw log lines (SHA-256 re-verified), and how to check it by hand. Detection combines YAML rules with two unsupervised, explainable ML models (a per-entity behaviour model and a graph link model for lateral movement) that corroborate the rules. An optional, clearly labelled AI summary can restate those facts; detection never uses an LLM.

## Live mode, knowledge graph and explanations (Phase 2)

```bash
make graph-up                                   # Neo4j in Docker (localhost only)
python -m forgetrace live --watch data/input/ --out out/live --graph   # follow a folder; new files and appended lines are picked up
make serve                                      # dashboard: Live, Knowledge graph, explanations
```

| What | How it works | Where |
|---|---|---|
| Unseen log formats | Syntax detection (JSON, CEF, syslog, key=value, CSV header) + configurable field aliases, timestamp formats, message patterns; vendor verdicts never mapped. A new dataset needs config, not code. | `config/field_aliases.yaml`, `config/field_map.yaml`, `config/site.yaml` |
| What can be detected on this data | Router measures which fields exist and disables rules that cannot work, listing them as blind spots | `run_plan.json`, `forgetrace/rules/router.py` |
| Real-time, TB-scale history | Micro-batches; each scans only the batch + 60 min; long-window rules use bucketed state; alerts merge into a persistent knowledge base; raw Parquet ages to a cold tier while the knowledge base and graph are kept | `forgetrace/live/`, `config/live.yml`, [docs/wp/LIVE.md](docs/wp/LIVE.md) |
| Long-term dependencies | Alerts sharing an uncommon user/IP/domain are linked at any time gap (RELATED) and grouped into campaigns in Neo4j | `forgetrace/graph/campaigns.py` |
| Manual verification | `GET /explain/{alert,incident,campaign}/{id}`; optional `?llm=true` narrative (OpenRouter, key from `OPENROUTER_API_KEY`, pseudonymised, validated, cached, spend-capped) | `forgetrace/report/` |

Batch analysis (`forgetrace run`, `forgetrace analyse`, `forgetrace stream`) still works as below. Scale results: [reports/scale.md](reports/scale.md) (provided firex-50G: 62M events in ≈ 22 min, 6.0 GB peak).

The architectural authority is `ForgeTrace — Research & Implementation Dossier-2.pdf` (§10–14). Deviations and every threshold are recorded one per line in [docs/DECISIONS.md](docs/DECISIONS.md). Progress, open risks and deferred work are in [WORKLOG.md](WORKLOG.md).

## How to run

### 1. Prerequisites and setup (once)

- macOS or Linux with **Python 3.11**.
- **Docker** is optional. You need it only for the Neo4j knowledge graph (`--graph` and the Knowledge graph page). Everything else runs without it.

```bash
make setup        # creates .venv and installs the pinned requirements.txt (DuckDB, FastAPI, scikit-learn, shap, neo4j, ...)
make graph-up     # optional: Neo4j 2025.09 Community on localhost:7474 / 7687 (user neo4j, password forgetrace-dev)
make check        # optional: lint + full test suite (162 tests)
```

If you change `NEO4J_PASSWORD` for Docker, export the same value before running ForgeTrace. If Docker Desktop is short of memory, 4 GB is enough for Neo4j (heap 2 GB + page cache 1 GB).

### 2. Try it on the dev sample (about 1 minute)

```bash
make sample       # deterministic synthetic logs with planted attacks A1, A2 and decoy D1
make run          # analyse -> workspace out/sample   (add GRAPH=1 to also load Neo4j)
make score        # compare with the sample's ground truth (only the scorer reads it)
make serve        # http://127.0.0.1:8000
```

### 3. Analyse your own logs (batch)

Put the files in `data/input/`. The folder is treated as read-only evidence and is git-ignored. Then run one of:

```bash
make analyze                                   # every log file in data/input/ -> workspace out/input
.venv/bin/python -m forgetrace run --input <files or folders> --out out/<name> [--graph]
```

Formats are detected per line (JSON, CEF, syslog, key=value, CSV with a header), so there is no format flag. Large files are ingested in parallel across CPU cores; set `FORGETRACE_WORKERS=<n>` to change the worker count. The provided firex-50G (62M events) takes about 22 minutes on an M2 Pro.

### 4. Real-time analysis (live mode)

Live mode follows files and folders. New files and appended lines are processed in micro-batches, and each batch is linked to everything seen before:

```bash
make live GRAPH=1 RESET=1                      # watch data/input/ -> workspace out/live, fresh knowledge base, with Neo4j
make live GRAPH=1                              # resume: keeps building on the existing knowledge base
.venv/bin/python -m forgetrace live --watch <files/folders> --out out/<name> [--graph] [--reset] \
    [--batch-mb 256] [--once] [--idle-exit 600]
```

- `--once` processes what is there now, then exits.
- `--idle-exit N` stops after N seconds with no new data.
- The ML models stay silent for the first `warmup_hours` (6 h of event time) while baselines form. After that they retrain as history grows.
- Progress is printed per batch and written to `out/<name>/live_status.json`. The dashboard's Live page refreshes every 5 seconds.
- Batch size, lookback, correlation window and the hot/cold retention tiers are set in `config/live.yml`.

### 5. Dashboard, explanations and the optional AI summary

```bash
export OPENROUTER_API_KEY=...                  # optional: enables the "AI summary" button (never stored or committed)
make serve                                     # http://127.0.0.1:8000
```

- **Overview / Incidents / Detections:** batch workspaces. Pick the workspace at the top.
- **Live:** recent batches and alerts. Each alert has a `rule` or `model` badge and its fused probability. Click one to see why it was flagged.
- **Knowledge graph:** incidents and campaigns as timelines, plus an entity explorer (needs Neo4j).
- **Explanation panel:**
  - the condition, or for a model flag its reasons against the entity's usual range
  - the raw log lines, re-read and SHA-256 verified
  - `sed`/`grep` commands to check by hand
  - benign look-alikes to rule out

  The same data is at `GET /explain/{alert,incident,campaign}/{id}` (`?llm=true` for the AI summary).

### 6. A new, unseen dataset

The workflow needs config only, no code changes:
1. Drop the files into `data/input/` and run `make analyze` (or let live mode pick them up).
2. Open `out/<workspace>/run_plan.json`. It lists:
   - the formats seen and the fill rate of each field
   - rules disabled because their fields are missing (blind spots)
   - learned site values, such as home countries
   - the features the ML models could use
3. If fields are missing, add aliases, timestamp formats or message patterns in `config/field_aliases.yaml`. Set the time zone or home countries in `config/site.yaml` if you know them.
4. Re-run. Lines that cannot be parsed are kept in `parse_errors` with their byte offset.

### 7. Tuning

| What | Where |
|---|---|
| Rules (filters, thresholds, sequences, first-seen) | `config/rules/*.yml` |
| ML on/off, features, behaviour-model budget (`ueba.alerts_per_day`), link-model thresholds, live retraining | `config/ml.yml` |
| Correlation weights, incident gate, risk bands | `config/correlation.yml` |
| Graph connection and what gets loaded | `config/graph.yml` |
| AI summary model and spend caps | `config/llm.yml` |

Every threshold and the reason for it is in [docs/DECISIONS.md](docs/DECISIONS.md).

### Command reference

```bash
make setup | sample | run [GRAPH=1] | analyze | live [GRAPH=1] [RESET=1] [WATCH=dir] | score | demo | serve | check | test
make graph-up | graph-down | bench DATA=<file> | eval DS=<name> EXP=<name> | clean
```

## Where the input logs come from

| Workspace | Input | How to fill it |
|---|---|---|
| `sample` | `data/sample/events.log`, a synthetic SimEDR-style log with planted attacks A1/A2 and decoy D1, generated by `make sample` | `make sample && make run` |
| `input` | every `*.log, *.json, *.jsonl, *.ndjson, *.cef, *.txt` file in **`data/input/`** (recursive) | copy files there and run `make analyze`, or upload them on the dashboard's **Data sources** page and click **Analyze input folder** |

`python -m forgetrace run --input <files or folders> --out out/<name>` works on anything else. Named profiles (ECS JSON, CEF, FortiGate key=value) are chosen by the keys a line has; any other JSON, syslog, key=value or CSV line is mapped through `config/field_aliases.yaml`; only lines with no recognisable syntax or timestamp go to `parse_errors` with their byte offset. Files in `data/input/` are treated as read-only evidence and are git-ignored.

## Is a machine-learning model flagging these?

Partly. Rules and two unsupervised models run side by side (`config/ml.yml`, DECISIONS D-89..D-93). No labels are used, and no LLM takes part in detection, linking or scoring. The optional AI summary only restates already-verified explanations.
- **Rules** (`config/rules/`) are filters, thresholds and first-seen baselines compiled to SQL.
- **Behaviour model (UEBA)**: an Isolation Forest per entity type (user, host, internal address, active external address) over hourly windows. It compares each entity with its own history. A flag lists the features that made it unusual, each with the entity's usual range ("auth fail = 51 (this entity's usual: median 0.0, p95 1.0)"), and cites the raw lines that show it. Its ATT&CK label comes from a fixed feature→technique table.
- **Graph link model**: flags an account or machine that opens several new logons or admin connections, in one hour, to destinations its peers never use (lateral movement). Each new link is one flag.
- **Models corroborate, they do not decide alone.** An incident needs at least one rule detection. A rule's label wins on a shared event, and model alerts never displace a rule-to-rule link. Agreement between detectors raises an alert's *fused p* (noisy-OR of detector priors), which is shown in the UI and explanations.
- **Live mode** trains on the knowledge base's history, retrains as it grows and judges only new data. Every alert shows a `rule`/`model` badge.
- **Linking** uses a fixed, documented formula over shared entities, time gaps and tactic order (§12). Every term is shown on each edge.
- **Risk and reachability** are fixed formulas over the incident and the asset fixture.

## Architecture and data flow

```
source logs (read-only)
   │  stream line by line, keep byte offset, line_no, SHA-256 line digest
   ▼
ingest ── config/field_map.yaml ──► events/*.parquet (+ parse_errors.parquet, files.json manifest)
   ▼                                   event_id = (file_id << 48) | byte_offset
DuckDB views over Parquet
   ▼
rules ── config/rules/*.yml ──► detections, event_labels (one primary technique per event + also_matched)
   ▼
correlate ── config/correlation.yml ──► alert_groups → candidate edges → scored edges → incidents (abstention gate) → paths
   ▼
reach ── config/reach.yml + config/assets.yaml ──► reachable assets, containment candidates
   ▼
incident_cache (precomputed JSON) ──► FastAPI + static page ──► GET /events/{id}/raw re-reads & re-verifies the line
```

| Module | Files |
|---|---|
| Ingestion and normalisation | [forgetrace/ingest/](forgetrace/ingest/) (`parsers.py`, `ingest.py`, `evidence.py`) |
| Detection engine | [forgetrace/rules/engine.py](forgetrace/rules/engine.py), [config/rules/](config/rules/), [config/attack.yml](config/attack.yml) |
| Correlation, incidents, paths | [forgetrace/correlate/correlate.py](forgetrace/correlate/correlate.py) |
| Reachability and containment | [forgetrace/reach/reach.py](forgetrace/reach/reach.py) |
| Pipeline / CLI | [forgetrace/pipeline.py](forgetrace/pipeline.py), `python -m forgetrace run|serve` |
| API and dashboard | [forgetrace/api/](forgetrace/api/) |
| Data generation and scoring | [tools/gen_scenarios.py](tools/gen_scenarios.py), [tools/score.py](tools/score.py) |

## Detection engine

- Rules are YAML and are validated by Pydantic at load time. A rule fails to load if its technique is unknown, its tactic is not valid for that technique, or it references a field outside the normalised envelope. Each rule declares one technique, a severity, a fixed confidence prior (0.5/0.7/0.9) and a `label_priority`.
- There are three rule types, all compiled to DuckDB SQL:
  - `match`: a Sigma-subset filter supporting eq, in, contains, regex, comparisons, null checks, and `rare` (value seen with ≤ N distinct peers).
  - `threshold`: a windowed `count(*) OVER (... RANGE ...)`, with an optional `followed_by` that can carry a process-tree `link`.
  - `baseline`: the first-seen pair after a warm-up period.
- Each raw event gets one primary technique (lowest `label_priority`). Every other matching rule is kept in `also_matched`.
- Vendor verdict fields (`threat.*`, `rule.*`, `labels.*`, `event.kind`, `event.severity`) are never mapped into the envelope, so rules cannot reference them. This is enforced by `tests/test_vendor_ban.py`.

| Rule | Technique | What it detects |
|---|---|---|
| R001 | T1110 | ≥ 20 auth failures from one source in 10 min |
| R001c | T1110 | ≥ 5 failures for (source, account) followed by a success ≤ 30 min |
| R002 | T1078 | successful logon from an external address |
| R003 | T1059.001 | PowerShell with -nop / -w hidden / -enc / DownloadString |
| R004 | T1027 | encoded command line (low label priority) |
| R005 | T1547.001 | Run-key write by a non-allow-listed process |
| R006 | T1136.001 | local account created |
| R007 | T1098 | account added to a privileged group |
| R008 | T1021 | first-seen user→host network/RDP logon after 6 h warm-up |
| R009 | T1071.001 | ≥ 10 low-byte connections in 2 h to an external IP no other host contacts |
| R010 | T1204.002 | Office app followed by a script interpreter it spawned (process-tree link) |
| R011 | T1041 | ≥ 100 MiB outbound to an external address |

## Correlation and attack-path reconstruction (dossier §12)

1. Detections are aggregated into alert groups per (rule, aggregate key) with a 15-minute gap. `raw_alert_count` counts the merged detections, and all member event IDs are kept.
2. Candidate edges need at least one shared-entity reason: `same_session`, `same_user`, `same_host`, `pivot_ip`, `pivot_host` (IP-to-host pivot) or `same_hash_or_domain`. Pairs more than 6 hours apart are never linked.
3. Each edge is scored as `s = clip(0.45·L + 0.20·T + 0.20·P + 0.10·R − 0.25·F)`:
   - L = noisy-OR of the reason weights
   - T = exp(−Δt/τ)
   - P = tactic progression
   - R = severity and target criticality
   - F = log-scaled degree of the strongest linking entity
   
   An edge is kept if s ≥ 0.45, with at most K = 3 edges in and out per node. Every edge stores its reasons, its L/T/P/R/F terms and its evidence event IDs. The dossier's worked example (s = 0.543) is reproduced in `tests/test_correlation.py`.
4. Union-find builds the components. A component becomes an incident only if it spans **≥ 2 distinct tactics**; otherwise it stays an "unlinked alert" (`GET /alerts`).
5. **Primary path**: the incident's groups ordered by timestamp, then tactic ordinal. Each hop cites the edge that justifies it. The dossier's DP chain (`J = Σ log s + λ Σ n`) is also computed and shown as `strongest_chain`; see the limitations below.

## Reachability and containment (dossier §14)

- **Compromised set:** accounts and hosts taken from the incident's own detections. Accounts the attacker created or modified count as suspected, with weight 0.5.
- **Context graph:** built only from:
  - observed interactive/RDP logons (`ADMIN_TO`, weight 1.0)
  - observed adds to a local Administrators group (1.0)
  - fixture `ADMIN_TO` / `MEMBER_OF` / `GROUP_ADMIN_TO` edges (0.7)
  - `CREDENTIAL_EXPOSURE`, meaning an interactive session on a controlled host within 7 days (0.5)
- **Search:** max-product search with hop limit 4. It reports assets with reach ≥ 0.3, ranked by criticality × reach. Each result carries its path, the kind of every edge (observed / configured / inferred), and the supporting event IDs or fixture rows.
- **`disable_account` simulation:** a non-destructive graph edit. It reports before/after critical counts, the relationships removed, and the fixed disclaimer from dossier §14. Nothing is ever disabled.

## API

| Method | Path | Returns |
|---|---|---|
| GET | `/health` | status, manifest digest, config hash, code version |
| GET | `/incidents?sort=risk` | id, risk, severity, tactics, raw alert count, top entities |
| GET | `/incidents/{id}` | full incident: `observed` (groups, raw events) and `inferred` (edges, paths, reachability) |
| GET | `/incidents/{id}/path` | primary path + dossier DP chain with step and edge evidence |
| GET | `/incidents/{id}/reach` (alias `/reachability`) | compromised set, reachable assets, disclaimer |
| POST | `/incidents/{id}/simulate` | body `{"actions":[{"type":"disable_account","target":"<account>"}]}` |
| GET | `/events/{event_id}/raw` | original raw line, file, offset, line_no, source_event_id, `verified` |
| GET | `/alerts?unlinked=true`, `/rules` | abstained components; loaded rules with compiled SQL |
| GET | `/workspaces`, `/overview`, `/detections`, `/metrics` | workspace list; ingest/detection statistics; all detections; scoring output |
| GET/POST/DELETE | `/inputs` | list `data/input/`; streamed raw-body upload (`?filename=`, name-validated, no overwrite unless asked); delete |
| POST/GET | `/runs`, `/runs/current` | start a background analysis of `sample` or `input`; poll its stage and progress |

All read endpoints take `?ws=<workspace>` (default: the most recently analysed).

## Dashboard

`make serve`, then open http://127.0.0.1:8000. The dashboard is a single offline page with sidebar navigation, a workspace switcher and a light/dark theme. Links are shareable, e.g. `/?ws=sample#/incidents/2/graph`.

| Page | What it shows |
|---|---|
| **Pipeline demo** | Guided 8-step walkthrough of `data/demo/demo_events.log` (5 hand-written events: 3 JSON, 2 CEF, 1 benign) showing each stage's real stored output: ingest (offsets, event IDs, SHA-256) → normalise and store (vendor field → envelope field trace, Parquet) → detect and flag (rule hits, label priority) → aggregate (groups, folded secondary label) → correlate (entity index, every candidate pair's L/T/P/R/F score, kept vs dropped) → attack graph (components, two-tactic gate) → path reconstruction → risk, reachability, containment and evidence check. Deep link: `#/demo/<step>` |
| **Overview** | Funnel (raw events → detections → alert groups → incidents → unlinked); source files, data span, run time, peak memory; detections by tactic in kill-chain order; events by type; highest-risk incidents; detections per rule; parse errors |
| **Incidents** | Risk-sorted list plus unlinked alerts. Per incident: severity, risk and its terms, key facts, a template summary (no AI), and tabs: **Attack path** (numbered kill-chain stepper with evidence links and the edge behind each hop), **Graph** (Cytoscape, primary-path hops highlighted, click a node or edge for its evidence and L/T/P/R/F breakdown), **Timeline** (filterable raw events), **Reachability & containment** (compromised set, reachable assets with typed paths, `disable_account` simulation with the fixed disclaimer), **Correlation evidence**, **Uncertainty** |
| **Detections** | Every rule hit, filterable by text, tactic, rule and whether it is in an incident; links to incidents and raw evidence |
| **Data sources** | Drag-and-drop upload into `data/input/` with progress, file list with remove, **Analyze input folder** with live progress, workspace table (open / re-run), and SHA-256 fingerprints of the files behind the active workspace |
| **Detection rules** | Loaded rules with technique, tactic, type, severity, confidence prior, label priority, file, and the compiled DuckDB SQL |
| **Evaluation** | Ground-truth metrics and per-step table (sample workspace only; labelled as synthetic) |

Clicking any event opens the **evidence drawer**. It shows the raw line re-read from the source with a verified/not-verified badge, both SHA-256 values, the event ID, the source event ID and the line/offset. It has copy and pretty-print buttons. All log-derived text is rendered as text, never HTML. The page sends a strict CSP (`script-src 'self'`, no inline styles or scripts) and makes no CDN requests.

## Dataset generation

`tools/gen_scenarios.py --start 2026-10-01T00:00:00Z --days 2 --seed 7 --events 20000 --cef-ratio 0.1 [--with-tags]` produces a deterministic SimEDR-style benign background. It uses a simulated clock and a seeded RNG, so the same seed gives a byte-identical file. 10% of lines are written as CEF. The planted scenarios are:

- **A1:** 50× 4625 from one external IP → 4624 → 4720 → 4732 Administrators → network logon to SRV-FILE-01 → 150 MiB to the same external IP.
- **A2:** WINWORD → `powershell -nop -w hidden -enc` → Run key → 12 low-byte beacons to a rare IP → RDP to SRV-DB-01.
- **D1:** benign decoy. An IT admin creates an account, adds it to a normal group, then 3 typo failures follow.

Vendor tags are off unless `--with-tags` is passed, and a test shows that detections are identical with and without tags. `ground_truth.json` lists, for each step, the technique, tactic, event IDs, line numbers and source event IDs.

## Evaluation results (actual `make score` output, seed 7)

| Metric | Result | Dossier "Great" target |
|---|---|---|
| Step recall | 11/11 = 100.0% | > 90% |
| Label accuracy, parent technique | 11/11 = 100.0% | > 85% |
| Label accuracy, sub-technique | 9/11 = 81.8% | > 85% (missed) |
| Attacks reconstructed in order (primary path) | 2/2 = 100.0% | all |
| False-alarm share | 0/2 = 0.0% (D1 rejected) | < 10% |
| Runtime (`make run`, 20,129 lines, 14.1 MB) | 1.14 s wall | < 1 h (full tier) |
| Peak RSS | 231.5 MiB | < 8 GB |

**How to read these numbers.** The generator, ground truth and rules were all written in the same session, so the sample metrics are optimistic: they show the pipeline works end to end, not that it generalises. The two sub-technique misses are real. R008 labels T1021, while ground truth says T1021.002 (SMB) for A1 and T1021.001 (RDP) for A2. Two independent checks were run outside the test suite:

- **`edr_events.json`** (10,000 SimEDR events, not generated here). The vendor labels were used for evaluation only. My primary labels agreed with them on T1059.001 (101/101), T1110 (98/98) and T1547.001 (88/88). Vendor T1486 (110, no rule) and T1071.001 (96) were not detected; the vendor's C2 destination is contacted by 16 hosts, which defeats R009's rarity condition. The file has no multi-stage ground truth, so the 13 Execution+Persistence incidents it produced cannot be scored.
- **The first 50 MB of `firex-10G.log`** (FortiGate). 99,262 lines parsed with 0 errors, at about 12.6 MB/s on one core, peak RSS 333 MiB. It produced 0 detections because the Phase 1 rules target endpoint telemetry.

## Completed in Phase 1

- Streaming ingestion of JSON, CEF and FortiGate KV with byte-offset event IDs, line numbers, SHA-256 line digests and `parse_errors`.
- Evidence retrieval with re-verification.
- YAML rule engine (match / threshold + followed_by / baseline) with label priority and `also_matched`.
- Explainable correlation following the dossier formula, with an abstention gate.
- Time-ordered primary path plus the DP chain.
- Incident-conditioned reachability and `disable_account` simulation with the verbatim disclaimer.
- Risk score (B-1) and merged-alert counts (B-3).
- FastAPI and an offline dashboard.
- Ground-truth scorer and 54 tests.

## Known limitations

- **Self-generated evaluation:** see above. No independent multi-stage ground truth was available locally. `firex-30G.log.manifest.json` describes files that are not present.
- **Dossier DP path:** with the dossier defaults (λ = 1) the `strongest_chain` drops weakly linked steps (A1 omits steps 3, 5, 6; A2 omits 1, 2, 5). For that reason the primary path follows the brief's time/tactic ordering ([DECISIONS D-30](docs/DECISIONS.md)).
- **Sub-techniques:** R008 emits the parent T1021. Separate RDP and SMB rules would fix this.
- **Missing rule coverage:** no rules for ransomware (T1486), firewall-only behaviours (port scan, DNS tunnelling, flood) or vendor C2 patterns that many hosts share.
- **Fixture:** `config/assets.yaml` is generated together with the sample. Configured edges are labelled as such in the output.
- **Reachability simplifications:** no network/segment factor; only `disable_account` is simulated.
- **Ingest scale:** ingest is single-process. It has been measured on 50 MB of firex only; the full tier has not been run. The text in `firex-10G.log` ends at about 4.8 GB, and the rest is binary.

## Deferred to Phase 2

Parallel byte-range ingestion; full-tier processing; top-k alternative attack paths; bounded connectors; privacy controls (pseudonymisation, retention, audit log, roles); LLM-generated reports; Docker deployment; live mode. Also: STIX-built ATT&CK table, `sequence` rule type, `/report` and `/metrics` endpoints, truncation backtest of reachability.
