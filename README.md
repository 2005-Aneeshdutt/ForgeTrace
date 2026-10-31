# ForgeTrace — Phase 1

ForgeTrace is a local, deterministic, offline investigation engine. It streams security logs into Parquet, runs YAML detection rules in DuckDB, and labels each detection with an ATT&CK technique and tactic. It then links detections into incidents using a transparent edge score, reconstructs the attack path, and estimates which critical assets are reachable next. Every claim traces back to the exact raw log line, and that line's SHA-256 is re-verified on each fetch. No LLM is used anywhere.

The architectural authority is `ForgeTrace — Research & Implementation Dossier-2.pdf` (§10–14). Deviations and every threshold are recorded one per line in [docs/DECISIONS.md](docs/DECISIONS.md). Progress, open risks and deferred work are in [WORKLOG.md](WORKLOG.md).

## Quick start

```bash
make setup     # python3.11 venv + pinned requirements.txt
make sample    # deterministic dev data: data/sample/events.log, ground_truth.json, config/assets.yaml
make run       # ingest -> detect -> correlate -> reach -> cache   (writes out/)
make score     # compare results with ground truth (only the scorer reads ground truth)
make test      # pytest (54 tests)
make serve     # http://127.0.0.1:8000 — dashboard + API (works offline; Cytoscape is vendored)
```

`make run INPUT="a.log b.json"` runs on other files. JSON (ECS/SimEDR), CEF and FortiGate key=value lines are auto-detected per line.

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

## Dashboard

`make serve`, then open http://127.0.0.1:8000.

- **Left panel:** incidents sorted by risk, showing severity, number of tactics and raw alert count, plus the unlinked (abstained) alerts.
- **Right panel:**
  - the attack sequence, with technique and tactic chips
  - a Cytoscape graph whose nodes are alert groups and whose dashed edges are inferred relationships labelled with their score. Clicking an edge shows its L/T/P/R/F terms, reasons and evidence IDs.
  - a timeline of the supporting raw events
  - the reachability table, the containment simulation and the uncertainty notes
- **Evidence drawer:** clicking any event opens it. The drawer shows the raw line, the event ID, the source event ID, the line number and the digest verification result.

All log-derived text is rendered with `textContent`. The page sends a strict CSP (`script-src 'self'`) and makes no CDN requests at runtime.

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
