# Decisions (one line each)

## Source-document discrepancies (found during inspection, 2026-10-31)
- D-01 `docs/ForgeTrace_Dossier.pdf` does not exist; the dossier is `ForgeTrace — Research & Implementation Dossier-2.pdf` at repo root and is used as the authority.
- D-02 The dossier has 22 sections; the requested sections 23 (dataset schema), 24 (ground-truth format) and 25 (CLAUDE.md) do not exist. Schema follows §13, ground truth follows the format in the task prompt, CLAUDE.md is derived from §18's working rules.
- D-03 `docs/PRD_Kill_Chain_Attack_Path.pdf` does not exist; PRD requirements are taken from the dossier's PRD-derived §2 and the task prompt.
- D-04 `tools/edr_log_generator.py` does not exist; `tools/gen_scenarios.py` reimplements a benign SimEDR-style generator whose output shape mirrors `edr_events.json` (ECS-like JSON). No reference generator was created or modified.
- D-05 `firex-30G.log.manifest.json` describes `firex-30G.log` + `firex-30G.win.jsonl`; neither is present, so the manifest cannot score the local `firex-10G.log`. Used only to understand the ground-truth shape (1-based lines, 0-based byte offsets, per-event `[line, byte, stream]`).
- D-06 `firex-10G.log` is FortiGate key=value text (not JSON/CEF) up to roughly byte 4.8 GB; sampled lines beyond that are binary (truncated or corrupt copy). Full-tier ingestion is deferred to Phase 2.
- D-07 `edr_events.json` vendor alerts carry `threat.*`, `rule.*`, `labels*`, `event.kind=alert`, `event.severity`; field_map.yaml never maps these, so they cannot reach the envelope or the rules.

## Engineering
- D-10 Stack: Python 3.11 venv, pinned in requirements.txt; httpx not installed (not approved) so API tests drive a live uvicorn via urllib.
- D-11 `line_digest` = SHA-256 hex of the raw line bytes without the trailing newline (dossier §13 suggests xxhash64, which is not in the approved stack; §3 names SHA-256).
- D-12 `event_id = (file_id << 48) | byte_offset`, file_id assigned 1..n by sorted input path; ground truth is generated with file_id=1 because the sample is a single file; scorer matches on line_no and also checks event_ids.
- D-13 Envelope additions beyond §13 forced by the scenarios: `host_ip`, `src_is_external`, `registry_path`, `registry_value`, `group_name`, `parent_process`, `byte_offset`, `line_no`, `raw_format`, `source_event_id`.
- D-14 Canonical user = lower-case bare account (domain stripped into `user_domain`) so `user` and `target_user` compare directly; dossier §11 suggests `domain\user`, but the dev data is single-domain.
- D-15 Ingest is single-process streaming (readline, 200k-row Parquet batches, zstd, 128k row groups); byte-range workers deferred to Phase 2.
- D-16 FortiGate key=value parser included in field_map/parsers so firex lines normalise, but full-tier runs are Phase 2.
- D-17 `ts` is stored as naive TIMESTAMP(us) holding UTC (tz-aware results would require pytz, which is outside the approved stack).
- D-18 Rule types: match, threshold (+followed_by), and a minimal `baseline` (first_seen after warm-up, dossier §12 table) needed for R008; `sequence` deferred.
- D-19 Added R010 (T1204.002, Office app followed by a script interpreter it spawned) beyond the brief's list so the A2 "winword.exe" step is detectable; R010 number was unused.
- D-20 Thresholds: R001 ≥20 fails/10 min per src_ip; R001c ≥5 fails/30 min per (src_ip,user) followed by success ≤30 min; R009 ≥10 conns/2 h per (host,dst_ip), bytes_out ≤2048, dst_ip contacted by ≤1 host; R011 bytes_out ≥100 MiB external; R008 warm-up 6 h.
- D-21 label_priority (lower wins): R002 15, R001 20, R001c 25, R003/R005/R009/R011 30, R010 35, R006/R007 40, R008 50, R004 90.
- D-22 Duplicate suppression (§12 step 1) at detection level: a detection whose members are a subset of a stronger same-technique detection gets duplicate_of and is excluded from correlation (R001 ⊂ R001c on A1).
- D-23 followed_by semantics: follower must occur within `within` after ≥count window members; members = those members + follower.
- D-24 Technique table is a hand-curated ATT&CK subset in config/attack.yml (STIX build script deferred); rule load rejects unknown techniques and invalid technique/tactic pairs.
- D-25 Correlation weights, reason weights, τ, P matrix, F saturation (500), θ_edge 0.45, K 3 are the dossier §12 defaults (config/correlation.yml); τ = 2 h only when same_user is the sole reason (matches the §12 worked example, which uses 30 min with same_user+same_host).
- D-26 Max candidate window 6 h (brief) instead of per-reason windows; skew tolerance 60 s.
- D-27 entity degree (F term): user→distinct hosts, host→distinct users, ip→distinct hosts using it as src/dst, domain→distinct hosts; strongest linking entity = highest reason weight, ties → highest degree (conservative).
- D-28 Detections whose member events all carry a different primary technique (label priority) are folded into the primary group as `also_matched` rather than becoming separate nodes (e.g. R004 on the R003 event, R008 on the R002 event).
- D-29 raw_alert_count = number of detections merged into the group (aggregation gap 15 min); member_event_count reported separately.
- D-30 Primary path = all incident groups ordered by (ts_first, tactic ordinal, first event_id) as the brief's Step 5 specifies; each hop cites its kept edge or says none exists. The dossier §12 step 8 DP (J = Σ log s + λ Σ n, λ = 1) is kept as `strongest_chain`; with dossier defaults it drops weakly-linked tail steps, so it is reported but not used as primary. Conflict noted deliberately.
- D-31 Abstention gate = ≥ 2 distinct tactics (brief); the dossier's alternative "critical group + corroboration" route and θ_incident/θ_path are not used in Phase 1.
- D-32 Risk (WP-17): 100 × (0.35·maxsev/4 + 0.25·max node criticality + 0.20·deepest ordinal/14 + 0.20·critical reachable/total critical); bands high ≥ 70, medium ≥ 40.
- D-33 Reachability per §14: compromised set from incident groups (actor accounts and hosts 1.0; accounts created/modified by them 0.5); edges ADMIN_TO observed (interactive/RDP logon, or add to local Administrators) 1.0, fixture ADMIN_TO/MEMBER_OF/GROUP_ADMIN_TO 0.7, CREDENTIAL_EXPOSURE (interactive session on host, 7-day lookback) 0.5; hop limit H = 4 graph edges (dossier) rather than the brief's "1–2 hops"; report reach ≥ 0.3, critical = criticality ≥ 0.8; network factor not modelled (treated as 1.0).
- D-34 Only disable_account is simulated in Phase 1 (isolate_host, block_ip, revoke_session rejected with an explicit error). Candidate ranking evaluates disable_account for every account in or on a path from the compromised set (≤ 20).
- D-35 total_critical_assets = hosts named in the fixture with criticality ≥ 0.8.
- D-36 API: brief's `/incidents/{id}/reach` plus dossier alias `/reachability`; `/alerts?unlinked=true` and `/rules` included; `/report` and `/metrics` deferred. Strict CSP (script/style 'self'); all log-derived strings rendered with textContent; Cytoscape canvas labels are not HTML.
- D-37 event_id values stay below 2^53 for file_id < 32, so they are exact as JavaScript numbers in the dashboard.
- D-38 Scoring: step found = any detection (incl. duplicates/folded) whose members intersect the step's lines; predicted label = the step events' primary technique; path order evaluated on the primary path with the dossier DP chain reported as a secondary line; runtime/peak RSS read from run_stats.json (ru_maxrss of the single run process).
