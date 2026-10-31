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
