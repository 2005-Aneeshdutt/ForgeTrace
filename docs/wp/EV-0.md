# EV-0 — Freeze interfaces (Must, 0.5 d, owner A)

**Responsibility.** Define the Phase 2 data contracts once, so the evaluation, dataset adapters, ML detectors, fusion and UI can be built in parallel against the same shapes.

**Inputs.** PHASE2.md "FROZEN INTERFACES"; the Phase 1 envelope (`forgetrace/ingest/ingest.py` `SCHEMA`), `detections` and `alert_groups` tables, and `data/sample/ground_truth.json`.

**Outputs.**
- `forgetrace/models.py`: Pydantic v2 models `Event`, `Reason`, `Detection`, `AlertGroup`, `RunPlan` (+ `DisabledDetector`), `GroundTruth` (+ `Attack`, `Step`, `LineRef`, `AuthEdge`).
- Arrow schemas `EVENT_SCHEMA` (envelope + `dataset`), `DETECTION_SCHEMA`, `ALERT_GROUP_SCHEMA` used for Parquet round trips.
- `ground_truth_from_legacy()` converting Phase 1 GT files (`decoy`, `event_ids`, `line_nos`) into `GroundTruth`.
- Pipeline writes the new columns: events gain `dataset`; detections gain `detector` (`rule:<id>`), `score`, `reasons`; alert groups gain `p_malicious` (null until FU-2) and `contributions` ({}).

**Dependencies.** None.

**Failure modes.** Envelope change breaks the vendor-ban test or old workspaces (old `out/` dirs lack the new columns → the API must tolerate absence until re-run); event_id above 2^53 in JSON (file_id < 32 keeps it exact, D-37).

**Tests.** `tests/test_models.py`: each model round-trips through JSON and through a Parquet file with its Arrow schema; legacy GT converts with every step's event_ids preserved; detections table carries the new columns after a run.

**Acceptance criteria (from PHASE2.md).** "Freeze interfaces above as Pydantic models + Parquet schemas; tests for round-trip."
