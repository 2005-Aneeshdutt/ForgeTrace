# SC-4 — Streaming / live analysis (micro-batches)

**Command.** `forgetrace stream --input FILE --out DIR [--batch-mb 1024] [--follow] [--graph]`.

**Method.** Line-aligned byte batches; each batch is ingested in parallel into the same workspace with continuing line numbers (event_id = (file_id << 48) | byte_offset is unchanged), then detection, correlation, reachability and the graph (with campaigns) are refreshed over all data so far. `--follow` keeps reading while the file grows (a live upload) and stops after `--idle-timeout` seconds without growth; a partial last line waits for its newline. `stream_status.json` (and `GET /stream/status`) records each batch: bytes, events, detections, incidents, campaigns, ingest and analysis seconds, and the time from start to the first incident and first campaign. The whole-file SHA-256 is computed incrementally.

**Equivalence.** Streaming the dev sample in 3 MB batches, or while it is being written in pieces cut mid-line, ends with exactly the events, detections and incidents of a batch run (tests/test_stream.py).

**Cost model.** Analysis re-runs over all data per batch, so total analysis time grows with the number of batches; batch size trades time-to-first-incident against total time. Graph per batch is a replace (alert-group ids are positional), MERGE keeps it idempotent.
