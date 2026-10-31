# LIVE — continuous analysis into a growing knowledge base (mentor's requirement)

`forgetrace live --watch <files/folders> --out out/<ws> [--graph] [--batch-mb N] [--once] [--idle-exit S] [--reset]`

**Problem.** Logs arrive continuously (e.g. 2 GB in 5 minutes) and accumulate into terabytes. Something arriving now must be linked to something seen days ago, yet no batch may re-scan history.

**Three time scales.**

| Layer | Holds | Bounded by |
|---|---|---|
| Raw events (Parquet, hot) | every parsed line, event_id = (file_id << 48) \| byte offset | `hot_days`; older files move to `cold/` (still used for evidence by event_id) |
| Rule state (DuckDB) | 5-minute buckets of count / sum / distinct values for threshold rules whose window exceeds `lookback_minutes`; keys already seen for first-seen rules | the longest rule window; first-seen keys grow with distinct keys only |
| Knowledge base (DuckDB `kb_alerts`, `kb_edges`) + Neo4j graph | alerts with stable ids, correlation edges, entities with first/last seen and counts, relationships with counts and sample event_ids, long-range RELATED links, campaigns, incidents | number of alerts and entities, not events — kept forever |

**Per batch.** (1) Discover new complete lines in watched files/folders (new files get new file ids; offsets are saved). (2) Parallel ingest of the batch. (3) Router: capability profile and site values (learned over hot data). (4) Detection: short-window rules on batch + lookback; long-window threshold rules on bucketed state; first-seen rules against the stored key set; only detections containing a new event are kept. (5) Alert groups merge into the knowledge base by (rule, aggregate key, time overlap) — a window spanning two batches extends the same alert. (6) Correlation: each updated alert against stored alerts of the last `correlate_window_hours` with the dossier §12 edge score. (7) Graph: entities and relationships accumulate, alerts and edges upsert, a :Batch marker makes replays no-ops, then RELATED links / campaigns (any time gap, uncommon shared entity) and incidents (LEADS_TO components with ≥ 2 tactics, stable id = earliest alert) are recomputed over the graph. (8) Tiering and `live_status.json`.

**Cost.** Work per batch is proportional to the batch + lookback; correlation reads a small table of recent alerts; graph-wide recomputation is O(alerts).

**Equivalence.** On the dev sample in 3 MB batches: the same 14 alerts, 19 edges and 2 incidents as a single batch run; re-running with no new data changes nothing; appended data is picked up incrementally (tests/test_live.py).

**Limits (stated, not hidden).** Long-window detections list members from the current batch only (earlier members are counted in the evidence text, not listed). Entity degree for the edge penalty F and IP→host resolution use the hot horizon. Incidents/campaigns are recomputed graph-wide each batch, fine for 10^5 alerts; beyond that, recompute only affected components.
