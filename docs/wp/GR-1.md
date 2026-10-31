# GR-1 — Neo4j graph store, hybrid with Parquet (owner decision, 2026-10-31)

**Why.** The mentor recommended a graph database: relationships (who logged on where, which host talks to which IP, which alert leads to which, what an attacker can reach) are first-class in a graph and can be updated incrementally as new data arrives. The owners chose a **hybrid**: raw events stay in Parquet/DuckDB (fast columnar scans for time-window detection rules, exact byte-offset evidence), and **Neo4j Community** holds the entity and attack graph. Every graph relationship carries raw `event_id`s, so the evidence chain is unchanged.

**Responsibility.** After `forgetrace run` (detect + correlate), load the run into Neo4j and serve graph queries; never decide detections in the graph.

**Graph model** (namespaced by workspace `ws` so several runs coexist).

| Node | Key | Properties |
|---|---|---|
| `:User` | ws, name | first/last seen |
| `:Host` | ws, name | criticality, asset type |
| `:IP` | ws, addr | external flag |
| `:Domain` | ws, name | — |
| `:Alert` | ws, group_id | rule, technique, tactic, severity, ts_first/last, member_count, sample event_ids, p_malicious |
| `:Technique` / `:Tactic` | id / name | name / ordinal |
| `:Incident` | ws, incident_id | risk, severity, tactics, ts_first/last |
| `:Run` | ws | config hash, dataset digest, finished_at |

| Relationship | Meaning | Properties |
|---|---|---|
| `(:User)-[:LOGGED_ON]->(:Host)` | successful logons | count, first, last, logon types, sample event_ids |
| `(:User)-[:FAILED_LOGON]->(:Host)` | failed logons | count, first, last, sample event_ids |
| `(:IP)-[:ASSIGNED_TO]->(:Host)` | endpoint-reported address | sample event_ids |
| `(:Host)-[:CONNECTED_TO]->(:IP)` | network connections | count, bytes_out, ports, first, last, sample event_ids |
| `(:Alert)-[:INVOLVES {role}]->(entity)` | alert entities | role = user / target_user / host / src_ip / dst_ip / domain |
| `(:Alert)-[:MAPS_TO]->(:Technique)-[:IN_TACTIC]->(:Tactic)` | ATT&CK | — |
| `(:Alert)-[:LEADS_TO]->(:Alert)` | kept correlation edge | score, terms, reasons, Δt, evidence event_ids |
| `(:Incident)-[:CONTAINS]->(:Alert)`, `(:Incident)-[:PATH_STEP {order}]->(:Alert)` | incident + primary path | — |
| `(:User)-[:ADMIN_TO {kind}]->(:Host)`, `(:User)-[:MEMBER_OF]->(:Group)-[:ADMIN_TO]->(:Host)` | reachability relations | kind = observed / configured, weight, event_ids |

**Loading.** Relationship aggregates are computed in DuckDB over Parquet (GROUP BY, all cores), then written with batched `UNWIND $rows MERGE …` (10k rows per transaction). MERGE on keys makes reloads idempotent; this is the hook for micro-batch / live mode (SC-4): a new batch merges into existing nodes and relationships.

**Interfaces.** `forgetrace/graph/` (schema, loader, queries); `forgetrace run --graph` (or `FORGETRACE_GRAPH=1`) loads after correlation; `make graph-up`/`graph-down`; API `/graph/*` endpoints. Connection from env `NEO4J_URI` (default bolt://127.0.0.1:7687), `NEO4J_USER`, `NEO4J_PASSWORD`. The pipeline still runs fully without Neo4j (graph step skipped with a logged reason).

**Failure modes.** Server down → skip with a clear message, never fail the run. Very high-cardinality relations (host→external IP on firewall data) → aggregate per pair and keep only sample event_ids (≤ 5) on the relationship. Log-derived strings stay strings (parameters only, never interpolated into Cypher).

**Tests.** Row builders are pure and unit-tested without a server; an integration test loads the dev sample into Neo4j (skipped when no server) and checks node/relationship counts, idempotent reload, and that every `LEADS_TO` carries evidence event_ids that exist in Parquet.

**Acceptance.** Dev sample and firex-10G load; reload is idempotent; incident path and entity neighbourhood queries answer under 500 ms; pipeline output unchanged with the graph step on or off.
