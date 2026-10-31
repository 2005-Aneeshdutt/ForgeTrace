# Scale and performance report

Machine: Apple M2 Pro (6 performance + 4 efficiency cores), 16 GB RAM, macOS, internal SSD. Python 3.11, DuckDB 2.0. Every number below comes from a file in `bench/` (raw measurements, including 1 s memory samples).

## 1. Provided `firex-10G.log` — commit e221a46 (`bench/firex-10G.json`)

| Input | Value |
|---|---|
| File | `data/input/firex_logs/firex-10G.log` (FortiGate key=value) |
| Size | 6,543,120,032 bytes (6.09 GiB) |
| Lines / events | 12,398,551 / 12,398,551 (0 parse errors, 0 empty) |
| Time span | 2026-10-23 08:48:26 → 2026-10-30 08:48:25 IST; 69.0% of events carry the final timestamp (see §4) |

| Stage | Seconds | Throughput | Notes |
|---|---|---|---|
| Ingest (parse + normalise + Parquet) | 90.3 | 69.1 MB/s | 9 worker processes, 98 line-aligned ranges of 64 MB |
| Detect (12 rules) | 8.6 | — | R001c 3.8 s, R001 2.5 s, others < 0.5 s |
| Correlate | 15.4 | — | 323 alert groups, 15,900 candidate edges, 860 kept |
| Reach + cache | 0.05 | — | 0 incidents (see §3) |
| **End to end** | **124.7** | **50.0 MB/s** | PRD target < 1 h: **pass** |
| Peak memory (all processes, 1 s sampling) | 3.92 GB | — | PRD target < 8 GB: **pass** |
| Parquet + DuckDB on disk | 824 MB | 12.6% of input | zstd |
| Neo4j graph load (`--graph`) | 6.4 | — | 0.7 s building rows in DuckDB + 5.7 s writing; 1,658 nodes, 145,433 relationships |

API latency on this workspace (in-process handler, 30 calls each; `bench/firex-10G.api_latency.json`):

| Endpoint | p95 ms | median ms |
|---|---|---|
| GET /incidents | 0.3 | 0.2 |
| GET /alerts?unlinked=true | 7.4 | 6.9 |
| GET /detections (1000) | 12.1 | 11.1 |
| GET /overview | 51.3 | 49.5 |
| GET /events/{id}/raw (seek + SHA-256 verify) | 23.0 | 22.0 |
| GET /graph/neighbors?key=ip:10.10.99.1 (Neo4j) | 26.9 | 11.8 |

PRD incident-open latency (< 500 ms on `/incidents/{id}/path`): **N/A** — this run emitted no incidents; every endpoint measured is far below 500 ms.

## 2. Before and after the scale fixes (same generated 10 GB file, 15.4M events, 19 users)

| | Phase 1 code (`e6d64a3`) | After fixes (`eb185b5`) |
|---|---|---|
| Ingest | ≈ 15.5 min, 1 process | 107 s, 9 processes (95.9 MB/s) |
| Detect | did not finish in 54 min (stopped) | 7.7 s |
| Correlate | not reached | 1.5 s (was 692 s with only the detection fix) |
| End to end | stopped at 1 h 09 min | **119 s** |
| Peak memory | — | 1.70 GB |

Outputs of the fixed code are byte-identical to the previous code on the dev sample, five D0 seeds and `edr_events.json` (docs/DECISIONS.md D-58).

## 3. Detection accuracy on firex-10G: N/A

There is no ground truth for `firex-10G.log` or `firex-50G.log`. The only manifest, `firex-30G.log.manifest.json`, is for seed 2 and does not match: none of its external attacker addresses occur in firex-10G. Recall, label accuracy, ordered paths and false-alarm rate will be reported on `firex-30G.log` (+ `firex-30G.win.jsonl`), which the owners are obtaining.

What the current (EDR-oriented) rule set produces on firex-10G, for context only: 326 detections (R001 brute force 321, R002 external interactive logon 5), 323 alert groups, 0 incidents — every connected component has a single tactic, so the ≥ 2-tactic gate rejects all of them. The 860 kept edges all join brute-force groups to each other. This is a rule-coverage gap for firewall data, addressed by the FortiGate rule pack (RT-2).

## 4. Data artifact

From line 3,848,244 onward (69.0% of firex-10G) every event has `eventtime=1793350105999999000` (2026-10-30 08:48:25.999999 IST), apparently the generator's end-of-window clamp. The same pattern starts at ≈ 35% of firex-50G. Time-window rules see that region as one instant, so counts per window are inflated there; this is reported, not corrected.

## 5. firex-50G

Run interrupted by the owner after ingest (488 ranges, 32.7 GB). To be re-run with progress reporting after the rule pack.
