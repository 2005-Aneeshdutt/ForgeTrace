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

## 5. firex-10G with the FortiGate rule pack (`bench/firex-10G.rules.json`, commit after 90aeb99)

| Stage | Baseline rules (12) | + FortiGate pack (29 rules), first run | + SQL prefilter and attacker↔victim graph scope |
|---|---|---|---|
| Ingest | 90.3 s | 99.7 s | 99.1 s |
| Detect | 8.6 s | 109.8 s (F001 31.6 s, F016 31.5 s, F009 25.6 s) | **26.2 s** (no rule above 4.7 s) |
| Correlate | 15.4 s | 45.0 s | 44.0 s |
| Graph load + campaigns | 6.4 s (load only) | 116.3 s (928,915 IP nodes) | **9.8 s** (4,347 IP nodes) |
| **End to end** | 124.7 s | 382.8 s | **194.1 s** |
| Peak memory (all processes) | 3.92 GB | 3.95 GB | 3.51 GB |

| Output | Baseline rules | + FortiGate pack |
|---|---|---|
| Detections / alert groups | 326 / 323 | 353 / 344 (18 rules fired) |
| Incidents (≥ 2 tactics) | 0 | 2 (both made of brute-force groups inflated by the timestamp clamp, D-74) |
| Graph campaigns (long-range, D-70) | — | 4, three spanning > 6 h; one joins XSS, SQLi, command injection, traversal, port scan, lateral sweeps and staged exfiltration over 129 h; one is a firewall admin account creation followed by an external interactive login |

Accuracy of these outputs is measured on firex-30G (labelled); firex-10G is the development set.

## 6. Provided `firex-50G.log` (`bench/firex-50G.analysis.json`)

32,702,905,053 bytes, 61,970,767 lines, 0 parse errors. Three full runs were needed to get through: the first two stopped in incident building / persistence because the timestamp clamp chains ~5,000 brute-force groups into one component (a 463 MB incident record, then 3.3 GB of edge-reason JSON; fixed by D-75–D-77). The final measurement re-analysed the ingested workspace with `forgetrace analyse`; the ingest time is from the immediately preceding run with the same ingest code.

| Stage | Seconds | Notes |
|---|---|---|
| Ingest | 473 | 9 workers, 488 ranges, ≈ 66 MB/s |
| Detect (29 rules) | 172.5 | slowest rules F016 24.7 s, F001 23.4 s, R001c 19.2 s |
| Correlate | 462.0 | 5,088 groups, 1,143,670 candidate edges (all inside one window because of the clamp), 14,400 kept |
| Reach + incident records + persist | 129.6 | 2 incidents; largest record 45 MB after bounding |
| Graph load + campaigns | 55.7 | 5,088 alerts, 12,721 IPs; 4 campaigns, 3 spanning > 6 h |
| **End to end** | **≈ 1,313 (21.9 min)** | PRD < 1 h: **pass** |
| Peak memory (all processes) | **6.0 GB** | PRD < 8 GB: **pass**; above the 6 GB stretch target |

All 17 FortiGate rules fired at least once. R001 produced 6,040 detections, nearly all from the clamped region (D-74). Accuracy: N/A for the same reason as §3 (no labels for this seed).

Next scale targets: correlation (7.7 min, single-threaded candidate-edge building over clamp-sized groups) and memory headroom (the Neo4j Docker VM reserves 8 GB on a 16 GB machine; swap reached 17.5 GB during the failed runs).
