# SC-1 — Profiling + benchmark matrix (Must, 0.5 d, owner B)

**Responsibility.** Measure where time goes before optimising, and publish the matrix workers × parser × size the later scale work is judged against.

**Inputs.** `tools/gen_bulk.py` files (1 GB, 10 GB; 50 GB blocked by disk — see docs/STATE.md §5.2); `tools/bench.py`; the STEP 0 profile (`data/bench/prof150.out`).

**Outputs.** `bench/matrix.json` + `reports/scale.md`: MB/s, peak RSS (psutil 1 s), CPU %, Parquet ratio per cell; throughput-vs-workers plot data.

**STEP 0 profile findings (cProfile, 150 MB slice, phase-1 code).**
1. Rule engine threshold-window merge is quadratic per group key: for each qualifying event it rescans `evs[: i + 1]` (engine.py `_run_rule`) — 19.2M `datetime.timestamp()` calls for 224k lines, ≈ 7–9 s of a 39 s profiled run. On 10 GB this grows with the square of the largest group.
2. Per-line Python normalisation (`normalise`, `_first`, `_flatten`, `classify`, `ipaddress` parsing) ≈ 13 s cumulative — the SC-2 target.
3. `_evidence_ids` in correlation ≈ 2.3 s; row-at-a-time `INSERT` of detections in `_write`.
4. Per-line SHA-256 is cheap relative to parsing at this size (SC-3 still removes it from the hot path).

**Matrix.** workers 1/2/4/8 × parser {phase-1 readline+orjson, pyarrow.json.read_json (explicit schema), DuckDB read_json (explicit columns)} × {1 GB, 10 GB}; 50 GB column marked blocked until disk space exists.

**Failure modes.** Concurrent CPU load on the machine distorts single-run numbers (record load average); first-run file cache vs warm cache (PHASE2 says cold cache: purge between runs needs sudo on macOS — otherwise label "warm").

**Acceptance criteria (plan).** "Published table: workers × parser × size."
