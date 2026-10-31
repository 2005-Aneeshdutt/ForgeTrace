"""Streaming / live analysis (docs/PHASE2.md SC-4; docs/wp/SC-4.md).

Why this exists: in live use logs keep arriving, and an analyst should see the first incident long
before a 50 GB file has been read. `stream` consumes a file (optionally following it while it grows,
e.g. during an upload) in line-aligned byte batches. Each batch is ingested in parallel into the same
workspace with continuing line numbers (event_ids stay (file_id << 48) | byte_offset), then detection,
correlation, reachability and the graph (including long-range campaigns) are refreshed over all data
seen so far - time-window and first-seen rules need history, and DuckDB scans the accumulated Parquet
with all cores. A status file records, per batch, bytes and events processed, detections, incidents,
campaigns and the time from start to the first incident.

The graph is rebuilt per batch (replace) because alert-group ids are positional; MERGE keeps it
idempotent, and RELATED/Campaign links are recomputed so far-apart alerts join as soon as both exist.
"""
from __future__ import annotations

import hashlib
import json
import multiprocessing as mp
import time
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime
from pathlib import Path

from forgetrace import config, store
from forgetrace.ingest.ingest import default_workers, ingest_batch
from forgetrace.pipeline import analyse, dumps, peak_rss_bytes


def _line_end(path: Path, start: int, want_end: int, size: int, final: bool) -> int:
    """Largest line boundary <= want_end (after start). At EOF of a finished file the tail counts."""
    if want_end >= size:
        if final:
            return size
        want_end = size
    with open(path, "rb") as f:
        pos = want_end
        while pos > start:
            step = min(1 << 20, pos - start)
            f.seek(pos - step)
            buf = f.read(step)
            i = buf.rfind(b"\n")
            if i >= 0:
                return pos - step + i + 1
            pos -= step
    return start


def stream(path: Path, out: Path, batch_bytes: int = 1 << 30, follow: bool = False, idle_timeout: float = 30.0,
           graph: bool = False, workspace: str | None = None, dataset: str | None = None, progress=None,
           workers: int | None = None) -> dict:
    report = progress or (lambda msg: None)
    path = Path(path).resolve()
    out.mkdir(parents=True, exist_ok=True)
    for d in ("events", "parse_errors"):
        for old in (out / d).glob("*.parquet") if (out / d).exists() else []:
            old.unlink()
    for f in ("forgetrace.duckdb", "parse_errors.parquet", "incidents.json"):
        (out / f).unlink(missing_ok=True)
    pool = ProcessPoolExecutor(max_workers=workers or default_workers(), mp_context=mp.get_context("spawn"))
    sha = hashlib.sha256()
    t0 = time.perf_counter()
    offset, base_line, batch, idle_since = 0, 0, 0, None
    totals = {"lines": 0, "events": 0, "errors": 0, "empty": 0}
    history, first_incident_s, first_campaign_s = [], None, None
    status_path = out / "stream_status.json"
    try:
        while True:
            size = path.stat().st_size
            if size <= offset:
                if not follow:
                    break
                idle_since = idle_since or time.perf_counter()
                if time.perf_counter() - idle_since > idle_timeout:
                    break
                time.sleep(1.0)
                continue
            final = not follow
            end = _line_end(path, offset, min(offset + batch_bytes, size), size, final)
            if end <= offset:  # only a partial line so far (file still growing)
                time.sleep(0.5)
                continue
            idle_since = None
            tb = time.perf_counter()
            st = ingest_batch(path, 1, offset, end, base_line, out, pool, batch, dataset=dataset)
            with open(path, "rb") as f:  # incremental whole-file digest, batch by batch
                f.seek(offset)
                left = end - offset
                while left:
                    chunk = f.read(min(8 << 20, left))
                    sha.update(chunk)
                    left -= len(chunk)
            for k in totals:
                totals[k] += st[k]
            base_line += st["lines"]
            ingest_s = time.perf_counter() - tb
            offset = end
            batch += 1
            con = store.connect(out)
            store.create_views(con, out)
            stages: dict = {}
            det, res, payloads, gstats = analyse(con, out, stages, lambda s, f: None, graph, workspace or out.name)
            con.close()
            (out / "incidents.json").write_text(dumps(payloads))
            el = time.perf_counter() - t0
            camps = (gstats or {}).get("campaigns", {}) if isinstance(gstats, dict) else {}
            if payloads and first_incident_s is None:
                first_incident_s = round(el, 1)
            if camps.get("campaigns") and first_campaign_s is None:
                first_campaign_s = round(el, 1)
            row = {"batch": batch, "bytes_done": offset, "bytes_total_seen": size, "events": totals["events"],
                   "ingest_s": round(ingest_s, 2), "analyse_s": round(sum(stages.values()), 2), "elapsed_s": round(el, 1),
                   "detections": det["detections"], "alert_groups": len(res["groups"]), "incidents": len(payloads),
                   "campaigns": camps.get("campaigns"), "long_range_campaigns": camps.get("long_range_campaigns"),
                   "graph": "skipped" if not graph else ("ok" if gstats and "skipped" not in gstats else gstats)}
            history.append(row)
            status_path.write_text(json.dumps({"state": "running", "file": str(path), "batches": history,
                                               "first_incident_s": first_incident_s,
                                               "first_campaign_s": first_campaign_s}, indent=1, default=str))
            report(f"batch {batch}: {offset / 2**30:.2f}/{size / 2**30:.2f} GiB, {totals['events']:,} events, "
                   f"{det['detections']} detections, {len(payloads)} incidents, "
                   f"{camps.get('campaigns', '-')} campaigns, ingest {ingest_s:.0f} s + analyse "
                   f"{sum(stages.values()):.0f} s, elapsed {el:.0f} s")
    finally:
        pool.shutdown()
    st = path.stat()
    files = [{"file_id": 1, "path": str(path), "size": offset, "mtime": st.st_mtime, "sha256": sha.hexdigest()}]
    manifest = {"files": files, "stats": totals, "parallel": {"workers": workers or default_workers(), "mode": "stream",
                                                             "batch_bytes": batch_bytes, "batches": batch},
                "manifest_digest": hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()}
    (out / "files.json").write_text(json.dumps(manifest, indent=1))
    summary = {"state": "done", "file": str(path), "batches": history, "first_incident_s": first_incident_s,
               "first_campaign_s": first_campaign_s, "wall_time_s": round(time.perf_counter() - t0, 2),
               "peak_rss_bytes": peak_rss_bytes(), "config_hash": config.config_hash(), "ingest": totals,
               "finished_at": datetime.now().astimezone().isoformat(timespec="seconds")}
    status_path.write_text(json.dumps(summary, indent=1, default=str))
    stats = {"stages": {"stream_s": summary["wall_time_s"]}, "wall_time_s": summary["wall_time_s"],
             "peak_rss_bytes": summary["peak_rss_bytes"], "config_hash": summary["config_hash"],
             "code_version": config.CODE_VERSION, "dataset": {"files": files, "manifest_digest": manifest["manifest_digest"]},
             "ingest": totals, "ingest_parallel": manifest["parallel"], "stream": summary,
             "incidents": history[-1]["incidents"] if history else 0, "detections": history[-1]["detections"] if history else 0,
             "finished_at": summary["finished_at"]}
    (out / "run_stats.json").write_text(json.dumps(stats, indent=1, default=str))
    return summary

