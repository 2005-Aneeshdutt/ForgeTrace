#!/usr/bin/env python3
"""Run `forgetrace run` on one input and record per-stage throughput and peak memory.

Why this exists: PHASE2 STEP 0.4 / SC-1 / SC-5 need measured numbers, not estimates. The run
happens in a child process; a psutil sampler polls the RSS of that process and all of its
children once per second (PHASE2 METRICS: "peak RSS (psutil 1 s sampling over all processes)")
and the stage timings come from the run's own run_stats.json. MB/s per stage is input bytes
divided by that stage's wall time, so later stages are comparable across parsers.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import psutil

ROOT = Path(__file__).resolve().parents[1]


def tree_rss(p: psutil.Process) -> int:
    total = 0
    for q in [p, *p.children(recursive=True)]:
        try:
            total += q.memory_info().rss
        except psutil.Error:
            pass
    return total


def git_sha() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    except Exception:
        return "unknown"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--out", required=True, help="workspace directory for the run")
    ap.add_argument("--report", required=True, help="bench JSON to write")
    ap.add_argument("--label", default="")
    a = ap.parse_args()
    inp = Path(a.input)
    size = sum(f.stat().st_size for f in ([inp] if inp.is_file() else inp.rglob("*")) if f.is_file())
    cmd = [sys.executable, "-m", "forgetrace", "run", "--input", str(inp), "--out", a.out]
    t0 = time.perf_counter()
    proc = subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    ps = psutil.Process(proc.pid)
    peak, samples = 0, []
    while proc.poll() is None:
        try:
            rss = tree_rss(ps)
            cpu = ps.cpu_percent(interval=None)
        except psutil.Error:
            break
        peak = max(peak, rss)
        samples.append({"t": round(time.perf_counter() - t0, 1), "rss_mb": round(rss / 2**20, 1), "cpu_pct": cpu})
        time.sleep(1.0)
    log = proc.stdout.read() if proc.stdout else ""
    wall = time.perf_counter() - t0
    if proc.returncode != 0:
        print(log[-4000:])
        raise SystemExit(f"run failed with exit code {proc.returncode}")
    stats = json.loads((Path(a.out) / "run_stats.json").read_text())
    mb = size / 2**20
    stages = {k.removesuffix("_s"): {"seconds": v, "mb_per_s": round(mb / v, 2) if v else None}
              for k, v in stats["stages"].items()}
    report = {
        "label": a.label, "measured_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "git_sha": git_sha(), "config_hash": stats.get("config_hash"),
        "machine": {"cpus": os.cpu_count(), "ram_gb": round(psutil.virtual_memory().total / 2**30, 1),
                    "platform": sys.platform},
        "input": {"path": str(inp), "bytes": size, "lines": stats["ingest"]["lines"],
                  "events": stats["ingest"]["events"], "parse_errors": stats["ingest"]["errors"]},
        "wall_time_s": round(wall, 2), "end_to_end_mb_per_s": round(mb / wall, 2),
        "stages": stages,
        "peak_rss_mb_psutil_1s": round(peak / 2**20, 1),
        "peak_rss_mb_ru_maxrss": round(stats["peak_rss_bytes"] / 2**20, 1),
        "parallel": (json.loads((Path(a.out) / "files.json").read_text()).get("parallel")
                     or {"workers": 1, "ranges": 1, "note": "sequential (pre-parallel ingest)"}),
        "parser": "readline + orjson/python per line, byte-range process pool",
        "counts": {k: stats.get(k) for k in ("detections", "alert_groups", "candidate_edges", "kept_edges",
                                             "incidents", "abstained_components")},
        "rss_samples": samples,
    }
    Path(a.report).parent.mkdir(parents=True, exist_ok=True)
    Path(a.report).write_text(json.dumps(report, indent=1, default=str))
    print(json.dumps({k: v for k, v in report.items() if k != "rss_samples"}, indent=1, default=str))


if __name__ == "__main__":
    main()
