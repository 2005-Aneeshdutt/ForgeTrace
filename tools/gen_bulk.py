#!/usr/bin/env python3
"""Large firex-style benchmark file, written one day at a time.

Why this exists: tools/gen_scenarios.py holds every event in memory before sorting and
writing, which is fine for the 14 MB dev sample but cannot produce the 10 GB / 50 GB scale
tiers (docs/PHASE2.md STEP 0.4, SC-1). This tool reuses the same `Gen` event shapes but
emits one simulated day per chunk (its own seed, sorted within the day) and appends it, so
memory is bounded by one day's events. Day 0 also carries the planted attacks A1/A2/D1.
The output is for throughput/memory measurement only; it has no ground-truth file and it
never writes config/assets.yaml.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gen_scenarios import Gen  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--size-gb", type=float, required=True, help="stop after the first day that crosses this size")
    ap.add_argument("--events-per-day", type=int, default=200_000)
    ap.add_argument("--seed", type=int, default=1000)
    ap.add_argument("--start", default="2026-09-01T00:00:00Z")
    ap.add_argument("--cef-ratio", type=float, default=0.1)
    a = ap.parse_args()
    target = int(a.size_gb * 1024**3)
    start = datetime.strptime(a.start, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    size, day, lines = 0, 0, 0
    with open(out, "wb") as f:
        while size < target:
            g = Gen(a.seed + day, start + timedelta(days=day), 1, a.cef_ratio, False)
            g.benign(a.events_per_day)
            if day == 0:
                g.attacks()
            g.events.sort(key=lambda x: (x[0], x[1]))
            buf = []
            for _, _, ev in g.events:
                s = g.to_cef(ev) if g.rng.random() < a.cef_ratio else json.dumps(ev, separators=(",", ":"))
                buf.append(s.encode())
            chunk = b"\n".join(buf) + b"\n"
            f.write(chunk)
            size += len(chunk)
            lines += len(buf)
            day += 1
            print(f"day {day}: {size / 1024**3:.2f} GB, {lines} lines", flush=True)
    meta = {"file": str(out), "bytes": os.path.getsize(out), "lines": lines, "days": day, "seed": a.seed,
            "events_per_day": a.events_per_day, "cef_ratio": a.cef_ratio, "start": a.start}
    out.with_suffix(out.suffix + ".meta.json").write_text(json.dumps(meta, indent=1))
    print(json.dumps(meta))


if __name__ == "__main__":
    main()
