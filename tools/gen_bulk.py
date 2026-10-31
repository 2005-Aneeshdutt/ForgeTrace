#!/usr/bin/env python3
"""Large firex-style benchmark file, written one day at a time.

Why this exists: tools/gen_scenarios.py holds every event in memory before sorting and
writing, which is fine for the 14 MB dev sample but cannot produce the 10 GB / 50 GB scale
tiers (docs/PHASE2.md STEP 0.4, SC-1). This tool reuses the same `Gen` event shapes but
emits one simulated day per chunk (its own seed, sorted within the day) and appends it, so
memory is bounded by one day's events. Day 0 also carries the planted attacks A1/A2/D1.
The output is for throughput/memory measurement only; it has no ground-truth file and it
never writes config/assets.yaml.

Realism (fixed after the STEP 0 run): the first version reused the dev sample's 19 users and 10
external IPs at 20x the dev density, so every user had ~240 failed logons a day and the brute-force
rules saw 34k qualifying windows. Now the population scales with volume (~2,000 EDR events per
user-day), failed logons are a per-user Poisson rate (mean 2 a day) instead of a share of all
events, and external destinations come from a 2,000-address pool.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gen_scenarios import IT_ADMIN  # noqa: E402
from gen_suite import BASE_MIX, SuiteGen  # noqa: E402

EVENTS_PER_USER_DAY = 2_000
TYPOS_PER_USER_DAY = 2.0


class BulkGen(SuiteGen):
    """One simulated day with a population sized to the event volume."""

    def __init__(self, seed: int, start: datetime, events: int, cef_ratio: float):
        mix = {k: v for k, v in BASE_MIX.items() if k != "typo"}
        tot = sum(mix.values())
        super().__init__({"seed": seed, "days": 1, "cef_ratio": cef_ratio, "mix": {k: v / tot for k, v in mix.items()}},
                         start)
        inv = random.Random(424242)  # same population every day
        extra = max(0, events // EVENTS_PER_USER_DAY - len(self.all_users))
        servers = [h for h in self.hosts if h.startswith("SRV-")]
        for i in range(extra):
            u, h = f"u{i:05d}", f"WS-D{i // 200:02d}-{i % 200:03d}"
            self.hosts[h] = (f"10.{20 + i // 60000}.{(i // 250) % 250}.{10 + i % 250}", "Windows 11 Enterprise 23H2")
            self.home[u] = h
            self.all_users.append(u)
            self.server_access[u] = ["SRV-DC-01"] + inv.sample([s for s in servers if s != "SRV-DC-01"], 1)
        self.ext_pool = [f"{inv.randint(11, 220)}.{inv.randint(0, 255)}.{inv.randint(0, 255)}.{inv.randint(1, 254)}"
                         for _ in range(2000)]

    def typos(self) -> None:
        r = self.rng
        for u in self.all_users + [IT_ADMIN]:
            k, p, lim = 0, 1.0, math.exp(-TYPOS_PER_USER_DAY)
            while True:  # Poisson draw (Knuth)
                p *= r.random()
                if p <= lim:
                    break
                k += 1
            h = self.home[u]
            for _ in range(k):
                self.logon(self.rand_ts(), h, u, self.hosts[h][0], ok=False, ltype="Interactive")


def make_day(job: tuple) -> bytes:
    """One simulated day as newline-terminated bytes (runs in a worker process)."""
    seed, day, start_iso, events_per_day, cef_ratio = job
    start = datetime.strptime(start_iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    g = BulkGen(seed + day, start + timedelta(days=day), events_per_day, cef_ratio)
    g.benign_mix(events_per_day)
    g.typos()
    if day == 0:
        g.attacks()
    g.events.sort(key=lambda x: (x[0], x[1]))
    buf = [(g.to_cef(ev) if g.rng.random() < cef_ratio else json.dumps(ev, separators=(",", ":"))).encode()
           for _, _, ev in g.events]
    return b"\n".join(buf) + b"\n"


def main() -> None:
    from concurrent.futures import ProcessPoolExecutor

    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--size-gb", type=float, required=True, help="stop after the first day that crosses this size")
    ap.add_argument("--events-per-day", type=int, default=200_000)
    ap.add_argument("--seed", type=int, default=1000)
    ap.add_argument("--start", default="2026-09-01T00:00:00Z")
    ap.add_argument("--cef-ratio", type=float, default=0.1)
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    a = ap.parse_args()
    target = int(a.size_gb * 1024**3)
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    job = lambda d: (a.seed, d, a.start, a.events_per_day, a.cef_ratio)  # noqa: E731
    first = make_day(job(0))  # day 0 sizes the run (and carries the planted attacks)
    days = max(1, math.ceil(target / len(first)))
    size, lines = 0, 0
    with open(out, "wb") as f, ProcessPoolExecutor(max_workers=a.workers) as pool:
        # Days are independent (own seed), so they are built in parallel and written in day order;
        # the bytes are identical to a sequential run.
        for day, chunk in enumerate([first] if days == 1 else [first, *pool.map(make_day, map(job, range(1, days)))]):
            f.write(chunk)
            size += len(chunk)
            lines += chunk.count(b"\n")
            if (day + 1) % 10 == 0 or day + 1 == days:
                print(f"day {day + 1}/{days}: {size / 1024**3:.2f} GB, {lines} lines", flush=True)
    g = BulkGen(a.seed, datetime.strptime(a.start, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc),
                a.events_per_day, a.cef_ratio)
    meta = {"file": str(out), "bytes": os.path.getsize(out), "lines": lines, "days": days, "seed": a.seed,
            "users": len(g.all_users) + 1, "external_ips": len(g.ext_pool),
            "events_per_day": a.events_per_day, "cef_ratio": a.cef_ratio, "start": a.start}
    out.with_suffix(out.suffix + ".meta.json").write_text(json.dumps(meta, indent=1))
    print(json.dumps(meta))


if __name__ == "__main__":
    main()
