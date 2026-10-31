#!/usr/bin/env python3
"""Run one frozen configuration over a D0 split and score it: the unit of the experiment ladder.

Why this exists: every ablation row (E0..E6) is "same frozen config over every seed of a split,
scored once" (docs/PHASE2.md EXPERIMENT LADDER). This runs `forgetrace run` per seed into
out/d0/<experiment>/seed_NN and then `forgetrace eval` over all of them together, so per-seed
values, mean ± sd and the pooled bootstrap CI land in one metrics file.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from gen_suite import TEST, TUNING  # noqa: E402

from forgetrace.eval.cli import main as eval_main  # noqa: E402
from forgetrace.pipeline import run  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--experiment", required=True)
    ap.add_argument("--split", choices=["tuning", "test"], required=True)
    ap.add_argument("--suite", default=str(ROOT / "data/d0"))
    ap.add_argument("--out", default=str(ROOT / "out/d0"))
    ap.add_argument("--name", help="metrics file name (default <experiment>_<split>)")
    a = ap.parse_args()
    seeds = TUNING if a.split == "tuning" else TEST
    gts, runs, labels = [], [], []
    for s in seeds:
        src = Path(a.suite) / f"seed_{s:02d}"
        if not (src / "events.log").exists():
            raise SystemExit(f"{src} missing: run `python tools/gen_suite.py` first")
        out = Path(a.out) / a.experiment / f"seed_{s:02d}"
        st = run([src / "events.log"], out, dataset="d0")
        print(f"seed {s:2d}: {st['wall_time_s']:.2f} s, {st['detections']} detections, {st['incidents']} incidents")
        gts.append(str(src / "ground_truth.json"))
        runs.append(str(out))
        labels.append(str(s))
    argv = ["--dataset", "d0", "--experiment", a.name or f"{a.experiment}_{a.split}", "--split", a.split]
    for g, r, lab in zip(gts, runs, labels):
        argv += ["--gt", g, "--run", r, "--seed-label", lab]
    eval_main(argv)


if __name__ == "__main__":
    main()
