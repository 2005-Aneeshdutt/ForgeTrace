"""CLI: python -m forgetrace run --input FILE... --out DIR | serve --out DIR | eval ..."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> None:
    import sys

    if sys.argv[1:2] == ["eval"]:  # evaluation CLI (reads ground truth; never imported by the pipeline)
        from forgetrace.eval.cli import main as eval_main

        eval_main(sys.argv[2:])
        return
    ap = argparse.ArgumentParser(prog="forgetrace")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--input", nargs="+", required=True, help="log files and/or folders (folders are scanned recursively)")
    r.add_argument("--out", default="out")
    r.add_argument("--dataset", default=None, help="dataset name stamped on every event (e.g. d0, lanl, ait)")
    r.add_argument("--graph", action="store_true", help="also load the run into Neo4j (docs/wp/GR-1.md)")
    r.add_argument("--quiet", action="store_true", help="no progress lines on stderr")
    s = sub.add_parser("serve")
    s.add_argument("--out", default="out")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    a = ap.parse_args()
    if a.cmd == "run":
        from forgetrace.pipeline import run

        stats = run([Path(p) for p in a.input], Path(a.out), dataset=a.dataset, graph=a.graph or None,
                    progress=None if a.quiet else _progress_printer())
        print(json.dumps({k: stats[k] for k in ("stages", "wall_time_s", "peak_rss_bytes", "ingest", "detections",
                                                "alert_groups", "kept_edges", "incidents", "abstained_components")},
                         indent=1))
    else:
        import os

        import uvicorn

        os.environ["FORGETRACE_OUT"] = str(Path(a.out).resolve())
        uvicorn.run("forgetrace.api.app:app", host=a.host, port=a.port, log_level="info")


def _progress_printer():
    """Progress lines on stderr: stage, percent, elapsed and an ETA from the rate so far (at most one
    line every 5 s per stage, plus one line whenever the stage changes)."""
    import sys
    import time

    t0 = time.perf_counter()
    state = {"stage": None, "last": 0.0}

    def report(stage: str, frac: float) -> None:
        now = time.perf_counter()
        if stage == state["stage"] and now - state["last"] < 5 and frac < 1.0:
            return
        state.update(stage=stage, last=now)
        el = now - t0
        eta = f", ETA {el / frac - el:5.0f} s" if 0.02 < frac < 1.0 else ""
        print(f"[forgetrace] {stage:<22} {100 * frac:5.1f}%  elapsed {el:6.0f} s{eta}", file=sys.stderr, flush=True)
    return report


if __name__ == "__main__":
    main()
