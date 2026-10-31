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
    s = sub.add_parser("serve")
    s.add_argument("--out", default="out")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    a = ap.parse_args()
    if a.cmd == "run":
        from forgetrace.pipeline import run

        stats = run([Path(p) for p in a.input], Path(a.out), dataset=a.dataset)
        print(json.dumps({k: stats[k] for k in ("stages", "wall_time_s", "peak_rss_bytes", "ingest", "detections",
                                                "alert_groups", "kept_edges", "incidents", "abstained_components")},
                         indent=1))
    else:
        import os

        import uvicorn

        os.environ["FORGETRACE_OUT"] = str(Path(a.out).resolve())
        uvicorn.run("forgetrace.api.app:app", host=a.host, port=a.port, log_level="info")


if __name__ == "__main__":
    main()
