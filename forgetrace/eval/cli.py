"""`forgetrace eval`: score run directories against ground truth and write metrics JSON.

Why this exists: PHASE2 requires one tool that computes every metric from a ground-truth file and
a run directory and writes metrics/<dataset>/<experiment>.json with CIs and provenance. Several
(--gt, --run) pairs are several seeds of the same experiment: each is scored on its own (per-run
values, mean ± sd) and their attacks/incidents are pooled for the bootstrap CI.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import statistics
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from forgetrace import config
from forgetrace.eval import metrics as M
from forgetrace.eval.groundtruth import GroundTruth, ground_truth_from_legacy
from forgetrace.eval.runview import attach_event_meta, load_run, resolve_steps
from forgetrace.eval.schema import PRD_TARGETS, MetricsFile, RunEntry, Summary

HEADLINE = ["step_recall", "label_acc_exact", "label_acc_parent", "ordered_path_rate", "mean_kendall_tau",
            "step_coverage_in_one_incident", "false_alert_rate", "purity", "ari", "nodes_to_inspect_mean",
            "nodes_malicious_share", "ndcg_at_10"]


def load_gt(path: Path, dataset: str) -> GroundTruth:
    raw = json.loads(path.read_text())
    if "incidents" in raw and "log" in raw:  # organisers' firex manifest
        from forgetrace.datasets.firex.adapter import ground_truth as firex_gt
        return firex_gt(path)
    if raw.get("attacks") and "decoy" in raw["attacks"][0]:
        return ground_truth_from_legacy(raw, dataset)
    return GroundTruth.model_validate(raw)


def git_state() -> tuple[str, bool]:
    try:
        sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=config.ROOT, text=True).strip()
        dirty = bool(subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"],
                                             cwd=config.ROOT, text=True).strip())
        return sha, dirty
    except Exception:
        return "unknown", True


def path_latency_ms(run_dir: Path, repeats: int = 20) -> dict:
    """p95 of the /incidents/{id}/path handler, in-process (no HTTP stack), each incident `repeats` times.
    Runs in a child process because the API resolves its workspace from the environment at import."""
    code = (
        "import json,sys,time\n"
        "from forgetrace.api import app as A\n"
        "ids=[r[0] for r in A.con(None).execute('SELECT incident_id FROM incident_cache').fetchall()]\n"
        "t=[]\n"
        f"for _ in range({repeats}):\n"
        "  for i in ids:\n"
        "    s=time.perf_counter(); A.incident_path(i, None); t.append((time.perf_counter()-s)*1000)\n"
        "print(json.dumps(t))\n")
    env = {**os.environ, "FORGETRACE_OUT": str(run_dir.resolve())}
    try:
        out = subprocess.run([sys.executable, "-c", code], env=env, cwd=config.ROOT, capture_output=True, text=True,
                             timeout=300, check=True).stdout
        t = sorted(json.loads(out))
    except Exception as e:  # report, never invent
        return {"value": None, "text": f"N/A (latency probe failed: {type(e).__name__})"}
    if not t:
        return {"value": None, "text": "N/A (no incidents to open)"}
    p95 = t[min(len(t) - 1, int(0.95 * len(t)))]
    return {"value": p95, "text": f"p95 {p95:.1f} ms over {len(t)} in-process handler calls (no HTTP stack)"}


def score_pair(gt_path: Path, run_dir: Path, dataset: str, latency: bool) -> tuple[dict, list, list, dict]:
    gt = load_gt(gt_path, dataset)
    rv = load_run(run_dir)
    steps = resolve_steps(gt, run_dir)
    need = set().union(*steps.values()) if steps else set()
    need |= {m for d in rv.detections for m in d.members}
    attach_event_meta(rv, run_dir, need)
    attacks = M.score_steps(gt, steps, rv)
    out = {**M.step_summary(attacks), **M.incident_summary(attacks, rv), **M.incident_ranking(attacks, rv)}
    out["event_level"] = M.event_level(attacks, rv)
    out["score_level"] = M.score_level(attacks, rv)
    out["attacks"] = [{
        "attack_id": a.attack_id, "is_decoy": a.is_decoy, "incident_id": a.incident_id, "ordered": a.ordered,
        "kendall_tau": a.tau, "missing_found_steps": a.missing_found, "coverage_one_incident": a.coverage_one_incident,
        "decoy_in_incidents": a.decoy_in_incidents,
        "steps": [{"order": s.order, "technique": s.technique, "found": s.found, "found_by": s.found_by,
                   "predicted": s.predicted, "label_exact": s.label_exact, "label_parent": s.label_parent,
                   "detectors": s.detectors, "gt_events": len(s.events)} for s in a.steps]} for a in attacks]
    st = rv.run_stats
    sysm = {"wall_time_s": st.get("wall_time_s"), "stages_s": st.get("stages"),
            "peak_rss_mb_ru_maxrss": round(st["peak_rss_bytes"] / 2**20, 1) if st.get("peak_rss_bytes") else None,
            "time_to_first_incident_s": st.get("wall_time_s"),
            "time_to_first_incident_note": "batch mode: first incident appears when the run finishes (SC-4 pending)"}
    if latency:
        sysm["p95_path_latency_ms"] = path_latency_ms(run_dir)
    inc_flags = [not (M._inc_events(i) & M.malicious_events(attacks)) for i in rv.incidents]
    return out, [a for a in attacks if not a.is_decoy], inc_flags, sysm


def main(argv: list[str] | None = None) -> Path:
    ap = argparse.ArgumentParser(prog="forgetrace eval")
    ap.add_argument("--gt", action="append", required=True, help="ground truth file (repeat per seed)")
    ap.add_argument("--run", action="append", required=True, help="run directory (same order as --gt)")
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--experiment", required=True)
    ap.add_argument("--split", default="all", choices=["tuning", "test", "all"])
    ap.add_argument("--seed-label", action="append", help="label per pair (e.g. the generator seed)")
    ap.add_argument("--bench", help="bench/<run>.json with psutil peak RSS and MB/s")
    ap.add_argument("--boot", type=int, default=1000)
    ap.add_argument("--no-latency", action="store_true")
    ap.add_argument("--metrics-dir", default=str(config.ROOT / "metrics"))
    a = ap.parse_args(argv)
    if len(a.gt) != len(a.run):
        ap.error("--gt and --run must be given the same number of times")
    runs, pooled_attacks, pooled_flags, systems = [], [], [], []
    for k, (g, r) in enumerate(zip(a.gt, a.run)):
        m, atk, flags, sysm = score_pair(Path(g), Path(r), a.dataset, latency=not a.no_latency)
        for x in atk:
            x.attack_id = f"{k}:{x.attack_id}"
        pooled_attacks += atk
        pooled_flags += flags
        systems.append(sysm)
        runs.append(RunEntry(run_dir=str(r), ground_truth=str(g),
                             ground_truth_sha256=hashlib.sha256(Path(g).read_bytes()).hexdigest(),
                             seed=(a.seed_label[k] if a.seed_label and k < len(a.seed_label) else k),
                             split=a.split, metrics=m))
    boot = {
        "step_recall": (pooled_attacks, M.recall_stat, "attacks"),
        "label_acc_exact": (pooled_attacks, M.label_exact_stat, "attacks"),
        "label_acc_parent": (pooled_attacks, M.label_parent_stat, "attacks"),
        "ordered_path_rate": (pooled_attacks, M.ordered_stat, "attacks"),
        "false_alert_rate": (pooled_flags, M.false_alert_stat, "incidents"),
    }
    summary = {}
    for name in HEADLINE:
        per = [rr.metrics[name]["value"] for rr in runs]
        vals = [v for v in per if v is not None]
        if name in boot:
            units, fn, unit = boot[name]
            point = fn(units)
            ci = M.bootstrap(units, fn, n=a.boot, seed=0)
            text = (f"{point:.3f} pooled over {len(units)} {unit}, 95% CI [{ci[0]:.3f}, {ci[1]:.3f}]"
                    if point is not None and ci else runs[0].metrics[name]["text"] if len(runs) == 1
                    else "N/A (no units to pool)")
            summary[name] = Summary(value=point, text=text, ci95=list(ci) if ci else None, ci_unit=unit, per_run=per,
                                    mean=statistics.fmean(vals) if vals else None,
                                    sd=statistics.stdev(vals) if len(vals) > 1 else None)
        else:
            only = runs[0].metrics[name]
            text = (only["text"] if only["value"] is None else f"{only['value']:.3f} ({only['text']})") \
                if len(runs) == 1 else (f"{statistics.fmean(vals):.3f} mean over {len(vals)} runs" if vals
                                        else "N/A (not computable in any run)")
            summary[name] = Summary(value=statistics.fmean(vals) if vals else None, text=text,
                                    per_run=per, mean=statistics.fmean(vals) if vals else None,
                                    sd=statistics.stdev(vals) if len(vals) > 1 else None)
    system = {"per_run": systems}
    walls = [s["wall_time_s"] for s in systems if s.get("wall_time_s") is not None]
    rss = [s["peak_rss_mb_ru_maxrss"] for s in systems if s.get("peak_rss_mb_ru_maxrss") is not None]
    lat = [s["p95_path_latency_ms"]["value"] for s in systems
           if isinstance(s.get("p95_path_latency_ms"), dict) and s["p95_path_latency_ms"]["value"] is not None]
    system["wall_time_s"] = max(walls) if walls else None
    system["peak_rss_mb"] = max(rss) if rss else None
    system["peak_rss_source"] = "ru_maxrss of the run process"
    if a.bench:
        b = json.loads(Path(a.bench).read_text())
        system["bench"] = {k: v for k, v in b.items() if k != "rss_samples"}
        system["peak_rss_mb"] = b.get("peak_rss_mb_psutil_1s") or system["peak_rss_mb"]
        system["peak_rss_source"] = "psutil 1 s sampling over the process tree (bench)"
    system["p95_path_latency_ms"] = max(lat) if lat else None
    prd = {}
    for k, t in PRD_TARGETS.items():
        v = summary[k].value if k in summary else system.get(k)
        ok = None if v is None else {"<": v < t["target"], ">": v > t["target"], "==": v == t["target"]}[t["op"]]
        prd[k] = {"value": v, "target": f"{t['op']} {t['target']}", "pass": ok}
    sha, dirty = git_state()
    mf = MetricsFile(
        dataset=a.dataset, experiment=a.experiment, split=a.split,
        created_at=datetime.now().astimezone().isoformat(timespec="seconds"), git_sha=sha, git_dirty=dirty,
        config_hash=config.config_hash(), code_version=config.CODE_VERSION,
        bootstrap={"resamples": a.boot, "seed": 0, "method": "percentile", "level": 0.95}, summary=summary,
        prd=prd, system=system, runs=runs,
        not_computed={
            "next_step_hit_at_3/5": "needs the truncation backtest (WP CO-4)",
            "time_to_first_incident": "batch mode only until SC-4; reported per run as the wall time",
        })
    out = Path(a.metrics_dir) / a.dataset / f"{a.experiment}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(mf.model_dump_json(indent=1))
    _print(mf, out)
    return out


def _print(mf: MetricsFile, out: Path) -> None:
    print(f"ForgeTrace eval — dataset={mf.dataset} experiment={mf.experiment} split={mf.split} "
          f"runs={len(mf.runs)} config={mf.config_hash[:12]} git={mf.git_sha[:10]}{' (dirty)' if mf.git_dirty else ''}")
    for k in HEADLINE:
        s = mf.summary[k]
        print(f"  {k:<30} {s.text}")
    print("  PRD targets:")
    for k, v in mf.prd.items():
        mark = "N/A" if v["pass"] is None else ("PASS" if v["pass"] else "FAIL")
        print(f"    {k:<26} {str(v['value']):<22} target {v['target']:<10} {mark}")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
