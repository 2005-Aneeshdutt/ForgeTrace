#!/usr/bin/env python3
"""Evaluate ForgeTrace on FVS validation logs (FortiGate key=value + ground_truth.json per directory).

Why this exists: the FVS suite ships an answer key per log. This tool runs the unchanged pipeline on the
.log files only (the pipeline never sees ground_truth.json, summary.json or AUDIT files), then scores the
stored results against the key. Like tools/score.py, it is the only component that reads that ground truth.

Matching is exact: a ground-truth event (file, byte_offset) is ForgeTrace event_id (file_id << 48) | offset,
so frozen or duplicated timestamps cannot cause mismatches. Decoys (is_decoy) are benign look-alikes:
flagging them is a false positive. Every metric is computed twice: on all steps, and excluding steps with
uses_unverified_logid (event types not present in the real samples).

Definitions
- alert-flagged event: member of any detection. incident-flagged event: member of an alert group that is
  part of an emitted incident (what an analyst is shown as an attack).
- line metrics: positives = attack-step events; precision/recall/F1 over events, at both levels; decoy
  events flagged are reported separately.
- step found: >= 1 of its events is alert-flagged. technique exact / parent: the majority primary label
  (label priority) of the step's flagged events equals the ground-truth technique / its parent.
- attack detected: >= 1 step found. attack in incident: >= 1 step event incident-flagged.
  step coverage: found steps / steps.
- decoy false positive: a decoy with >= 1 event alert-flagged (alert FP) or incident-flagged (incident FP).
  false-alarm incident: an incident sharing no event with any real attack.
- latency (event time): first flagged attack event minus the attack's first event, in minutes.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

import duckdb

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _ratio(n: float, d: float) -> float | None:
    return round(n / d, 4) if d else None


def _prf(tp: int, fp: int, fn: int) -> dict:
    p, r = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
    f1 = round(2 * p * r / (p + r), 4) if p and r else (0.0 if p is not None and r is not None else None)
    return {"tp": tp, "fp": fp, "fn": fn, "precision": p, "recall": r, "f1": f1}


def run_pipeline(log: Path, out: Path) -> dict:
    from forgetrace.pipeline import run

    t = time.perf_counter()
    stats = run([log], out)
    return {"wall_s": round(time.perf_counter() - t, 2), "stats": stats}


def load_run(out: Path) -> dict:
    con = duckdb.connect(str(out / "forgetrace.duckdb"), read_only=True)
    files = {Path(f["path"]).name: f["file_id"] for f in json.loads((out / "files.json").read_text())["files"]}
    alert_ev: set[int] = set()
    det_rules: dict[int, set[str]] = defaultdict(set)
    for rid, mem in con.execute("SELECT rule_id, member_event_ids FROM detections").fetchall():
        for m in mem:
            alert_ev.add(m)
            det_rules[m].add(rid)
    labels = dict(con.execute("SELECT event_id, primary_technique FROM event_labels").fetchall())
    groups = {g: json.loads(m) if isinstance(m, str) else m
              for g, m in con.execute("SELECT group_id, member_event_ids FROM alert_groups").fetchall()}
    incidents = []
    for (js,) in con.execute("SELECT json FROM incident_cache ORDER BY incident_id").fetchall():
        inc = json.loads(js)
        incidents.append({"id": inc["incident_id"], "tactics": inc["tactics"],
                          "events": {e for g in inc["group_ids"] for e in groups.get(g, [])}})
    inc_ev = set().union(*(i["events"] for i in incidents)) if incidents else set()
    ts = {}
    n_events = con.execute("SELECT count(*) FROM events").fetchone()[0]
    n_errors = con.execute("SELECT count(*) FROM parse_errors").fetchone()[0] if _has(con, "parse_errors") else 0
    con.close()
    return {"con_path": out / "forgetrace.duckdb", "files": files, "alert_ev": alert_ev, "det_rules": det_rules,
            "labels": labels, "incidents": incidents, "inc_ev": inc_ev, "ts": ts, "n_events": n_events,
            "n_errors": n_errors}


def _has(con, t: str) -> bool:
    try:
        con.execute(f"SELECT 1 FROM {t} LIMIT 0")
        return True
    except duckdb.Error:
        return False


def event_times(db: Path, ids: set[int]) -> dict[int, datetime]:
    if not ids:
        return {}
    con = duckdb.connect(str(db), read_only=True)
    rows = con.execute("SELECT event_id, ts FROM events WHERE event_id IN (SELECT unnest(?))", [sorted(ids)]).fetchall()
    con.close()
    return dict(rows)


def score(gt: dict, R: dict, exclude_unverified: bool) -> dict:
    fid = R["files"]

    def eids(step) -> set[int]:
        return {(fid[e["file"]] << 48) | e["byte_offset"] for e in step["events"] if e["file"] in fid}

    attacks = [a for a in gt["attacks"] if not a["is_decoy"]]
    decoys = [a for a in gt["attacks"] if a["is_decoy"]]
    attack_ev: set[int] = set()
    att_rows, step_rows = [], []
    per_tech: dict[str, Counter] = defaultdict(Counter)
    for a in attacks:
        steps = [s for s in a["steps"] if not (exclude_unverified and s.get("uses_unverified_logid"))]
        if not steps:
            continue
        found_steps, inc_hit = 0, False
        a_ev = set()
        for s in steps:
            ev = eids(s)
            a_ev |= ev
            hit = ev & R["alert_ev"]
            labs = Counter(R["labels"][e] for e in hit if R["labels"].get(e))
            pred = labs.most_common(1)[0][0] if labs else None
            gtt = s["technique_id"]
            found = bool(hit)
            row = {"attack_id": a["attack_id"], "tier": a["tier"], "chain": a["chain"], "order": s["order"], "step": s["step"],
                   "variant": s["variant"], "technique": gtt, "tactic": s["tactic"], "events": len(ev),
                   "events_flagged": len(hit), "found": found, "in_incident": bool(ev & R["inc_ev"]),
                   "predicted": pred, "technique_exact": found and pred == gtt,
                   "technique_parent": found and pred is not None and pred.split(".")[0] == gtt.split(".")[0],
                   "rules": ",".join(sorted({r for e in hit for r in R["det_rules"][e]})),
                   "unverified_logid": bool(s.get("uses_unverified_logid")), "evasion": bool(s.get("evasion"))}
            step_rows.append(row)
            found_steps += found
            inc_hit |= row["in_incident"]
            t = per_tech[gtt]
            t["steps"] += 1
            t["found"] += found
            t["exact"] += row["technique_exact"]
            t["parent"] += row["technique_parent"]
        attack_ev |= a_ev
        att_rows.append({"attack_id": a["attack_id"], "tier": a["tier"], "chain": a["chain"], "steps": len(steps),
                         "steps_found": found_steps, "step_coverage": _ratio(found_steps, len(steps)),
                         "detected": found_steps > 0, "in_incident": inc_hit, "_events": a_ev})
    # latency (event time) for detected attacks
    need = set().union(*(r["_events"] for r in att_rows)) if att_rows else set()
    tmap = event_times(R["con_path"], need)
    for r in att_rows:
        evs = [tmap[e] for e in r["_events"] if e in tmap]
        hits = [tmap[e] for e in r["_events"] & R["alert_ev"] if e in tmap]
        r["latency_min"] = round((min(hits) - min(evs)).total_seconds() / 60, 1) if hits and evs else None
        del r["_events"]
    decoy_ev = set()
    dec_alert = dec_inc = 0
    for d in decoys:
        ev = set().union(*(eids(s) for s in d["steps"])) - attack_ev
        decoy_ev |= ev
        dec_alert += bool(ev & R["alert_ev"])
        dec_inc += bool(ev & R["inc_ev"])
    false_inc = [i["id"] for i in R["incidents"] if not (i["events"] & attack_ev)]

    def line_level(flagged: set[int]) -> dict:
        tp = len(flagged & attack_ev)
        m = _prf(tp, len(flagged - attack_ev), len(attack_ev - flagged))
        m["decoy_events_flagged"] = len(flagged & decoy_ev)
        m["decoy_event_rate"] = _ratio(len(flagged & decoy_ev), len(decoy_ev))
        m["flagged_events"] = len(flagged)
        return m

    found = [s for s in step_rows if s["found"]]
    by_tier = {}
    for tier in sorted({r["tier"] for r in att_rows}):
        rs = [r for r in att_rows if r["tier"] == tier]
        by_tier[tier] = {"attacks": len(rs), "detected": sum(r["detected"] for r in rs),
                         "in_incident": sum(r["in_incident"] for r in rs),
                         "detection_rate": _ratio(sum(r["detected"] for r in rs), len(rs)),
                         "step_coverage": _ratio(sum(r["steps_found"] for r in rs), sum(r["steps"] for r in rs))}
    lat = sorted(r["latency_min"] for r in att_rows if r["latency_min"] is not None)
    summary = {
        "attacks": len(att_rows), "steps": len(step_rows), "attack_events": len(attack_ev),
        "decoys": len(decoys), "decoy_events": len(decoy_ev),
        "line_alert": line_level(R["alert_ev"]), "line_incident": line_level(R["inc_ev"]),
        "attack_detection_rate": _ratio(sum(r["detected"] for r in att_rows), len(att_rows)),
        "attack_in_incident_rate": _ratio(sum(r["in_incident"] for r in att_rows), len(att_rows)),
        "step_recall": _ratio(len(found), len(step_rows)),
        "technique_exact_acc": _ratio(sum(s["technique_exact"] for s in found), len(found)),
        "technique_parent_acc": _ratio(sum(s["technique_parent"] for s in found), len(found)),
        "by_tier": by_tier,
        "decoy_fp_alert_rate": _ratio(dec_alert, len(decoys)), "decoy_fp_incident_rate": _ratio(dec_inc, len(decoys)),
        "decoys_flagged_alert": dec_alert, "decoys_in_incident": dec_inc,
        "incidents": len(R["incidents"]), "false_alarm_incidents": len(false_inc),
        "false_alarm_incident_share": _ratio(len(false_inc), len(R["incidents"])),
        "latency_min_median": lat[len(lat) // 2] if lat else None, "latency_min_max": lat[-1] if lat else None,
        "techniques": {k: {**v, "recall": _ratio(v["found"], v["steps"])} for k, v in sorted(per_tech.items())},
    }
    return {"summary": summary, "attacks": att_rows, "steps": step_rows}


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        path.write_text("")
        return
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def fmt(v) -> str:
    return "N/A" if v is None else (f"{v:.3f}" if isinstance(v, float) else str(v))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="Validation dataset/scratch_ref", help="folder with one sub-folder per log")
    ap.add_argument("--out", default="out/fvs", help="ForgeTrace workspaces")
    ap.add_argument("--results", default="results")
    ap.add_argument("--reuse", action="store_true", help="score existing workspaces instead of re-running")
    ap.add_argument("--only", nargs="*", help="sub-folder names to evaluate")
    a = ap.parse_args()
    root, out = Path(a.root), Path(a.out)
    run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    res = Path(a.results) / run_id
    res.mkdir(parents=True, exist_ok=False)  # earlier runs are never overwritten
    dirs = sorted(d for d in root.iterdir() if (d / "ground_truth.json").exists() and (not a.only or d.name in a.only))
    table = []
    all_att = {False: [], True: []}
    for i, d in enumerate(dirs, 1):
        gt = json.loads((d / "ground_truth.json").read_text())
        logs = [d / f["name"] for f in gt["files"]]
        ws = out / d.name
        meta = {"dataset": d.name, "split": gt.get("split"), "profile": gt.get("profile", "validation"),
                "fvs_version": gt.get("fvs_version"), "seed": gt.get("seed"),
                "bytes": sum(p.stat().st_size for p in logs)}
        print(f"[{i}/{len(dirs)}] {d.name}: {meta['bytes'] / 1e6:.0f} MB {'(reuse)' if a.reuse else 'running pipeline'}", flush=True)
        if not a.reuse or not (ws / "forgetrace.duckdb").exists():
            meta["run"] = run_pipeline(logs[0] if len(logs) == 1 else logs[0].parent, ws)
            print(f"    pipeline {meta['run']['wall_s']} s", flush=True)
        rs = json.loads((ws / "run_stats.json").read_text()) if (ws / "run_stats.json").exists() else {}
        meta["runtime_s"] = rs.get("wall_time_s") or (meta.get("run") or {}).get("wall_s")
        meta["peak_rss_mb"] = round(rs["peak_rss_bytes"] / 2**20, 1) if rs.get("peak_rss_bytes") else None
        meta["mb_per_s"] = _ratio(meta["bytes"] / 1e6, meta["runtime_s"] or 0)
        R = load_run(ws)
        meta.update(events_parsed=R["n_events"], parse_errors=R["n_errors"])
        out_m = {"meta": meta}
        for excl in (False, True):
            s = score(gt, R, excl)
            key = "excl_unverified" if excl else "all_steps"
            out_m[key] = s["summary"]
            all_att[excl] += [{**r, "dataset": d.name} for r in s["attacks"]]
            if not excl:
                write_csv(res / f"{d.name}.attacks.csv", s["attacks"])
                write_csv(res / f"{d.name}.steps.csv", s["steps"])
            table.append({"dataset": d.name, "split": meta["split"], "profile": meta["profile"], "steps": key, **{
                k: s["summary"][k] for k in ("attacks", "attack_detection_rate", "attack_in_incident_rate", "step_recall",
                                             "technique_exact_acc", "technique_parent_acc", "decoys",
                                             "decoy_fp_alert_rate", "decoy_fp_incident_rate", "incidents",
                                             "false_alarm_incidents", "latency_min_median")},
                "line_alert_p": s["summary"]["line_alert"]["precision"], "line_alert_r": s["summary"]["line_alert"]["recall"],
                "line_alert_f1": s["summary"]["line_alert"]["f1"], "line_inc_p": s["summary"]["line_incident"]["precision"],
                "line_inc_r": s["summary"]["line_incident"]["recall"], "line_inc_f1": s["summary"]["line_incident"]["f1"],
                "runtime_s": meta["runtime_s"], "mb_per_s": meta["mb_per_s"]})
        (res / f"{d.name}.metrics.json").write_text(json.dumps(out_m, indent=1, default=str))
        sm = out_m["all_steps"]
        print(f"    attacks detected {fmt(sm['attack_detection_rate'])} · in incident {fmt(sm['attack_in_incident_rate'])} · "
              f"step recall {fmt(sm['step_recall'])} · decoy FP (incident) {fmt(sm['decoy_fp_incident_rate'])}", flush=True)
    write_csv(res / "summary.csv", table)
    # pooled over all datasets (micro averages over attacks / steps / decoys)
    pooled = {}
    for excl in (False, True):
        rows = [t for t in table if t["steps"] == ("excl_unverified" if excl else "all_steps")]
        ms = [json.loads((res / f"{r['dataset']}.metrics.json").read_text())["excl_unverified" if excl else "all_steps"] for r in rows]
        att = all_att[excl]
        tiers = {}
        for t in sorted({r["tier"] for r in att}):
            rr = [r for r in att if r["tier"] == t]
            tiers[t] = f"{sum(r['detected'] for r in rr)}/{len(rr)} detected, {sum(r['in_incident'] for r in rr)}/{len(rr)} in incident"
        n_steps = sum(m["steps"] for m in ms)
        found = sum(round((m["step_recall"] or 0) * m["steps"]) for m in ms)
        la = {k: sum(m["line_alert"][k] for m in ms) for k in ("tp", "fp", "fn")}
        li = {k: sum(m["line_incident"][k] for m in ms) for k in ("tp", "fp", "fn")}
        pooled["excl_unverified" if excl else "all_steps"] = {
            "attacks": len(att), "detected": sum(r["detected"] for r in att), "in_incident": sum(r["in_incident"] for r in att),
            "attack_detection_rate": _ratio(sum(r["detected"] for r in att), len(att)),
            "attack_in_incident_rate": _ratio(sum(r["in_incident"] for r in att), len(att)),
            "step_recall": _ratio(found, n_steps), "steps": n_steps, "by_tier": tiers,
            "decoys": sum(m["decoys"] for m in ms), "decoys_flagged_alert": sum(m["decoys_flagged_alert"] for m in ms),
            "decoys_in_incident": sum(m["decoys_in_incident"] for m in ms),
            "incidents": sum(m["incidents"] for m in ms), "false_alarm_incidents": sum(m["false_alarm_incidents"] for m in ms),
            "line_alert": _prf(**la), "line_incident": _prf(**li)}
    (res / "pooled.json").write_text(json.dumps(pooled, indent=1))
    lines = [f"# FVS evaluation {run_id}", "", f"Datasets: {', '.join(d.name for d in dirs)} (from `{root}`).",
             "Pipeline unchanged and untuned; it read only the .log files.", ""]
    for key, title in (("all_steps", "All steps"), ("excl_unverified", "Excluding steps with unverified logids")):
        p = pooled[key]
        lines += [f"## Pooled — {title}", "",
                  f"- Attacks detected: {p['detected']}/{p['attacks']} ({fmt(p['attack_detection_rate'])}); in an incident: "
                  f"{p['in_incident']}/{p['attacks']} ({fmt(p['attack_in_incident_rate'])})",
                  "- By tier: " + "; ".join(f"{k}: {v}" for k, v in p["by_tier"].items()),
                  f"- Step recall: {fmt(p['step_recall'])} of {p['steps']} steps",
                  f"- Line level (alerts): P {fmt(p['line_alert']['precision'])} R {fmt(p['line_alert']['recall'])} "
                  f"F1 {fmt(p['line_alert']['f1'])}; (incidents): P {fmt(p['line_incident']['precision'])} "
                  f"R {fmt(p['line_incident']['recall'])} F1 {fmt(p['line_incident']['f1'])}",
                  f"- Decoys flagged by an alert: {p['decoys_flagged_alert']}/{p['decoys']}; inside an incident: "
                  f"{p['decoys_in_incident']}/{p['decoys']}",
                  f"- Incidents: {p['incidents']}, false-alarm incidents: {p['false_alarm_incidents']}", ""]
    cols = ["dataset", "split", "profile", "attack_detection_rate", "attack_in_incident_rate", "step_recall", "technique_parent_acc",
            "technique_exact_acc", "line_alert_p", "line_alert_r", "line_inc_p", "line_inc_r", "decoy_fp_alert_rate",
            "decoy_fp_incident_rate", "incidents", "false_alarm_incidents", "latency_min_median", "runtime_s"]
    for key in ("all_steps", "excl_unverified"):
        lines += [f"## Per dataset — {key}", "", "| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
        lines += ["| " + " | ".join(fmt(t[c]) for c in cols) + " |" for t in table if t["steps"] == key]
        lines.append("")
    lines += ["Definitions: see the docstring of `tools/eval_fvs.py`. Per-attack and per-step rows: `<dataset>.attacks.csv`, "
              "`<dataset>.steps.csv`; full metrics incl. per-technique recall: `<dataset>.metrics.json`."]
    (res / "REPORT.md").write_text("\n".join(lines) + "\n")
    print(f"\nresults: {res}", flush=True)


if __name__ == "__main__":
    main()
