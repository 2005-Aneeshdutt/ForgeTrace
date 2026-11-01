#!/usr/bin/env python3
"""Ablation on FVS validation logs: what each detector layer contributes to the metrics.

Why this exists: the system combines YAML rules, two unsupervised models (behaviour/UEBA and graph link) and
a fusion score. This tool re-analyses the same ingested events with layers switched off and scores every
variant with tools/eval_fvs.py, so each layer's effect is measured on identical input:

  rules        rules only (ML off)
  rules+ueba   rules + behaviour model
  rules+link   rules + graph link model
  full         rules + both models (the shipped configuration)
  ml_only      models only (no rules); by design (D-92) model alerts never form an incident alone, so its
               incident numbers are 0 and its alert-level numbers show what the models find by themselves

Fusion never changes what is detected (D-91), so it is measured as ranking quality on the full variant:
average precision of alert groups ranked by fused p_malicious versus by the detector's own prior, where a
group is positive if it contains a real attack event (decoy and benign groups are negatives).
Like eval_fvs.py, this tool is the only reader of the ground truth; the pipeline sees only the .log files.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

import duckdb

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

VARIANTS = ["rules", "rules+ueba", "rules+link", "full", "ml_only"]


def _set_variant(name: str) -> None:
    """Switch detector layers in-process (no config file is edited)."""
    import forgetrace.pipeline as pl
    from forgetrace.ml.link import link_detections
    from forgetrace.ml.ueba import detections as ueba_detections
    from forgetrace.rules.engine import load_rules

    use_ueba = name in ("rules+ueba", "full", "ml_only")
    use_link = name in ("rules+link", "full", "ml_only")

    def run_ml(con, fill):
        u_rows, _, u_info = ueba_detections(con, "events", fill) if use_ueba else ([], None, "off")
        l_rows, _, l_info = link_detections(con, "events", fill) if use_link else ([], None, "off")
        return u_rows + l_rows, {"m1_ueba": u_info, "m2_link": l_info, "detections": len(u_rows) + len(l_rows)}

    pl.run_ml = run_ml
    pl.load_rules = (lambda: []) if name == "ml_only" else load_rules


def average_precision(scored: list[tuple[float, bool]]) -> float | None:
    """AP of a ranking (ties broken pessimistically: negatives first within equal scores)."""
    pos = sum(y for _, y in scored)
    if not pos:
        return None
    hits, ap = 0, 0.0
    for i, (_, y) in enumerate(sorted(scored, key=lambda t: (-t[0], t[1])), 1):
        if y:
            hits += 1
            ap += hits / i
    return round(ap / pos, 4)


def fusion_ranking(ws: Path, gt: dict) -> dict:
    con = duckdb.connect(str(ws / "forgetrace.duckdb"), read_only=True)
    fid = {Path(f["path"]).name: f["file_id"] for f in json.loads((ws / "files.json").read_text())["files"]}
    attack = {(fid[e["file"]] << 48) | e["byte_offset"] for a in gt["attacks"] if not a["is_decoy"]
              for s in a["steps"] for e in s["events"] if e["file"] in fid}
    rows = con.execute("SELECT member_event_ids, p_malicious, contributions, rule_id FROM alert_groups").fetchall()
    con.close()
    fused, prior = [], []
    for mem, p, contrib, rid in rows:
        mem = json.loads(mem) if isinstance(mem, str) else mem
        c = json.loads(contrib) if isinstance(contrib, str) else (contrib or {})
        y = bool(set(mem) & attack)
        fused.append((float(p or 0), y))
        prior.append((float(c.get(rid, p or 0)), y))
    k = 10
    top = lambda sc: round(sum(y for _, y in sorted(sc, key=lambda t: (-t[0], t[1]))[:k]) / min(k, len(sc)), 3) if sc else None  # noqa: E731
    return {"groups": len(rows), "attack_groups": sum(y for _, y in fused),
            "ap_fused": average_precision(fused), "ap_prior": average_precision(prior),
            "p_at_10_fused": top(fused), "p_at_10_prior": top(prior)}


def main() -> None:
    from eval_fvs import _prf, _ratio, fmt, load_run, score

    from forgetrace.pipeline import reanalyse, run

    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="Validation dataset/scratch_ref")
    ap.add_argument("--out", default="out/fvs_ablation")
    ap.add_argument("--results", default="results")
    ap.add_argument("--only", nargs="*")
    a = ap.parse_args()
    root, out = Path(a.root), Path(a.out)
    res = Path(a.results) / ("ablation-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
    res.mkdir(parents=True, exist_ok=False)
    dirs = sorted(d for d in root.iterdir() if (d / "ground_truth.json").exists() and (not a.only or d.name in a.only))
    table, fusion = [], {}
    for i, d in enumerate(dirs, 1):
        gt = json.loads((d / "ground_truth.json").read_text())
        ws = out / d.name
        for j, v in enumerate(VARIANTS):
            _set_variant(v)
            print(f"[{i}/{len(dirs)}] {d.name} · {v}", flush=True)
            if j == 0:
                run([d / gt["files"][0]["name"]], ws)
            else:
                reanalyse(ws)
            R = load_run(ws)
            for key, excl in (("all_steps", False), ("excl_unverified", True)):
                s = score(gt, R, excl)["summary"]
                table.append({"dataset": d.name, "split": gt.get("split"), "profile": gt.get("profile", "validation"),
                              "variant": v, "steps": key, **{k: s[k] for k in (
                                  "attacks", "attack_detection_rate", "attack_in_incident_rate", "step_recall",
                                  "technique_parent_acc", "decoys", "decoys_flagged_alert", "decoys_in_incident",
                                  "incidents", "false_alarm_incidents")},
                              **{f"alert_{k}": s["line_alert"][k] for k in ("tp", "fp", "fn")},
                              **{f"inc_{k}": s["line_incident"][k] for k in ("tp", "fp", "fn")}})
            if v == "full":
                fusion[d.name] = fusion_ranking(ws, gt)
        _set_variant("full")
    (res / "ablation.json").write_text(json.dumps({"rows": table, "fusion": fusion}, indent=1))

    def pooled(rows):
        att = sum(r["attacks"] for r in rows)
        inc = sum(round((r["attack_in_incident_rate"] or 0) * r["attacks"]) for r in rows)
        det = sum(round((r["attack_detection_rate"] or 0) * r["attacks"]) for r in rows)
        la = _prf(*(sum(r[f"alert_{k}"] for r in rows) for k in ("tp", "fp", "fn")))
        li = _prf(*(sum(r[f"inc_{k}"] for r in rows) for k in ("tp", "fp", "fn")))
        return {"attacks": att, "detected": det, "in_incident": inc,
                "decoys": sum(r["decoys"] for r in rows), "decoys_alert": sum(r["decoys_flagged_alert"] for r in rows),
                "decoys_incident": sum(r["decoys_in_incident"] for r in rows),
                "incidents": sum(r["incidents"] for r in rows), "false_incidents": sum(r["false_alarm_incidents"] for r in rows),
                "alert": la, "incident": li}

    lines = [f"# Detector ablation ({res.name})", "", f"Datasets: {', '.join(d.name for d in dirs)}; same ingested events for "
             "every variant; pipeline sees only the .log files.", ""]
    groups = {"tune": [d.name for d in dirs if d.name in ("t1", "v110_3", "v120_3")],
              "held-out": [d.name for d in dirs if d.name not in ("t1", "v110_3", "v120_3")]}
    groups["all"] = [d.name for d in dirs]
    for gname, names in groups.items():
        if not names:
            continue
        lines += [f"## {gname} ({', '.join(names)}) — all steps", "",
                  "| variant | attacks in incident | attacks touched | steps found | technique (parent) | alert-line P / R | "
                  "incident-line P / R / F1 | decoys alerted | decoys in incident | incidents (false) |",
                  "|---|---|---|---|---|---|---|---|---|---|"]
        for v in VARIANTS:
            rows = [r for r in table if r["variant"] == v and r["steps"] == "all_steps" and r["dataset"] in names]
            p = pooled(rows)
            found = steps = 0
            par_num = 0.0
            for r in rows:
                gtn = json.loads((root / r["dataset"] / "ground_truth.json").read_text())
                n = sum(len(s["steps"]) for s in gtn["attacks"] if not s["is_decoy"])
                f = round((r["step_recall"] or 0) * n)
                found, steps = found + f, steps + n
                par_num += (r["technique_parent_acc"] or 0) * f
            lines.append(f"| {v} | {p['in_incident']}/{p['attacks']} | {p['detected']}/{p['attacks']} | {found}/{steps} "
                         f"({_ratio(found, steps):.2f}) | {fmt(_ratio(par_num, found))} | {fmt(p['alert']['precision'])} / "
                         f"{fmt(p['alert']['recall'])} | {fmt(p['incident']['precision'])} / {fmt(p['incident']['recall'])} / "
                         f"{fmt(p['incident']['f1'])} | {p['decoys_alert']}/{p['decoys']} | {p['decoys_incident']}/{p['decoys']} | "
                         f"{p['incidents']} ({p['false_incidents']}) |")
        lines.append("")
    lines += ["## Fusion: ranking alert groups (full variant)", "",
              "| dataset | groups | attack groups | AP fused p | AP detector prior | P@10 fused | P@10 prior |",
              "|---|---|---|---|---|---|---|"]
    lines += [f"| {k} | {v['groups']} | {v['attack_groups']} | {fmt(v['ap_fused'])} | {fmt(v['ap_prior'])} | "
              f"{fmt(v['p_at_10_fused'])} | {fmt(v['p_at_10_prior'])} |" for k, v in fusion.items()]
    lines += ["", "ml_only: model alerts cannot form an incident alone (D-92), so its incident columns are 0 by design.",
              "Neo4j and the LLM narrative do not change detection, so they have no row."]
    (res / "ABLATION.md").write_text("\n".join(lines) + "\n")
    print(f"\nresults: {res}", flush=True)


if __name__ == "__main__":
    main()
