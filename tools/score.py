#!/usr/bin/env python3
"""Ground-truth scoring (dossier §2 metrics). The ONLY component that reads ground truth.

Step found: >= 1 detection's member raw events intersect the step's ground-truth lines.
Label accuracy: the step events' primary technique (label priority) vs ground truth, at parent
(T1110) and exact sub-technique (T1110.001) level, over found steps.
Path order: found steps all sit in one incident's primary path, in ground-truth order
(Kendall tau = 1 on found steps; ties when two steps share one alert group are reported).
False-alarm share: incidents with zero overlap with any non-decoy attack / incidents emitted.
Runtime and peak RSS come from out/run_stats.json (measured by `forgetrace run`).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

import duckdb


def load(out: Path):
    con = duckdb.connect(str(out / "forgetrace.duckdb"), read_only=True)
    line_to_eid = {}
    for f in json.loads((out / "files.json").read_text())["files"]:
        for ln, eid in con.execute("SELECT line_no, event_id FROM events WHERE file_id = ?", [f["file_id"]]).fetchall():
            line_to_eid[(Path(f["path"]).name, ln)] = eid
    dets = con.execute("SELECT detection_id, rule_id, technique_id, member_event_ids FROM detections").fetchall()
    labels = dict(con.execute("SELECT event_id, primary_technique FROM event_labels").fetchall())
    incidents = [json.loads(j) for (j,) in con.execute("SELECT json FROM incident_cache ORDER BY incident_id").fetchall()]
    con.close()
    return line_to_eid, dets, labels, incidents


def step_events(step: dict, gt_file: str, line_to_eid: dict) -> set[int]:
    return {line_to_eid[(gt_file, ln)] for ln in step["line_nos"] if (gt_file, ln) in line_to_eid}


def score(gt: dict, out: Path) -> dict:
    line_to_eid, dets, labels, incidents = load(out)
    gt_file = gt["dataset"]["file"]
    det_events: dict[int, list[str]] = {}
    for did, rid, tech, mem in dets:
        for m in mem:
            det_events.setdefault(m, []).append(rid)
    res = {"attacks": [], "eventid_mismatches": 0}
    all_attack_events: set[int] = set()
    steps_total = steps_found = parent_ok = sub_ok = 0
    for atk in gt["attacks"]:
        evs_by_step = []
        for st in atk["steps"]:
            ev = step_events(st, gt_file, line_to_eid)
            res["eventid_mismatches"] += len(set(st["event_ids"]) ^ ev)
            evs_by_step.append(ev)
        if atk.get("decoy"):
            in_inc = [i["incident_id"] for i in incidents
                      if set().union(*evs_by_step) & {x for n in i["observed"]["nodes"] for x in n["member_event_ids"]}]
            det_steps = [st["order"] for st, ev in zip(atk["steps"], evs_by_step) if ev & det_events.keys()]
            res["attacks"].append({"attack_id": atk["attack_id"], "decoy": True, "in_incidents": in_inc,
                                   "steps_with_detections": det_steps, "rejected": not in_inc})
            continue
        for ev in evs_by_step:
            all_attack_events |= ev
        rows = []
        for st, ev in zip(atk["steps"], evs_by_step):
            found = bool(ev & det_events.keys())
            techs = sorted({labels[e] for e in ev if e in labels})
            pred = techs[0] if len(techs) == 1 else (max(techs, key=lambda t: sum(labels.get(e) == t for e in ev)) if techs else None)
            rows.append({"order": st["order"], "gt_technique": st["technique"], "found": found, "predicted": pred,
                         "parent_ok": found and pred is not None and pred.split(".")[0] == st["technique"].split(".")[0],
                         "sub_ok": found and pred == st["technique"],
                         "rules": sorted({r for e in ev for r in det_events.get(e, [])})})
        steps_total += len(rows)
        steps_found += sum(r["found"] for r in rows)
        parent_ok += sum(r["parent_ok"] for r in rows)
        sub_ok += sum(r["sub_ok"] for r in rows)
        order = path_order(rows, evs_by_step, incidents, labels, "primary_path")
        chain = path_order(rows, evs_by_step, incidents, labels, "strongest_chain")
        res["attacks"].append({"attack_id": atk["attack_id"], "steps": rows, "path": order, "strongest_chain": chain})
    false_alarms = [i["incident_id"] for i in incidents
                    if not ({x for n in i["observed"]["nodes"] for x in n["member_event_ids"]} & all_attack_events)]
    found_total = steps_found
    res["metrics"] = {
        "step_recall": _ratio(steps_found, steps_total),
        "label_accuracy_parent": _ratio(parent_ok, found_total),
        "label_accuracy_subtechnique": _ratio(sub_ok, found_total),
        "attacks_in_correct_order": _ratio(sum(a["path"]["in_order"] for a in res["attacks"] if not a.get("decoy")),
                                           sum(1 for a in res["attacks"] if not a.get("decoy"))),
        "false_alarm_share": _ratio(len(false_alarms), len(incidents)) if incidents else
        {"value": None, "text": "N/A (no incidents emitted)"},
        "false_alarm_incidents": false_alarms,
        "incidents_emitted": len(incidents),
    }
    return res


def path_order(rows, evs_by_step, incidents, labels, key) -> dict:
    found = [(r["order"], ev) for r, ev in zip(rows, evs_by_step) if r["found"]]
    if not found:
        return {"in_order": False, "reason": "no steps found"}
    best = None
    for inc in incidents:
        nodes = {n["group_id"]: n for n in inc["observed"]["nodes"]}
        path = inc["inferred"][key]["group_ids"]
        pos = {}
        for order, ev in found:
            cands = [i for i, g in enumerate(path) if set(nodes[g]["member_event_ids"]) & ev]
            prim = [i for i in cands if any(labels.get(e) == nodes[path[i]]["technique_id"] for e in ev)]
            if prim or cands:
                pos[order] = (prim or cands)[0]
        if best is None or len(pos) > len(best[1]):
            best = (inc["incident_id"], pos)
    inc_id, pos = best
    missing = [o for o, _ in found if o not in pos]
    seq = [pos[o] for o, _ in found if o in pos]
    discordant = sum(1 for i in range(len(seq)) for j in range(i + 1, len(seq)) if seq[i] > seq[j])
    ties = sum(1 for i in range(len(seq)) for j in range(i + 1, len(seq)) if seq[i] == seq[j])
    return {"incident_id": inc_id, "positions": {str(k): v for k, v in pos.items()}, "missing_found_steps": missing,
            "discordant_pairs": discordant, "tied_pairs": ties, "in_order": not missing and discordant == 0}


def _ratio(n, d) -> dict:
    if not d:
        return {"value": None, "text": "N/A (denominator is zero)"}
    return {"value": n / d, "text": f"{n}/{d} = {100 * n / d:.1f}%"}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--gt", default="data/sample/ground_truth.json")
    ap.add_argument("--out", default="out")
    a = ap.parse_args()
    t0 = time.perf_counter()
    out = Path(a.out)
    gt = json.loads(Path(a.gt).read_text())
    stats = json.loads((out / "run_stats.json").read_text())
    res = score(gt, out)
    src = Path(a.gt).parent / gt["dataset"]["file"]
    fp = hashlib.sha256(src.read_bytes()).hexdigest() if src.exists() else None
    m = res["metrics"]
    print("ForgeTrace Phase 1 — evaluation against ground truth")
    print(f"dataset   : {src}  sha256={fp}  (ground truth sha256={gt['dataset']['sha256']}, "
          f"{'MATCH' if fp == gt['dataset']['sha256'] else 'MISMATCH'})")
    print(f"generator : seed={gt['dataset']['seed']} start={gt['dataset']['start']} days={gt['dataset']['days']} "
          f"events={gt['dataset']['events']} cef_ratio={gt['dataset']['cef_ratio']} with_tags={gt['dataset']['with_tags']}")
    print(f"config    : {stats['config_hash']}  code={stats['code_version']}")
    print(f"gt event_id/line consistency: {res['eventid_mismatches']} mismatching event ids")
    print()
    for atk in res["attacks"]:
        if atk.get("decoy"):
            print(f"{atk['attack_id']} (decoy): steps with detections={atk['steps_with_detections']} "
                  f"in incidents={atk['in_incidents']} -> {'REJECTED (correct)' if atk['rejected'] else 'PROMOTED (false alarm)'}")
            continue
        print(f"{atk['attack_id']}:")
        for r in atk["steps"]:
            print(f"  step {r['order']}: gt={r['gt_technique']:<10} found={'Y' if r['found'] else 'N'} "
                  f"pred={str(r['predicted']):<10} parent={'Y' if r['parent_ok'] else 'N'} sub={'Y' if r['sub_ok'] else 'N'} "
                  f"rules={','.join(r['rules'])}")
        p, c = atk["path"], atk["strongest_chain"]
        print(f"  primary path : incident {p.get('incident_id')} positions={p.get('positions')} "
              f"missing={p.get('missing_found_steps')} discordant={p.get('discordant_pairs')} ties={p.get('tied_pairs')} "
              f"-> {'IN ORDER' if p['in_order'] else 'NOT IN ORDER'}")
        print(f"  dossier DP chain (secondary): missing={c.get('missing_found_steps')} -> "
              f"{'IN ORDER' if c['in_order'] else 'NOT COMPLETE/ORDERED'}")
    print()
    print(f"1. Step recall                    : {m['step_recall']['text']}")
    print(f"2. Label accuracy (parent)        : {m['label_accuracy_parent']['text']}")
    print(f"3. Label accuracy (sub-technique) : {m['label_accuracy_subtechnique']['text']}")
    print(f"4. Attacks reconstructed in order : {m['attacks_in_correct_order']['text']}")
    print(f"5. False-alarm share              : {m['false_alarm_share']['text']} (false-alarm incidents: {m['false_alarm_incidents']})")
    print(f"6. Runtime (forgetrace run)       : {stats['wall_time_s']} s wall  stages={stats['stages']}")
    print(f"7. Peak RSS (forgetrace run)      : {stats['peak_rss_bytes'] / 2**20:.1f} MiB ({stats['peak_rss_note']})")
    print(f"   scoring runtime                : {time.perf_counter() - t0:.3f} s")
    res["run_stats"] = {k: stats[k] for k in ("wall_time_s", "peak_rss_bytes", "stages", "config_hash")}
    res["dataset_sha256"] = fp
    (out / "metrics.json").write_text(json.dumps(res, indent=1, default=str))
    sys.exit(0)


if __name__ == "__main__":
    main()
