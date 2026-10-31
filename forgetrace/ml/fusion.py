"""Combine evidence from different detectors on the same entity and time (PHASE2 FU-2, label-free form).

Why this exists: a weak rule hit, a behaviour anomaly and a new lateral link on the same account within an
hour mean more together than apart. Without labels a learned, calibrated combiner cannot be fitted, so the
combination is the PHASE2 fallback: noisy-OR of detector priors, p = 1 - prod(1 - prior_d) over the distinct
detectors that flagged an entity of the group within `fusion.window_minutes`. The result is stored as the
group's p_malicious with each detector's contribution, used to rank and explained; it never changes what
was detected.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from forgetrace.ml.ueba import ml_config

KEYS = ("user", "target_user", "host", "src_ip", "dst_ip")


def corroborating(con, groups: list[dict]) -> dict[str, dict[str, float]]:
    """Model flags absorbed as duplicates of a rule detection (same events, D-92) still count as agreement for
    the group holding that rule detection: group_id -> {model rule_id: prior}."""
    try:
        rows = con.execute("""SELECT duplicate_of, rule_id, confidence FROM detections
                              WHERE rule_id LIKE 'ML-%' AND duplicate_of IS NOT NULL""").fetchall()
    except Exception:  # noqa: BLE001 - no detections table (unit fixtures)
        return {}
    holder = {d: g["group_id"] for g in groups for d in g.get("detection_ids", [])}
    out: dict[str, dict[str, float]] = defaultdict(dict)
    for dup_of, rid, conf in rows:
        if dup_of in holder:
            out[holder[dup_of]][rid] = max(out[holder[dup_of]].get(rid, 0.0), float(conf))
    return out


def fuse(groups: list[dict], extra: dict[str, dict[str, float]] | None = None) -> None:
    win = timedelta(minutes=int(ml_config()["fusion"]["window_minutes"]))
    index: dict[str, list[int]] = defaultdict(list)
    for i, g in enumerate(groups):
        for k in KEYS:
            for v in g["entities"].get(k, []):
                index[f"{'user' if k == 'target_user' else 'ip' if k.endswith('ip') else k}:{v}"].append(i)
    cap = int(ml_config()["fusion"].get("max_entity_groups", 10))
    index = {k: v for k, v in index.items() if len(v) <= cap}  # a hub entity (shared by many groups) is not agreement
    for i, g in enumerate(groups):
        best: dict[str, float] = {g["rule_id"]: float(g["confidence"]), **(extra or {}).get(g["group_id"], {})}
        lo, hi = g["ts_first"] - win, g["ts_last"] + win
        for k in KEYS:
            for v in g["entities"].get(k, []):
                for j in index.get(f"{'user' if k == 'target_user' else 'ip' if k.endswith('ip') else k}:{v}", []):
                    o = groups[j]
                    if j != i and o["ts_last"] >= lo and o["ts_first"] <= hi:
                        best[o["rule_id"]] = max(best.get(o["rule_id"], 0.0), float(o["confidence"]))
        p = 1.0
        for v in best.values():
            p *= 1 - v
        g["p_malicious"] = round(1 - p, 4)
        g["contributions"] = {k: round(v, 4) for k, v in sorted(best.items())}
