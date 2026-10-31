"""Evaluation metrics v2 (docs/PHASE2.md METRICS; plan §2 "Evaluation metrics framework").

Why this exists: a change can help one level and hurt another, so ForgeTrace is scored at five
levels - step, attack, incident, event and system - plus ML-score and ranking metrics. Every
function here is pure (RunView + resolved ground-truth events in, numbers out) so each one is
unit-tested on a toy with a hand-computed answer (tests/test_eval_metrics.py).

Sources: step/label/order/false-alarm definitions follow the PRD as restated in PHASE2; AUC-PR
and Recall@B rather than ROC-AUC because attack events are rare (Arp et al., USENIX Security
2022; reporting style of Euler, NDSS, and UltraLMD++); ARI is Hubert & Arabie (1985); NDCG is
Jarvelin & Kekalainen (2002); percentile bootstrap over attacks/incidents (Efron & Tibshirani).
Metrics that cannot be computed return None with a reason - never 0 or 100.
"""
from __future__ import annotations

import math
import random
from collections import Counter
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Callable, Sequence

from forgetrace.eval.groundtruth import GroundTruth
from forgetrace.eval.runview import RunView

FALLBACK_S = 60


def parent(t: str | None) -> str | None:
    return t.split(".")[0] if t else None


# ============================================================================ step + attack level
@dataclass
class StepResult:
    attack_id: str
    order: int
    technique: str
    events: set[int]
    found: bool = False
    found_by: str | None = None          # "event" | "same_host_60s"
    predicted: str | None = None
    label_exact: bool = False
    label_parent: bool = False
    detectors: list[str] = field(default_factory=list)


@dataclass
class AttackResult:
    attack_id: str
    is_decoy: bool
    steps: list[StepResult]
    incident_id: int | None = None
    positions: dict[int, int] = field(default_factory=dict)
    missing_found: list[int] = field(default_factory=list)
    discordant: int = 0
    tied: int = 0
    tau: float | None = None
    ordered: bool = False
    coverage_one_incident: float = 0.0
    decoy_in_incidents: list[int] = field(default_factory=list)


def score_steps(gt: GroundTruth, step_events: dict[tuple[str, int], set[int]], rv: RunView) -> list[AttackResult]:
    det_of_event: dict[int, list] = {}
    for d in rv.detections:
        for m in d.members:
            det_of_event.setdefault(m, []).append(d)
    results = []
    for a in gt.attacks:
        steps = []
        for s in a.steps:
            ev = step_events.get((a.attack_id, s.order), set())
            r = StepResult(a.attack_id, s.order, s.technique, ev)
            hit = [d for e in ev for d in det_of_event.get(e, [])]
            if hit:
                r.found, r.found_by = True, "event"
                techs = Counter(rv.labels[e] for e in ev if e in rv.labels)
                r.predicted = _majority(techs) if techs else _majority(Counter(d.technique_id for d in hit))
            else:
                fb = _fallback(s, ev, rv)
                if fb:
                    r.found, r.found_by, hit = True, "same_host_60s", fb
                    r.predicted = _majority(Counter(d.technique_id for d in fb))
            r.detectors = sorted({d.detector for d in hit})
            r.label_exact = r.found and r.predicted == s.technique
            r.label_parent = r.found and parent(r.predicted) == parent(s.technique)
            steps.append(r)
        ar = AttackResult(a.attack_id, a.is_decoy, steps)
        all_ev = set().union(*(r.events for r in steps)) if steps else set()
        if a.is_decoy:
            ar.decoy_in_incidents = [i.incident_id for i in rv.incidents if all_ev & _inc_events(i)]
        else:
            _order(ar, rv)
            ar.coverage_one_incident = max(
                (sum(1 for r in steps if r.events & _inc_events(i)) / len(steps) for i in rv.incidents), default=0.0)
        results.append(ar)
    return results


def _majority(c: Counter) -> str:
    return sorted(c.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]


def _fallback(step, ev: set[int], rv: RunView) -> list:
    """Plan §2: time-window fallback ±60 s on the same host, when no member intersects."""
    metas = [rv.ev_meta[e] for e in ev if e in rv.ev_meta]
    hosts = {h.upper() for _, h in metas if h} | {h.upper() for h in step.hosts}
    times = [t for t, _ in metas] + [t for t in (step.t_start, step.t_end) if t]
    if not hosts or not times:
        return []
    lo, hi = min(times) - timedelta(seconds=FALLBACK_S), max(times) + timedelta(seconds=FALLBACK_S)
    out = []
    for d in rv.detections:
        for m in d.members:
            meta = rv.ev_meta.get(m)
            if meta and meta[1] and meta[1].upper() in hosts and lo <= meta[0] <= hi:
                out.append(d)
                break
    return out


def _inc_events(i) -> set[int]:
    return {e for mem in i.nodes.values() for e in mem}


def _order(ar: AttackResult, rv: RunView) -> None:
    found = [r for r in ar.steps if r.found and r.events]
    if not found:
        return
    best = None
    for inc in rv.incidents:
        pos = {}
        for r in found:
            cands = [k for k, g in enumerate(inc.path) if set(inc.nodes.get(g, [])) & r.events]
            prim = [k for k in cands if any(rv.labels.get(e) == inc.node_technique.get(inc.path[k]) for e in r.events)]
            if prim or cands:
                pos[r.order] = (prim or cands)[0]
        if pos and (best is None or len(pos) > len(best[1])):
            best = (inc.incident_id, pos)
    if best is None:
        ar.missing_found = [r.order for r in found]
        return
    ar.incident_id, ar.positions = best
    ar.missing_found = [r.order for r in found if r.order not in ar.positions]
    seq = [ar.positions[r.order] for r in sorted(found, key=lambda r: r.order) if r.order in ar.positions]
    ar.discordant, ar.tied, ar.tau = kendall(seq)
    ar.ordered = not ar.missing_found and ar.discordant == 0


def kendall(seq: Sequence[int]) -> tuple[int, int, float | None]:
    """Kendall tau-a of predicted positions against ground-truth order 0..n-1.
    Returns (discordant pairs, tied pairs, tau); tau is None for fewer than 2 items."""
    n = len(seq)
    if n < 2:
        return 0, 0, None
    conc = disc = ties = 0
    for i in range(n):
        for j in range(i + 1, n):
            if seq[i] < seq[j]:
                conc += 1
            elif seq[i] > seq[j]:
                disc += 1
            else:
                ties += 1
    return disc, ties, (conc - disc) / (n * (n - 1) / 2)


def step_summary(attacks: list[AttackResult]) -> dict:
    real = [a for a in attacks if not a.is_decoy]
    steps = [s for a in real for s in a.steps]
    found = [s for s in steps if s.found]
    taus = [a.tau for a in real if a.tau is not None]
    return {
        "step_recall": ratio(len(found), len(steps)),
        "step_recall_event_only": ratio(sum(s.found_by == "event" for s in steps), len(steps)),
        "label_acc_exact": ratio(sum(s.label_exact for s in found), len(found)),
        "label_acc_parent": ratio(sum(s.label_parent for s in found), len(found)),
        "ordered_path_rate": ratio(sum(a.ordered for a in real), len(real)),
        "mean_kendall_tau": value(sum(taus) / len(taus), f"mean over {len(taus)} attacks with >= 2 placed steps")
        if taus else na("no attack has two found steps placed in one incident path"),
        "step_coverage_in_one_incident": value(sum(a.coverage_one_incident for a in real) / len(real),
                                               f"mean over {len(real)} attacks") if real else na("no attacks"),
        "decoys_promoted": value(sum(bool(a.decoy_in_incidents) for a in attacks if a.is_decoy),
                                 f"of {sum(a.is_decoy for a in attacks)} decoys"),
    }


# ============================================================================ incident level
def malicious_events(attacks: list[AttackResult]) -> set[int]:
    return {e for a in attacks if not a.is_decoy for s in a.steps for e in s.events}


def attack_of_events(attacks: list[AttackResult]) -> dict[int, str]:
    out = {}
    for a in attacks:
        if not a.is_decoy:
            for s in a.steps:
                for e in s.events:
                    out.setdefault(e, a.attack_id)
    return out


def incident_summary(attacks: list[AttackResult], rv: RunView) -> dict:
    mal = malicious_events(attacks)
    false_inc = [i.incident_id for i in rv.incidents if not (_inc_events(i) & mal)]
    nodes = [(g, mem) for i in rv.incidents for g, mem in i.nodes.items()]
    mal_nodes = sum(1 for _, mem in nodes if set(mem) & mal)
    pur, ari_v = purity_ari(attacks, rv)
    return {
        "false_alert_rate": ratio(len(false_inc), len(rv.incidents)) if rv.incidents
        else na("no incidents emitted"),
        "false_alert_incidents": false_inc,
        "incidents": len(rv.incidents),
        "purity": pur,
        "ari": ari_v,
        "nodes_to_inspect_mean": value(len(nodes) / len(rv.incidents), f"{len(nodes)} nodes / {len(rv.incidents)} incidents")
        if rv.incidents else na("no incidents emitted"),
        "nodes_malicious_share": ratio(mal_nodes, len(nodes)) if nodes else na("no incident nodes"),
    }


def detection_truth(attacks: list[AttackResult], rv: RunView) -> dict[str, str]:
    """True class of each non-duplicate detection: the attack most of its members belong to,
    else a unique benign class (benign detections should not be grouped together)."""
    aoe = attack_of_events(attacks)
    out = {}
    for d in rv.detections:
        if d.duplicate_of:
            continue
        c = Counter(aoe[m] for m in d.members if m in aoe)
        out[d.detection_id] = _majority(c) if c else f"benign:{d.detection_id}"
    return out


def purity_ari(attacks: list[AttackResult], rv: RunView) -> tuple[dict, dict]:
    truth = detection_truth(attacks, rv)
    inc_of = {d: i.incident_id for i in rv.incidents for d in i.detection_ids}
    pred = {d: (f"inc:{inc_of[d]}" if d in inc_of else f"single:{d}") for d in truth}
    in_inc = [d for d in truth if d in inc_of]
    if in_inc:
        by_c: dict[str, Counter] = {}
        for d in in_inc:
            by_c.setdefault(pred[d], Counter())[truth[d]] += 1
        p = value(sum(max(c.values()) for c in by_c.values()) / len(in_inc),
                  f"over {len(in_inc)} detections in {len(by_c)} incidents")
    else:
        p = na("no detections inside incidents")
    a = value(ari([truth[d] for d in truth], [pred[d] for d in truth]), f"over {len(truth)} detections") \
        if len(truth) >= 2 else na("fewer than two detections")
    return p, a


def ari(labels_true: Sequence[str], labels_pred: Sequence[str]) -> float:
    """Adjusted Rand index (Hubert & Arabie 1985) from the contingency table."""
    n = len(labels_true)
    comb = lambda x: x * (x - 1) / 2  # noqa: E731
    cont = Counter(zip(labels_true, labels_pred))
    a_sum = sum(comb(v) for v in Counter(labels_true).values())
    b_sum = sum(comb(v) for v in Counter(labels_pred).values())
    idx = sum(comb(v) for v in cont.values())
    expected = a_sum * b_sum / comb(n) if n > 1 else 0.0
    max_idx = (a_sum + b_sum) / 2
    if max_idx == expected:
        return 1.0
    return (idx - expected) / (max_idx - expected)


# ============================================================================ event level
def prf(pred: set[int], truth: set[int]) -> dict:
    tp = len(pred & truth)
    p = tp / len(pred) if pred else None
    r = tp / len(truth) if truth else None
    f = 2 * p * r / (p + r) if p and r else (0.0 if p is not None and r is not None else None)
    return {"tp": tp, "predicted": len(pred), "truth": len(truth), "precision": p, "recall": r, "f1": f}


def event_level(attacks: list[AttackResult], rv: RunView) -> dict:
    mal = malicious_events(attacks)
    by_det: dict[str, set[int]] = {}
    by_tech: dict[str, set[int]] = {}
    for d in rv.detections:
        by_det.setdefault(d.detector, set()).update(d.members)
        by_tech.setdefault(d.technique_id, set()).update(d.members)
    truth_tech: dict[str, set[int]] = {}
    for a in attacks:
        if not a.is_decoy:
            for s in a.steps:
                truth_tech.setdefault(s.technique, set()).update(s.events)
    return {
        "note": "per-detector recall uses all malicious events as the denominator",
        "per_detector": {k: prf(v, mal) for k, v in sorted(by_det.items())},
        "per_technique": {t: prf(by_tech.get(t, set()), truth_tech.get(t, set()))
                          for t in sorted(set(by_tech) | set(truth_tech))},
    }


# ============================================================================ ML score level
def average_precision(scores: Sequence[float], labels: Sequence[bool]) -> float | None:
    """AP = sum_k (R_k - R_{k-1}) P_k over distinct score thresholds (ties scored together)."""
    pos = sum(labels)
    if not pos:
        return None
    pairs = sorted(zip(scores, labels), key=lambda x: -x[0])
    ap = tp = fp = 0.0
    prev_r = 0.0
    i = 0
    while i < len(pairs):
        j = i
        while j < len(pairs) and pairs[j][0] == pairs[i][0]:
            tp += pairs[j][1]
            fp += not pairs[j][1]
            j += 1
        r = tp / pos
        ap += (r - prev_r) * (tp / (tp + fp))
        prev_r, i = r, j
    return ap


def recall_at_budget(items: Sequence[tuple[float, bool, object]], budget_per_day: int) -> float | None:
    """items = (score, is_positive, day). Analyst reviews the top-B alerts of each day."""
    pos = sum(1 for _, y, _ in items if y)
    if not pos:
        return None
    by_day: dict[object, list] = {}
    for s, y, d in items:
        by_day.setdefault(d, []).append((s, y))
    hit = 0
    for rows in by_day.values():
        rows.sort(key=lambda x: -x[0])
        hit += sum(y for _, y in rows[:budget_per_day])
    return hit / pos


def alerts_per_day_at_recall(scores: Sequence[float], labels: Sequence[bool], days: float,
                             target: float = 0.9) -> float | None:
    pos = sum(labels)
    if not pos or days <= 0:
        return None
    pairs = sorted(zip(scores, labels), key=lambda x: -x[0])
    tp = 0
    i = 0
    while i < len(pairs):
        j = i
        while j < len(pairs) and pairs[j][0] == pairs[i][0]:
            tp += pairs[j][1]
            j += 1
        if tp / pos >= target:
            return j / days
        i = j
    return None


def score_level(attacks: list[AttackResult], rv: RunView, budgets=(10, 50, 100)) -> dict:
    mal = malicious_events(attacks)
    dets = [d for d in rv.detections if not d.duplicate_of]
    out: dict = {}
    for name, sel in [("all_detectors", dets)] + [(k, [d for d in dets if d.detector == k])
                                                   for k in sorted({d.detector for d in dets})
                                                   if not k.startswith("rule:")]:
        if not sel:
            continue
        ys = [bool(set(d.members) & mal) for d in sel]
        sc = [d.score for d in sel]
        if not any(ys):
            out[name] = na("no detection overlaps a malicious event")
            continue
        items = [(d.score, y, d.ts_first.date()) for d, y in zip(sel, ys)]
        apd = alerts_per_day_at_recall(sc, ys, rv.days)
        out[name] = {
            "unit": "detection (positive if any member event is malicious)",
            "n": len(sel), "positives": sum(ys),
            "score_source": "rule prior confidence" if all(d.detector.startswith("rule:") for d in sel) else "detector score",
            "auc_pr": average_precision(sc, ys),
            **{f"recall_at_{b}_per_day": recall_at_budget(items, b) for b in budgets},
            "alerts_per_day_at_90pct_recall": apd if apd is not None else "N/A (90% recall never reached)",
        }
    return out


# ============================================================================ ranking + reach
def ndcg_at_k(relevance_in_rank_order: Sequence[float], k: int = 10) -> float | None:
    dcg = sum(r / math.log2(i + 2) for i, r in enumerate(relevance_in_rank_order[:k]))
    ideal = sorted(relevance_in_rank_order, reverse=True)[:k]
    idcg = sum(r / math.log2(i + 2) for i, r in enumerate(ideal))
    return dcg / idcg if idcg else None


def incident_ranking(attacks: list[AttackResult], rv: RunView, k: int = 10) -> dict:
    mal = malicious_events(attacks)
    ranked = sorted(rv.incidents, key=lambda i: (-i.risk, i.incident_id))
    rel = [1.0 if _inc_events(i) & mal else 0.0 for i in ranked]
    v = ndcg_at_k(rel, k)
    return {f"ndcg_at_{k}": value(v, "binary relevance: incident overlaps a non-decoy attack; ranked by risk")
            if v is not None else na("no relevant incident to rank")}


def hit_at_k(ranked: Sequence[str], true_next: set[str], k: int) -> bool:
    return bool(set(ranked[:k]) & true_next)


# ============================================================================ helpers + bootstrap
def value(v, text: str = "") -> dict:
    return {"value": v, "text": text}


def na(reason: str) -> dict:
    return {"value": None, "text": f"N/A ({reason})"}


def ratio(n: int, d: int) -> dict:
    if not d:
        return na("denominator is zero")
    return {"value": n / d, "text": f"{n}/{d} = {100 * n / d:.1f}%", "num": n, "den": d}


def bootstrap(units: Sequence, stat: Callable[[Sequence], float | None], n: int = 1000, seed: int = 0,
              alpha: float = 0.05) -> tuple[float, float] | None:
    """Percentile bootstrap CI: resample `units` (attacks or incidents) with replacement."""
    if not units:
        return None
    rng = random.Random(seed)
    vals = []
    for _ in range(n):
        v = stat([units[rng.randrange(len(units))] for _ in units])
        if v is not None:
            vals.append(v)
    if not vals:
        return None
    vals.sort()
    lo = vals[int(math.floor(alpha / 2 * (len(vals) - 1)))]
    hi = vals[int(math.ceil((1 - alpha / 2) * (len(vals) - 1)))]
    return lo, hi


def recall_stat(attacks: Sequence[AttackResult]) -> float | None:
    steps = [s for a in attacks for s in a.steps]
    return sum(s.found for s in steps) / len(steps) if steps else None


def label_exact_stat(attacks: Sequence[AttackResult]) -> float | None:
    f = [s for a in attacks for s in a.steps if s.found]
    return sum(s.label_exact for s in f) / len(f) if f else None


def label_parent_stat(attacks: Sequence[AttackResult]) -> float | None:
    f = [s for a in attacks for s in a.steps if s.found]
    return sum(s.label_parent for s in f) / len(f) if f else None


def ordered_stat(attacks: Sequence[AttackResult]) -> float | None:
    return sum(a.ordered for a in attacks) / len(attacks) if attacks else None


def false_alert_stat(flags: Sequence[bool]) -> float | None:
    return sum(flags) / len(flags) if flags else None
