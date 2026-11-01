"""M2: anomalous links in the login / admin-connection graph - lateral movement (PHASE2 ML-3).

Why this exists: lateral movement shows up as an account or machine reaching a host it has no reason to
reach. Following the link-prediction framing of Euler (King & Huang, NDSS 2023) and UltraLMD++ (2025), an
edge is unusual when it is new for an established source AND unlikely given the graph: here the score is
peer reach (of the sources that share destinations with this source, how many ever reached this
destination - a common-neighbour / Adamic-Adar-style similarity). UltraLMD++'s finding that lateral
movement clusters is used as the post-filter: a novel edge is kept only if its source or destination has
other novel edges in the same window. Unsupervised and explainable: every flagged edge says how many
destinations the source had before and what share of its peers ever went there; each new link is its own
detection (its own hop in a chain). Relationship types and
admin ports are configuration (config/ml.yml link.edges).
"""
from __future__ import annotations

import math
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from forgetrace.ml.ueba import ml_config


def _edges(con, view: str, spec: dict) -> list[tuple]:
    return con.execute(f"""SELECT CAST({spec['src']} AS VARCHAR) AS s, CAST({spec['dst']} AS VARCHAR) AS d, min(ts) AS t0,
                                  max(ts) AS t1, count(*) AS n, list(event_id ORDER BY ts, event_id)[1:10] AS sample
                           FROM {view} WHERE {spec['where']} GROUP BY 1, 2 ORDER BY t0, s, d""").fetchall()


def link_detections(con, view: str, fill: dict[str, float], history: dict[str, list[tuple]] | None = None,
                    min_ts: datetime | None = None) -> tuple[list[dict], dict, dict]:
    """Batch: history None -> the first part of `view` is the baseline (warm-up). Live: `history` maps edge type
    to earlier (src, dst, first_ts) rows and only edges first seen at/after `min_ts` are judged.
    Returns (detection rows, new edges per type for the caller to persist, info)."""
    from forgetrace.ml.rows import ml_detection_row

    cfg = ml_config()
    lc = cfg["link"]
    tech = cfg["techniques"]["link"]
    w = int(cfg["window_minutes"])
    rows, new_edges, info = [], {}, {}
    if not cfg.get("enabled"):
        return rows, new_edges, {"skipped": "ML disabled"}
    for etype, spec in lc["edges"].items():
        needed = {"user", "host"} if etype == "logon" else {"src_ip", "dst_ip", "dst_port"}
        if any(fill.get(f, 0) == 0 for f in needed):
            info[etype] = "required fields absent"
            continue
        cur = _edges(con, view, spec)
        new_edges[etype] = [(s, d, t0) for s, d, t0, *_ in cur]
        if not cur:
            continue
        bucket = lambda t: t - timedelta(minutes=t.minute % w, seconds=t.second, microseconds=t.microsecond)  # noqa: E731
        dsts: dict[str, dict] = defaultdict(dict)     # src -> {dst: first seen}
        reached: dict[str, set] = defaultdict(set)
        if history is not None:
            for s, d, t in history.get(etype, []):
                dsts[s].setdefault(d, t)
                reached[d].add(s)
            judge_from = min_ts
        else:
            t_min, t_max = cur[0][2], max(r[3] for r in cur)
            judge_from = min(t_min + timedelta(hours=float(lc.get("warmup_hours", 6))), t_min + (t_max - t_min) / 4)
        cands = []
        for s, d, t0, t1, n, sample in cur:
            if d in dsts[s]:
                continue
            # Only destinations established before this window describe the source: a burst of new links in
            # one window must not vouch for each other.
            est = [x for x, tx in dsts[s].items() if tx < bucket(t0)]
            hist = len(est)
            if t0 >= judge_from and hist >= int(lc["min_src_history"]):
                # Adamic-Adar-style peer weights: sharing a rarely used destination makes a stronger peer than
                # sharing a hub everyone uses (a domain controller), so hubs do not make everyone a peer.
                wts: dict[str, float] = defaultdict(float)
                hub = float(lc.get("hub_share", 0.5)) * max(1, len(dsts))
                for x in est:
                    if len(reached[x]) <= min(5000, hub):  # a destination most sources use says nothing about similarity
                        wx = 1.0 / math.log(2 + len(reached[x]))
                        for p in reached[x]:
                            if p != s:
                                wts[p] += wx
                peers = set(wts)
                tot = sum(wts.values())  # no informative peers -> nothing similar ever went there (reach 0)
                reach = (sum(wts[p] for p in peers & reached[d]) / tot) if tot else 0.0
                if reach <= float(lc["max_peer_reach"]):
                    cands.append({"s": s, "d": d, "t0": t0, "t1": t1, "n": n, "sample": list(sample), "hist": hist,
                                  "peers": len(peers), "reach": reach})
            dsts[s][d] = t0
            reached[d].add(s)
        by_src: dict[tuple, list] = defaultdict(list)
        by_dst: dict[tuple, list] = defaultdict(list)
        for c in cands:
            by_src[(c["s"], bucket(c["t0"]))].append(c)
            by_dst[(c["d"], bucket(c["t0"]))].append(c)
        k = int(lc["neighbour_filter"])
        kept = [c for c in cands if len(by_src[(c["s"], bucket(c["t0"]))]) >= k or len(by_dst[(c["d"], bucket(c["t0"]))]) >= k]
        groups: dict[tuple, list] = defaultdict(list)
        for c in kept:
            groups[(c["s"], bucket(c["t0"]))].append(c)
        # One detection per new link (each is its own hop in a chain); the window's other new links are context.
        agg = ["user", "host"] if etype == "logon" else ["src_ip", "dst_ip"]
        n_det = 0
        for (s, win), cs in sorted(groups.items(), key=lambda kv: (kv[0][1], kv[0][0])):
            cs.sort(key=lambda c: (c["t0"], c["d"]))
            for c in cs:
                others = [o["d"] for o in cs if o is not c]
                text = (f"{s} -> {c['d']} for the first time ({c['n']} event(s)); {s} had {c['hist']} earlier destinations "
                        f"and {c['reach']:.0%} of its {c['peers']} peers ever reached {c['d']}")
                reasons = [{"feature": "new_link", "value": c["d"], "baseline": f"{c['hist']} earlier destinations; peers reaching "
                            f"it {c['reach']:.0%} of {c['peers']}", "contribution": round(1 - c["reach"], 4), "text": text}]
                if others:
                    reasons.append({"feature": "new_links_same_window", "value": len(cs), "baseline": f"fewer than {k}",
                                    "contribution": None,
                                    "text": f"{s} also opened new links to {', '.join(others[:5])}"
                                            f"{' …' if len(others) > 5 else ''} in the same {w}-minute window"})
                ev = (f"graph link model ({etype}): {text}. In the {w}-minute window from {win} {s} opened {len(cs)} new "
                      f"link(s) its peers do not use.")
                rows.append(ml_detection_row(
                    rule_id=f"ML-LINK-{etype}", title=f"New, out-of-pattern {etype.replace('_', ' ')} link (graph link model)",
                    detector="m2_authgraph", technique=tech["technique"], tactic=tech["tactic"], members=sorted(c["sample"]),
                    ts_first=c["t0"], ts_last=c["t1"], evidence=ev, score=round(1 - c["reach"], 4), reasons=reasons,
                    aggregate_by=agg, severity=int(lc["severity"]), confidence=float(lc["prior"])))
                n_det += 1
        info[etype] = {"edges": len(cur), "candidates": len(cands), "kept": len(kept), "detections": n_det,
                       "judged_from": str(judge_from)}
    return rows, new_edges, info


__all__ = ["link_detections", "Any"]
