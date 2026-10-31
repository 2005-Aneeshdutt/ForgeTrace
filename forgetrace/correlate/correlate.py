"""Explainable correlation (dossier §12).

Pipeline: detections -> aggregate into alert groups -> entity index -> candidate edges
(at least one shared-entity reason, never time alone) -> score s = clip(0.45L + 0.20T +
0.20P + 0.10R - 0.25F) -> keep s >= theta and L > 0, top-K in/out -> union-find ->
abstain unless >= 2 distinct tactics -> best temporal path by DP (J = sum log s + lambda sum n).
Every loop iterates over explicitly sorted keys so output is deterministic.
"""
from __future__ import annotations

import json
import math
from collections import defaultdict
from datetime import datetime

import duckdb

from forgetrace import assets, config

ENT = ["user", "target_user", "host", "host_ip", "src_ip", "dst_ip", "logon_id", "domain_name", "process",
       "group_name"]


# ----------------------------------------------------------------------------- aggregation
def aggregate(con: duckdb.DuckDBPyConnection) -> list[dict]:
    cfg = config.correlation()
    rows = con.execute("""SELECT detection_id, rule_id, rule_title, technique_id, technique_name, tactic,
        tactic_ordinal, kill_chain_phase, severity, confidence, ts_first, ts_last, member_event_ids,
        aggregate_by, entities, evidence FROM detections WHERE duplicate_of IS NULL""").fetchall()
    dets = []
    for r in rows:
        d = dict(zip(["detection_id", "rule_id", "rule_title", "technique_id", "technique_name", "tactic",
                      "tactic_ordinal", "kill_chain_phase", "severity", "confidence", "ts_first", "ts_last",
                      "member_event_ids", "aggregate_by", "entities", "evidence"], r))
        d["entities"] = json.loads(d["entities"]) if d["entities"] else {}
        d["aggregate_key"] = "|".join(f"{k}={','.join(d['entities'].get(k, []))}" for k in d["aggregate_by"])
        dets.append(d)
    # Label priority (one primary technique per raw event): a detection none of whose member events
    # carries its technique as primary label is folded into the groups holding those events as
    # also_matched, instead of becoming a separate node (keeps valid secondary matches visible).
    prim = dict(con.execute("SELECT event_id, primary_technique FROM event_labels").fetchall())
    secondary = [d for d in dets if all(prim.get(m) != d["technique_id"] for m in d["member_event_ids"])]
    dets = [d for d in dets if d not in secondary]
    dets.sort(key=lambda d: (d["rule_id"], d["aggregate_key"], d["ts_first"], d["detection_id"]))
    groups: list[dict] = []
    cur = None
    for d in dets:
        if (cur and cur["rule_id"] == d["rule_id"] and cur["aggregate_key"] == d["aggregate_key"]
                and (d["ts_first"] - cur["ts_last"]).total_seconds() <= cfg["agg_gap_s"]):
            cur["detection_ids"].append(d["detection_id"])
            cur["member_event_ids"] = sorted(set(cur["member_event_ids"]) | set(d["member_event_ids"]))
            cur["ts_last"] = max(cur["ts_last"], d["ts_last"])
            cur["raw_alert_count"] += 1
            cur["evidence"].append(d["evidence"])
            for k in ENT:
                cur["entities"][k] = sorted(set(cur["entities"].get(k, [])) | set(d["entities"].get(k, [])))
            continue
        cur = {k: d[k] for k in ("rule_id", "rule_title", "technique_id", "technique_name", "tactic",
                                 "tactic_ordinal", "kill_chain_phase", "severity", "confidence", "ts_first",
                                 "ts_last", "aggregate_key")}
        cur.update(detection_ids=[d["detection_id"]], member_event_ids=sorted(d["member_event_ids"]),
                   raw_alert_count=1, evidence=[d["evidence"]],
                   entities={k: sorted(d["entities"].get(k, [])) for k in ENT})
        groups.append(cur)
    groups.sort(key=lambda g: (g["ts_first"], g["tactic_ordinal"], g["member_event_ids"][0]))
    for i, g in enumerate(groups, 1):
        g["group_id"] = f"G{i:04d}"
        g["member_count"] = len(g["member_event_ids"])
        g["also_matched"] = []
    for d in sorted(secondary, key=lambda d: d["detection_id"]):
        for g in groups:
            if any(prim.get(m) == g["technique_id"] for m in set(d["member_event_ids"]) & set(g["member_event_ids"])):
                g["also_matched"].append({"detection_id": d["detection_id"], "rule_id": d["rule_id"],
                                          "technique_id": d["technique_id"], "tactic": d["tactic"],
                                          "evidence": d["evidence"]})
    return groups


# ----------------------------------------------------------------------------- entity statistics
def entity_stats(con: duckdb.DuckDBPyConnection, groups: list[dict]) -> dict[str, int]:
    """distinct_peers per entity (dossier §11 'Benign-frequency statistics'), computed only for
    entities that appear in groups: user->hosts, host->users, ip->hosts, domain->hosts, session->1."""
    want = defaultdict(set)
    for g in groups:
        for k in ("user", "target_user"):
            want["user"].update(g["entities"][k])
        want["host"].update(g["entities"]["host"])
        for k in ("src_ip", "dst_ip", "host_ip"):
            want["ip"].update(g["entities"][k])
        want["domain"].update(g["entities"]["domain_name"])
    deg: dict[str, int] = {}
    con.execute("CREATE OR REPLACE TEMP TABLE _w(t VARCHAR, v VARCHAR)")
    for t in sorted(want):
        for v in sorted(want[t]):
            con.execute("INSERT INTO _w VALUES (?, ?)", [t, v])
    q = """
      SELECT 'user', w.v, count(DISTINCT e.host) FROM _w w JOIN events e ON e.user = w.v WHERE w.t='user' GROUP BY 1,2
      UNION ALL SELECT 'host', w.v, count(DISTINCT e.user) FROM _w w JOIN events e ON e.host = w.v WHERE w.t='host' GROUP BY 1,2
      UNION ALL SELECT 'ip', w.v, count(DISTINCT e.host) FROM _w w JOIN events e
            ON (e.src_ip = w.v OR e.dst_ip = w.v) WHERE w.t='ip' GROUP BY 1,2
      UNION ALL SELECT 'domain', w.v, count(DISTINCT e.host) FROM _w w JOIN events e ON e.domain_name = w.v
            WHERE w.t='domain' GROUP BY 1,2"""
    for t, v, c in con.execute(q).fetchall():
        deg[f"{t}:{v}"] = int(c)
    return deg


def ip_host_map(con: duckdb.DuckDBPyConnection) -> dict[str, set[str]]:
    """Observed ip -> host bindings (host.ip reported by the endpoint itself)."""
    m: dict[str, set[str]] = defaultdict(set)
    for ip, host in con.execute("SELECT DISTINCT host_ip, host FROM events WHERE host_ip IS NOT NULL AND host IS NOT NULL").fetchall():
        m[ip].add(host)
    return m


# ----------------------------------------------------------------------------- scoring
def progression(a_ord: int, b_ord: int, p: dict) -> float:
    d = b_ord - a_ord
    if d > 0:
        return p["forward"]
    if d == 0:
        return p["same"]
    if d == -1:
        return p["one_back"]
    return p["further_back"]


def score_edge(reasons: list[dict], dt_s: float, a_ord: int, b_ord: int, max_sev: int, target_crit: float,
               strongest_deg: int, cfg: dict | None = None) -> dict:
    cfg = cfg or config.correlation()
    w = cfg["weights"]
    prod = 1.0
    for r in reasons:
        prod *= 1.0 - r["weight"]
    L = 1.0 - prod
    types = {r["type"] for r in reasons}
    tau = cfg["tau_same_user_only_s"] if types == {"same_user"} else cfg["tau_s"]
    T = math.exp(-max(0.0, dt_s) / tau)
    P = progression(a_ord, b_ord, cfg["progression"])
    R = 0.5 * max_sev / 4 + 0.5 * target_crit
    F = min(1.0, math.log10(1 + strongest_deg) / math.log10(1 + cfg["degree_saturation"]))
    raw = w["L"] * L + w["T"] * T + w["P"] * P + w["R"] * R - w["F"] * F
    s = min(1.0, max(0.0, raw))
    return {"score": round(s, 4), "terms": {"L": round(L, 4), "T": round(T, 4), "P": P, "R": round(R, 4),
                                            "F": round(F, 4)},
            "weighted": {"L": round(w["L"] * L, 4), "T": round(w["T"] * T, 4), "P": round(w["P"] * P, 4),
                         "R": round(w["R"] * R, 4), "F": round(-w["F"] * F, 4)},
            "tau_s": tau}


def _keys(g: dict, ipmap: dict) -> dict[str, set[tuple[str, str]]]:
    """Entity link keys for a group, as (reason_family, entity_key)."""
    e = g["entities"]
    users = set(e["user"]) | set(e["target_user"])
    resolved_src = {h for ip in e["src_ip"] for h in ipmap.get(ip, ())}
    resolved_dst = {h for ip in e["dst_ip"] for h in ipmap.get(ip, ())}
    return {
        "session": {("same_session", f"session:{v}") for v in e["logon_id"]},
        "user": {("same_user", f"user:{v}") for v in users},
        "host": {("same_host", f"host:{v}") for v in e["host"]},
        "ip": {("pivot_ip", f"ip:{v}") for v in set(e["src_ip"]) | set(e["dst_ip"])},
        "domain": {("same_hash_or_domain", f"domain:{v}") for v in e["domain_name"]},
        "src_host": {f"host:{h}" for h in resolved_src},
        "dst_host": {f"host:{h}" for h in resolved_dst},
    }


def candidate_edges(groups: list[dict], ipmap: dict, deg: dict, con: duckdb.DuckDBPyConnection) -> list[dict]:
    cfg = config.correlation()
    rw = cfg["reason_weights"]
    order = {g["group_id"]: (g["ts_first"], g["tactic_ordinal"], g["member_event_ids"][0]) for g in groups}
    keys = {g["group_id"]: _keys(g, ipmap) for g in groups}
    gid = {g["group_id"]: g for g in groups}
    # Entity index: entity_key -> groups (only entities that appear in groups).
    index: dict[str, list[str]] = defaultdict(list)
    for g in groups:
        k = keys[g["group_id"]]
        ents = {ek for fam in ("session", "user", "host", "ip", "domain") for _, ek in k[fam]}
        ents |= k["src_host"] | k["dst_host"]
        for ek in sorted(ents):
            index[ek].append(g["group_id"])
    pairs = set()
    for ek in sorted(index):
        ids = index[ek]
        for i in range(len(ids)):
            for j in range(len(ids)):
                if i != j:
                    a, b = sorted((ids[i], ids[j]), key=lambda x: order[x])
                    pairs.add((a, b))
    edges = []
    for a_id, b_id in sorted(pairs, key=lambda p: (order[p[0]], order[p[1]])):
        a, b = gid[a_id], gid[b_id]
        if (b["ts_first"] - a["ts_first"]).total_seconds() < -cfg["skew_s"]:
            continue
        if (b["ts_first"] - a["ts_last"]).total_seconds() > cfg["window_s"]:
            continue
        ka, kb = keys[a_id], keys[b_id]
        reasons = []
        for fam in ("session", "user", "host", "ip", "domain"):
            for typ, ek in sorted(ka[fam] & kb[fam]):
                reasons.append({"type": typ, "entity_key": ek, "weight": rw[typ]})
        # IP-to-host pivot: b originates from a's host, or a connected to b's host.
        a_hosts = {f"host:{h}" for h in a["entities"]["host"]}
        b_hosts = {f"host:{h}" for h in b["entities"]["host"]}
        for ek in sorted((kb["src_host"] & a_hosts) | (ka["dst_host"] & b_hosts)):
            reasons.append({"type": "pivot_host", "entity_key": ek, "weight": rw["pivot_host"]})
        if not reasons:
            continue
        # Degree of the strongest linking entity (highest weight; ties -> highest degree, conservative).
        def _deg(ek):
            t, v = ek.split(":", 1)
            return deg.get(f"{'ip' if t == 'ip' else t}:{v}", 1 if t == "session" else 0)
        strongest = sorted(reasons, key=lambda r: (-r["weight"], -_deg(r["entity_key"]), r["entity_key"]))[0]
        dt = max(0.0, (b["ts_first"] - a["ts_last"]).total_seconds())
        crit = max([assets.criticality(h) for h in b["entities"]["host"]] or [assets.default_criticality()])
        sc = score_edge(reasons, dt, a["tactic_ordinal"], b["tactic_ordinal"], max(a["severity"], b["severity"]),
                        crit, _deg(strongest["entity_key"]), cfg)
        edges.append({"edge_id": f"{a_id}:{b_id}", "src_group_id": a_id, "dst_group_id": b_id,
                      "reasons": reasons, "strongest_entity": strongest["entity_key"],
                      "strongest_entity_degree": _deg(strongest["entity_key"]), "target_criticality": crit,
                      "score": sc["score"], "score_terms": sc["terms"], "weighted_terms": sc["weighted"],
                      "tau_s": sc["tau_s"], "delta_t_s": round(dt, 3), "kind": "inferred",
                      "connector_event_id": None})
    _evidence_ids(edges, gid, con)
    return edges


def _evidence_ids(edges: list[dict], gid: dict, con: duckdb.DuckDBPyConnection) -> None:
    """Events in both endpoints that carry the shared entity values (dossier §13 edges)."""
    col = {"session": ["logon_id"], "user": ["user", "target_user"], "host": ["host"], "ip": ["src_ip", "dst_ip"],
           "domain": ["domain_name"]}
    for e in edges:
        ids = set()
        for r in e["reasons"]:
            t, v = r["entity_key"].split(":", 1)
            cols = col.get(t, [])
            if r["type"] == "pivot_host":
                cols = ["host"]
            for g in (gid[e["src_group_id"]], gid[e["dst_group_id"]]):
                mem = g["member_event_ids"]
                if not cols:
                    continue
                cond = " OR ".join(f'"{c}" = ?' for c in cols)
                q = f"SELECT event_id FROM events WHERE event_id IN (SELECT unnest(?)) AND ({cond})"
                ids.update(x[0] for x in con.execute(q, [mem] + [v] * len(cols)).fetchall())
            if r["type"] == "pivot_host":  # the pivoting event: b's member whose src_ip resolves to a's host
                b = gid[e["dst_group_id"]]
                q = ("SELECT e.event_id FROM events e WHERE e.event_id IN (SELECT unnest(?)) AND e.src_ip IN "
                     "(SELECT DISTINCT host_ip FROM events WHERE host = ? AND host_ip IS NOT NULL)")
                ids.update(x[0] for x in con.execute(q, [b["member_event_ids"], v]).fetchall())
        e["evidence_event_ids"] = sorted(ids)[:200]


def prune(edges: list[dict]) -> list[dict]:
    cfg = config.correlation()
    kept = [e for e in edges if e["score"] >= cfg["theta_edge"] and e["score_terms"]["L"] > 0]
    K = cfg["k_degree"]
    out_c, in_c = defaultdict(int), defaultdict(int)
    final = []
    for e in sorted(kept, key=lambda e: (-e["score"], e["edge_id"])):
        if out_c[e["src_group_id"]] >= K or in_c[e["dst_group_id"]] >= K:
            e["pruned_reason"] = f"top-K={K} degree cap"
            continue
        out_c[e["src_group_id"]] += 1
        in_c[e["dst_group_id"]] += 1
        final.append(e)
    return sorted(final, key=lambda e: e["edge_id"])


# ----------------------------------------------------------------------------- incidents + paths
class UF:
    def __init__(self, items):
        self.p = {i: i for i in items}

    def find(self, x):
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            lo, hi = sorted((ra, rb))
            self.p[hi] = lo


def best_path(nodes: list[str], edges: list[dict], gid: dict, lam: float) -> tuple[list[str], list[str], float]:
    """Max-J path over the incident DAG (edges point earlier -> later), DP in topological order."""
    n = {v: gid[v]["severity"] / 4 * gid[v]["confidence"] for v in nodes}
    order = sorted(nodes, key=lambda v: (gid[v]["ts_first"], gid[v]["tactic_ordinal"], gid[v]["member_event_ids"][0]))
    inc = defaultdict(list)
    for e in edges:
        inc[e["dst_group_id"]].append(e)
    best: dict[str, tuple[float, list[str], list[str]]] = {}
    for v in order:
        cand = [(lam * n[v], [v], [])]
        for e in sorted(inc[v], key=lambda e: e["edge_id"]):
            u = e["src_group_id"]
            if u in best:
                J, p, pe = best[u]
                cand.append((J + math.log(max(e["score"], 1e-9)) + lam * n[v], p + [v], pe + [e["edge_id"]]))
        cand.sort(key=lambda c: (-round(c[0], 9), -len(c[1]), c[1]))
        best[v] = cand[0]
    J, p, pe = sorted(best.values(), key=lambda c: (-round(c[0], 9), -len(c[1]), c[1]))[0]
    return p, pe, J


def primary_path(members: list[str], edges: list[dict], gid: dict) -> dict:
    """Primary attack path (brief Step 5): every incident group ordered by (ts_first, tactic ordinal,
    first event_id). Each hop cites the kept inferred edge that justifies it; a hop with no direct
    edge is reported as such rather than invented."""
    order = sorted(members, key=lambda v: (gid[v]["ts_first"], gid[v]["tactic_ordinal"], gid[v]["member_event_ids"][0]))
    by_pair = {(e["src_group_id"], e["dst_group_id"]): e for e in edges}
    hops = []
    for a, b in zip(order, order[1:]):
        e = by_pair.get((a, b))
        if e is None:  # best kept edge into b from any earlier path node
            prior = [by_pair[(x, b)] for x in order[: order.index(b)] if (x, b) in by_pair]
            e = max(prior, key=lambda x: (x["score"], x["edge_id"])) if prior else None
        hops.append({"from": a, "to": b, "edge_id": e["edge_id"] if e else None,
                     "score": e["score"] if e else None,
                     "note": None if e and e["src_group_id"] == a else
                     ("linked from an earlier step" if e else "no direct inferred edge; same connected component")})
    return {"rank": 1, "group_ids": order, "hops": hops,
            "edge_ids": [h["edge_id"] for h in hops if h["edge_id"]],
            "stages": [gid[v]["tactic"] for v in order],
            "method": "groups ordered by timestamp, then ATT&CK tactic ordinal, then first event_id"}


def build_incidents(groups: list[dict], edges: list[dict]) -> tuple[list[dict], list[dict]]:
    cfg = config.correlation()
    att = config.attack()
    gid = {g["group_id"]: g for g in groups}
    uf = UF(sorted(gid))
    for e in edges:
        uf.union(e["src_group_id"], e["dst_group_id"])
    comps: dict[str, list[str]] = defaultdict(list)
    for g in sorted(gid):
        comps[uf.find(g)].append(g)
    incidents, abstained = [], []
    for root in sorted(comps, key=lambda r: min(gid[g]["ts_first"] for g in comps[r])):
        members = sorted(comps[root], key=lambda v: (gid[v]["ts_first"], gid[v]["tactic_ordinal"]))
        tactics = []
        for v in members:
            if gid[v]["tactic"] not in tactics:
                tactics.append(gid[v]["tactic"])
        ces = [e for e in edges if e["src_group_id"] in comps[root]]
        if len(set(tactics)) < cfg["min_distinct_tactics"]:
            abstained.append({"group_ids": members, "tactics": tactics, "edge_ids": [e["edge_id"] for e in ces],
                              "reason": f"only {len(set(tactics))} distinct tactic(s); "
                                        f"gate requires >= {cfg['min_distinct_tactics']} (dossier §12 step 7)"})
            continue
        path, path_edges, J = best_path(members, ces, gid, cfg["path_lambda"])
        status = "emitted"
        if cfg.get("theta_path") is not None and J < cfg["theta_path"]:
            status = "abstained-path"
        max_ord = max(t["ordinal"] for t in att["tactics"].values())
        incidents.append({
            "status": status, "group_ids": members, "edge_ids": sorted(e["edge_id"] for e in ces),
            "tactics": tactics, "techniques": sorted({gid[v]["technique_id"] for v in members}),
            "ts_first": min(gid[v]["ts_first"] for v in members), "ts_last": max(gid[v]["ts_last"] for v in members),
            "raw_alert_count_total": sum(gid[v]["raw_alert_count"] for v in members),
            "member_event_count": len({x for v in members for x in gid[v]["member_event_ids"]}),
            "primary_path": primary_path(members, ces, gid),
            "strongest_chain": {"rank": 2, "group_ids": path, "edge_ids": path_edges, "objective_J": round(J, 4),
                                "stages": [gid[v]["tactic"] for v in path],
                                "method": "dossier §12 step 8 DP: J = sum log(s_e) + lambda * sum n(v)",
                                "uncovered_group_ids": [v for v in members if v not in path]},
            "timeline_order": members,
            "max_severity": max(gid[v]["severity"] for v in members),
            "deepest_tactic_ordinal": max(gid[v]["tactic_ordinal"] for v in members),
            "max_tactic_ordinal": max_ord,
        })
    for i, inc in enumerate(incidents, 1):
        inc["incident_id"] = i
    return incidents, abstained


def correlate(con: duckdb.DuckDBPyConnection) -> dict:
    groups = aggregate(con)
    deg = entity_stats(con, groups)
    ipmap = ip_host_map(con)
    cand = candidate_edges(groups, ipmap, deg, con)
    kept = prune(cand)
    incidents, abstained = build_incidents(groups, kept)
    return {"groups": groups, "candidate_edges": cand, "edges": kept, "incidents": incidents,
            "abstained": abstained, "entity_degree": deg}


def iso(ts: datetime) -> str:
    return ts.isoformat() + "Z" if ts.tzinfo is None else ts.isoformat()
