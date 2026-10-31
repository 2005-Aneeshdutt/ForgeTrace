"""Read queries over the Neo4j graph for the API (docs/wp/GR-1.md).

Every query is parameterised; labels and relationship types come from fixed allow-lists, never
from request input. Results are plain JSON (node/edge lists) so the UI renders them as text.
"""
from __future__ import annotations

import json
import threading
from typing import Any

from forgetrace.graph.loader import connect, graph_config, uid

KEY_LABEL = {"user": "User", "host": "Host", "ip": "IP", "domain": "Domain", "group": "Group",
             "alert": "Alert", "incident": "Incident"}
REACH_RELS = "LOGGED_ON|ADMIN_TO|MEMBER_OF"
VIA_REASON = {"user": "same_user", "host": "same_host", "ip": "pivot_ip", "domain": "same_hash_or_domain"}

_drv = None
_why: str | None = None
_lock = threading.Lock()


def driver():
    """Process-wide driver, (re)connected lazily; returns (driver | None, reason)."""
    global _drv, _why
    with _lock:
        if _drv is not None:
            try:
                _drv.verify_connectivity()
                return _drv, None
            except Exception:
                _drv = None
        _drv, _why = connect()
        return _drv, _why


def _node(n) -> dict[str, Any]:
    d = dict(n)
    return {"id": d.get("uid"), "label": next(iter(n.labels), None),
            "props": {k: (v.iso_format() if hasattr(v, "iso_format") else v) for k, v in d.items() if k not in ("uid", "ws")}}


def _rel(r) -> dict[str, Any]:
    return {"type": r.type, "from": r.start_node.get("uid"), "to": r.end_node.get("uid"),
            "props": {k: (v.iso_format() if hasattr(v, "iso_format") else v) for k, v in dict(r).items()}}


def _run(cypher: str, **params) -> list:
    drv, why = driver()
    if drv is None:
        raise RuntimeError(why)
    with drv.session(database=graph_config()["database"]) as s:
        return list(s.run(cypher, **params))


def status() -> dict[str, Any]:
    drv, why = driver()
    if drv is None:
        return {"available": False, "reason": why}
    rows = _run("MATCH (n) WHERE n.ws IS NOT NULL RETURN n.ws AS ws, count(*) AS nodes ORDER BY ws")
    return {"available": True, "uri": graph_config()["uri"], "workspaces": [dict(r) for r in rows]}


def incident_graph(ws: str, incident_id: int) -> dict[str, Any]:
    rows = _run("""MATCH (i:Incident {uid: $iu})-[:CONTAINS]->(a:Alert)
                   OPTIONAL MATCH (a)-[inv:INVOLVES]->(e)
                   OPTIONAL MATCH (i)-[ps:PATH_STEP]->(a)
                   RETURN a, ps.order AS step, collect(DISTINCT inv) AS invs, collect(DISTINCT e) AS ents""",
                iu=uid(ws, f"incident:{incident_id}"))
    if not rows:
        return {"nodes": [], "edges": [], "found": False}
    nodes, edges = {}, []
    alert_uids = []
    for r in rows:
        a = _node(r["a"])
        a["props"]["path_step"] = r["step"]
        nodes[a["id"]] = a
        alert_uids.append(a["id"])
        for e in r["ents"]:
            nodes.setdefault(e.get("uid"), _node(e))
        edges += [_rel(x) for x in r["invs"]]
    for r in _run("""MATCH (a:Alert)-[l:LEADS_TO]->(b:Alert) WHERE a.uid IN $ids AND b.uid IN $ids RETURN l""",
                  ids=alert_uids):
        edges.append(_rel(r["l"]))
    return {"found": True, "nodes": list(nodes.values()), "edges": edges}


def neighbors(ws: str, key: str, limit: int = 100) -> dict[str, Any]:
    kind, _, val = key.partition(":")
    label = KEY_LABEL.get(kind)
    if label is None or not val:
        raise ValueError(f"key must look like user:<name>, host:<name>, ip:<addr>; got {key!r}")
    rows = _run(f"""MATCH (n:{label} {{uid: $u}})-[r]-(m) RETURN n, r, m
                    ORDER BY coalesce(r.count, 0) DESC, m.uid LIMIT $limit""",
                u=uid(ws, f"{kind}:{val}") if kind not in ("alert", "incident") else uid(ws, key), limit=limit)
    if not rows:
        return {"found": False, "nodes": [], "edges": []}
    nodes = {rows[0]["n"].get("uid"): _node(rows[0]["n"])}
    for r in rows:
        nodes.setdefault(r["m"].get("uid"), _node(r["m"]))
    return {"found": True, "nodes": list(nodes.values()), "edges": [_rel(r["r"]) for r in rows]}


def reach_paths(ws: str, user: str, max_hops: int = 3, min_criticality: float = 0.8, limit: int = 25) -> dict[str, Any]:
    """Shortest relationship paths from an account to critical hosts (dossier §14 relations in the graph)."""
    max_hops = max(1, min(int(max_hops), 4))
    rows = _run(f"""MATCH (u:User {{uid: $u}}), (h:Host {{ws: $ws}}) WHERE h.criticality >= $c
                    MATCH p = shortestPath((u)-[:{REACH_RELS}*1..{max_hops}]->(h))
                    RETURN h.name AS host, h.criticality AS criticality, length(p) AS hops,
                           [r IN relationships(p) | {{type: type(r), from: startNode(r).uid, to: endNode(r).uid,
                             kind: r.kind, sample_event_ids: r.sample_event_ids}}] AS via
                    ORDER BY hops, criticality DESC, host LIMIT $limit""",
                u=uid(ws, f"user:{user}"), ws=ws, c=float(min_criticality), limit=limit)
    return {"user": user, "max_hops": max_hops, "min_criticality": min_criticality, "paths": [dict(r) for r in rows],
            "note": "Relationship paths are possibilities, not observed attacker activity (dossier §14)."}


def campaign_list(ws: str) -> dict[str, Any]:
    """Long-range campaigns (forgetrace/graph/campaigns.py) with their alerts in time order."""
    from forgetrace.graph.campaigns import campaigns as _campaigns

    drv, why = driver()
    if drv is None:
        raise RuntimeError(why)
    rows = _campaigns(drv, ws)
    return {"campaigns": rows, "count": len(rows),
            "note": "Campaigns join alerts that share an uncommon address, account or domain at any time gap; "
                    "they are inferences with the shared entity and gap on every link."}


def chain_members(ws: str, label: str, chain_id: str) -> tuple[list[str], list[dict]]:
    """Alert ids of an incident/campaign in order, and the links between them (for explanations)."""
    if label not in ("Incident", "Campaign"):
        raise ValueError("label must be Incident or Campaign")
    rel = "CONTAINS" if label == "Incident" else "INCLUDES"
    u = chain_id if chain_id.startswith(f"{ws}|") else (uid(ws, f"campaign:{chain_id}") if label == "Campaign"
                                                       else uid(ws, f"incident:{chain_id}"))
    rows = _run(f"""MATCH (c:{label} {{uid: $u}})-[x:{rel}]->(a:Alert) RETURN a.uid AS uid, a.group_id AS gid
                    ORDER BY x.order""", u=u)
    if not rows:
        raise ValueError(f"{label.lower()} {chain_id!r} not found")
    ids = [r["uid"] for r in rows]
    links = []
    for r in _run("""MATCH (a:Alert)-[e:LEADS_TO|RELATED]->(b:Alert) WHERE a.uid IN $ids AND b.uid IN $ids
                     RETURN a.uid AS a, b.uid AS b, type(e) AS t, e.reasons_json AS reasons, e.delta_t_s AS dt,
                            e.gap_s AS gap, e.score AS score, e.via AS via""", ids=ids):
        if r["reasons"]:  # windowed LEADS_TO: the dossier §12 reasons
            reasons = json.loads(r["reasons"])
        elif r["via"]:  # long-range RELATED: one shared uncommon entity
            kind, _, value = r["via"].split("|", 1)[-1].partition(":")
            reasons = [{"type": VIA_REASON.get(kind, "same_" + kind), "entity_key": f"{kind}:{value}"}]
        else:
            reasons = []
        links.append({"src": r["a"], "dst": r["b"], "kind": r["t"], "reasons": reasons,
                      "gap_s": r["dt"] if r["dt"] is not None else r["gap"], "score": r["score"]})
    gid = {r["uid"]: r["gid"] for r in rows}
    best: dict[str, dict] = {}
    for ln in links:  # one incoming link per step: windowed LEADS_TO first, then the shortest RELATED gap
        k = ln["dst"]
        rank = (ln["kind"] != "LEADS_TO", ln["gap_s"] or 0)
        if k not in best or rank < (best[k]["kind"] != "LEADS_TO", best[k]["gap_s"] or 0):
            best[k] = ln
    return [gid[i] for i in ids], [{**v, "dst": gid[v["dst"]]} for v in best.values()]


def incident_list(ws: str) -> dict[str, Any]:
    rows = _run("""MATCH (i:Incident {ws: $ws}) OPTIONAL MATCH (i)-[:CONTAINS]->(a:Alert)
                   RETURN i.uid AS id, i.tactics AS tactics, i.ts_first AS ts_first, i.ts_last AS ts_last,
                          i.max_severity AS max_severity, count(a) AS alerts, collect(a.rule_id)[0..12] AS rules
                   ORDER BY i.ts_first""", ws=ws)
    return {"incidents": [dict(r) for r in rows], "count": len(rows)}
