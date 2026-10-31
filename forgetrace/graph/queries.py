"""Read queries over the Neo4j graph for the API (docs/wp/GR-1.md).

Every query is parameterised; labels and relationship types come from fixed allow-lists, never
from request input. Results are plain JSON (node/edge lists) so the UI renders them as text.
"""
from __future__ import annotations

import threading
from typing import Any

from forgetrace.graph.loader import connect, graph_config, uid

KEY_LABEL = {"user": "User", "host": "Host", "ip": "IP", "domain": "Domain", "group": "Group",
             "alert": "Alert", "incident": "Incident"}
REACH_RELS = "LOGGED_ON|ADMIN_TO|MEMBER_OF"

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
