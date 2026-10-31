"""Incident-conditioned reachability and containment simulation (dossier §14).

Why this exists: from the entities an incident shows as compromised, estimate which other
hosts an attacker could plausibly control next, using only (a) relationships observed in the
logs and (b) relationships configured in config/assets.yaml. Every reach edge carries its
kind (observed / configured / inferred), weight and evidence. Containment is a non-destructive
graph edit followed by the same search. Output is an estimate, never a guarantee.
"""
from __future__ import annotations

import math
from datetime import timedelta

import duckdb
import networkx as nx

from forgetrace import assets, config


def _cfg() -> dict:
    return config.load_yaml(config.CONFIG_DIR / "reach.yml")


def compromised_set(incident: dict, gid: dict) -> dict[str, dict]:
    """Step 1: compromised accounts/hosts derived from the incident, never from the fixture."""
    cfg = _cfg()
    C: dict[str, dict] = {}

    def add(node, weight, reason, eids):
        # Group member ids are sorted, so the 50 smallest of a union come from the first 50 of each list;
        # Phase 1 rebuilt a set of the whole group per entity (millions of ids on firex-50G).
        head = eids[:50]
        cur = C.get(node)
        if cur is None or weight > cur["weight"]:
            C[node] = {"node": node, "weight": weight, "reason": reason, "evidence_event_ids": sorted(head)[:50]}
        elif weight == cur["weight"]:
            cur["evidence_event_ids"] = sorted(set(cur["evidence_event_ids"]) | set(head))[:50]

    for v in incident["group_ids"]:
        g = gid[v]
        for u in g["entities"]["user"]:
            add(f"account:{u}", 1.0, f"account performs detected action ({g['rule_id']} {g['technique_id']})",
                g["member_event_ids"])
        for h in g["entities"]["host"]:
            add(f"host:{h}", 1.0, f"host of detected activity ({g['rule_id']} {g['technique_id']})",
                g["member_event_ids"])
        for u in g["entities"]["target_user"]:
            if f"account:{u}" not in C:
                add(f"account:{u}", cfg["weights"]["suspected_start"],
                    f"suspected: account created/modified by a compromised account ({g['rule_id']})",
                    g["member_event_ids"])
    return C


REACH_EVENTS_SQL = """CREATE OR REPLACE TABLE reach_events AS
    SELECT event_id, ts, event_type, logon_type, user, target_user, host, group_name FROM events
    WHERE event_type IN ('auth_success', 'group_add')"""


def _source(con: duckdb.DuckDBPyConnection) -> str:
    """reach_events when the run materialised it (pipeline), else the full events view (old workspaces)."""
    try:
        con.execute("SELECT 1 FROM reach_events LIMIT 0")
        return "reach_events"
    except duckdb.Error:
        return "events"


def context_graph(con: duckdb.DuckDBPyConnection, incident: dict) -> tuple[nx.DiGraph, bool]:
    """Step 2: edges mean 'control of source plausibly enables control of target'."""
    cfg = _cfg()
    src = _source(con)
    w = cfg["weights"]
    G = nx.DiGraph()
    end = incident["ts_last"]
    start = end - timedelta(seconds=cfg["lookback_s"])

    def add(src, dst, rel, kind, weight, evidence):
        cur = G.get_edge_data(src, dst)
        if cur is None or weight > cur["weight"]:
            G.add_edge(src, dst, relation=rel, kind=kind, weight=weight, evidence=evidence)

    admin_types = [t.lower() for t in cfg["admin_logon_types"]]
    for user, host, eids in con.execute(
            f"""SELECT user, host, list(event_id ORDER BY ts, event_id)[1:5] FROM {src}
               WHERE event_type = 'auth_success' AND lower(logon_type) IN (SELECT unnest(?))
                 AND user IS NOT NULL AND host IS NOT NULL AND ts BETWEEN ? AND ?
               GROUP BY user, host ORDER BY user, host""", [admin_types, start, end]).fetchall():
        add(f"account:{user}", f"host:{host}", "ADMIN_TO", "observed", w["observed_admin_to"],
            {"event_ids": eids, "text": f"observed interactive logon of {user} on {host}"})
    for user, host, eids in con.execute(
            f"""SELECT user, host, list(event_id ORDER BY ts, event_id)[1:5] FROM {src}
               WHERE event_type = 'auth_success' AND lower(logon_type) IN (SELECT unnest(?))
                 AND user IS NOT NULL AND host IS NOT NULL AND ts BETWEEN ? AND ?
               GROUP BY user, host ORDER BY user, host""",
            [[t.lower() for t in cfg["exposure_logon_types"]], start, end]).fetchall():
        add(f"host:{host}", f"account:{user}", "CREDENTIAL_EXPOSURE", "inferred", w["credential_exposure"],
            {"event_ids": eids, "text": f"{user} had an interactive session on {host}; an attacker there could obtain it"})
    for tgt, host, grp, eids in con.execute(
            f"""SELECT target_user, host, group_name, list(event_id ORDER BY ts, event_id)[1:5] FROM {src}
               WHERE event_type = 'group_add' AND target_user IS NOT NULL AND host IS NOT NULL
                 AND lower(group_name) IN (SELECT unnest(?)) AND ts BETWEEN ? AND ?
               GROUP BY ALL ORDER BY ALL""",
            [[g.lower() for g in cfg["local_admin_groups"]], start, end]).fetchall():
        add(f"account:{tgt}", f"host:{host}", "ADMIN_TO", "observed", w["observed_member_of"],
            {"event_ids": eids, "text": f"{tgt} added to local group {grp} on {host}"})
    fx = config.assets()
    if fx:
        disabled = {a["account"] for a in fx.get("accounts", []) if not a.get("enabled", True)}
        for i, r in enumerate(fx.get("admin_to", [])):
            if r["account"] not in disabled:
                add(f"account:{r['account']}", f"host:{r['host']}", "ADMIN_TO", "configured", w["configured"],
                    {"fixture": f"assets.yaml admin_to[{i}]", "text": f"configured: {r['account']} admin to {r['host']}"})
        for i, r in enumerate(fx.get("memberships", [])):
            if r["account"] not in disabled:
                add(f"account:{r['account']}", f"group:{r['group']}", "MEMBER_OF", "configured", w["configured"],
                    {"fixture": f"assets.yaml memberships[{i}]", "text": f"configured: {r['account']} member of {r['group']}"})
        for grp, spec in sorted(fx.get("groups", {}).items()):
            for h in spec.get("admin_to", []):
                add(f"group:{grp}", f"host:{h}", "GROUP_ADMIN_TO", "configured", w["configured"],
                    {"fixture": f"assets.yaml groups.{grp}", "text": f"configured: group {grp} admin to {h}"})
    return G, fx is not None


def search(G: nx.DiGraph, C: dict[str, dict], hop_limit: int) -> dict[str, dict]:
    """Step 3: max-product reach with a hop limit (Bellman-Ford over -log weights, H rounds)."""
    best: dict[str, dict] = {n: {"reach": c["weight"], "hops": 0, "path": [n], "start": n} for n, c in sorted(C.items())}
    frontier = dict(best)
    for _ in range(hop_limit):
        nxt = {}
        for u in sorted(frontier):
            if u not in G:
                continue
            for v in sorted(G.successors(u)):
                r = frontier[u]["reach"] * G[u][v]["weight"]
                cur = best.get(v)
                if cur is None or r > cur["reach"] + 1e-12:
                    rec = {"reach": r, "hops": frontier[u]["hops"] + 1, "path": frontier[u]["path"] + [v],
                           "start": frontier[u]["start"]}
                    best[v] = rec
                    nxt[v] = rec
        frontier = nxt
        if not frontier:
            break
    return best


def reachability(con: duckdb.DuckDBPyConnection, incident: dict, gid: dict, remove_accounts: list[str] | None = None,
                 G: nx.DiGraph | None = None) -> dict:
    cfg = _cfg()
    C = compromised_set(incident, gid)
    fixture = config.assets() is not None  # same test context_graph applies
    if G is None:
        G, fixture = context_graph(con, incident)
    G = G.copy()
    removed = []
    for acct in remove_accounts or []:
        node = f"account:{acct}"
        if node in G:
            for u, v, d in sorted(list(G.in_edges(node, data=True)) + list(G.out_edges(node, data=True))):
                removed.append(_edge(u, v, d))
            G.remove_node(node)
        C.pop(node, None)
    best = search(G, C, cfg["hop_limit"])
    thr = assets.critical_threshold()
    rows = []
    for node, rec in sorted(best.items()):
        if not node.startswith("host:") or node in C or rec["reach"] < cfg["min_reach"]:
            continue
        host = node.split(":", 1)[1]
        crit = assets.criticality(host)
        path_edges = [_edge(a, b, G[a][b]) for a, b in zip(rec["path"], rec["path"][1:])]
        kinds = sorted({e["kind"] for e in path_edges})
        rows.append({"asset": host, "criticality": crit, "critical": crit >= thr, "reach": round(rec["reach"], 4),
                     "rank_score": round(crit * rec["reach"], 4), "hops": rec["hops"], "start": rec["start"],
                     "start_evidence_event_ids": C[rec["start"]]["evidence_event_ids"][:10],
                     "path": rec["path"], "path_edges": path_edges,
                     "supporting_event_ids": sorted({x for e in path_edges for x in e["evidence"].get("event_ids", [])}),
                     "explanation": f"{rec['start'].split(':', 1)[1]} -> {host} in {rec['hops']} hop(s) via "
                                    + " -> ".join(e["relation"] for e in path_edges)
                                    + f" ({', '.join(kinds)}); reach {rec['reach']:.2f}"})
    rows.sort(key=lambda r: (-r["rank_score"], r["asset"]))
    total_crit = _total_critical()
    return {"compromised": [C[k] for k in sorted(C)], "reachable": rows,
            "critical_reachable": sum(r["critical"] for r in rows), "total_critical_assets": total_crit,
            "mode": "observed+configured" if fixture else "observed-only (no assets.yaml fixture)",
            "hop_limit": cfg["hop_limit"], "min_reach": cfg["min_reach"], "removed_relationships": removed,
            "graph": {"nodes": G.number_of_nodes(), "edges": G.number_of_edges()}}


def simulate(con, incident: dict, gid: dict, actions: list[dict]) -> dict:
    cfg = _cfg()
    unsupported = [a for a in actions if a.get("type") != "disable_account"]
    if unsupported:
        raise ValueError(f"unsupported action(s) in Phase 1: {[a.get('type') for a in unsupported]}; only disable_account")
    G, _ = context_graph(con, incident)
    before = reachability(con, incident, gid, G=G)
    targets = [a["target"].lower() for a in actions]
    after = reachability(con, incident, gid, remove_accounts=targets, G=G)
    b_set = {r["asset"] for r in before["reachable"] if r["critical"]}
    a_set = {r["asset"] for r in after["reachable"] if r["critical"]}
    X, Y = before["critical_reachable"], after["critical_reachable"]
    return {"actions": actions, "simulation_only": True,
            "before_critical_reachable": X, "after_critical_reachable": Y,
            "no_longer_reachable_critical": sorted(b_set - a_set),
            "still_reachable_critical": [{"asset": r["asset"], "explanation": r["explanation"],
                                          "supporting_event_ids": r["supporting_event_ids"]}
                                         for r in after["reachable"] if r["critical"]],
            "removed_relationships": after["removed_relationships"],
            "removed_from_compromised_set": [f"account:{t}" for t in targets],
            "caveat": "Cached tickets or tokens are not modelled (dossier §14).",
            "disclaimer": cfg["disclaimer"].format(X=X, Y=Y)}


def candidate_actions(con, incident: dict, gid: dict, G: nx.DiGraph | None = None) -> list[dict]:
    """Step 5 (subset): rank disable_account over accounts in or reachable from the compromised set."""
    if G is None:
        G, _ = context_graph(con, incident)
    base = reachability(con, incident, gid, G=G)
    accts = sorted({n for n in (list(G.nodes) + [c["node"] for c in base["compromised"]])
                    if n.startswith("account:")} & set(_reached_accounts(G, base)))
    out = []
    for a in accts[:20]:
        r = reachability(con, incident, gid, remove_accounts=[a.split(":", 1)[1]], G=G)
        out.append({"action": {"type": "disable_account", "target": a.split(":", 1)[1]},
                    "before": base["critical_reachable"], "after": r["critical_reachable"],
                    "reduction": base["critical_reachable"] - r["critical_reachable"]})
    out.sort(key=lambda x: (-x["reduction"], x["action"]["target"]))
    return out


def _reached_accounts(G, base) -> list[str]:
    nodes = {c["node"] for c in base["compromised"]}
    for r in base["reachable"]:
        nodes |= {p for p in r["path"] if p.startswith("account:")}
    return sorted(nodes)


def _total_critical() -> int:
    fx = config.assets()
    if not fx:
        return 0
    hosts = set()
    for h in [r["host"] for r in fx.get("admin_to", [])] + [h for g in fx.get("groups", {}).values() for h in g.get("admin_to", [])]:
        hosts.add(h)
    return sum(assets.criticality(h) >= assets.critical_threshold() for h in hosts)


def _edge(u, v, d) -> dict:
    return {"src": u, "dst": v, "relation": d["relation"], "kind": d["kind"], "weight": d["weight"],
            "log_weight": round(math.log(d["weight"]), 4), "evidence": d["evidence"]}
