"""Long-range correlation in the graph: campaigns (docs/wp/GR-2.md).

Why this exists: the windowed correlator links alert groups at most 6 h apart (dossier §12), which
keeps edges explainable but cannot connect slow attacks - a scan on Monday, a web shell on Tuesday,
exfiltration on Thursday from the same address. The mentor's reason for a graph database is exactly
this: when data keeps arriving, relationships between far-apart points are a graph traversal, not a
time-window join. Here alerts that share an *uncommon* entity (an address, account, subnet or domain
seen in at most `max_entity_alerts` alerts) are linked by RELATED edges whatever the gap; LEADS_TO
(windowed) and RELATED edges together form connected components, and a component that spans at
least two ATT&CK tactics becomes a :Campaign. High-degree entities (the firewall's own management
address, a DNS resolver) are excluded, as the degree penalty F does in §12, so popularity never links.

The graph never replaces incidents: campaigns are an additional, long-range view, each carrying the
shared entities and gaps that justify it. Everything is recomputed per workspace and idempotent.
"""
from __future__ import annotations

import time
from collections import defaultdict
from typing import Any

from forgetrace.graph.loader import graph_config, uid

LINK_LABELS = ["IP", "User", "Domain"]  # hosts are too often shared by unrelated activity on one server


def link_and_group(driver, ws: str, max_entity_alerts: int | None = None, min_tactics: int = 2,
                   database: str | None = None) -> dict[str, Any]:
    cfg = graph_config()
    k = max_entity_alerts or cfg.get("campaigns", {}).get("max_entity_alerts", 25)
    db = database or cfg["database"]
    t0 = time.perf_counter()
    with driver.session(database=db) as s:
        s.run("MATCH (c:Campaign {ws: $ws}) DETACH DELETE c", ws=ws).consume()
        s.run("MATCH (:Alert {ws: $ws})-[r:RELATED]->() DELETE r", ws=ws).consume()
        s.run("CREATE CONSTRAINT campaign_uid IF NOT EXISTS FOR (n:Campaign) REQUIRE n.uid IS UNIQUE").consume()
        related = s.run("""
            MATCH (e)<-[:INVOLVES]-(a:Alert {ws: $ws})
            WHERE any(l IN labels(e) WHERE l IN $labels)
            WITH e, collect(DISTINCT a) AS alerts
            WHERE size(alerts) >= 2 AND size(alerts) <= $k
            UNWIND alerts AS a
            UNWIND alerts AS b
            WITH e, a, b, size(alerts) AS deg
            WHERE a.ts_first < b.ts_first OR (a.ts_first = b.ts_first AND a.uid < b.uid)
            MERGE (a)-[r:RELATED {via: e.uid}]->(b)
            SET r.entity_alerts = deg,
                r.gap_s = duration.inSeconds(datetime(a.ts_last), datetime(b.ts_first)).seconds
            RETURN count(r) AS n""", ws=ws, labels=LINK_LABELS, k=k).single()["n"]
        alerts = s.run("""MATCH (a:Alert {ws: $ws})
                          RETURN a.uid AS uid, a.tactic AS tactic, a.technique_id AS tech,
                                 a.ts_first AS t0, a.ts_last AS t1""", ws=ws).data()
        links = s.run("""MATCH (a:Alert {ws: $ws})-[r:LEADS_TO|RELATED]->(b:Alert)
                         RETURN a.uid AS a, b.uid AS b, type(r) AS t, r.gap_s AS gap""", ws=ws).data()
        info = {a["uid"]: a for a in alerts}
        parent = {u: u for u in info}

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        for ln in links:
            ra, rb = find(ln["a"]), find(ln["b"])
            if ra != rb:
                parent[max(ra, rb)] = min(ra, rb)
        comps: dict[str, list[str]] = defaultdict(list)
        for u in info:
            comps[find(u)].append(u)
        rel_in: dict[str, int] = defaultdict(int)
        max_gap: dict[str, float] = defaultdict(float)
        for ln in links:
            r = find(ln["a"])
            if ln["t"] == "RELATED":
                rel_in[r] += 1
                max_gap[r] = max(max_gap[r], float(ln["gap"] or 0))
        rows = []
        for root, members in comps.items():
            tactics = sorted({info[m]["tactic"] for m in members})
            if len(members) < 2 or len(tactics) < min_tactics:
                continue
            members.sort(key=lambda m: (info[m]["t0"], m))
            rows.append({"members": members, "tactics": tactics,
                         "techniques": sorted({info[m]["tech"] for m in members}),
                         "ts_first": info[members[0]]["t0"], "ts_last": max(info[m]["t1"] for m in members),
                         "related_edges": rel_in[root], "max_related_gap_s": max_gap[root]})
        rows.sort(key=lambda r: (r["ts_first"], r["members"][0]))
        for i, r in enumerate(rows, 1):
            r["uid"], r["campaign_id"] = uid(ws, f"campaign:{i}"), i
        s.execute_write(lambda tx: tx.run("""
            UNWIND $rows AS r
            MERGE (c:Campaign {uid: r.uid})
            SET c.ws = $ws, c.campaign_id = r.campaign_id, c.tactics = r.tactics, c.techniques = r.techniques,
                c.ts_first = r.ts_first, c.ts_last = r.ts_last, c.alerts = size(r.members),
                c.related_edges = r.related_edges, c.max_related_gap_s = r.max_related_gap_s,
                c.long_range = r.max_related_gap_s > $window_s
            WITH c, r UNWIND range(0, size(r.members) - 1) AS i
            MATCH (a:Alert {uid: r.members[i]}) MERGE (c)-[x:INCLUDES]->(a) SET x.order = i + 1""",
                                          rows=rows, ws=ws, window_s=6 * 3600).consume())
    return {"related_edges": related, "components_checked": len(comps), "campaigns": len(rows),
            "long_range_campaigns": sum(r["max_related_gap_s"] > 6 * 3600 for r in rows),
            "max_entity_alerts": k, "seconds": round(time.perf_counter() - t0, 3)}


def campaigns(driver, ws: str, database: str | None = None) -> list[dict[str, Any]]:
    with driver.session(database=database or graph_config()["database"]) as s:
        return s.run("""MATCH (c:Campaign {ws: $ws})-[x:INCLUDES]->(a:Alert)
                        WITH c, a ORDER BY x.order
                        RETURN c.campaign_id AS campaign_id, c.tactics AS tactics, c.techniques AS techniques,
                               c.ts_first AS ts_first, c.ts_last AS ts_last, c.long_range AS long_range,
                               c.max_related_gap_s AS max_related_gap_s,
                               collect({group_id: a.group_id, rule_id: a.rule_id, technique_id: a.technique_id,
                                        tactic: a.tactic, ts_first: a.ts_first}) AS alerts
                        ORDER BY c.campaign_id""", ws=ws).data()
