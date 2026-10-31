"""Enrich the Neo4j knowledge graph with one live batch (forgetrace/live/engine.py; docs/wp/LIVE.md).

Why this exists: in live use the graph is the long-term memory - raw Parquet ages out to cold storage,
but entities, their relationships and the alerts linking them stay. Each batch therefore *accumulates*
rather than replaces: entity nodes keep first_seen / last_seen / event counts, relationships keep
counts, byte totals, first/last times and a few sample raw event_ids, alerts are upserted by their
stable knowledge-base id, and correlation edges are merged. A :Batch marker makes a replayed batch a
no-op. Afterwards RELATED links / campaigns (long-range, any time gap) and incidents (windowed LEADS_TO
components with >= 2 tactics) are recomputed over the graph, which costs O(alerts), not O(logs).
All values are parameters; no log-derived string is ever interpolated into Cypher.
"""
from __future__ import annotations

import json
import time
from typing import Any

import duckdb

from forgetrace import assets, config
from forgetrace.graph.loader import LABELS, ROLE_LABEL, SCHEMA, connect, graph_config, uid

ACC = """ON CREATE SET e.count = r.count, e.first = r.first, e.last = r.last, e.sample_event_ids = r.sample
         ON MATCH SET e.count = e.count + r.count,
                      e.first = CASE WHEN r.first < e.first THEN r.first ELSE e.first END,
                      e.last = CASE WHEN r.last > e.last THEN r.last ELSE e.last END,
                      e.sample_event_ids = CASE WHEN size(e.sample_event_ids) < 5
                                                THEN (e.sample_event_ids + r.sample)[0..5] ELSE e.sample_event_ids END"""
ENTITY = """ON CREATE SET n.first_seen = r.first, n.last_seen = r.last, n.events = r.count
            ON MATCH SET n.events = n.events + r.count,
                         n.first_seen = CASE WHEN r.first < n.first_seen THEN r.first ELSE n.first_seen END,
                         n.last_seen = CASE WHEN r.last > n.last_seen THEN r.last ELSE n.last_seen END"""


def _rows(con, sql: str, params: list | None = None) -> list[dict]:
    cur = con.execute(sql, params or [])
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


def batch_rows(con: duckdb.DuckDBPyConnection, ws: str, updated: list[dict], edges: list[dict]) -> dict[str, list[dict]]:
    """Rows for one batch from `batch_events` (the new raw events) and the updated knowledge-base alerts."""
    k = graph_config()["sample_event_ids"]
    agg = f"count(*) AS count, min(ts) AS first, max(ts) AS last, list(event_id ORDER BY ts, event_id)[1:{k}] AS sample"
    rows: dict[str, list[dict]] = {}
    alert_ips = sorted({ip for a in updated for r in ("src_ip", "dst_ip", "host_ip")
                        for ip in json.loads(a["entities"]).get(r, [])})
    rows["users"] = _rows(con, f'SELECT "user" AS key, {agg} FROM batch_events WHERE "user" IS NOT NULL GROUP BY 1')
    rows["hosts"] = _rows(con, f"SELECT host AS key, {agg} FROM batch_events WHERE host IS NOT NULL GROUP BY 1")
    # addresses: internal ones and those named by alerts (external fan-out stays in Parquet, D-73)
    rows["ips"] = _rows(con, f"""SELECT ip AS key, any_value(ext) AS external, count(*) AS count, min(ts) AS first,
                                        max(ts) AS last, list(event_id ORDER BY ts, event_id)[1:{k}] AS sample FROM (
            SELECT src_ip AS ip, src_is_external AS ext, ts, event_id FROM batch_events WHERE src_ip IS NOT NULL
            UNION ALL SELECT dst_ip, dst_is_external, ts, event_id FROM batch_events WHERE dst_ip IS NOT NULL)
            WHERE ext = false OR ip IN (SELECT unnest(?)) GROUP BY ip""", [alert_ips])
    for name, et in (("logged_on", "auth_success"), ("failed_logon", "auth_fail")):
        rows[name] = _rows(con, f"""SELECT "user" AS u, host AS h, {agg} FROM batch_events
                                    WHERE event_type = ? AND "user" IS NOT NULL AND host IS NOT NULL GROUP BY 1, 2""", [et])
    rows["assigned"] = _rows(con, f"""SELECT host_ip AS ip, host AS h, {agg} FROM batch_events
                                      WHERE host_ip IS NOT NULL AND host IS NOT NULL GROUP BY 1, 2""")
    rows["connected"] = _rows(con, f"""SELECT src_ip AS s, dst_ip AS d, sum(coalesce(bytes_out, 0)) AS bytes_out, {agg}
        FROM batch_events WHERE src_ip IS NOT NULL AND dst_ip IS NOT NULL
          AND ((src_is_external = false AND dst_is_external = false)
               OR (src_ip IN (SELECT unnest(?)) AND dst_ip IN (SELECT unnest(?))))
        GROUP BY 1, 2""", [alert_ips, alert_ips])
    rc = config.load_yaml(config.CONFIG_DIR / "reach.yml")
    rows["admin"] = _rows(con, f"""SELECT target_user AS u, host AS h, {agg} FROM batch_events
        WHERE event_type = 'group_add' AND target_user IS NOT NULL AND host IS NOT NULL
          AND lower(group_name) IN (SELECT unnest(?)) GROUP BY 1, 2""", [[g.lower() for g in rc["local_admin_groups"]]])
    for name in ("logged_on", "failed_logon", "admin"):
        for r in rows[name]:
            r["user_uid"], r["host_uid"] = uid(ws, f"user:{r['u']}"), uid(ws, f"host:{r['h']}")
    for r in rows["assigned"]:
        r["ip_uid"], r["host_uid"] = uid(ws, f"ip:{r['ip']}"), uid(ws, f"host:{r['h']}")
    for r in rows["connected"]:
        r["src_uid"], r["dst_uid"] = uid(ws, f"ip:{r['s']}"), uid(ws, f"ip:{r['d']}")
    for lab, name in (("user", "users"), ("host", "hosts"), ("ip", "ips")):
        for r in rows[name]:
            r["uid"] = uid(ws, f"{lab}:{r['key']}")
            if lab == "host":
                r["criticality"], r["asset_type"] = assets.criticality(r["key"]), assets.asset_type(r["key"])
    rows["alerts"], rows["involves"] = [], []
    for a in updated:
        au = uid(ws, f"alert:{a['uid']}")
        rows["alerts"].append({"uid": au, "kb_uid": a["uid"], "rule_id": a["rule_id"], "title": a["rule_title"],
                               "technique_id": a["technique_id"], "tactic": a["tactic"], "severity": a["severity"],
                               "ts_first": a["ts_first"].isoformat(), "ts_last": a["ts_last"].isoformat(),
                               "member_count": a["member_count"], "sample_event_ids": json.loads(a["sample_event_ids"])[:20],
                               "technique_uid": uid(ws, a["technique_id"]), "group_id": a["uid"]})
        for role, vals in json.loads(a["entities"]).items():
            lab = ROLE_LABEL.get(role)
            for v in (vals if lab else [])[:200]:
                rows["involves"].append({"alert_uid": au, "label": lab, "uid": uid(ws, f"{lab.lower()}:{v}"),
                                         "key": v, "role": role})
    rows["leads_to"] = [{"src": uid(ws, f"alert:{e['src_group_id']}"), "dst": uid(ws, f"alert:{e['dst_group_id']}"),
                         "edge_id": e["edge_id"], "score": float(e["score"]), "score_terms": json.dumps(e["score_terms"]),
                         "reasons_json": json.dumps(e["reasons"]), "reason_types": sorted({r["type"] for r in e["reasons"]}),
                         "delta_t_s": float(e["delta_t_s"]), "evidence_event_ids": e.get("evidence_event_ids", [])}
                        for e in edges]
    att = config.attack()
    rows["tactic"] = [{"uid": uid(ws, t), "name": t, "ordinal": v["ordinal"]} for t, v in att["tactics"].items()]
    rows["technique"] = [{"uid": uid(ws, t), "id": t, "name": v["name"],
                          "tactic_uids": [uid(ws, ta) for ta in v.get("tactics", []) if ta in att["tactics"]]}
                         for t, v in att["techniques"].items()]
    return rows


WRITES = [
    ("tactic", "UNWIND $rows AS r MERGE (t:Tactic {uid: r.uid}) SET t.ws = $ws, t.name = r.name, t.ordinal = r.ordinal"),
    ("technique", """UNWIND $rows AS r MERGE (t:Technique {uid: r.uid}) SET t.ws = $ws, t.id = r.id, t.name = r.name
                     WITH t, r UNWIND r.tactic_uids AS tu MATCH (ta:Tactic {uid: tu}) MERGE (t)-[:IN_TACTIC]->(ta)"""),
    ("users", f"UNWIND $rows AS r MERGE (n:User {{uid: r.uid}}) {ENTITY} SET n.ws = $ws, n.name = r.key"),
    ("hosts", f"""UNWIND $rows AS r MERGE (n:Host {{uid: r.uid}}) {ENTITY}
                  SET n.ws = $ws, n.name = r.key, n.criticality = r.criticality, n.asset_type = r.asset_type"""),
    ("ips", f"UNWIND $rows AS r MERGE (n:IP {{uid: r.uid}}) {ENTITY} SET n.ws = $ws, n.addr = r.key, n.external = r.external"),
    ("alerts", """UNWIND $rows AS r MERGE (a:Alert {uid: r.uid})
                  SET a.ws = $ws, a.group_id = r.group_id, a.rule_id = r.rule_id, a.title = r.title,
                      a.technique_id = r.technique_id, a.tactic = r.tactic, a.severity = r.severity,
                      a.ts_first = r.ts_first, a.ts_last = r.ts_last, a.member_count = r.member_count,
                      a.sample_event_ids = r.sample_event_ids
                  WITH a, r OPTIONAL MATCH (t:Technique {uid: r.technique_uid})
                  FOREACH (_ IN CASE WHEN t IS NULL THEN [] ELSE [1] END | MERGE (a)-[:MAPS_TO]->(t))"""),
    ("involves", """UNWIND $rows AS r MATCH (a:Alert {uid: r.alert_uid})
                    CALL (r) {
                      WITH r WHERE r.label = 'User' MERGE (e:User {uid: r.uid}) SET e.ws = $ws, e.name = r.key RETURN e
                      UNION WITH r WHERE r.label = 'Host' MERGE (e:Host {uid: r.uid}) SET e.ws = $ws, e.name = r.key RETURN e
                      UNION WITH r WHERE r.label = 'IP' MERGE (e:IP {uid: r.uid}) SET e.ws = $ws, e.addr = r.key RETURN e
                      UNION WITH r WHERE r.label = 'Domain' MERGE (e:Domain {uid: r.uid}) SET e.ws = $ws, e.name = r.key RETURN e
                    }
                    MERGE (a)-[:INVOLVES {role: r.role}]->(e)"""),
    ("leads_to", """UNWIND $rows AS r MATCH (a:Alert {uid: r.src}), (b:Alert {uid: r.dst})
                    MERGE (a)-[e:LEADS_TO {edge_id: r.edge_id}]->(b)
                    SET e.score = r.score, e.score_terms = r.score_terms, e.reasons_json = r.reasons_json,
                        e.reason_types = r.reason_types, e.delta_t_s = r.delta_t_s, e.evidence_event_ids = r.evidence_event_ids"""),
    ("logged_on", f"""UNWIND $rows AS r MERGE (u:User {{uid: r.user_uid}}) SET u.ws = $ws, u.name = r.u
                      MERGE (h:Host {{uid: r.host_uid}}) SET h.ws = $ws, h.name = r.h
                      MERGE (u)-[e:LOGGED_ON]->(h) {ACC}"""),
    ("failed_logon", f"""UNWIND $rows AS r MERGE (u:User {{uid: r.user_uid}}) SET u.ws = $ws, u.name = r.u
                         MERGE (h:Host {{uid: r.host_uid}}) SET h.ws = $ws, h.name = r.h
                         MERGE (u)-[e:FAILED_LOGON]->(h) {ACC}"""),
    ("assigned", f"""UNWIND $rows AS r MERGE (i:IP {{uid: r.ip_uid}}) SET i.ws = $ws, i.addr = r.ip
                     MERGE (h:Host {{uid: r.host_uid}}) SET h.ws = $ws, h.name = r.h
                     MERGE (i)-[e:ASSIGNED_TO]->(h) {ACC}"""),
    ("connected", f"""UNWIND $rows AS r MERGE (s:IP {{uid: r.src_uid}}) SET s.ws = $ws, s.addr = r.s
                      MERGE (d:IP {{uid: r.dst_uid}}) SET d.ws = $ws, d.addr = r.d
                      MERGE (s)-[e:CONNECTED_TO]->(d) {ACC}
                      SET e.bytes_out = coalesce(e.bytes_out, 0) + r.bytes_out"""),
    ("admin", f"""UNWIND $rows AS r MERGE (u:User {{uid: r.user_uid}}) SET u.ws = $ws, u.name = r.u
                  MERGE (h:Host {{uid: r.host_uid}}) SET h.ws = $ws, h.name = r.h
                  MERGE (u)-[e:ADMIN_TO {{kind: 'observed'}}]->(h) {ACC}"""),
]


def sync_batch(con: duckdb.DuckDBPyConnection, ws: str, batch_no: int, updated: list[dict], edges: list[dict]) -> dict[str, Any]:
    cfg = graph_config()
    drv, why = connect(cfg)
    if drv is None:
        return {"skipped": why}
    t0 = time.perf_counter()
    try:
        with drv.session(database=cfg["database"]) as s:
            for stmt in SCHEMA + ["CREATE CONSTRAINT batch_uid IF NOT EXISTS FOR (n:Batch) REQUIRE n.uid IS UNIQUE"]:
                s.run(stmt).consume()
            bu = uid(ws, f"batch:{batch_no}")
            if s.run("MATCH (b:Batch {uid: $u}) RETURN count(b) AS c", u=bu).single()["c"]:
                return {"skipped": f"batch {batch_no} already applied"}
            rows = batch_rows(con, ws, updated, edges)
            counts = {}
            for step, cypher in WRITES:
                data = rows.get(step, [])
                for i in range(0, len(data), cfg["batch_rows"]):
                    chunk = data[i:i + cfg["batch_rows"]]
                    s.execute_write(lambda tx, c=chunk, q=cypher: tx.run(q, rows=c, ws=ws).consume())
                counts[step] = len(data)
            s.run("MERGE (b:Batch {uid: $u}) SET b.ws = $ws, b.batch = $n, b.applied_at = datetime()",
                  u=bu, ws=ws, n=batch_no).consume()
        from forgetrace.graph.campaigns import link_and_group, live_incidents

        camp = link_and_group(drv, ws, database=cfg["database"])
        inc = live_incidents(drv, ws, database=cfg["database"])
        return {"rows": counts, "campaigns": camp, "incidents": inc, "seconds": round(time.perf_counter() - t0, 3)}
    except Exception as e:  # never fail the live loop because of the graph
        return {"skipped": f"graph sync failed: {type(e).__name__}: {str(e)[:300]}"}
    finally:
        drv.close()


__all__ = ["sync_batch", "batch_rows", "LABELS"]
