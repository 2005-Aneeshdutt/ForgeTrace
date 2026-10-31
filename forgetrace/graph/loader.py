"""Load a finished run into Neo4j: the relationship layer of the hybrid store (docs/wp/GR-1.md).

Why this exists: the mentor-recommended graph database makes relationships first-class - who
logged on where, which addresses talk, which alert leads to which, what an attacker can reach -
and can be updated incrementally as new batches arrive. Raw events stay in Parquet (columnar scans
for time-window rules, byte-offset evidence); the graph holds entities, alerts, correlation edges,
incidents and reachability relations, and every relationship keeps raw event_ids as evidence.

Relationship aggregates are computed in DuckDB over Parquet (multi-threaded GROUP BY), then written
with `UNWIND $rows MERGE ...` in batches. Keys are `uid = "<ws>|<natural key>"` under uniqueness
constraints, so MERGE makes a reload idempotent - the basis for live micro-batch updates (SC-4).
All values are passed as query parameters; log-derived strings are never interpolated into Cypher.
"""
from __future__ import annotations

import json
import os
import time
from collections.abc import Callable, Iterator
from typing import Any

import duckdb

from forgetrace import assets, config

LABELS = ["User", "Host", "IP", "Domain", "Group", "Alert", "Incident", "Technique", "Tactic", "Run"]
ROLE_LABEL = {"user": "User", "target_user": "User", "host": "Host", "src_ip": "IP", "dst_ip": "IP", "host_ip": "IP",
              "domain_name": "Domain"}


def graph_config() -> dict:
    cfg = config.load_yaml(config.CONFIG_DIR / "graph.yml")
    cfg["uri"] = os.environ.get("NEO4J_URI", cfg["uri"])
    cfg["user"] = os.environ.get("NEO4J_USER", cfg["user"])
    cfg["password"] = os.environ.get("NEO4J_PASSWORD", "forgetrace-dev")
    return cfg


def connect(cfg: dict | None = None):
    """Return (driver, None) or (None, reason). The pipeline never fails because the graph is down."""
    cfg = cfg or graph_config()
    try:
        from neo4j import GraphDatabase

        drv = GraphDatabase.driver(cfg["uri"], auth=(cfg["user"], cfg["password"]))
        drv.verify_connectivity()
        return drv, None
    except Exception as e:  # report, never raise into the pipeline
        return None, f"Neo4j not reachable at {cfg['uri']}: {type(e).__name__}: {e}"


def uid(ws: str, key: Any) -> str:
    return f"{ws}|{key}"


# ----------------------------------------------------------------------------- row builders (pure DuckDB)
def build_rows(con: duckdb.DuckDBPyConnection, ws: str, cfg: dict | None = None) -> dict[str, list[dict]]:
    """Everything the graph needs, as plain dict rows. No Neo4j access, so it is unit-testable."""
    cfg = cfg or graph_config()
    k = cfg["sample_event_ids"]
    rows: dict[str, list[dict]] = {}
    att = config.attack()
    rows["tactic"] = [{"uid": uid(ws, t), "name": t, "ordinal": v["ordinal"]} for t, v in att["tactics"].items()]
    rows["technique"] = [{"uid": uid(ws, t), "id": t, "name": v["name"],
                          "tactic_uids": [uid(ws, ta) for ta in v.get("tactics", []) if ta in att["tactics"]]}
                         for t, v in att["techniques"].items()]
    # alerts (alert groups) and the entities they involve
    alerts, involves = [], []
    for gid, rule, tech, tactic, ts_first, ts_last, cnt, mem, ents, sev, pm in con.execute(
            """SELECT group_id, rule_id, technique_id, tactic, ts_first, ts_last, raw_alert_count, member_event_ids,
                      entities, severity, p_malicious FROM alert_groups ORDER BY group_id""").fetchall():
        members = json.loads(mem)  # persisted run tables store each value as JSON text (pipeline.persist)
        alerts.append({"uid": uid(ws, f"alert:{gid}"), "group_id": gid, "rule_id": rule, "technique_id": tech,
                       "tactic": tactic, "ts_first": json.loads(ts_first), "ts_last": json.loads(ts_last),
                       "raw_alert_count": int(json.loads(cnt)), "member_count": len(members),
                       "sample_event_ids": members[:20], "severity": int(json.loads(sev)),
                       "p_malicious": None if pm in (None, "null") else float(json.loads(pm)),
                       "technique_uid": uid(ws, tech)})
        for role, vals in json.loads(ents).items():
            lab = ROLE_LABEL.get(role)
            for v in vals if lab else []:
                involves.append({"alert_uid": uid(ws, f"alert:{gid}"), "label": lab,
                                 "uid": uid(ws, f"{lab.lower()}:{v}"), "key": v, "role": role})
    rows["alert"], rows["involves"] = alerts, involves
    rows["leads_to"] = [{"src": uid(ws, f"alert:{s}"), "dst": uid(ws, f"alert:{d}"), "edge_id": eid,
                         "score": float(json.loads(sc)), "score_terms": st, "reasons_json": rs,
                         "reason_types": sorted({r["type"] for r in json.loads(rs)}),
                         "delta_t_s": float(json.loads(dt)), "evidence_event_ids": json.loads(ev or "[]")}
                        for eid, s, d, sc, st, rs, dt, ev in con.execute(
                            """SELECT edge_id, src_group_id, dst_group_id, score, score_terms, reasons, delta_t_s,
                                      evidence_event_ids FROM edges ORDER BY edge_id""").fetchall()]
    incs, contains, steps = [], [], []
    for (js,) in con.execute("SELECT json FROM incident_cache ORDER BY incident_id").fetchall():
        p = json.loads(js)
        iu = uid(ws, f"incident:{p['incident_id']}")
        incs.append({"uid": iu, "incident_id": p["incident_id"], "risk_score": p["risk_score"],
                     "severity": p["severity"], "status": p["status"], "tactics": p["tactics"],
                     "ts_first": p["ts_first"], "ts_last": p["ts_last"]})
        contains += [{"inc": iu, "alert": uid(ws, f"alert:{g}")} for g in p["group_ids"]]
        steps += [{"inc": iu, "alert": uid(ws, f"alert:{g}"), "order": i}
                  for i, g in enumerate(p["inferred"]["primary_path"]["group_ids"], 1)]
    rows["incident"], rows["contains"], rows["path_step"] = incs, contains, steps
    # entity relationships aggregated from raw events
    agg = f"count(*) AS n, min(ts) AS first, max(ts) AS last, list(event_id ORDER BY ts, event_id)[1:{k}] AS sample"
    for name, etype in (("logged_on", "auth_success"), ("failed_logon", "auth_fail")):
        rows[name] = [{"user_uid": uid(ws, f"user:{u}"), "user": u, "host_uid": uid(ws, f"host:{h}"), "host": h,
                       "count": n, "first": f, "last": la, "sample_event_ids": s, "logon_types": [t for t in lt if t]}
                      for u, h, n, f, la, s, lt in con.execute(
                          f"""SELECT user, host, {agg}, list(DISTINCT logon_type) FROM events
                              WHERE event_type = ? AND user IS NOT NULL AND host IS NOT NULL
                              GROUP BY user, host ORDER BY user, host""", [etype]).fetchall()]
    rows["assigned"] = [{"ip_uid": uid(ws, f"ip:{ip}"), "ip": ip, "host_uid": uid(ws, f"host:{h}"), "host": h,
                         "count": n, "first": f, "last": la, "sample_event_ids": s}
                        for ip, h, n, f, la, s in con.execute(
                            f"""SELECT host_ip, host, {agg} FROM events WHERE host_ip IS NOT NULL AND host IS NOT NULL
                                GROUP BY host_ip, host ORDER BY host_ip, host""").fetchall()]
    rows["connected"] = _connections(con, ws, cfg, alerts_ips=sorted(
        {r["key"] for r in involves if r["label"] == "IP"}))
    rows["admin"], rows["member_of"], rows["group_admin"] = _admin_relations(con, ws, k)
    users = {r["user"] for r in rows["logged_on"] + rows["failed_logon"]}
    hosts = {r["host"] for r in rows["logged_on"] + rows["failed_logon"] + rows["assigned"]}
    rows["host"] = [{"uid": uid(ws, f"host:{h}"), "name": h, "criticality": assets.criticality(h),
                     "asset_type": assets.asset_type(h)} for h in sorted(hosts | {r["key"] for r in involves
                                                                                  if r["label"] == "Host"})]
    rows["user"] = [{"uid": uid(ws, f"user:{u}"), "name": u} for u in sorted(users | {r["key"] for r in involves
                                                                                      if r["label"] == "User"})]
    return rows


def _connections(con, ws: str, cfg: dict, alerts_ips: list[str]) -> list[dict]:
    sc, k = cfg["connections"], cfg["sample_event_ids"]
    if sc.get("all"):
        where = "TRUE"
    else:
        parts = []
        if sc.get("internal_to_internal"):
            parts.append("(src_is_external = false AND dst_is_external = false)")
        if sc.get("touching_alert_ips") and alerts_ips:
            parts.append("(src_ip IN (SELECT unnest(?)) OR dst_ip IN (SELECT unnest(?)))")
        if not parts:
            return []
        where = " OR ".join(parts)
    params = [alerts_ips, alerts_ips] if "unnest(?)" in where else []
    return [{"src_uid": uid(ws, f"ip:{s}"), "src": s, "src_ext": se, "dst_uid": uid(ws, f"ip:{d}"), "dst": d,
             "dst_ext": de, "count": n, "bytes_out": int(b or 0), "ports": [p for p in ports if p is not None],
             "first": f, "last": la, "sample_event_ids": smp}
            for s, se, d, de, n, b, ports, f, la, smp in con.execute(
                f"""SELECT src_ip, any_value(src_is_external), dst_ip, any_value(dst_is_external), count(*),
                           sum(bytes_out), list(DISTINCT dst_port)[1:10], min(ts), max(ts),
                           list(event_id ORDER BY ts, event_id)[1:{k}]
                    FROM events WHERE src_ip IS NOT NULL AND dst_ip IS NOT NULL AND ({where})
                    GROUP BY src_ip, dst_ip ORDER BY src_ip, dst_ip""", params).fetchall()]


def _admin_relations(con, ws: str, k: int) -> tuple[list[dict], list[dict], list[dict]]:
    """Reachability relations (dossier §14): observed local-admin group adds plus the asset fixture."""
    rc = config.load_yaml(config.CONFIG_DIR / "reach.yml")
    admin = []
    src = "reach_events"
    try:
        con.execute("SELECT 1 FROM reach_events LIMIT 0")
    except duckdb.Error:
        src = "events"
    for tgt, host, n, first, last, sample in con.execute(
            f"""SELECT target_user, host, count(*), min(ts), max(ts), list(event_id ORDER BY ts, event_id)[1:{k}]
                FROM {src} WHERE event_type = 'group_add' AND target_user IS NOT NULL AND host IS NOT NULL
                  AND lower(group_name) IN (SELECT unnest(?)) GROUP BY ALL ORDER BY ALL""",
            [[g.lower() for g in rc["local_admin_groups"]]]).fetchall():
        admin.append({"user_uid": uid(ws, f"user:{tgt}"), "user": tgt, "host_uid": uid(ws, f"host:{host}"),
                      "host": host, "kind": "observed", "weight": rc["weights"]["observed_member_of"],
                      "sample_event_ids": sample, "count": n, "first": first, "last": last})
    member_of, group_admin = [], []
    fx = config.assets()
    if fx:
        w = rc["weights"]["configured"]
        disabled = {a["account"] for a in fx.get("accounts", []) if not a.get("enabled", True)}
        for r in fx.get("admin_to", []):
            if r["account"] not in disabled:
                admin.append({"user_uid": uid(ws, f"user:{r['account']}"), "user": r["account"],
                              "host_uid": uid(ws, f"host:{r['host']}"), "host": r["host"], "kind": "configured",
                              "weight": w, "sample_event_ids": [], "count": 0, "first": None, "last": None})
        for r in fx.get("memberships", []):
            if r["account"] not in disabled:
                member_of.append({"user_uid": uid(ws, f"user:{r['account']}"), "user": r["account"],
                                  "group_uid": uid(ws, f"group:{r['group']}"), "group": r["group"], "weight": w})
        for grp, spec in sorted(fx.get("groups", {}).items()):
            for h in spec.get("admin_to", []):
                group_admin.append({"group_uid": uid(ws, f"group:{grp}"), "group": grp,
                                    "host_uid": uid(ws, f"host:{h}"), "host": h, "weight": w})
    return admin, member_of, group_admin


# ----------------------------------------------------------------------------- Cypher
SCHEMA = [f"CREATE CONSTRAINT {lab.lower()}_uid IF NOT EXISTS FOR (n:{lab}) REQUIRE n.uid IS UNIQUE" for lab in LABELS] \
    + [f"CREATE INDEX {lab.lower()}_ws IF NOT EXISTS FOR (n:{lab}) ON (n.ws)" for lab in LABELS]

WRITES: list[tuple[str, str]] = [
    ("tactic", "UNWIND $rows AS r MERGE (t:Tactic {uid: r.uid}) SET t.ws = $ws, t.name = r.name, t.ordinal = r.ordinal"),
    ("technique", """UNWIND $rows AS r MERGE (t:Technique {uid: r.uid}) SET t.ws = $ws, t.id = r.id, t.name = r.name
                     WITH t, r UNWIND r.tactic_uids AS tu MATCH (ta:Tactic {uid: tu}) MERGE (t)-[:IN_TACTIC]->(ta)"""),
    ("user", "UNWIND $rows AS r MERGE (u:User {uid: r.uid}) SET u.ws = $ws, u.name = r.name"),
    ("host", """UNWIND $rows AS r MERGE (h:Host {uid: r.uid})
                SET h.ws = $ws, h.name = r.name, h.criticality = r.criticality, h.asset_type = r.asset_type"""),
    ("alert", """UNWIND $rows AS r MERGE (a:Alert {uid: r.uid})
                 SET a.ws = $ws, a.group_id = r.group_id, a.rule_id = r.rule_id, a.technique_id = r.technique_id,
                     a.tactic = r.tactic, a.ts_first = r.ts_first, a.ts_last = r.ts_last,
                     a.raw_alert_count = r.raw_alert_count, a.member_count = r.member_count,
                     a.sample_event_ids = r.sample_event_ids, a.severity = r.severity, a.p_malicious = r.p_malicious
                 WITH a, r OPTIONAL MATCH (t:Technique {uid: r.technique_uid})
                 FOREACH (_ IN CASE WHEN t IS NULL THEN [] ELSE [1] END | MERGE (a)-[:MAPS_TO]->(t))"""),
    ("involves", """UNWIND $rows AS r MATCH (a:Alert {uid: r.alert_uid})
                    CALL (r) {
                      WITH r WHERE r.label = 'User' MERGE (e:User {uid: r.uid}) SET e.ws = $ws, e.name = r.key RETURN e
                      UNION WITH r WHERE r.label = 'Host' MERGE (e:Host {uid: r.uid}) SET e.ws = $ws, e.name = r.key RETURN e
                      UNION WITH r WHERE r.label = 'IP' MERGE (e:IP {uid: r.uid}) SET e.ws = $ws, e.addr = r.key RETURN e
                      UNION WITH r WHERE r.label = 'Domain' MERGE (e:Domain {uid: r.uid}) SET e.ws = $ws, e.name = r.key RETURN e
                    }
                    MERGE (a)-[i:INVOLVES {role: r.role}]->(e)"""),
    ("leads_to", """UNWIND $rows AS r MATCH (a:Alert {uid: r.src}), (b:Alert {uid: r.dst})
                    MERGE (a)-[e:LEADS_TO {edge_id: r.edge_id}]->(b)
                    SET e.score = r.score, e.score_terms = r.score_terms, e.reasons_json = r.reasons_json,
                        e.reason_types = r.reason_types, e.delta_t_s = r.delta_t_s,
                        e.evidence_event_ids = r.evidence_event_ids"""),
    ("incident", """UNWIND $rows AS r MERGE (i:Incident {uid: r.uid})
                    SET i.ws = $ws, i.incident_id = r.incident_id, i.risk_score = r.risk_score, i.severity = r.severity,
                        i.status = r.status, i.tactics = r.tactics, i.ts_first = r.ts_first, i.ts_last = r.ts_last"""),
    ("contains", "UNWIND $rows AS r MATCH (i:Incident {uid: r.inc}), (a:Alert {uid: r.alert}) MERGE (i)-[:CONTAINS]->(a)"),
    ("path_step", """UNWIND $rows AS r MATCH (i:Incident {uid: r.inc}), (a:Alert {uid: r.alert})
                     MERGE (i)-[s:PATH_STEP]->(a) SET s.order = r.order"""),
    ("logged_on", """UNWIND $rows AS r MERGE (u:User {uid: r.user_uid}) SET u.ws = $ws, u.name = r.user
                     MERGE (h:Host {uid: r.host_uid}) SET h.ws = $ws, h.name = r.host
                     MERGE (u)-[e:LOGGED_ON]->(h)
                     SET e.count = r.count, e.first = r.first, e.last = r.last, e.logon_types = r.logon_types,
                         e.sample_event_ids = r.sample_event_ids"""),
    ("failed_logon", """UNWIND $rows AS r MERGE (u:User {uid: r.user_uid}) SET u.ws = $ws, u.name = r.user
                        MERGE (h:Host {uid: r.host_uid}) SET h.ws = $ws, h.name = r.host
                        MERGE (u)-[e:FAILED_LOGON]->(h)
                        SET e.count = r.count, e.first = r.first, e.last = r.last, e.sample_event_ids = r.sample_event_ids"""),
    ("assigned", """UNWIND $rows AS r MERGE (ip:IP {uid: r.ip_uid}) SET ip.ws = $ws, ip.addr = r.ip
                    MERGE (h:Host {uid: r.host_uid}) SET h.ws = $ws, h.name = r.host
                    MERGE (ip)-[e:ASSIGNED_TO]->(h)
                    SET e.count = r.count, e.first = r.first, e.last = r.last, e.sample_event_ids = r.sample_event_ids"""),
    ("connected", """UNWIND $rows AS r MERGE (s:IP {uid: r.src_uid}) SET s.ws = $ws, s.addr = r.src, s.external = r.src_ext
                     MERGE (d:IP {uid: r.dst_uid}) SET d.ws = $ws, d.addr = r.dst, d.external = r.dst_ext
                     MERGE (s)-[e:CONNECTED_TO]->(d)
                     SET e.count = r.count, e.bytes_out = r.bytes_out, e.ports = r.ports, e.first = r.first,
                         e.last = r.last, e.sample_event_ids = r.sample_event_ids"""),
    ("admin", """UNWIND $rows AS r MERGE (u:User {uid: r.user_uid}) SET u.ws = $ws, u.name = r.user
                 MERGE (h:Host {uid: r.host_uid}) SET h.ws = $ws, h.name = r.host
                 MERGE (u)-[e:ADMIN_TO {kind: r.kind}]->(h)
                 SET e.weight = r.weight, e.count = r.count, e.first = r.first, e.last = r.last,
                     e.sample_event_ids = r.sample_event_ids"""),
    ("member_of", """UNWIND $rows AS r MERGE (u:User {uid: r.user_uid}) SET u.ws = $ws, u.name = r.user
                     MERGE (g:Group {uid: r.group_uid}) SET g.ws = $ws, g.name = r.group
                     MERGE (u)-[e:MEMBER_OF]->(g) SET e.weight = r.weight, e.kind = 'configured'"""),
    ("group_admin", """UNWIND $rows AS r MERGE (g:Group {uid: r.group_uid}) SET g.ws = $ws, g.name = r.group
                       MERGE (h:Host {uid: r.host_uid}) SET h.ws = $ws, h.name = r.host
                       MERGE (g)-[e:ADMIN_TO {kind: 'configured'}]->(h) SET e.weight = r.weight"""),
]


def _batches(rows: list[dict], n: int) -> Iterator[list[dict]]:
    for i in range(0, len(rows), n):
        yield rows[i:i + n]


def load(driver, rows: dict[str, list[dict]], ws: str, run_meta: dict, replace: bool = True,
         progress: Callable[[str, int, int], None] | None = None, database: str = "neo4j") -> dict:
    """Write rows to Neo4j. replace=True first removes this workspace's previous graph (a full re-run);
    replace=False merges into it (incremental / live batches). Returns per-step counts and seconds."""
    report = progress or (lambda step, done, total: None)
    n = graph_config()["batch_rows"]
    out: dict[str, Any] = {"steps": {}}
    t0 = time.perf_counter()
    with driver.session(database=database) as s:
        for stmt in SCHEMA:
            s.run(stmt).consume()
        if replace:
            t = time.perf_counter()
            s.run("MATCH (n {ws: $ws}) CALL (n) { DETACH DELETE n } IN TRANSACTIONS OF 10000 ROWS", ws=ws).consume()
            out["steps"]["clear"] = {"seconds": round(time.perf_counter() - t, 3)}
        for step, cypher in WRITES:
            data = rows.get(step, [])
            t, done = time.perf_counter(), 0
            for batch in _batches(data, n):
                s.execute_write(lambda tx, b=batch: tx.run(cypher, rows=b, ws=ws).consume())
                done += len(batch)
                report(step, done, len(data))
            out["steps"][step] = {"rows": len(data), "seconds": round(time.perf_counter() - t, 3)}
        s.run("MERGE (r:Run {uid: $uid}) SET r.ws = $ws, r += $meta", uid=uid(ws, "run"), ws=ws,
              meta={k: v for k, v in run_meta.items() if isinstance(v, (str, int, float, bool))}).consume()
        counts = s.run("MATCH (n {ws: $ws}) RETURN labels(n)[0] AS label, count(*) AS c ORDER BY label", ws=ws).data()
        rels = s.run("MATCH (n {ws: $ws})-[r]->() RETURN type(r) AS type, count(*) AS c ORDER BY type", ws=ws).data()
    out["nodes"] = {r["label"]: r["c"] for r in counts}
    out["relationships"] = {r["type"]: r["c"] for r in rels}
    out["seconds"] = round(time.perf_counter() - t0, 3)
    return out


def load_run(con: duckdb.DuckDBPyConnection, ws: str, run_meta: dict, progress=None) -> dict:
    """Build rows from a run's DuckDB catalog and load them; returns stats or {'skipped': reason}."""
    cfg = graph_config()
    drv, why = connect(cfg)
    if drv is None:
        return {"skipped": why}
    try:
        t = time.perf_counter()
        rows = build_rows(con, ws, cfg)
        build_s = round(time.perf_counter() - t, 3)
        res = load(drv, rows, ws, run_meta, progress=progress, database=cfg["database"])
        res["build_rows_seconds"] = build_s
        res["uri"] = cfg["uri"]
        return res
    finally:
        drv.close()
