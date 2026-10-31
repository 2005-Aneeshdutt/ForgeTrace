"""`forgetrace run`: ingest -> detect -> correlate -> reach -> cache (dossier §10 process model).

Writes out/forgetrace.duckdb (detections, event_labels, alert_groups, edges, incidents, paths,
incident_cache, abstained, rules), out/incidents.json and out/run_stats.json (wall time, peak
RSS, config hash, dataset fingerprint). Stages run sequentially; the whole run is re-done from
scratch each time, so repeated runs never duplicate incidents.
"""
from __future__ import annotations

import json
import resource
import sys
import time
from datetime import datetime
from pathlib import Path

import duckdb
import pyarrow as pa

from forgetrace import assets, config, store
from forgetrace.correlate.correlate import correlate
from forgetrace.ingest.ingest import ingest, split_event_id
from forgetrace.reach.reach import REACH_EVENTS_SQL, candidate_actions, context_graph, reachability
from forgetrace.rules.engine import detect, load_rules, rules_summary


def _iso(v):
    if isinstance(v, datetime):
        return v.isoformat(timespec="microseconds") + "Z"
    raise TypeError(type(v))


def dumps(o) -> str:
    return json.dumps(o, default=_iso, sort_keys=True, separators=(",", ":"))


def peak_rss_bytes() -> int:
    r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(r if sys.platform == "darwin" else r * 1024)  # macOS reports bytes, Linux KiB


def display_id(eid: int) -> str:
    f, o = split_event_id(eid)
    return f"F{f:02d}:{o:012d}"


LOG_SUFFIXES = {".log", ".json", ".jsonl", ".ndjson", ".cef", ".txt"}


def expand_inputs(paths: list[Path]) -> list[Path]:
    """Files are taken as given; a directory contributes every log-like file inside it
    (recursive, sorted, hidden files and README skipped)."""
    out: list[Path] = []
    for p in paths:
        p = Path(p)
        if p.is_dir():
            out += sorted(f for f in p.rglob("*") if f.is_file() and f.suffix.lower() in LOG_SUFFIXES
                          and not any(part.startswith(".") for part in f.relative_to(p).parts)
                          and f.name.lower() != "readme.md")
        elif p.is_file():
            out.append(p)
        else:
            raise FileNotFoundError(f"input not found: {p}")
    if not out:
        raise ValueError("no log files found in the given input(s)")
    return out


def run(inputs: list[Path], out: Path, progress=None, dataset: str | None = None, graph: bool | None = None,
        workspace: str | None = None) -> dict:
    """progress(stage, fraction) is optional; used by the API's background runs and the CLI.
    graph=True (or FORGETRACE_GRAPH=1) loads the run into Neo4j after correlation (docs/wp/GR-1.md);
    an unreachable server skips that step with a reason and never fails the run."""
    import os

    graph = graph if graph is not None else os.environ.get("FORGETRACE_GRAPH") == "1"
    inputs = expand_inputs(inputs)
    report = progress or (lambda stage, frac: None)
    t0 = time.perf_counter()
    stages = {}
    out.mkdir(parents=True, exist_ok=True)
    db = out / "forgetrace.duckdb"
    if db.exists():
        db.unlink()
    t = time.perf_counter()
    report("ingest", 0.0)
    manifest = ingest(inputs, out, progress=lambda d, t: report("ingest", 0.8 * d / max(t, 1)), dataset=dataset)
    stages["ingest_s"] = round(time.perf_counter() - t, 3)
    con = store.connect(out)
    store.create_views(con, out)
    det, res, payloads, graph_stats = analyse(con, out, stages, report, graph, workspace,
                                              manifest_digest=manifest["manifest_digest"])
    con.close()
    (out / "incidents.json").write_text(dumps(payloads))
    stats = {"stages": stages, "wall_time_s": round(time.perf_counter() - t0, 3), "peak_rss_bytes": peak_rss_bytes(),
             "peak_rss_note": "ru_maxrss of the main process; parallel ingest workers are child processes "
                             "(tools/bench.py samples the whole process tree)",
             "config_hash": config.config_hash(), "code_version": config.CODE_VERSION,
             "dataset": {"files": manifest["files"], "manifest_digest": manifest["manifest_digest"]},
             "ingest": manifest["stats"], "ingest_parallel": manifest.get("parallel"),
             "detections": det["detections"], "rule_seconds": det["rule_seconds"],
             "alert_groups": len(res["groups"]), "candidate_edges": len(res["candidate_edges"]),
             "kept_edges": len(res["edges"]), "incidents": len(payloads), "abstained_components": len(res["abstained"]),
             "graph": graph_stats if graph else {"skipped": "graph step not requested (--graph or FORGETRACE_GRAPH=1)"}}
    stats["finished_at"] = datetime.now().astimezone().isoformat(timespec="seconds")
    (out / "run_stats.json").write_text(json.dumps(stats, indent=1, default=str))
    report("done", 1.0)
    return stats


def reanalyse(out: Path, graph: bool = False, workspace: str | None = None, progress=None) -> dict:
    """Re-run detect -> correlate -> reach -> persist (-> graph) on an already-ingested workspace (rule
    tuning, or a fix after ingest). The ingest of `out` is reused as is; run_stats records that."""
    report = progress or (lambda stage, frac: None)
    t0 = time.perf_counter()
    prev = json.loads((out / "run_stats.json").read_text()) if (out / "run_stats.json").exists() else {}
    manifest = json.loads((out / "files.json").read_text())
    db = out / "forgetrace.duckdb"
    if db.exists():
        db.unlink()
    con = store.connect(out)
    store.create_views(con, out)
    stages: dict = {}
    det, res, payloads, graph_stats = analyse(con, out, stages, report, graph, workspace,
                                              manifest_digest=manifest["manifest_digest"])
    con.close()
    (out / "incidents.json").write_text(dumps(payloads))
    stats = {"stages": stages, "analysis_wall_time_s": round(time.perf_counter() - t0, 3),
             "ingest_reused": {"stats": manifest["stats"], "parallel": manifest.get("parallel"),
                               "ingest_s_from_previous_run": prev.get("stages", {}).get("ingest_s")},
             "peak_rss_bytes": peak_rss_bytes(), "config_hash": config.config_hash(), "code_version": config.CODE_VERSION,
             "dataset": {"files": manifest["files"], "manifest_digest": manifest["manifest_digest"]},
             "ingest": manifest["stats"], "detections": det["detections"], "rule_seconds": det["rule_seconds"],
             "alert_groups": len(res["groups"]), "candidate_edges": len(res["candidate_edges"]),
             "kept_edges": len(res["edges"]), "incidents": len(payloads), "abstained_components": len(res["abstained"]),
             "graph": graph_stats if graph else {"skipped": "graph step not requested"},
             "finished_at": datetime.now().astimezone().isoformat(timespec="seconds")}
    (out / "run_stats.json").write_text(json.dumps(stats, indent=1, default=str))
    report("done", 1.0)
    return stats


def analyse(con: duckdb.DuckDBPyConnection, out: Path, stages: dict, report, graph: bool, workspace: str | None,
            manifest_digest: str | None = None, replace_graph: bool = True):
    """Detect -> correlate -> reach -> persist (-> graph) over everything ingested into `out` so far.
    Shared by the batch run and the streaming mode (forgetrace/stream.py)."""
    t = time.perf_counter()
    report("detect", 0.82)
    from forgetrace.rules.router import plan as route

    all_rules = load_rules()
    rules, run_plan, cap = route(con, all_rules, dataset=out.name)
    (out / "run_plan.json").write_text(json.dumps({**run_plan.model_dump(), "data": cap}, indent=1, default=str))
    det = detect(con, rules)
    det["run_plan"] = {"enabled": len(run_plan.enabled), "disabled": len(run_plan.disabled)}
    stages["detect_s"] = round(time.perf_counter() - t, 3)
    t = time.perf_counter()
    report("correlate", 0.88)
    res = correlate(con)
    stages["correlate_s"] = round(time.perf_counter() - t, 3)
    t = time.perf_counter()
    report("reach", 0.93)
    # Reachability only reads successful logons and group additions; materialise them once so each
    # incident's context graph scans a small table instead of every Parquet part (kept for the API).
    con.execute(REACH_EVENTS_SQL)
    payloads = build_payloads(con, res)
    stages["reach_and_cache_s"] = round(time.perf_counter() - t, 3)
    persist(con, res, payloads, rules)
    graph_stats = None
    if graph:
        from forgetrace.graph.loader import load_run as graph_load

        t = time.perf_counter()
        report("graph", 0.96)
        ws = workspace or out.name
        graph_stats = graph_load(con, ws, {"workspace": ws, "config_hash": config.config_hash(),
                                           "manifest_digest": manifest_digest or ""},
                                 progress=lambda step, done, total: report(f"graph:{step}", 0.96 + 0.03 * done / max(total, 1)))
        stages["graph_s"] = round(time.perf_counter() - t, 3)
    return det, res, payloads, graph_stats


# An incident record embeds at most this many member ids per node and timeline rows; full membership
# stays in the alert_groups table (GET /incidents/{id}/events pages it). On firex-50G the timestamp
# clamp yields groups with millions of members, and embedding them stalled the run (DECISIONS D-75).
MAX_PERSISTED_CANDIDATES = 100_000  # dropped candidate edges stored (all are scored; run_stats counts all)
MAX_NODE_MEMBERS = 10_000          # per node, incidents with <= LARGE_INCIDENT_NODES nodes
MAX_NODE_MEMBERS_LARGE = 200       # per node, larger incidents
LARGE_INCIDENT_NODES = 50
MAX_TIMELINE_EVENTS = 2_000        # per incident, in total
LARGE_INCIDENT_EDGES = 500
EDGE_EVIDENCE_LARGE = 10           # evidence ids kept per edge inside a large incident record


def build_payloads(con: duckdb.DuckDBPyConnection, res: dict) -> list[dict]:
    cfg = config.correlation()
    gid = {g["group_id"]: g for g in res["groups"]}
    eby = {e["edge_id"]: e for e in res["edges"]}
    payloads = []
    for inc in res["incidents"]:
        G, _ = context_graph(con, inc)  # built once per incident (Phase 1 built it twice)
        reach = reachability(con, inc, gid, G=G)
        cands = candidate_actions(con, inc, gid, G=G)
        nodes = []
        cap = MAX_NODE_MEMBERS if len(inc["group_ids"]) <= LARGE_INCIDENT_NODES else MAX_NODE_MEMBERS_LARGE
        for v in inc["group_ids"]:
            g = dict(gid[v])
            g["criticality"] = max([assets.criticality(h) for h in g["entities"]["host"]] or [assets.default_criticality()])
            if len(g["member_event_ids"]) > cap:
                g["member_event_ids"] = g["member_event_ids"][:cap]
                g["member_event_ids_truncated"] = True
            nodes.append(g)
        max_crit = max(n["criticality"] for n in nodes)
        rw = cfg["risk"]
        terms = {
            "severity": round(rw["severity"] * inc["max_severity"] / 4, 4),
            "criticality": round(rw["criticality"] * max_crit, 4),
            "tactic_depth": round(rw["tactic_depth"] * inc["deepest_tactic_ordinal"] / inc["max_tactic_ordinal"], 4),
            "reach": round(rw["reach"] * (reach["critical_reachable"] / reach["total_critical_assets"]
                                          if reach["total_critical_assets"] else 0.0), 4),
        }
        risk = round(100 * sum(terms.values()), 1)
        bands = cfg["severity_bands"]
        sev = "high" if risk >= bands["high"] else "medium" if risk >= bands["medium"] else "low"
        full = [gid[v]["member_event_ids"] for v in inc["group_ids"]]
        total = sum(len(m) for m in full)
        truncated = None
        if total <= MAX_TIMELINE_EVENTS:
            mem = sorted({x for m in full for x in m})
        else:  # head and tail of every group within one per-incident budget (members sorted = file order)
            k = max(1, MAX_TIMELINE_EVENTS // (2 * len(full)))
            mem = sorted({x for m in full for x in (m[:k] + m[-k:])})[:MAX_TIMELINE_EVENTS]
            truncated = {"member_events_total": inc["member_event_count"], "shown": len(mem),
                         "rule": f"first and last {k} member events of each group, at most {MAX_TIMELINE_EVENTS} "
                                 "in total; page the rest via GET /incidents/{id}/events"}
        events = timeline(con, mem, nodes)
        entity_keys = sorted({f"{k}:{v}" for n in nodes for k in ("user", "host", "src_ip", "dst_ip")
                              for v in n["entities"][k]})
        payloads.append({
            "incident_id": inc["incident_id"], "status": inc["status"], "risk_score": risk, "risk_terms": terms,
            "severity": sev, "ts_first": inc["ts_first"], "ts_last": inc["ts_last"], "tactics": inc["tactics"],
            "techniques": inc["techniques"], "group_ids": inc["group_ids"], "edge_ids": inc["edge_ids"],
            "raw_alert_count_total": inc["raw_alert_count_total"], "member_event_count": inc["member_event_count"],
            "entity_keys": entity_keys, "abstention_reason": None,
            "config_hash": config.config_hash(), "code_version": config.CODE_VERSION,
            "observed": {"nodes": nodes, "events": events,
                         "note": "Detections and raw events; every item carries raw event IDs.",
                         **({"events_truncated": truncated} if truncated else {})},
            "inferred": {"edges": _incident_edges([eby[e] for e in inc["edge_ids"]]), "primary_path": inc["primary_path"],
                         "strongest_chain": inc["strongest_chain"], "reachability": reach,
                         "containment_candidates": cands,
                         "note": "Edges, paths and reachability are inferences with score terms, never facts."},
            "uncertainty": uncertainty(inc, reach),
        })
    payloads.sort(key=lambda p: (-p["risk_score"], p["incident_id"]))
    return payloads


def _incident_edges(edges: list[dict]) -> list[dict]:
    """Edges as embedded in an incident record: unchanged up to LARGE_INCIDENT_EDGES, otherwise each keeps
    its first EDGE_EVIDENCE_LARGE evidence ids (the edges table keeps all of them)."""
    if len(edges) <= LARGE_INCIDENT_EDGES:
        return edges
    out = []
    for e in edges:
        ev = e.get("evidence_event_ids") or []
        if len(ev) > EDGE_EVIDENCE_LARGE:
            e = {**e, "evidence_event_ids": ev[:EDGE_EVIDENCE_LARGE], "evidence_event_ids_truncated": len(ev)}
        out.append(e)
    return out


def uncertainty(inc: dict, reach: dict) -> list[str]:
    u = ["All edges are inferred from shared entities plus time and tactic progression (dossier §12)."]
    nod = [h for h in inc["primary_path"]["hops"] if h["edge_id"] is None]
    if nod:
        u.append(f"{len(nod)} primary-path hop(s) have no direct inferred edge.")
    if inc["strongest_chain"]["uncovered_group_ids"]:
        u.append("The highest-J chain (dossier DP) omits groups " + ", ".join(inc["strongest_chain"]["uncovered_group_ids"])
                 + "; they are linked to the incident by kept edges but lower the chain objective.")
    if not reach["mode"].startswith("observed+"):
        u.append("Reachability ran in observed-only mode (no fixture).")
    u.append("Bounded connectors and alternative top-k paths are not implemented in Phase 1.")
    return u


def timeline(con, mem: list[int], nodes: list[dict]) -> list[dict]:
    rows = con.execute("""SELECT e.event_id, e.ts, e.line_no, e.source_event_id, e.raw_format, e.event_type,
            e.user, e.target_user, e.host, e.src_ip, e.dst_ip, e.process, left(e.command_line, 200), e.bytes_out,
            l.primary_rule, l.primary_technique, l.also_matched
        FROM events e LEFT JOIN event_labels l USING (event_id)
        WHERE e.event_id IN (SELECT unnest(?)) ORDER BY e.ts, e.event_id""", [mem]).fetchall()
    cols = ["event_id", "ts", "line_no", "source_event_id", "raw_format", "event_type", "user", "target_user", "host",
            "src_ip", "dst_ip", "process", "command_line", "bytes_out", "primary_rule", "primary_technique", "also_matched"]
    groups_of: dict[int, list[str]] = {}
    for n in nodes:  # node order preserved, as the Phase 1 per-event scan did
        for m in set(n["member_event_ids"]):
            groups_of.setdefault(m, []).append(n["group_id"])
    out = []
    for r in rows:
        d = dict(zip(cols, r))
        d["display_id"] = display_id(d["event_id"])
        d["group_ids"] = groups_of.get(d["event_id"], [])
        out.append(d)
    return out


def persist(con: duckdb.DuckDBPyConnection, res: dict, payloads: list[dict], rules) -> None:
    def table(name, rows, cols):
        # One columnar insert per table (Phase 1 issued one INSERT per row).
        con.execute(f"DROP TABLE IF EXISTS {name}")
        con.execute(f"CREATE TABLE {name} ({', '.join(f'{c} VARCHAR' for c in cols)})")
        if not rows:
            return
        data = {c: [r.get(c) if isinstance(r.get(c), str) or r.get(c) is None else dumps(r.get(c)) for r in rows]
                for c in cols}
        con.register("_persist_batch", pa.table(data, schema=pa.schema([(c, pa.string()) for c in cols])))
        con.execute(f"INSERT INTO {name} SELECT * FROM _persist_batch")
        con.unregister("_persist_batch")

    table("alert_groups", res["groups"], ["group_id", "rule_id", "technique_id", "tactic", "ts_first", "ts_last",
                                          "raw_alert_count", "detection_ids", "member_event_ids", "entities",
                                          "severity", "also_matched", "aggregate_key", "p_malicious", "contributions",
                                          "evidence"])
    table("edges", res["edges"], ["edge_id", "src_group_id", "dst_group_id", "reasons", "score", "score_terms",
                                  "weighted_terms", "delta_t_s", "evidence_event_ids", "connector_event_id", "kind"])
    cand = res["candidate_edges"]
    if len(cand) > MAX_PERSISTED_CANDIDATES:  # keep every kept edge plus the strongest dropped ones (D-77)
        kept_ids = {e["edge_id"] for e in res["edges"]}
        dropped = sorted((e for e in cand if e["edge_id"] not in kept_ids), key=lambda e: (-e["score"], e["edge_id"]))
        cand = [e for e in cand if e["edge_id"] in kept_ids] + dropped[:MAX_PERSISTED_CANDIDATES]
    table("candidate_edges", cand, ["edge_id", "src_group_id", "dst_group_id", "score", "score_terms",
                                                      "weighted_terms", "reasons", "delta_t_s", "tau_s",
                                                      "strongest_entity", "strongest_entity_degree",
                                                      "target_criticality", "pruned_reason"])
    table("abstained", [{"group_ids": a["group_ids"], "tactics": a["tactics"], "reason": a["reason"],
                         "edge_ids": a["edge_ids"]} for a in res["abstained"]],
          ["group_ids", "tactics", "reason", "edge_ids"])
    con.execute("DROP TABLE IF EXISTS incident_cache")
    con.execute("CREATE TABLE incident_cache (incident_id INTEGER, risk_score DOUBLE, json VARCHAR, bytes INTEGER)")
    con.execute("DROP TABLE IF EXISTS paths")
    con.execute("CREATE TABLE paths (incident_id INTEGER, rank INTEGER, group_ids VARCHAR, edge_ids VARCHAR, "
                "objective_J DOUBLE, stages VARCHAR)")
    for p in payloads:
        js = dumps(p)
        con.execute("INSERT INTO incident_cache VALUES (?, ?, ?, ?)", [p["incident_id"], p["risk_score"], js, len(js)])
        pp, sc = p["inferred"]["primary_path"], p["inferred"]["strongest_chain"]
        con.execute("INSERT INTO paths VALUES (?, 1, ?, ?, NULL, ?)",
                    [p["incident_id"], dumps(pp["group_ids"]), dumps(pp["edge_ids"]), dumps(pp["stages"])])
        con.execute("INSERT INTO paths VALUES (?, 2, ?, ?, ?, ?)",
                    [p["incident_id"], dumps(sc["group_ids"]), dumps(sc["edge_ids"]), sc["objective_J"],
                     dumps(sc["stages"])])
    con.execute("DROP TABLE IF EXISTS incidents")
    con.execute("""CREATE TABLE incidents AS SELECT incident_id, json->>'$.status' AS status, risk_score,
        json->>'$.severity' AS severity, json->'$.tactics' AS tactics, json->'$.group_ids' AS group_ids,
        json->'$.edge_ids' AS edge_ids, CAST(json->>'$.raw_alert_count_total' AS INTEGER) AS raw_alert_count_total,
        json->>'$.ts_first' AS ts_first, json->>'$.ts_last' AS ts_last, json->>'$.config_hash' AS config_hash
        FROM incident_cache""")
    con.execute("DROP TABLE IF EXISTS rules")
    con.execute("CREATE TABLE rules (json VARCHAR)")
    con.execute("INSERT INTO rules VALUES (?)", [dumps(rules_summary(rules))])
