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

from forgetrace import assets, config, store
from forgetrace.correlate.correlate import correlate
from forgetrace.ingest.ingest import ingest, split_event_id
from forgetrace.reach.reach import candidate_actions, reachability
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


def run(inputs: list[Path], out: Path, progress=None, dataset: str | None = None) -> dict:
    """progress(stage, fraction) is optional; used by the API's background runs."""
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
    t = time.perf_counter()
    report("detect", 0.82)
    rules = load_rules()
    det = detect(con, rules)
    stages["detect_s"] = round(time.perf_counter() - t, 3)
    t = time.perf_counter()
    report("correlate", 0.88)
    res = correlate(con)
    stages["correlate_s"] = round(time.perf_counter() - t, 3)
    t = time.perf_counter()
    report("reach", 0.93)
    payloads = build_payloads(con, res)
    stages["reach_and_cache_s"] = round(time.perf_counter() - t, 3)
    persist(con, res, payloads, rules)
    con.close()
    (out / "incidents.json").write_text(dumps(payloads))
    stats = {"stages": stages, "wall_time_s": round(time.perf_counter() - t0, 3), "peak_rss_bytes": peak_rss_bytes(),
             "peak_rss_note": "ru_maxrss of the single ForgeTrace process (all stages run in-process)",
             "config_hash": config.config_hash(), "code_version": config.CODE_VERSION,
             "dataset": {"files": manifest["files"], "manifest_digest": manifest["manifest_digest"]},
             "ingest": manifest["stats"], "detections": det["detections"], "rule_seconds": det["rule_seconds"],
             "alert_groups": len(res["groups"]), "candidate_edges": len(res["candidate_edges"]),
             "kept_edges": len(res["edges"]), "incidents": len(payloads), "abstained_components": len(res["abstained"])}
    stats["finished_at"] = datetime.now().astimezone().isoformat(timespec="seconds")
    (out / "run_stats.json").write_text(json.dumps(stats, indent=1, default=str))
    report("done", 1.0)
    return stats


def build_payloads(con: duckdb.DuckDBPyConnection, res: dict) -> list[dict]:
    cfg = config.correlation()
    gid = {g["group_id"]: g for g in res["groups"]}
    eby = {e["edge_id"]: e for e in res["edges"]}
    payloads = []
    for inc in res["incidents"]:
        reach = reachability(con, inc, gid)
        cands = candidate_actions(con, inc, gid)
        nodes = []
        for v in inc["group_ids"]:
            g = dict(gid[v])
            g["criticality"] = max([assets.criticality(h) for h in g["entities"]["host"]] or [assets.default_criticality()])
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
        mem = sorted({x for n in nodes for x in n["member_event_ids"]})
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
                         "note": "Detections and raw events; every item carries raw event IDs."},
            "inferred": {"edges": [eby[e] for e in inc["edge_ids"]], "primary_path": inc["primary_path"],
                         "strongest_chain": inc["strongest_chain"], "reachability": reach,
                         "containment_candidates": cands,
                         "note": "Edges, paths and reachability are inferences with score terms, never facts."},
            "uncertainty": uncertainty(inc, reach),
        })
    payloads.sort(key=lambda p: (-p["risk_score"], p["incident_id"]))
    return payloads


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
    out = []
    for r in rows:
        d = dict(zip(cols, r))
        d["display_id"] = display_id(d["event_id"])
        d["group_ids"] = [n["group_id"] for n in nodes if d["event_id"] in set(n["member_event_ids"])]
        out.append(d)
    return out


def persist(con: duckdb.DuckDBPyConnection, res: dict, payloads: list[dict], rules) -> None:
    def table(name, rows, cols):
        con.execute(f"DROP TABLE IF EXISTS {name}")
        con.execute(f"CREATE TABLE {name} ({', '.join(f'{c} VARCHAR' for c in cols)})")
        for r in rows:
            con.execute(f"INSERT INTO {name} VALUES ({', '.join('?' * len(cols))})",
                        [r.get(c) if isinstance(r.get(c), str) or r.get(c) is None else dumps(r.get(c)) for c in cols])

    table("alert_groups", res["groups"], ["group_id", "rule_id", "technique_id", "tactic", "ts_first", "ts_last",
                                          "raw_alert_count", "detection_ids", "member_event_ids", "entities",
                                          "severity", "also_matched", "aggregate_key", "p_malicious", "contributions"])
    table("edges", res["edges"], ["edge_id", "src_group_id", "dst_group_id", "reasons", "score", "score_terms",
                                  "weighted_terms", "delta_t_s", "evidence_event_ids", "connector_event_id", "kind"])
    table("candidate_edges", res["candidate_edges"], ["edge_id", "src_group_id", "dst_group_id", "score", "score_terms",
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
