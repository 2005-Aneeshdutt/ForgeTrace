"""Step-by-step pipeline walkthrough for small (demo) workspaces.

Why this exists: to explain ForgeTrace end to end on a handful of events, the dashboard's Demo
page shows the real intermediate output of every stage (dossier §10 process model): raw lines
and their event IDs (§11), the field-by-field normalisation trace (§13 envelope), rule hits and
label priority, alert groups, every candidate edge with its score terms and keep/drop decision
(§12), the incident graph and path, then risk, reachability and evidence verification (§14).
Nothing here recomputes results: it reads what `forgetrace run` stored, plus a re-parse of each
raw line purely to show which vendor field fed which envelope field.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import duckdb

from forgetrace import config
from forgetrace.ingest.evidence import get_raw
from forgetrace.ingest.ingest import line_digest, make_event_id, strip_eol
from forgetrace.ingest.parsers import ParseError, normalise, parse_cef, parse_json, parse_kv, sniff

MAX_EVENTS = 200
SHOWN_FIELDS = ["ts", "source_type", "event_type", "outcome", "user", "target_user", "host", "host_ip", "src_ip",
                "dst_ip", "src_is_external", "dst_is_external", "dst_port", "process", "parent_process",
                "command_line", "logon_type", "logon_id", "group_name", "registry_path", "bytes_out",
                "vendor_event_code", "domain_name"]


def _j(v):
    return json.loads(v) if isinstance(v, str) and v[:1] in "[{\"0123456789-tfn" else v


def _raw_fields(content: bytes, fmt: str) -> dict:
    if fmt == "ecs_json":
        return parse_json(content)
    if fmt == "cef":
        return parse_cef(content, config.field_map()["formats"]["cef"]["label_fields"])
    return parse_kv(content)


def _trace(content: bytes) -> dict:
    """Which vendor field produced which envelope field, and what normalisation changed."""
    fmt = sniff(content)
    raw = _raw_fields(content, fmt)
    spec = config.field_map()["formats"][fmt]
    norm = normalise(raw, fmt)
    rows = []
    ts_src = spec["timestamp"].get("field") or "+".join(spec["timestamp"].get("fallback", []))
    rows.append({"field": "ts", "source": ts_src, "raw": raw.get(spec["timestamp"].get("field", ""), None),
                 "value": datetime.fromtimestamp(norm["ts"] / 1e6, tz=timezone.utc).isoformat().replace("+00:00", "Z"),
                 "how": f"parsed as {spec['timestamp']['kind']} → stored as UTC microseconds"})
    for field, paths in spec["fields"].items():
        for pth in paths:
            v = raw.get(pth)
            if isinstance(v, list):
                v = v[0] if v else None
            if v not in (None, ""):
                rows.append({"field": field, "source": pth, "raw": v, "value": norm.get(field), "how": None})
                break
        else:
            lv = raw.get(f"label:{field}") if fmt == "cef" else None
            if lv not in (None, ""):
                lab = next((k for k, t in spec.get("label_fields", {}).items() if t == field), "?")
                rows.append({"field": field, "source": f"csN/cnN labelled '{lab}'", "raw": lv,
                             "value": norm.get(field), "how": None})
    for r in rows:
        if r["how"] is None:
            r["how"] = "copied" if str(r["raw"]) == str(r["value"]) else "normalised"
    rule = next((r for r in config.field_map()["event_types"] if all(
        str(norm.get(k)) in [str(x) for x in vals] for k, vals in r["when"].items())), None)
    rows.append({"field": "event_type", "source": "derived", "raw": None, "value": norm["event_type"],
                 "how": ("field_map event_types rule: " + " and ".join(f"{k} ∈ {{{', '.join(map(str, v))}}}" for k, v in rule["when"].items()))
                 if rule else "no event_types rule matched"})
    for k in ("src_is_external", "dst_is_external"):
        if norm.get(k) is not None:
            rows.append({"field": k, "source": "derived", "raw": None, "value": norm[k],
                         "how": "IP outside config internal_networks" if norm[k] else "IP inside config internal_networks"})
    banned = sorted(k for k in raw if k.startswith(("threat.", "rule.", "labels")) or k in ("event.kind", "event.severity"))
    return {"format": fmt, "source_type": spec["source_type"], "mapping": rows, "ignored_vendor_fields": banned,
            "raw_field_count": len(raw)}


def build(d: Path, con: duckdb.DuckDBPyConnection) -> dict:
    files = json.loads((d / "files.json").read_text())
    stats = json.loads((d / "run_stats.json").read_text())
    if files["stats"]["lines"] > MAX_EVENTS:
        raise ValueError(f"the walkthrough is meant for small demo files (≤ {MAX_EVENTS} lines); "
                         f"this workspace has {files['stats']['lines']}")
    # ---- 1. ingest: stream each file line by line, exactly as ingest does
    lines = []
    for f in files["files"]:
        off, ln = 0, 0
        with open(f["path"], "rb") as fh:
            while True:
                line = fh.readline()
                if not line:
                    break
                ln += 1
                content = strip_eol(line)
                try:
                    fmt = sniff(content)
                except ParseError:
                    fmt = "unknown"
                eid = make_event_id(f["file_id"], off)
                lines.append({"file": Path(f["path"]).name, "file_id": f["file_id"], "line_no": ln, "byte_offset": off,
                              "length": len(line), "format": fmt, "event_id": eid,
                              "display_id": f"F{f['file_id']:02d}:{off:012d}", "sha256": line_digest(content),
                              "raw": content.decode("utf-8", "replace")})
                off += len(line)
    # ---- 2. normalise + store
    cols = ["event_id", "line_no", "source_event_id", "raw_format"] + SHOWN_FIELDS
    env = {r[0]: dict(zip(cols, r)) for r in con.execute(
        f"SELECT {', '.join(chr(34) + c + chr(34) for c in cols)} FROM events ORDER BY event_id").fetchall()}
    for e in env.values():
        e["ts"] = str(e["ts"])
    for ln in lines:
        ln["envelope"] = {k: v for k, v in env.get(ln["event_id"], {}).items() if v is not None}
        try:
            ln["trace"] = _trace(ln["raw"].encode())
        except Exception as exc:  # malformed line: shown as a parse error, never hidden
            ln["trace"] = {"error": str(exc)}
    parts = sorted((d / "events").glob("*.parquet"))
    storage = {"parquet_files": [{"name": f"events/{p.name}", "bytes": p.stat().st_size} for p in parts],
               "rows": con.execute("SELECT count(*) FROM events").fetchone()[0],
               "columns": len(con.execute("SELECT * FROM events LIMIT 0").description),
               "parse_errors": con.execute("SELECT count(*) FROM parse_errors").fetchone()[0],
               "duckdb": "forgetrace.duckdb (view `events` over the Parquet files)",
               "manifest": [{"file_id": f["file_id"], "file": Path(f["path"]).name, "size": f["size"], "sha256": f["sha256"]}
                            for f in files["files"]]}
    # ---- 3. detect
    dets = [dict(zip(["detection_id", "rule_id", "rule_title", "technique_id", "technique_name", "tactic", "severity",
                      "confidence", "member_event_ids", "evidence", "duplicate_of"], r)) for r in con.execute(
        """SELECT detection_id, rule_id, rule_title, technique_id, technique_name, tactic, severity, confidence,
                  member_event_ids, evidence, duplicate_of FROM detections ORDER BY ts_first, rule_id""").fetchall()]
    labels = {r[0]: {"primary_rule": r[1], "primary_technique": r[2], "primary_tactic": r[3], "also_matched": r[4] or []}
              for r in con.execute("SELECT event_id, primary_rule, primary_technique, primary_tactic, also_matched "
                                   "FROM event_labels").fetchall()}
    for ln in lines:
        ln["label"] = labels.get(ln["event_id"])
    rules_loaded = json.loads(con.execute("SELECT json FROM rules").fetchone()[0])
    # ---- 4. aggregate
    groups = []
    for r in con.execute("""SELECT group_id, rule_id, technique_id, tactic, ts_first, raw_alert_count, detection_ids,
                                   member_event_ids, entities, also_matched FROM alert_groups ORDER BY group_id""").fetchall():
        g = dict(zip(["group_id", "rule_id", "technique_id", "tactic", "ts_first", "raw_alert_count", "detection_ids",
                      "member_event_ids", "entities", "also_matched"], r))
        for k in ("ts_first", "raw_alert_count", "detection_ids", "member_event_ids", "entities", "also_matched"):
            g[k] = _j(g[k])
        g["entities"] = {k: v for k, v in g["entities"].items() if v}
        groups.append(g)
    # ---- 5. correlate
    kept = {r[0] for r in con.execute("SELECT edge_id FROM edges").fetchall()}
    cand = []
    for r in con.execute("""SELECT edge_id, src_group_id, dst_group_id, score, score_terms, weighted_terms, reasons,
                                   delta_t_s, tau_s, strongest_entity, strongest_entity_degree, target_criticality,
                                   pruned_reason FROM candidate_edges""").fetchall():
        e = dict(zip(["edge_id", "src_group_id", "dst_group_id", "score", "score_terms", "weighted_terms", "reasons",
                      "delta_t_s", "tau_s", "strongest_entity", "strongest_entity_degree", "target_criticality",
                      "pruned_reason"], r))
        for k in ("score", "score_terms", "weighted_terms", "reasons", "delta_t_s", "tau_s", "strongest_entity_degree",
                  "target_criticality"):
            e[k] = _j(e[k])
        e["kept"] = e["edge_id"] in kept
        theta = config.correlation()["theta_edge"]
        e["decision"] = ("kept" if e["kept"] else e.get("pruned_reason") or
                         (f"dropped: score {e['score']} < θ_edge {theta}" if e["score"] < theta else "dropped"))
        cand.append(e)
    cand.sort(key=lambda e: e["edge_id"])
    index: dict[str, list[str]] = {}
    for g in groups:
        for k in ("user", "target_user", "host", "src_ip", "dst_ip", "logon_id"):
            for v in g["entities"].get(k, []):
                index.setdefault(f"{'session' if k == 'logon_id' else 'user' if k == 'target_user' else 'ip' if k.endswith('ip') else k}:{v}", []).append(g["group_id"])
    shared = {k: sorted(set(v)) for k, v in sorted(index.items()) if len(set(v)) > 1}
    incidents = [json.loads(j) for (j,) in con.execute("SELECT json FROM incident_cache ORDER BY incident_id").fetchall()]
    abstained = [{"group_ids": _j(g), "tactics": _j(t), "reason": r} for g, t, r in
                 con.execute("SELECT group_ids, tactics, reason FROM abstained").fetchall()]
    # ---- 8. evidence check on the first flagged event
    flagged = [ln for ln in lines if ln.get("label")]
    verify = get_raw(flagged[0]["event_id"], d, con) if flagged else None
    return {"files": storage["manifest"], "stats": stats, "lines": lines, "storage": storage,
            "rules": [{"id": r["id"], "title": r["title"], "technique": r["technique"], "tactic": r["tactic"],
                       "type": r["type"], "label_priority": r["label_priority"],
                       "matched": sorted({m for dd in dets if dd["rule_id"] == r["id"] for m in dd["member_event_ids"]})}
                      for r in rules_loaded],
            "detections": dets, "groups": groups, "candidate_edges": cand, "shared_entities": shared,
            "theta_edge": config.correlation()["theta_edge"], "weights": config.correlation()["weights"],
            "incidents": incidents, "abstained": abstained, "verify": verify}
