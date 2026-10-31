"""Human-verifiable explanations for alerts, incidents and campaigns (mentor: "manual verification").

Why this exists: without ground truth for a new dataset, a person must be able to decide from the
output alone whether an attack really happened. Every explanation therefore states, deterministically
and only from stored facts: what was seen (who / where / when), why the rule fired (its condition in
plain English next to the observed numbers), the raw log lines it rests on (file, line number, the
re-read text and whether its SHA-256 still matches), how to check it by hand (grep/sed commands and
what to look for), what benign activity looks the same (config/explain.yml), and data-quality caveats
(e.g. a timestamp shared by a large share of the data). An optional LLM narrative may restate these
facts (forgetrace/report/llm.py) but never adds to them. No LLM here.
"""
from __future__ import annotations

import hashlib
import json
import shlex
from functools import lru_cache
from pathlib import Path
from typing import Any

import duckdb

from forgetrace import config
from forgetrace.ingest.evidence import get_raw
from forgetrace.rules.engine import load_rules

REASON_TEXT = {"same_session": "the same logon session {v}", "same_user": "the same account {v}",
               "same_host": "the same host {v}", "pivot_ip": "the same IP address {v}",
               "pivot_host": "a connection originating from host {v}", "same_hash_or_domain": "the same domain/hash {v}",
               "observed_connector": "an observed connecting event {v}"}
OP_TEXT = {"eq": "is", "ne": "is not", "in": "is one of", "contains": "contains", "startswith": "starts with",
           "endswith": "ends with", "regex": "matches the pattern", "gte": "is at least", "lte": "is at most",
           "gt": "is more than", "lt": "is less than", "is_null": "is empty", "not_null": "is present"}


# ----------------------------------------------------------------------------- rule text
def condition_text(node: dict) -> str:
    """A rule filter in plain English."""
    if "all" in node:
        return " AND ".join(condition_text(c) for c in node["all"])
    if "any" in node:
        return "(" + " OR ".join(condition_text(c) for c in node["any"]) + ")"
    if "not" in node:
        return f"NOT ({condition_text(node['not'])})"
    f, op, v = node["field"], node["op"], node.get("value")
    if op == "rare":
        return f"{f} is seen with at most {node['max_distinct']} distinct {node['by']} in the data"
    if op in ("is_null", "not_null"):
        return f"{f} {OP_TEXT[op]}"
    val = ", ".join(map(str, v)) if isinstance(v, list) else str(v)
    return f"{f} {OP_TEXT.get(op, op)} {val}"


@lru_cache(maxsize=1)
def _rules() -> dict:
    return {r.id: r for r in load_rules()}


def rule_text(rule_id: str) -> dict:
    r = _rules().get(rule_id)
    if r is None:
        return {"rule": rule_id, "condition": "rule definition not found"}
    out = {"rule": r.id, "title": r.title, "type": r.type, "condition": condition_text(r.filter),
           "author": r.author, "severity": r.severity, "prior_confidence": r.confidence}
    if r.threshold:
        th = r.threshold
        metric = (f"{th.count} or more distinct values of {th.distinct}" if th.distinct else
                  f"a total {th.sum} of at least {th.min}" if th.sum else f"{th.count} or more such events")
        out["threshold"] = f"{metric} for the same {', '.join(r.group_by)} within {th.window}"
    if r.followed_by:
        out["followed_by"] = (f"then, within {r.followed_by.within} and for the same {', '.join(r.followed_by.join_on)}: "
                              f"an event where {condition_text(r.followed_by.filter)}")
    if r.first_seen:
        out["first_seen"] = (f"the first time this {', '.join(r.first_seen.keys)} combination appears, "
                             f"after a {r.first_seen.warmup} learning period")
    return out


def _guidance(technique: str) -> dict:
    g = config.load_yaml(config.CONFIG_DIR / "explain.yml")
    return g.get(technique.split(".")[0], g["default"])


# ----------------------------------------------------------------------------- data access (batch or live)
def _has(con, table: str) -> bool:
    try:
        con.execute(f"SELECT 1 FROM {table} LIMIT 0")
        return True
    except duckdb.Error:
        return False


def _j(v):
    if isinstance(v, str):
        try:
            return json.loads(v)
        except ValueError:
            return v
    return v


def load_alert(con, alert_id: str) -> dict | None:
    """An alert by knowledge-base uid (live) or alert-group id (batch), normalised to one shape."""
    if _has(con, "kb_alerts"):
        cur = con.execute("SELECT * FROM kb_alerts WHERE uid = ?", [alert_id])
        row = cur.fetchone()
        if row:
            a = dict(zip([d[0] for d in cur.description], row))
            return {"id": a["uid"], "rule_id": a["rule_id"], "title": a["rule_title"], "technique_id": a["technique_id"],
                    "technique_name": a["technique_name"], "tactic": a["tactic"], "severity": a["severity"],
                    "ts_first": a["ts_first"], "ts_last": a["ts_last"], "member_count": a["member_count"],
                    "event_ids": _j(a["sample_event_ids"]), "entities": _j(a["entities"]), "evidence": _j(a["evidence"])}
    if _has(con, "alert_groups"):
        cur = con.execute("SELECT * FROM alert_groups WHERE group_id = ?", [alert_id])
        row = cur.fetchone()
        if row:
            a = {k: _j(v) for k, v in zip([d[0] for d in cur.description], row)}
            att = config.attack()["techniques"].get(a["technique_id"], {})
            mem = a["member_event_ids"]
            return {"id": a["group_id"], "rule_id": a["rule_id"], "title": rule_text(a["rule_id"]).get("title"),
                    "technique_id": a["technique_id"], "technique_name": att.get("name"), "tactic": a["tactic"],
                    "severity": a["severity"], "ts_first": a["ts_first"], "ts_last": a["ts_last"],
                    "member_count": len(mem), "event_ids": mem[:50], "entities": a["entities"],
                    "evidence": a.get("evidence") or []}
    return None


def data_quality(con, out: Path) -> list[str]:
    """Workspace-level caveats, computed once and cached (generic: no dataset named)."""
    p = out / "data_quality.json"
    if p.exists():
        return json.loads(p.read_text())
    notes = []
    try:
        total = con.execute("SELECT count(*) FROM events").fetchone()[0]
        top = con.execute("SELECT ts, count(*) c FROM events GROUP BY ts ORDER BY c DESC LIMIT 1").fetchone()
        if total and top and top[1] >= 1000 and top[1] / total >= 0.01:
            notes.append(f"{top[1]:,} of {total:,} events ({100 * top[1] / total:.1f}%) carry the identical timestamp "
                         f"{top[0]}; time-window counts that include that instant may be inflated, so check the order "
                         f"of the cited lines (line numbers) rather than their timestamps.")
        err = con.execute("SELECT count(*) FROM parse_errors").fetchone()[0] if _has(con, "parse_errors") else 0
        if err:
            notes.append(f"{err:,} lines could not be parsed; they are listed in parse_errors and were not analysed.")
    except duckdb.Error as e:
        notes.append(f"data-quality checks unavailable: {e}")
    try:
        p.write_text(json.dumps(notes))
    except OSError:
        pass
    return notes


# ----------------------------------------------------------------------------- explanations
def _evidence(con, out: Path, ids: list[int], limit: int) -> list[dict]:
    rows = []
    for eid in sorted(set(ids))[:limit]:
        r = get_raw(int(eid), out, con)
        rows.append({"event_id": int(eid), "display_id": r.get("display_id"), "file": r.get("file"),
                     "line_no": r.get("line_no"), "raw": r.get("raw"), "verified": r.get("verified"),
                     "note": r.get("reason")})
    return rows


def _verify_cmds(ev: list[dict], entities: dict, files: dict[str, str]) -> list[str]:
    steps = []
    by_file: dict[str, list[int]] = {}
    for e in ev:
        if e["file"] and e["line_no"]:
            by_file.setdefault(e["file"], []).append(e["line_no"])
    for f, lines in by_file.items():
        path = shlex.quote(files.get(f, f))
        lo, hi = min(lines), max(lines)
        steps.append(f"Print the cited lines: sed -n '{lo},{hi}p' {path}" if hi - lo <= 200 else
                     f"Print the first cited line: sed -n '{lo}p' {path} (cited lines span {lo}-{hi})")
        for key in ("src_ip", "user", "host", "dst_ip", "domain_name"):
            for v in (entities.get(key) or [])[:1]:
                steps.append(f"Every line mentioning {key} {v}: grep -nF {shlex.quote(str(v))} {path} | less")
                break
    return steps


def _files(out: Path) -> dict[str, str]:
    try:
        return {Path(f["path"]).name: f["path"] for f in json.loads((out / "files.json").read_text())["files"]}
    except (OSError, ValueError, KeyError):
        return {}


def explain_alert(con, out: Path, alert_id: str, evidence_lines: int = 8) -> dict[str, Any]:
    a = load_alert(con, alert_id)
    if a is None:
        return {"kind": "alert", "id": alert_id, "error": "alert not found"}
    rt = rule_text(a["rule_id"])
    ents = {k: v for k, v in (a["entities"] or {}).items() if v}
    ev = _evidence(con, out, a["event_ids"], evidence_lines)
    who = "; ".join(f"{k} {', '.join(map(str, v[:5]))}{' …' if len(v) > 5 else ''}" for k, v in ents.items()
                    if k in ("user", "target_user", "host", "src_ip", "dst_ip", "domain_name"))
    guide = _guidance(a["technique_id"])
    facts = {
        "kind": "alert", "id": a["id"],
        "headline": f"{a['title']} — {a['technique_name'] or a['technique_id']} ({a['technique_id']}, {a['tactic']})",
        "summary": (f"Rule {a['rule_id']} fired: {a['title'].lower()}. It covers {a['member_count']:,} log event(s) "
                    f"between {a['ts_first']} and {a['ts_last']} (UTC)" + (f", involving {who}." if who else ".")),
        "when": {"first": str(a["ts_first"]), "last": str(a["ts_last"]), "timezone": "UTC"},
        "entities": ents,
        "why_flagged": {**rt, "observed": a["evidence"][-5:] if isinstance(a["evidence"], list) else [a["evidence"]],
                        "technique": {"id": a["technique_id"], "name": a["technique_name"], "tactic": a["tactic"]}},
        "evidence": ev,
        "how_to_verify": [f"Confirm in the raw lines below that: {rt.get('condition')}"]
                         + ([f"Confirm the threshold: {rt['threshold']}"] if rt.get("threshold") else [])
                         + ([f"Confirm the follow-up: {rt['followed_by']}"] if rt.get("followed_by") else [])
                         + _verify_cmds(ev, ents, _files(out)) + guide["check"],
        "benign_explanations": guide["benign"],
        "data_quality": data_quality(con, out),
        "verification_status": ("all cited lines re-read and digest-verified" if ev and all(e["verified"] for e in ev)
                                else "some cited lines could not be re-verified (see notes)"),
    }
    facts["facts_hash"] = hashlib.sha256(json.dumps(facts, sort_keys=True, default=str).encode()).hexdigest()
    return facts


def _link_text(reasons: list[dict], dt_s: float | None, score: float | None) -> str:
    rs = [REASON_TEXT.get(r["type"], r["type"]).format(v=r["entity_key"].split(":", 1)[-1]) for r in reasons[:4]]
    more = f" (+{len(reasons) - 4} more shared entities)" if len(reasons) > 4 else ""
    when = "" if dt_s is None else (f", {dt_s / 60:.0f} minutes later" if dt_s < 86400 else f", {dt_s / 86400:.1f} days later")
    sc = "" if score is None else f"; link score {score:.2f}"
    return f"linked by {', '.join(rs)}{more}{when}{sc}"


def explain_chain(con, out: Path, kind: str, chain_id: str, alert_ids: list[str], links: list[dict],
                  evidence_per_step: int = 3) -> dict[str, Any]:
    """An incident or campaign: ordered steps, why consecutive steps are linked, and how to verify."""
    steps, all_ev, tactics = [], [], []
    by_dst = {ln["dst"]: ln for ln in links}
    for i, aid in enumerate(alert_ids, 1):
        a = load_alert(con, aid)
        if a is None:
            continue
        ev = _evidence(con, out, a["event_ids"], evidence_per_step)
        all_ev += ev
        if a["tactic"] not in tactics:
            tactics.append(a["tactic"])
        ln = by_dst.get(aid)
        ents = {k: v for k, v in (a["entities"] or {}).items() if v and k in
                ("user", "target_user", "host", "host_ip", "src_ip", "dst_ip", "domain_name")}
        steps.append({"order": i, "alert_id": aid, "rule_id": a["rule_id"], "what": a["title"], "entities": ents,
                      "technique": f"{a['technique_id']} {a['technique_name'] or ''}".strip(), "tactic": a["tactic"],
                      "when": str(a["ts_first"]), "events": a["member_count"],
                      "linked_from_previous": _link_text(ln.get("reasons", []), ln.get("gap_s"), ln.get("score"))
                      if ln else ("first step" if i == 1 else "same component; no direct link to the previous step"),
                      "evidence": ev})
    span = f"{steps[0]['when']} to {steps[-1]['when']}" if steps else ""
    facts = {
        "kind": kind, "id": chain_id,
        "headline": f"{len(steps)}-step {kind} across {len(tactics)} ATT&CK tactics: {' → '.join(tactics)}",
        "summary": (f"{len(steps)} alerts from {span} (UTC) are connected through shared entities. In order: "
                    + "; ".join(f"{s['order']}. {s['what']} ({s['technique']})" for s in steps[:12])
                    + (" …" if len(steps) > 12 else "") + "."),
        "steps": steps,
        "how_to_verify": ["For each step, open its cited lines and confirm the activity happened as described",
                          "For each link, confirm the shared entity appears in both steps' lines and that the order "
                          "of events (line numbers / times) matches the stated sequence",
                          "Decide whether the sequence tells one story (the same actor progressing) or coincidences "
                          "(an entity shared by unrelated activity)"] + _verify_cmds(all_ev[:20], {}, _files(out)),
        "uncertainties": ["Links are inferences from shared entities, time and tactic order (dossier §12), not facts",
                          "A step marked 'no direct link' joined through another step of the same component"],
        "data_quality": data_quality(con, out),
    }
    facts["facts_hash"] = hashlib.sha256(json.dumps(facts, sort_keys=True, default=str).encode()).hexdigest()
    return facts


def explain_batch_incident(con, out: Path, incident_id: int) -> dict[str, Any]:
    row = con.execute("SELECT json FROM incident_cache WHERE incident_id = ?", [incident_id]).fetchone()
    if row is None:
        return {"kind": "incident", "id": incident_id, "error": "incident not found"}
    p = json.loads(row[0])
    edges = {e["edge_id"]: e for e in p["inferred"]["edges"]}
    links = []
    for h in p["inferred"]["primary_path"]["hops"]:
        e = edges.get(h["edge_id"]) if h["edge_id"] else None
        if e:
            links.append({"dst": h["to"], "reasons": e["reasons"], "gap_s": e.get("delta_t_s"), "score": e["score"]})
    ex = explain_chain(con, out, "incident", str(incident_id), p["inferred"]["primary_path"]["group_ids"], links)
    ex["risk"] = {"score": p["risk_score"], "severity": p["severity"], "terms": p["risk_terms"]}
    return ex
