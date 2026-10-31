"""YAML rule loader, SQL compiler and detector (dossier §10 'rules'/'detect', §12 rule types).

Why this exists: detection must be configuration-driven (B-4) and auditable. Each rule's
filter compiles to a DuckDB WHERE clause over the normalised envelope; thresholds use a
SQL window count; followed_by / first_seen add a bounded join. Rules may only reference
envelope fields (ALLOWED_FIELDS) so vendor verdict fields can never be used.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Literal

import duckdb
import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

from forgetrace import config
from forgetrace.ingest.ingest import SCHEMA

# Detection may never read these (also enforced by tests/test_vendor_ban.py).
BANNED_PREFIXES = ("threat.", "rule.", "labels", "event.kind", "event.severity")
NON_DETECTION_FIELDS = {"event_id", "file_id", "byte_offset", "line_no", "line_digest", "source_event_id"}
ALLOWED_FIELDS = set(SCHEMA.names) - NON_DETECTION_FIELDS
ENTITY_FIELDS = ["user", "target_user", "host", "host_ip", "src_ip", "dst_ip", "logon_id", "domain_name",
                 "process", "group_name"]
OPS = {"eq", "ne", "in", "contains", "startswith", "endswith", "regex", "gte", "lte", "gt", "lt",
       "is_null", "not_null", "rare"}


def parse_duration(s: str) -> int:
    m = re.fullmatch(r"(\d+)\s*([smhd])", str(s).strip())
    if not m:
        raise ValueError(f"bad duration {s!r}")
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


class Threshold(BaseModel):
    count: int = Field(ge=1)
    window: str

    @property
    def seconds(self) -> int:
        return parse_duration(self.window)


class FollowedBy(BaseModel):
    filter: dict
    join_on: list[str]
    within: str
    link: dict[str, str] = {}   # follower field -> window-event field that must be equal (case-insensitive)


class FirstSeen(BaseModel):
    keys: list[str]
    warmup: str


class Rule(BaseModel):
    id: str
    version: int
    title: str
    author: str
    technique: str
    tactic: str
    severity: int = Field(ge=1, le=4)
    confidence: float
    label_priority: int
    type: Literal["match", "threshold", "baseline"]
    filter: dict
    group_by: list[str] = []
    threshold: Threshold | None = None
    followed_by: FollowedBy | None = None
    first_seen: FirstSeen | None = None
    aggregate_by: list[str]
    source_file: str = ""

    @field_validator("confidence")
    @classmethod
    def _conf(cls, v):
        if v not in (0.5, 0.7, 0.9):
            raise ValueError("confidence must be a declared prior 0.5/0.7/0.9 (dossier §12)")
        return v

    @model_validator(mode="after")
    def _check(self):
        tech = config.attack()["techniques"].get(self.technique)
        if tech is None or tech.get("deprecated") or tech.get("revoked"):
            raise ValueError(f"{self.id}: unknown/deprecated technique {self.technique}")
        if self.tactic not in tech["tactics"]:
            raise ValueError(f"{self.id}: tactic {self.tactic} not valid for {self.technique}")
        if self.type == "threshold" and (self.threshold is None or not self.group_by):
            raise ValueError(f"{self.id}: threshold rule needs threshold and group_by")
        if self.type == "baseline" and self.first_seen is None:
            raise ValueError(f"{self.id}: baseline rule needs first_seen")
        for f in referenced_fields(self):
            if f not in ALLOWED_FIELDS:
                raise ValueError(f"{self.id}: field {f!r} is not an allowed envelope field")
        return self


def _walk_fields(node: Any, out: set) -> None:
    if isinstance(node, dict):
        if "field" in node:
            out.add(node["field"])
            if node.get("op") == "rare":
                out.add(node["by"])
        for k in ("all", "any"):
            for c in node.get(k, []):
                _walk_fields(c, out)
        if "not" in node:
            _walk_fields(node["not"], out)


def referenced_fields(rule: Rule) -> set[str]:
    out: set[str] = set(rule.group_by) | set(rule.aggregate_by)
    _walk_fields(rule.filter, out)
    if rule.followed_by:
        _walk_fields(rule.followed_by.filter, out)
        out |= set(rule.followed_by.join_on) | set(rule.followed_by.link) | set(rule.followed_by.link.values())
    if rule.first_seen:
        out |= set(rule.first_seen.keys)
    return out


def load_rules(rules_dir: Path | None = None) -> list[Rule]:
    rules_dir = rules_dir or config.CONFIG_DIR / "rules"
    rules, seen = [], set()
    for p in sorted(rules_dir.glob("*.yml")):
        docs = yaml.safe_load(p.read_text()) or []
        for d in docs:
            try:
                r = Rule(**d, source_file=p.name)
            except Exception as e:
                raise ValueError(f"{p.name}: rule {d.get('id')}: {e}") from None
            if r.id in seen:
                raise ValueError(f"{p.name}: duplicate rule id {r.id}")
            seen.add(r.id)
            rules.append(r)
    return rules


# ----------------------------------------------------------------------------- SQL compiler
def lit(v: Any) -> str:
    if isinstance(v, bool):
        return "TRUE" if v else "FALSE"
    if isinstance(v, (int, float)):
        return repr(v)
    return "'" + str(v).replace("'", "''") + "'"


def compile_filter(node: dict) -> str:
    if "all" in node:
        return "(" + " AND ".join(compile_filter(c) for c in node["all"]) + ")"
    if "any" in node:
        return "(" + " OR ".join(compile_filter(c) for c in node["any"]) + ")"
    if "not" in node:
        return f"(NOT COALESCE({compile_filter(node['not'])}, FALSE))"
    f, op, v, ci = node["field"], node["op"], node.get("value"), node.get("ci", False)
    if f not in ALLOWED_FIELDS or op not in OPS:
        raise ValueError(f"bad condition {node}")
    col = f'"{f}"'
    s = f"lower({col})" if ci else col

    def L(x):
        return lit(str(x).lower()) if ci else lit(x)

    if op == "eq":
        return f"({s} = {L(v)})"
    if op == "ne":
        return f"({s} IS DISTINCT FROM {L(v)})"
    if op == "in":
        return f"({s} IN ({', '.join(L(x) for x in v)}))"
    if op == "contains":
        return f"contains({s}, {L(v)})"
    if op == "startswith":
        return f"starts_with({s}, {L(v)})"
    if op == "endswith":
        return f"ends_with({s}, {L(v)})"
    if op == "regex":
        return f"regexp_matches({col}, {lit(v)})"
    if op in ("gte", "lte", "gt", "lt"):
        sym = {"gte": ">=", "lte": "<=", "gt": ">", "lt": "<"}[op]
        return f"({col} {sym} {lit(v)})"
    if op == "is_null":
        return f"({col} IS NULL)"
    if op == "not_null":
        return f"({col} IS NOT NULL)"
    if op == "rare":  # value seen with at most max_distinct values of `by` across the whole dataset
        by = node["by"]
        if by not in ALLOWED_FIELDS:
            raise ValueError(f"bad rare.by {by}")
        return (f"({col} IN (SELECT {col} FROM events WHERE {col} IS NOT NULL GROUP BY {col} "
                f"HAVING count(DISTINCT \"{by}\") <= {int(node['max_distinct'])}))")
    raise ValueError(op)


def compile_rule(rule: Rule) -> dict[str, str]:
    """Return the SQL statements a rule runs (exposed for snapshot tests / GET /rules)."""
    where = compile_filter(rule.filter)
    sql = {"filter": f"SELECT event_id, ts, {', '.join(_q(rule))} FROM events WHERE {where}"}
    if rule.type == "threshold":
        keys = ", ".join(f'"{k}"' for k in rule.group_by)
        wl = "".join(f', lower("{v}") AS "_w_{v}"' for v in (rule.followed_by.link.values() if rule.followed_by else []))
        sql["threshold"] = (
            f"SELECT event_id, ts, {keys}{wl}, count(*) OVER (PARTITION BY {keys} ORDER BY ts "
            f"RANGE BETWEEN INTERVAL {rule.threshold.seconds} SECOND PRECEDING AND CURRENT ROW) AS win_count "
            f"FROM events WHERE {where} AND " + " AND ".join(f'"{k}" IS NOT NULL' for k in rule.group_by)
            + f" ORDER BY {keys}, ts, event_id")
        if rule.followed_by:
            fb = rule.followed_by
            fl = "".join(f', lower("{k}")' for k in fb.link)
            sql["followed_by"] = (f"SELECT event_id, ts, {', '.join(chr(34) + k + chr(34) for k in fb.join_on)}{fl} "
                                  f"FROM events WHERE {compile_filter(fb.filter)} ORDER BY ts, event_id")
    if rule.type == "baseline":
        keys = ", ".join(f'"{k}"' for k in rule.first_seen.keys)
        warm = parse_duration(rule.first_seen.warmup)
        sql["baseline"] = (
            f"SELECT event_id, ts, {keys} FROM (SELECT event_id, ts, {keys}, row_number() OVER "
            f"(PARTITION BY {keys} ORDER BY ts, event_id) AS rn FROM events WHERE {where}) "
            f"WHERE rn = 1 AND ts >= (SELECT min(ts) FROM events) + INTERVAL {warm} SECOND ORDER BY ts, event_id")
    return sql


def _q(rule: Rule) -> list[str]:
    return [f'"{k}"' for k in sorted(set(rule.group_by) | set(rule.aggregate_by))]


# ----------------------------------------------------------------------------- detection
def _run_rule(con: duckdb.DuckDBPyConnection, rule: Rule) -> list[dict]:
    sql = compile_rule(rule)
    dets: list[dict] = []
    if rule.type == "match":
        for eid, ts, *_ in con.execute(sql["filter"] + " ORDER BY ts, event_id").fetchall():
            dets.append({"members": [eid], "ts_first": ts, "ts_last": ts,
                         "evidence": f"{rule.title}: single event matched filter"})
    elif rule.type == "baseline":
        keys = rule.first_seen.keys
        for eid, ts, *kv in con.execute(sql["baseline"]).fetchall():
            pair = ", ".join(f"{k}={v}" for k, v in zip(keys, kv))
            dets.append({"members": [eid], "ts_first": ts, "ts_last": ts,
                         "evidence": f"first-seen ({pair}) after {rule.first_seen.warmup} warm-up"})
    else:
        rows = con.execute(sql["threshold"]).fetchall()
        n, W = rule.threshold.count, rule.threshold.seconds
        nk = len(rule.group_by)
        # Merge every qualifying window per key into maximal detections (members never dropped).
        nl = len(rule.followed_by.link) if rule.followed_by else 0
        by_key: dict[tuple, list] = {}
        wlink: dict[int, tuple] = {}
        for eid, ts, *rest in rows:
            by_key.setdefault(tuple(rest[:nk]), []).append((ts, eid, rest[nk + nl]))
            wlink[eid] = tuple(rest[nk:nk + nl])
        followers = None
        if rule.followed_by:
            followers = {}
            nj = len(rule.followed_by.join_on)
            for eid, ts, *kv in con.execute(sql["followed_by"]).fetchall():
                followers.setdefault(tuple(kv[:nj]), []).append((ts, eid, tuple(kv[nj:])))
        for key in sorted(by_key, key=lambda k: tuple(str(x) for x in k)):
            evs = by_key[key]
            cur: list | None = None
            windows = []
            for i, (ts, eid, cnt) in enumerate(evs):
                if cnt >= n:
                    # window members: events within W before this one
                    lo = ts.timestamp() - W
                    mem = [(t, e) for t, e, _ in evs[: i + 1] if t.timestamp() >= lo]
                    if cur and mem[0][0].timestamp() <= cur[-1][0].timestamp() + W:
                        cur.extend(m for m in mem if m not in cur)
                    else:
                        if cur:
                            windows.append(cur)
                        cur = list(mem)
            if cur:
                windows.append(cur)
            keydesc = ", ".join(f"{k}={v}" for k, v in zip(rule.group_by, key))
            for win in windows:
                win.sort()
                ev = f"count={len(win)} >= {n} within {rule.threshold.window} for {keydesc}"
                members = [e for _, e in win]
                ts_last = win[-1][0]
                if rule.followed_by:
                    fb = rule.followed_by
                    jk = tuple(key[rule.group_by.index(k)] for k in fb.join_on)
                    lim = parse_duration(fb.within)
                    # Follower must come after a window member and within `within` of it; members are
                    # restricted to the window events preceding the follower inside that bound.
                    hit, pre = None, []
                    for t, e, flink in followers.get(jk, []):
                        if e in members:
                            continue
                        pre = [(wt, we) for wt, we in win if 0 <= t.timestamp() - wt.timestamp() <= lim
                               and (not nl or wlink[we] == flink)]
                        if len(pre) >= n:
                            hit = (t, e)
                            break
                    if hit is None:
                        continue
                    members = [we for _, we in pre] + [hit[1]]
                    ts_first, ts_last = pre[0][0], hit[0]
                    ev = (f"count={len(pre)} >= {n} within {fb.within} before follower for {keydesc}; "
                          f"followed by matching event {hit[1]} on {', '.join(fb.join_on)}"
                          + "".join(f"; follower.{k} == window.{v}" for k, v in fb.link.items()))
                    dets.append({"members": members, "ts_first": ts_first, "ts_last": ts_last, "evidence": ev,
                                 "aggregate_key": keydesc})
                    continue
                dets.append({"members": members, "ts_first": win[0][0], "ts_last": ts_last, "evidence": ev,
                             "aggregate_key": keydesc})
    return dets


def detect(con: duckdb.DuckDBPyConnection, rules: list[Rule]) -> dict:
    att = config.attack()
    rows, timing = [], {}
    import time

    for rule in rules:
        t0 = time.perf_counter()
        dets = _run_rule(con, rule)
        timing[rule.id] = round(time.perf_counter() - t0, 4)
        tech = att["techniques"][rule.technique]
        tac = att["tactics"][rule.tactic]
        for d in dets:
            rows.append({
                "detection_id": f"{rule.id}:{d['members'][0]}", "rule_id": rule.id, "rule_version": rule.version,
                "rule_author": rule.author, "rule_title": rule.title, "technique_id": rule.technique,
                "technique_name": tech["name"], "tactic": rule.tactic, "tactic_ordinal": tac["ordinal"],
                "kill_chain_phase": tac["kill_chain_phase"], "severity": rule.severity,
                "confidence": rule.confidence, "label_priority": rule.label_priority,
                "ts_first": d["ts_first"], "ts_last": d["ts_last"], "member_event_ids": d["members"],
                "member_count": len(d["members"]), "evidence": d["evidence"],
                "aggregate_by": rule.aggregate_by,
                # PHASE2 frozen Detection: rules score with their prior confidence; the reason is the matched condition.
                "detector": f"rule:{rule.id}", "score": rule.confidence,
                "reasons": [{"feature": f"rule:{rule.id}", "value": len(d["members"]), "baseline": None,
                             "contribution": None, "text": d["evidence"]}],
            })
    _duplicates(rows)
    _write(con, rows)
    _labels(con)
    return {"detections": len(rows), "rule_seconds": timing}


def _duplicates(rows: list[dict]) -> None:
    """Dossier §12 step 1: a detection whose members are all inside a stronger detection of the
    same technique is marked duplicate_of (kept for audit, excluded from correlation)."""
    by_tech: dict[str, list[dict]] = {}
    for r in rows:
        r["duplicate_of"] = None
        by_tech.setdefault(r["technique_id"], []).append(r)
    for group in by_tech.values():
        for r in group:
            ms = set(r["member_event_ids"])
            for o in group:
                if o is r:
                    continue
                stronger = (o["severity"], -o["label_priority"], o["detection_id"]) > \
                           (r["severity"], -r["label_priority"], r["detection_id"])
                if stronger and ms <= set(o["member_event_ids"]):
                    r["duplicate_of"] = o["detection_id"]
                    break


def _write(con: duckdb.DuckDBPyConnection, rows: list[dict]) -> None:
    con.execute("DROP TABLE IF EXISTS detections")
    con.execute("""CREATE TABLE detections (detection_id VARCHAR, rule_id VARCHAR, rule_version INT,
        rule_author VARCHAR, rule_title VARCHAR, technique_id VARCHAR, technique_name VARCHAR, tactic VARCHAR,
        tactic_ordinal INT, kill_chain_phase VARCHAR, severity INT, confidence DOUBLE, label_priority INT,
        ts_first TIMESTAMP, ts_last TIMESTAMP, member_event_ids BIGINT[], member_count INT,
        evidence VARCHAR, aggregate_by VARCHAR[], duplicate_of VARCHAR, entities JSON,
        detector VARCHAR, score DOUBLE, reasons JSON)""")
    rows.sort(key=lambda r: (r["ts_first"], r["rule_id"], r["detection_id"]))
    for r in rows:
        con.execute("INSERT INTO detections VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,?,?,?)",
                    [r[k] for k in ("detection_id", "rule_id", "rule_version", "rule_author", "rule_title",
                                    "technique_id", "technique_name", "tactic", "tactic_ordinal",
                                    "kill_chain_phase", "severity", "confidence", "label_priority", "ts_first",
                                    "ts_last", "member_event_ids", "member_count", "evidence", "aggregate_by",
                                    "duplicate_of", "detector", "score")] + [dumps(r["reasons"])])
    # Entities: distinct envelope entity values over each detection's member events.
    aggs = ", ".join(f"list(DISTINCT e.\"{f}\" ORDER BY e.\"{f}\") FILTER (WHERE e.\"{f}\" IS NOT NULL) AS \"{f}\""
                     for f in ENTITY_FIELDS)
    con.execute(f"""CREATE OR REPLACE TEMP TABLE _ent AS
        SELECT d.detection_id, {aggs}
        FROM detections d, unnest(d.member_event_ids) AS m(eid) JOIN events e ON e.event_id = m.eid
        GROUP BY d.detection_id""")
    obj = ", ".join(f"'{f}', coalesce(_ent.\"{f}\", [])" for f in ENTITY_FIELDS)
    con.execute(f"UPDATE detections SET entities = json_object({obj}) FROM _ent "
                f"WHERE detections.detection_id = _ent.detection_id")


def _labels(con: duckdb.DuckDBPyConnection) -> None:
    """One primary technique per raw event (lowest label_priority, then rule_id); the rest go to
    also_matched so valid secondary matches are never discarded."""
    con.execute("""CREATE OR REPLACE TABLE event_labels AS
        WITH m AS (
          SELECT DISTINCT eid AS event_id, rule_id, technique_id, tactic, label_priority
          FROM detections, unnest(member_event_ids) AS u(eid)),
        r AS (SELECT *, row_number() OVER (PARTITION BY event_id ORDER BY label_priority, rule_id) AS rn FROM m)
        SELECT event_id,
               max(CASE WHEN rn = 1 THEN rule_id END) AS primary_rule,
               max(CASE WHEN rn = 1 THEN technique_id END) AS primary_technique,
               max(CASE WHEN rn = 1 THEN tactic END) AS primary_tactic,
               list(struct_pack(rule_id := rule_id, technique_id := technique_id) ORDER BY label_priority, rule_id)
                 FILTER (WHERE rn > 1) AS also_matched
        FROM r GROUP BY event_id ORDER BY event_id""")


def rules_summary(rules: list[Rule]) -> list[dict]:
    return [{"id": r.id, "title": r.title, "technique": r.technique, "tactic": r.tactic, "author": r.author,
             "type": r.type, "severity": r.severity, "confidence": r.confidence,
             "label_priority": r.label_priority, "source_file": r.source_file,
             "sql": compile_rule(r)} for r in rules]


def dumps(o) -> str:
    return json.dumps(o, default=str)
