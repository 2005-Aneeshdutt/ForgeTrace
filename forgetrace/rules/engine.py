"""YAML rule loader, SQL compiler and detector (dossier §10 'rules'/'detect', §12 rule types).

Why this exists: detection must be configuration-driven (B-4) and auditable. Each rule's
filter compiles to a DuckDB WHERE clause over the normalised envelope; thresholds use a
SQL window count; followed_by / first_seen add a bounded join. Rules may only reference
envelope fields (ALLOWED_FIELDS) so vendor verdict fields can never be used.
"""
from __future__ import annotations

import bisect
import json
import re
from pathlib import Path
from typing import Any, Literal

import duckdb
import pyarrow as pa
import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

from forgetrace import config
from forgetrace.ingest.ingest import SCHEMA

# Detection may never read these (also enforced by tests/test_vendor_ban.py).
BANNED_PREFIXES = ("threat.", "rule.", "labels", "event.kind", "event.severity")
NON_DETECTION_FIELDS = {"event_id", "file_id", "byte_offset", "line_no", "line_digest", "source_event_id", "dataset"}
ALLOWED_FIELDS = set(SCHEMA.names) - NON_DETECTION_FIELDS
ENTITY_FIELDS = ["user", "target_user", "host", "host_ip", "src_ip", "dst_ip", "logon_id", "domain_name",
                 "process", "group_name"]
_DET_ARROW = pa.schema([
    ("detection_id", pa.string()), ("rule_id", pa.string()), ("rule_version", pa.int32()), ("rule_author", pa.string()),
    ("rule_title", pa.string()), ("technique_id", pa.string()), ("technique_name", pa.string()), ("tactic", pa.string()),
    ("tactic_ordinal", pa.int32()), ("kill_chain_phase", pa.string()), ("severity", pa.int32()), ("confidence", pa.float64()),
    ("label_priority", pa.int32()), ("ts_first", pa.timestamp("us")), ("ts_last", pa.timestamp("us")),
    ("member_event_ids", pa.list_(pa.int64())), ("member_count", pa.int32()), ("evidence", pa.string()),
    ("aggregate_by", pa.list_(pa.string())), ("duplicate_of", pa.string()), ("detector", pa.string()),
    ("score", pa.float64()), ("reasons", pa.string()),
])
OPS = {"eq", "ne", "in", "contains", "startswith", "endswith", "regex", "gte", "lte", "gt", "lt",
       "is_null", "not_null", "rare"}


def parse_duration(s: str) -> int:
    m = re.fullmatch(r"(\d+)\s*([smhd])", str(s).strip())
    if not m:
        raise ValueError(f"bad duration {s!r}")
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


class Threshold(BaseModel):
    """count: events in the window >= count (default); distinct: distinct values of a field >= count
    (port scans, password spraying, impossible travel); sum: total of a numeric field >= min (staged
    exfiltration). All evaluated as a sliding window ending at each event (DECISIONS D-68)."""
    count: int | None = Field(default=None, ge=1)
    window: str
    distinct: str | None = None
    sum: str | None = None
    min: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def _shape(self) -> "Threshold":
        if self.distinct and self.sum:
            raise ValueError("threshold: use either distinct or sum")
        if self.sum and self.min is None:
            raise ValueError("threshold.sum needs min")
        if not self.sum and self.count is None:
            raise ValueError("threshold needs count")
        for f in (self.distinct, self.sum):
            if f and f not in ALLOWED_FIELDS:
                raise ValueError(f"threshold field {f!r} is not an envelope field")
        return self

    @property
    def seconds(self) -> int:
        return parse_duration(self.window)

    @property
    def value(self) -> int:
        return self.min if self.sum else self.count

    def sql(self) -> str:
        if self.distinct:
            return f'count(DISTINCT "{self.distinct}")'
        if self.sum:
            return f'sum(coalesce("{self.sum}", 0))'
        return "count(*)"

    def describe(self) -> str:
        return (f"distinct {self.distinct}" if self.distinct else f"sum {self.sum}" if self.sum else "count")


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
        # Only groups whose window metric reaches the threshold at least once can produce a detection,
        # so the rest never leave DuckDB (on firex-10G this keeps millions of rows out of Python).
        link_cols = "".join(f', "_w_{v}"' for v in (rule.followed_by.link.values() if rule.followed_by else []))
        not_null = " AND ".join(f'"{k}" IS NOT NULL' for k in rule.group_by)
        sql["threshold"] = (
            f"SELECT event_id, ts, {keys}{link_cols}, win_count FROM ("
            f"SELECT event_id, ts, {keys}{wl}, {rule.threshold.sql()} OVER (PARTITION BY {keys} ORDER BY ts "
            f"RANGE BETWEEN INTERVAL {rule.threshold.seconds} SECOND PRECEDING AND CURRENT ROW) AS win_count "
            f"FROM events WHERE {where} AND {not_null}"
            f") QUALIFY max(win_count) OVER (PARTITION BY {keys}) >= {rule.threshold.value} "
            f"ORDER BY {keys}, ts, event_id")
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
        n, W = rule.threshold.value, rule.threshold.seconds
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
            ftimes = {k: [t.timestamp() for t, _, _ in v] for k, v in followers.items()}
        for key in sorted(by_key, key=lambda k: tuple(str(x) for x in k)):
            evs = by_key[key]
            windows = merge_windows(evs, n, W)
            keydesc = ", ".join(f"{k}={v}" for k, v in zip(rule.group_by, key))
            for win in windows:
                ev = (f"count={len(win)} >= {n} within {rule.threshold.window} for {keydesc}" if not
                      (rule.threshold.distinct or rule.threshold.sum) else
                      f"{rule.threshold.describe()} >= {n} within {rule.threshold.window} for {keydesc} "
                      f"({len(win)} events)")
                members = [e for _, e in win]
                ts_last = win[-1][0]
                if rule.followed_by:
                    fb = rule.followed_by
                    jk = tuple(key[rule.group_by.index(k)] for k in fb.join_on)
                    hit, pre = first_follower(win, followers.get(jk, []), n, parse_duration(fb.within),
                                              wlink if nl else None, ftimes.get(jk, []))
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


# ----------------------------------------------------------------------------- threshold windows
# Why this exists: a threshold rule turns every event whose SQL window count reaches `count` into a
# window of the events in the preceding W seconds, and overlapping or touching windows (next window
# starts within W of the previous window's last event) merge into one maximal detection, so no
# member is ever dropped. Phase 1 rebuilt each window by rescanning all earlier events of the key
# and de-duplicated with list membership, which is O(k^2) per group key; on dense keys (an Office
# launch every few minutes for R010, a user's typo failures for R001c) a 10 GB run did not finish
# detection in 54 min. Events of a key arrive sorted by (ts, event_id), so a two-pointer sweep gives
# the same windows in O(k): the window start only moves forward, and a merged window is a union of
# index ranges that never leaves a gap above the current start. Pinned to the Phase 1 output by
# tests/test_engine_windows.py.
def merge_windows(evs: list[tuple], n: int, W: float) -> list[list[tuple]]:
    """evs = [(ts, event_id, window_count)] sorted by (ts, event_id). Returns sorted [(ts, event_id)] lists."""
    T = [ts.timestamp() for ts, _, _ in evs]
    windows: list[list[int]] = []
    cur: list[int] | None = None
    lo = 0
    for i in range(len(evs)):
        if evs[i][2] < n:
            continue
        lim = T[i] - W
        while T[lo] < lim:
            lo += 1
        if cur is not None and T[lo] <= T[cur[-1]] + W:
            cur.extend(range(max(lo, cur[-1] + 1), i + 1))
        else:
            if cur is not None:
                windows.append(cur)
            cur = list(range(lo, i + 1))
    if cur is not None:
        windows.append(cur)
    return [[(evs[j][0], evs[j][1]) for j in w] for w in windows]


def first_follower(win: list[tuple], followers: list[tuple], n: int, lim: float,
                   wlink: dict | None, ftimes: list[float] | None = None) -> tuple[tuple | None, list]:
    """First follower (in (ts, event_id) order) preceded within `lim` seconds by >= n window members
    (with matching link values when the rule has a `link`). Binary search replaces the Phase 1 scan
    of the whole window per follower, and `ftimes` (the followers' sorted timestamps) lets the scan
    start at the window instead of at the key's first follower; followers outside
    [first member, last member + lim] cannot have members before them within lim, so skipping them
    changes nothing. The boundary test is the original float expression."""
    Tw = [t.timestamp() for t, _ in win]
    members = {e for _, e in win}
    if not Tw:
        return None, []
    if ftimes is None:
        ftimes = [t.timestamp() for t, _, _ in followers]
    lo = bisect.bisect_left(ftimes, Tw[0] - 1)
    for idx in range(lo, len(followers)):
        t, e, flink = followers[idx]
        tf = ftimes[idx]
        if tf - Tw[-1] > lim + 1:
            break
        if e in members:
            continue
        if tf < Tw[0]:
            continue
        a = bisect.bisect_left(Tw, tf - lim - 1)
        b = bisect.bisect_right(Tw, tf + 1)
        pre = [win[k] for k in range(a, b) if 0 <= tf - Tw[k] <= lim and (wlink is None or wlink[win[k][1]] == flink)]
        if len(pre) >= n:
            return (t, e), pre
    return None, []


def detection_row(rule: Rule, d: dict) -> dict:
    """One detection in the stored shape; d = {members, ts_first, ts_last, evidence}."""
    att = config.attack()
    tech = att["techniques"][rule.technique]
    tac = att["tactics"][rule.tactic]
    return {
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
    }


def detect(con: duckdb.DuckDBPyConnection, rules: list[Rule], extra_rows: list[dict] | None = None) -> dict:
    """Run rules over the `events` view and store detections. extra_rows are detections produced
    elsewhere (the live engine's bucketed long-window rules and first-seen state)."""
    rows, timing = list(extra_rows or []), {}
    import time

    for rule in rules:
        t0 = time.perf_counter()
        dets = _run_rule(con, rule)
        timing[rule.id] = round(time.perf_counter() - t0, 4)
        rows.extend(detection_row(rule, d) for d in dets)
    _duplicates(rows)
    _write(con, rows)
    _labels(con)
    return {"detections": len(rows), "rule_seconds": timing}


def _duplicates(rows: list[dict]) -> None:
    """Dossier §12 step 1: a detection whose members are all inside a stronger detection of the
    same technique is marked duplicate_of (kept for audit, excluded from correlation).
    A superset must contain the detection's first member, so candidates come from an event index
    instead of comparing every pair (Phase 1 was O(d^2) set builds per technique). Among qualifying
    candidates the earliest in input order wins, exactly as the Phase 1 scan did."""
    by_tech: dict[str, list[dict]] = {}
    for r in rows:
        r["duplicate_of"] = None
        by_tech.setdefault(r["technique_id"], []).append(r)
    for group in by_tech.values():
        sets = [set(r["member_event_ids"]) for r in group]
        holders: dict[int, list[int]] = {}
        for j, ms in enumerate(sets):
            for m in ms:
                holders.setdefault(m, []).append(j)
        # A rule is never absorbed by a model flag (models corroborate rules, D-92); among rules: Phase 1 order.
        rank = [(not str(r.get("rule_id", "")).startswith("ML-"), r["severity"], -r["label_priority"], r["detection_id"]) for r in group]
        for i, r in enumerate(group):
            key = rank[i]
            for j in holders.get(r["member_event_ids"][0], []):  # ascending j = Phase 1 scan order
                if j == i:
                    continue
                o = group[j]
                if rank[j] > key and sets[i] <= sets[j]:
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
    cols = ("detection_id", "rule_id", "rule_version", "rule_author", "rule_title", "technique_id", "technique_name",
            "tactic", "tactic_ordinal", "kill_chain_phase", "severity", "confidence", "label_priority", "ts_first",
            "ts_last", "member_event_ids", "member_count", "evidence", "aggregate_by", "duplicate_of", "detector", "score")
    # One columnar insert instead of a statement per detection.
    batch = pa.table({**{c: [r[c] for r in rows] for c in cols}, "reasons": [dumps(r["reasons"]) for r in rows]},
                     schema=_DET_ARROW)
    con.register("_det_batch", batch)
    con.execute(f"INSERT INTO detections ({', '.join(cols)}, reasons) SELECT {', '.join(cols)}, reasons FROM _det_batch")
    con.unregister("_det_batch")
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
