"""Load a finished run directory into plain Python structures for scoring.

Why this exists: the metrics in forgetrace/eval/metrics.py must be unit-testable on hand-built
toys (PHASE2 METRICS: "every metric unit-tested on a toy ground truth"), so they take a RunView
rather than a DuckDB connection. This module is the only place that reads a run's tables for
evaluation, and it resolves GroundTruth locators (event_ids, line_refs, auth edges) to event ids.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

import duckdb

from forgetrace.eval.groundtruth import GroundTruth, Step


@dataclass
class Det:
    detection_id: str
    detector: str
    technique_id: str
    members: list[int]
    score: float
    ts_first: datetime
    duplicate_of: str | None = None


@dataclass
class Incident:
    incident_id: int
    risk: float
    nodes: dict[str, list[int]]            # group_id -> member event ids
    node_technique: dict[str, str]         # group_id -> technique
    path: list[str]                        # primary path group ids, in order
    detection_ids: list[str] = field(default_factory=list)


@dataclass
class RunView:
    detections: list[Det]
    labels: dict[int, str]                 # event_id -> primary technique
    incidents: list[Incident]
    group_of_detection: dict[str, str]     # detection_id -> group_id (non-duplicates)
    ev_meta: dict[int, tuple[datetime, str | None]] = field(default_factory=dict)  # event_id -> (ts, host)
    days: float = 1.0                      # span of the data in days (for alerts/day)
    run_stats: dict = field(default_factory=dict)


def load_run(run_dir: Path) -> RunView:
    con = duckdb.connect(str(run_dir / "forgetrace.duckdb"), read_only=True)
    cols = {r[0] for r in con.execute("DESCRIBE detections").fetchall()}
    det_sql = ("detector, score" if {"detector", "score"} <= cols else "'rule:' || rule_id, confidence")
    dets = [Det(detection_id=r[0], detector=r[1], score=float(r[2]), technique_id=r[3], members=list(r[4]),
                ts_first=r[5], duplicate_of=r[6]) for r in con.execute(
        f"SELECT detection_id, {det_sql}, technique_id, member_event_ids, ts_first, duplicate_of "
        f"FROM detections ORDER BY detection_id").fetchall()]
    labels = dict(con.execute("SELECT event_id, primary_technique FROM event_labels").fetchall())
    g_of_d = {}
    for gid, dids in con.execute("SELECT group_id, detection_ids FROM alert_groups").fetchall():
        for d in json.loads(dids):
            g_of_d[d] = gid
    incs = []
    for (js,) in con.execute("SELECT json FROM incident_cache ORDER BY incident_id").fetchall():
        p = json.loads(js)
        nodes = {n["group_id"]: list(n["member_event_ids"]) for n in p["observed"]["nodes"]}
        tech = {n["group_id"]: n["technique_id"] for n in p["observed"]["nodes"]}
        dids = sorted(d for d, g in g_of_d.items() if g in nodes)
        incs.append(Incident(p["incident_id"], float(p.get("risk_score") or 0), nodes, tech,
                             list(p["inferred"]["primary_path"]["group_ids"]), dids))
    lo, hi = con.execute("SELECT min(ts), max(ts) FROM events").fetchone()
    days = max((hi - lo).total_seconds() / 86400, 1 / 24) if lo and hi else 1.0
    con.close()
    stats_p = run_dir / "run_stats.json"
    return RunView(dets, labels, incs, g_of_d, days=days,
                   run_stats=json.loads(stats_p.read_text()) if stats_p.exists() else {})


def attach_event_meta(rv: RunView, run_dir: Path, event_ids: set[int]) -> None:
    """Fetch (ts, host) for the given events (GT step events + detection members) for the
    same-host ±60 s fallback; bounded by the number of labelled and detected events."""
    if not event_ids:
        return
    con = duckdb.connect(str(run_dir / "forgetrace.duckdb"), read_only=True)
    con.execute("CREATE TEMP TABLE _ids (event_id BIGINT)")
    con.executemany("INSERT INTO _ids VALUES (?)", [(e,) for e in event_ids])
    for eid, ts, host in con.execute("SELECT e.event_id, e.ts, e.host FROM events e JOIN _ids USING (event_id)").fetchall():
        rv.ev_meta[eid] = (ts, host)
    con.close()


def resolve_steps(gt: GroundTruth, run_dir: Path) -> dict[tuple[str, int], set[int]]:
    """(attack_id, step order) -> event ids, from whichever locator the step carries."""
    con = duckdb.connect(str(run_dir / "forgetrace.duckdb"), read_only=True)
    files = {Path(f["path"]).name: f["file_id"] for f in json.loads((run_dir / "files.json").read_text())["files"]}
    out: dict[tuple[str, int], set[int]] = {}
    for a in gt.attacks:
        for s in a.steps:
            out[(a.attack_id, s.order)] = _resolve(con, files, s)
    con.close()
    return out


def _resolve(con, files: dict[str, int], s: Step) -> set[int]:
    ids = set(s.event_ids)
    if s.line_refs:
        by_file: dict[int, list[int]] = {}
        for r in s.line_refs:
            if r.file in files:
                by_file.setdefault(files[r.file], []).append(r.line)
        for fid, lines in by_file.items():
            ids |= {e for (e,) in con.execute(
                "SELECT event_id FROM events WHERE file_id = ? AND list_contains(?, line_no)", [fid, lines]).fetchall()}
    for e in s.edges:
        # A red-team auth edge = successful logon on dst from src (host or IP) within ±60 s of t.
        ids |= {r[0] for r in con.execute(
            """SELECT event_id FROM events WHERE event_type IN ('auth_success', 'logon')
               AND upper(host) = upper(?) AND (upper(coalesce(src_ip, '')) = upper(?) OR upper(coalesce(host_ip, '')) = upper(?))
               AND ts BETWEEN ? AND ?""",
            [e.dst, e.src, e.src, e.t - timedelta(seconds=60), e.t + timedelta(seconds=60)]).fetchall()}
    return ids
