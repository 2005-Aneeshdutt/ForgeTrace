"""Investigation API (dossier §13 API contract) + analyst workflow (workspaces, uploads, runs).

Workspaces: FORGETRACE_OUT is either one result directory (contains forgetrace.duckdb) or a root
whose subdirectories are workspaces: `sample` (data/sample/events.log) and `input` (the
data/input/ drop folder). Every read endpoint takes `?ws=` and serves precomputed incident JSON
from that workspace's DuckDB. Evidence is re-read from the immutable source by event_id only.
Uploads stream to data/input/ (no file paths accepted, names validated). Local-only by default.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

import duckdb
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from forgetrace import config
from forgetrace.ingest.evidence import get_raw
from forgetrace.reach.reach import reachability, simulate
from forgetrace.rules.engine import load_rules, rules_summary

STATIC = Path(__file__).parent / "static"
OUT = Path(os.environ.get("FORGETRACE_OUT", config.ROOT / "out")).resolve()
INPUT_DIR = Path(os.environ.get("FORGETRACE_INPUT", config.ROOT / "data" / "input")).resolve()
SOURCES = {"demo": config.ROOT / "data" / "demo" / "demo_events.log",
           "sample": config.ROOT / "data" / "sample" / "events.log", "input": INPUT_DIR}
ALLOWED_SUFFIXES = {".log", ".json", ".jsonl", ".ndjson", ".cef", ".txt"}
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
MAX_UPLOAD = int(os.environ.get("FORGETRACE_MAX_UPLOAD", 8 * 2**30))

app = FastAPI(title="ForgeTrace", version=config.CODE_VERSION)
app.mount("/static", StaticFiles(directory=STATIC), name="static")

_cons: dict[str, tuple] = {}
_lock = threading.Lock()
_job: dict[str, Any] = {"state": "idle"}


# ----------------------------------------------------------------------------- workspaces
def _rel(p: Path) -> str:
    return str(p.relative_to(config.ROOT)) if p.is_relative_to(config.ROOT) else str(p)


def _db_file(d: Path) -> Path:
    """Live workspaces are read from the snapshot the live engine publishes after every batch."""
    snap = d / "live_snapshot.duckdb"
    return snap if snap.exists() else d / "forgetrace.duckdb"


def ws_dirs() -> dict[str, Path]:
    if (OUT / "forgetrace.duckdb").exists() or (OUT / "live_snapshot.duckdb").exists():
        return {OUT.name: OUT}
    found = {d.name: d for d in sorted(OUT.iterdir()) if d.is_dir() and
             ((d / "forgetrace.duckdb").exists() or (d / "live_snapshot.duckdb").exists())} \
        if OUT.exists() else {}
    for name in SOURCES:  # always offer the runnable workspaces, even before their first run
        found.setdefault(name, OUT / name)
    return found


def default_ws() -> str:
    dirs = ws_dirs()
    ready = [n for n, d in dirs.items() if (d / "forgetrace.duckdb").exists()]
    if not ready:
        raise HTTPException(503, "no analysed workspace yet; run `make run` or analyse the input folder")
    return max(ready, key=lambda n: (dirs[n] / "run_stats.json").stat().st_mtime
               if (dirs[n] / "run_stats.json").exists() else 0)


def ws_dir(ws: str | None) -> tuple[str, Path]:
    name = ws or default_ws()
    d = ws_dirs().get(name)
    if d is None:
        raise HTTPException(404, f"unknown workspace {name!r}")
    if _job.get("state") == "running" and _job.get("workspace") == name:
        raise HTTPException(409, f"workspace {name!r} is being re-analysed; try again when the run finishes")
    if not _db_file(d).exists():
        raise HTTPException(404, f"workspace {name!r} has not been analysed yet")
    return name, d


def con(ws: str | None) -> duckdb.DuckDBPyConnection:
    name, d = ws_dir(ws)
    f = _db_file(d)
    stamp = f.stat().st_mtime_ns
    with _lock:
        c, seen = _cons.get(name, (None, None))
        if c is None or seen != stamp:  # a newer live snapshot was published
            if c is not None:
                c.close()
            c = duckdb.connect(str(f), read_only=True)
            _cons[name] = (c, stamp)
    return c.cursor()


def _drop_con(name: str) -> None:
    with _lock:
        c = _cons.pop(name, None)
        if c is not None:
            c[0].close()


@app.middleware("http")
async def security_headers(request, call_next):
    resp = await call_next(request)
    resp.headers["Content-Security-Policy"] = ("default-src 'self'; script-src 'self'; style-src 'self'; "
                                               "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
                                               "frame-ancestors 'none'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


# ----------------------------------------------------------------------------- models
class Health(BaseModel):
    status: str
    workspace: str
    manifest_digest: str | None
    config_hash: str
    code_version: str
    incidents: int


class IncidentSummary(BaseModel):
    incident_id: int
    risk_score: float
    severity: str
    status: str
    ts_first: str
    ts_last: str
    tactics: list[str]
    tactic_count: int
    techniques: list[str]
    raw_alert_count_total: int
    member_event_count: int
    top_entities: list[str]


class RawEvidence(BaseModel):
    event_id: int
    display_id: str
    file_id: int
    byte_offset: int
    file: str | None
    line_no: int | None
    source_event_id: str | None
    raw: str | None
    stored_digest: str | None
    digest: str | None
    verified: bool
    reason: str | None


class Action(BaseModel):
    type: Literal["disable_account"]
    target: str = Field(min_length=1, max_length=256)


class SimulateRequest(BaseModel):
    actions: list[Action] = Field(min_length=1, max_length=20)


class SimulateResponse(BaseModel):
    actions: list[dict[str, Any]]
    simulation_only: bool
    before_critical_reachable: int
    after_critical_reachable: int
    no_longer_reachable_critical: list[str]
    still_reachable_critical: list[dict[str, Any]]
    removed_relationships: list[dict[str, Any]]
    removed_from_compromised_set: list[str]
    caveat: str
    disclaimer: str


class RunRequest(BaseModel):
    workspace: Literal["demo", "sample", "input"]


# ----------------------------------------------------------------------------- helpers
def _payload(incident_id: int, ws: str | None) -> dict:
    row = con(ws).execute("SELECT json FROM incident_cache WHERE incident_id = ?", [incident_id]).fetchone()
    if row is None:
        raise HTTPException(404, "incident not found")
    return json.loads(row[0])


def _internal(p: dict) -> tuple[dict, dict]:
    gid = {}
    for n in p["observed"]["nodes"]:
        n = dict(n)
        n["ts_first"] = datetime.fromisoformat(n["ts_first"].rstrip("Z"))
        n["ts_last"] = datetime.fromisoformat(n["ts_last"].rstrip("Z"))
        gid[n["group_id"]] = n
    inc = {"group_ids": p["group_ids"], "ts_last": datetime.fromisoformat(p["ts_last"].rstrip("Z"))}
    return inc, gid


def _read_json(path: Path) -> dict | None:
    return json.loads(path.read_text()) if path.exists() else None


# ----------------------------------------------------------------------------- core routes (dossier §13)
@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/health", response_model=Health)
def health(ws: str | None = None):
    name, d = ws_dir(ws)
    mf = _read_json(d / "files.json")
    n = con(name).execute("SELECT count(*) FROM incident_cache").fetchone()[0]
    return Health(status="ok", workspace=name, manifest_digest=mf["manifest_digest"] if mf else None,
                  config_hash=config.config_hash(), code_version=config.CODE_VERSION, incidents=n)


@app.get("/incidents", response_model=list[IncidentSummary])
def incidents(ws: str | None = None, sort: Literal["risk", "time"] = "risk", limit: int = 500):
    out = []
    for (js,) in con(ws).execute("SELECT json FROM incident_cache").fetchall():
        p = json.loads(js)
        out.append(IncidentSummary(
            incident_id=p["incident_id"], risk_score=p["risk_score"], severity=p["severity"], status=p["status"],
            ts_first=p["ts_first"], ts_last=p["ts_last"], tactics=p["tactics"], tactic_count=len(p["tactics"]),
            techniques=p["techniques"], raw_alert_count_total=p["raw_alert_count_total"],
            member_event_count=p["member_event_count"],
            top_entities=[k for k in p["entity_keys"] if k.startswith(("user:", "host:"))][:8]))
    key = (lambda s: (-s.risk_score, s.incident_id)) if sort == "risk" else (lambda s: (s.ts_first, s.incident_id))
    return sorted(out, key=key)[:limit]


@app.get("/incidents/{incident_id}")
def incident(incident_id: int, ws: str | None = None) -> dict[str, Any]:
    return _payload(incident_id, ws)


@app.get("/incidents/{incident_id}/path")
def incident_path(incident_id: int, ws: str | None = None) -> dict[str, Any]:
    p = _payload(incident_id, ws)
    edges = {e["edge_id"]: e for e in p["inferred"]["edges"]}
    nodes = {n["group_id"]: n for n in p["observed"]["nodes"]}

    def expand(path):
        return {**path, "steps": [{"group_id": g, "tactic": nodes[g]["tactic"], "technique_id": nodes[g]["technique_id"],
                                   "technique_name": nodes[g]["technique_name"], "ts_first": nodes[g]["ts_first"],
                                   "member_event_ids": nodes[g]["member_event_ids"]} for g in path["group_ids"]],
                "edges": [edges[e] for e in path["edge_ids"] if e in edges]}

    return {"incident_id": incident_id, "primary": expand(p["inferred"]["primary_path"]),
            "alternatives": [expand(p["inferred"]["strongest_chain"])],
            "note": "Top-k alternative paths are deferred to Phase 2; the alternative shown is the dossier DP chain."}


@app.get("/incidents/{incident_id}/reach")
@app.get("/incidents/{incident_id}/reachability")
def incident_reach(incident_id: int, ws: str | None = None) -> dict[str, Any]:
    p = _payload(incident_id, ws)
    inc, gid = _internal(p)
    r = reachability(con(ws), inc, gid)
    r["disclaimer"] = config.load_yaml(config.CONFIG_DIR / "reach.yml")["disclaimer"].format(
        X=r["critical_reachable"], Y=r["critical_reachable"])
    r["containment_candidates"] = p["inferred"]["containment_candidates"]
    return r


@app.post("/incidents/{incident_id}/simulate", response_model=SimulateResponse)
def incident_simulate(incident_id: int, body: SimulateRequest, ws: str | None = None):
    p = _payload(incident_id, ws)
    inc, gid = _internal(p)
    return simulate(con(ws), inc, gid, [a.model_dump() for a in body.actions])


@app.get("/events/{event_id}/raw", response_model=RawEvidence)
def event_raw(event_id: int, ws: str | None = None):
    if event_id < 0:
        raise HTTPException(400, "event_id must be a non-negative integer")
    _, d = ws_dir(ws)
    r = get_raw(event_id, d, con(ws))
    if r["reason"] in ("unknown file_id", "event_id not found in events or parse_errors"):
        raise HTTPException(404, r["reason"])
    return r


@app.get("/alerts")
def alerts(ws: str | None = None, unlinked: bool = True) -> list[dict[str, Any]]:
    c = con(ws)
    groups = {g: (r, t, tac, ts, ents) for g, r, t, tac, ts, ents in c.execute(
        "SELECT group_id, rule_id, technique_id, tactic, ts_first, entities FROM alert_groups").fetchall()}
    out = []
    for g_ids, tactics, reason in c.execute("SELECT group_ids, tactics, reason FROM abstained").fetchall():
        ids = json.loads(g_ids)
        detail = []
        for g in ids:
            r, t, tac, ts, ents = groups[g]
            e = json.loads(ents)
            detail.append({"group_id": g, "rule_id": r, "technique_id": t, "tactic": tac, "ts_first": json.loads(ts),
                           "users": e.get("user", []), "hosts": e.get("host", [])})
        out.append({"group_ids": ids, "tactics": json.loads(tactics), "reason": reason, "groups": detail})
    return out


@app.get("/rules")
def rules() -> list[dict[str, Any]]:
    return rules_summary(load_rules())


# ----------------------------------------------------------------------------- analyst workflow
@app.get("/workspaces")
def workspaces() -> list[dict[str, Any]]:
    out = []
    for name, d in ws_dirs().items():
        live = _read_json(d / "live_status.json")
        if live:  # live workspace: summarised from the engine's status file
            out.append({"name": name, "analysed": _db_file(d).exists(), "live": True, "runnable": False, "source": None,
                        "finished_at": live.get("updated_at"), "incidents": None,
                        "events": (live.get("totals") or {}).get("events"), "files": [], "has_metrics": False,
                        "alerts": (live.get("knowledge_base") or {}).get("alerts"), "batches": live.get("batches")})
            continue
        st = _read_json(d / "run_stats.json")
        out.append({"name": name, "analysed": (d / "forgetrace.duckdb").exists(), "live": False,
                    "runnable": name in SOURCES and not (OUT / "forgetrace.duckdb").exists(),
                    "source": _rel(SOURCES[name]) if name in SOURCES else None,
                    "finished_at": st.get("finished_at") if st else None,
                    "incidents": st.get("incidents") if st else None,
                    "events": st["ingest"]["events"] if st else None,
                    "files": [Path(f["path"]).name for f in st["dataset"]["files"]] if st else [],
                    "has_metrics": (d / "metrics.json").exists()})
    return out


@app.get("/overview")
def overview(ws: str | None = None) -> dict[str, Any]:
    name, d = ws_dir(ws)
    c = con(name)
    st = _read_json(d / "run_stats.json") or {}
    q = lambda sql: c.execute(sql).fetchall()  # noqa: E731
    span = q("SELECT min(ts), max(ts) FROM events")[0]
    return {
        "workspace": name, "run": st,
        "files": [{"file_id": f["file_id"], "name": Path(f["path"]).name, "path": f["path"], "size": f["size"],
                   "sha256": f["sha256"]} for f in st.get("dataset", {}).get("files", [])],
        "time_span": [str(span[0]) if span[0] else None, str(span[1]) if span[1] else None],
        "events_by_type": [{"key": k or "(unclassified)", "count": n} for k, n in
                           q("SELECT event_type, count(*) FROM events GROUP BY 1 ORDER BY 2 DESC")],
        "events_by_format": [{"key": k, "count": n} for k, n in
                             q("SELECT raw_format, count(*) FROM events GROUP BY 1 ORDER BY 2 DESC")],
        "detections_by_tactic": [{"key": k, "ordinal": o, "count": n} for k, o, n in
                                 q("SELECT tactic, min(tactic_ordinal), count(*) FROM detections GROUP BY 1 ORDER BY 2")],
        "detections_by_rule": [{"key": r, "technique": t, "title": ti, "count": n, "events": m} for r, t, ti, n, m in
                               q("SELECT rule_id, technique_id, any_value(rule_title), count(*), sum(member_count) "
                                 "FROM detections GROUP BY 1, 2 ORDER BY 1")],
        "parse_errors": [{"line_no": ln, "file_id": f, "error": e, "preview": p} for f, ln, e, p in
                         q("SELECT file_id, line_no, error, preview FROM parse_errors ORDER BY file_id, line_no LIMIT 50")],
        "funnel": {"events": st.get("ingest", {}).get("events"), "detections": st.get("detections"),
                   "alert_groups": st.get("alert_groups"), "incidents": st.get("incidents"),
                   "unlinked": st.get("abstained_components")},
    }


@app.get("/detections")
def detections(ws: str | None = None, limit: int = 1000) -> list[dict[str, Any]]:
    c = con(ws)
    inc_of: dict[str, int] = {}
    for iid, js in c.execute("SELECT incident_id, json FROM incident_cache").fetchall():
        for n in json.loads(js)["observed"]["nodes"]:
            for did in n["detection_ids"]:
                inc_of[did] = iid
            for a in n.get("also_matched", []):
                inc_of[a["detection_id"]] = iid
    rows = c.execute("""SELECT detection_id, rule_id, rule_title, technique_id, technique_name, tactic, severity,
            confidence, ts_first, ts_last, member_count, member_event_ids[1:20], evidence, duplicate_of, entities
        FROM detections ORDER BY ts_first, rule_id LIMIT ?""", [limit]).fetchall()
    cols = ["detection_id", "rule_id", "rule_title", "technique_id", "technique_name", "tactic", "severity",
            "confidence", "ts_first", "ts_last", "member_count", "member_event_ids", "evidence", "duplicate_of", "entities"]
    out = []
    for r in rows:
        d = dict(zip(cols, r))
        d["ts_first"], d["ts_last"] = str(d["ts_first"]), str(d["ts_last"])
        e = json.loads(d.pop("entities") or "{}")
        d.update(users=e.get("user", []), hosts=e.get("host", []), src_ips=e.get("src_ip", []),
                 dst_ips=e.get("dst_ip", []), incident_id=inc_of.get(d["detection_id"]))
        out.append(d)
    return out


@app.get("/metrics")
def metrics(ws: str | None = None) -> dict[str, Any]:
    _, d = ws_dir(ws)
    m = _read_json(d / "metrics.json")
    if m is None:
        raise HTTPException(404, "no evaluation for this workspace (only workspaces with ground truth are scored: "
                                 "run `make score`)")
    return m


@app.get("/inputs")
def list_inputs() -> dict[str, Any]:
    INPUT_DIR.mkdir(parents=True, exist_ok=True)
    files = [{"name": str(f.relative_to(INPUT_DIR)), "size": f.stat().st_size,
              "modified": datetime.fromtimestamp(f.stat().st_mtime).astimezone().isoformat(timespec="seconds")}
             for f in sorted(INPUT_DIR.rglob("*")) if f.is_file() and f.suffix.lower() in ALLOWED_SUFFIXES
             and not any(p.startswith(".") for p in f.relative_to(INPUT_DIR).parts) and f.name.lower() != "readme.md"]
    return {"folder": _rel(INPUT_DIR),
            "files": files, "allowed_suffixes": sorted(ALLOWED_SUFFIXES), "max_upload_bytes": MAX_UPLOAD}


def _safe_name(name: str) -> Path:
    if not NAME_RE.fullmatch(name) or Path(name).suffix.lower() not in ALLOWED_SUFFIXES or name.lower() == "readme.md":
        raise HTTPException(400, f"invalid file name; use letters, digits, '.', '_', '-' and one of "
                                 f"{sorted(ALLOWED_SUFFIXES)}")
    p = (INPUT_DIR / name).resolve()
    if p.parent != INPUT_DIR:
        raise HTTPException(400, "invalid file name")
    return p


@app.post("/inputs")
async def upload(request: Request, filename: str, overwrite: bool = False) -> dict[str, Any]:
    """Raw-body upload (Content-Type: application/octet-stream), streamed to disk in chunks."""
    INPUT_DIR.mkdir(parents=True, exist_ok=True)
    dest = _safe_name(filename)
    if dest.exists() and not overwrite:
        raise HTTPException(409, f"{filename} already exists in the input folder")
    if _job.get("state") == "running" and _job.get("workspace") == "input":
        raise HTTPException(409, "the input folder is being analysed; upload after the run finishes")
    tmp = INPUT_DIR / f".{dest.name}.part"
    size = 0
    try:
        with open(tmp, "wb") as f:
            async for chunk in request.stream():
                size += len(chunk)
                if size > MAX_UPLOAD:
                    raise HTTPException(413, f"upload exceeds {MAX_UPLOAD} bytes")
                f.write(chunk)
        if size == 0:
            raise HTTPException(400, "empty upload")
        os.replace(tmp, dest)
    finally:
        if tmp.exists():
            tmp.unlink()
    return {"name": dest.name, "size": size}


@app.delete("/inputs/{name}")
def delete_input(name: str) -> dict[str, Any]:
    p = _safe_name(name)
    if not p.exists():
        raise HTTPException(404, "no such file")
    if _job.get("state") == "running" and _job.get("workspace") == "input":
        raise HTTPException(409, "the input folder is being analysed")
    p.unlink()
    return {"deleted": name}


def _run_job(name: str) -> None:
    from forgetrace.pipeline import run

    def progress(stage, frac):
        _job.update(stage=stage, progress=round(frac, 3))

    try:
        _drop_con(name)
        stats = run([SOURCES[name]], OUT / name, progress=progress)
        _job.update(state="done", finished=time.time(), stats={k: stats[k] for k in (
            "wall_time_s", "incidents", "detections", "alert_groups", "abstained_components", "ingest")})
    except Exception as e:  # surfaced to the UI verbatim; never crashes the server
        _job.update(state="failed", finished=time.time(), error=f"{type(e).__name__}: {e}",
                    trace=traceback.format_exc(limit=3))
    finally:
        _drop_con(name)


@app.post("/runs")
def start_run(body: RunRequest) -> dict[str, Any]:
    if (OUT / "forgetrace.duckdb").exists():
        raise HTTPException(400, "server started on a single result directory; start with `make serve` to run analyses")
    if _job.get("state") == "running":
        raise HTTPException(409, f"an analysis of {_job['workspace']!r} is already running")
    src = SOURCES[body.workspace]
    if body.workspace == "input" and not list_inputs()["files"]:
        raise HTTPException(400, f"the input folder {list_inputs()['folder']} has no log files; upload or copy some first")
    if body.workspace in ("sample", "demo") and not src.exists():
        raise HTTPException(400, f"{_rel(src)} is missing" + ("; run `make sample`" if body.workspace == "sample" else ""))
    _job.clear()
    _job.update(state="running", workspace=body.workspace, started=time.time(), stage="queued", progress=0.0)
    threading.Thread(target=_run_job, args=(body.workspace,), daemon=True).start()
    return dict(_job)


@app.get("/walkthrough")
def walkthrough(ws: str = "demo") -> dict[str, Any]:
    """Every stage's stored output for a small workspace (the dashboard's Demo page)."""
    from forgetrace.api.walkthrough import build

    _, d = ws_dir(ws)
    try:
        return build(d, con(ws))
    except ValueError as e:
        raise HTTPException(400, str(e)) from None


@app.get("/runs/current")
def run_status() -> dict[str, Any]:
    j = dict(_job)
    if "started" in j:
        j["elapsed_s"] = round((j.get("finished") or time.time()) - j["started"], 2)
    return j


# ----------------------------------------------------------------------------- graph store (docs/wp/GR-1.md)
def _graph(fn, *args, **kw):
    from forgetrace.graph import queries

    try:
        return getattr(queries, fn)(*args, **kw)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except RuntimeError as e:  # server unreachable
        raise HTTPException(503, f"graph store unavailable: {e}")


@app.get("/graph/status")
def graph_status() -> dict[str, Any]:
    return _graph("status")


@app.get("/graph/incidents/{incident_id}")
def graph_incident(incident_id: int, ws: str | None = None) -> dict[str, Any]:
    return _graph("incident_graph", ws or default_ws(), incident_id)


@app.get("/graph/neighbors")
def graph_neighbors(key: str, ws: str | None = None, limit: int = 100) -> dict[str, Any]:
    limit = max(1, min(limit, 500))
    return _graph("neighbors", ws or default_ws(), key, limit)


@app.get("/graph/reach")
def graph_reach(user: str, ws: str | None = None, max_hops: int = 3, min_criticality: float = 0.8) -> dict[str, Any]:
    return _graph("reach_paths", ws or default_ws(), user, max_hops, min_criticality)


@app.get("/graph/campaigns")
def graph_campaigns(ws: str | None = None) -> dict[str, Any]:
    return _graph("campaign_list", ws or default_ws())


@app.get("/stream/status")
def stream_status(ws: str | None = None) -> dict[str, Any]:
    """Progress of a `forgetrace stream` run: batches done, events, detections, incidents, first-incident time."""
    name = ws or default_ws()
    d = ws_dirs().get(name)
    p = d / "stream_status.json" if d else None
    if p is None or not p.exists():
        raise HTTPException(404, f"no stream status for workspace {name!r}")
    return json.loads(p.read_text())


@app.get("/incidents/{incident_id}/events")
def incident_events(incident_id: int, ws: str | None = None, offset: int = 0, limit: int = 200) -> dict[str, Any]:
    """Page through every member event of an incident (its record embeds at most a sample, D-75)."""
    limit = max(1, min(limit, 2000))
    offset = max(0, offset)
    p = _payload(incident_id, ws)
    c = con(ws)
    total = c.execute("""SELECT count(DISTINCT m) FROM alert_groups g, unnest(CAST(g.member_event_ids AS BIGINT[])) u(m)
                         WHERE g.group_id IN (SELECT unnest(?))""", [p["group_ids"]]).fetchone()[0]
    have = {r[0] for r in c.execute("DESCRIBE events").fetchall()}  # older workspaces lack later fields
    cols = [k for k in ["event_id", "ts", "line_no", "event_type", "user", "host", "src_ip", "dst_ip", "dst_port",
                        "url", "message"] if k in have]
    rows = c.execute(f"""WITH ids AS (SELECT DISTINCT m AS event_id FROM alert_groups g,
                                     unnest(CAST(g.member_event_ids AS BIGINT[])) u(m) WHERE g.group_id IN (SELECT unnest(?)))
                        SELECT {", ".join("e." + k for k in cols)}
                        FROM events e JOIN ids USING (event_id) ORDER BY e.ts, e.event_id LIMIT ? OFFSET ?""",
                     [p["group_ids"], limit, offset]).fetchall()
    return {"incident_id": incident_id, "total": total, "offset": offset, "limit": limit,
            "events": [{**dict(zip(cols, r)), "ts": str(r[1])} for r in rows]}


# ----------------------------------------------------------------------------- explanations + live (mentor)
def _ws_path(ws: str | None) -> tuple[str, Path]:
    return ws_dir(ws)


def _maybe_llm(facts: dict, llm: bool) -> dict:
    if llm:
        from forgetrace.report.llm import narrate

        facts = {**facts, "narrative": narrate(facts, run_id=facts.get("id"))}
    return facts


@app.get("/explain/alert/{alert_id}")
def explain_alert_ep(alert_id: str, ws: str | None = None, llm: bool = False) -> dict[str, Any]:
    from forgetrace.report.explain import explain_alert

    name, d = _ws_path(ws)
    return _maybe_llm(explain_alert(con(name), d, alert_id), llm)


@app.get("/explain/incident/{incident_id}")
def explain_incident_ep(incident_id: str, ws: str | None = None, llm: bool = False) -> dict[str, Any]:
    """Batch incidents by number; live incidents by graph id (the members and links come from Neo4j)."""
    from forgetrace.report.explain import explain_batch_incident, explain_chain

    name, d = _ws_path(ws)
    c = con(name)
    if incident_id.isdigit() and _has_table(c, "incident_cache"):
        return _maybe_llm(explain_batch_incident(c, d, int(incident_id)), llm)
    members, links = _graph("chain_members", name, "Incident", incident_id)
    return _maybe_llm(explain_chain(c, d, "incident", incident_id, members, links), llm)


@app.get("/explain/campaign/{campaign_id}")
def explain_campaign_ep(campaign_id: str, ws: str | None = None, llm: bool = False) -> dict[str, Any]:
    from forgetrace.report.explain import explain_chain

    name, d = _ws_path(ws)
    members, links = _graph("chain_members", name, "Campaign", campaign_id)
    return _maybe_llm(explain_chain(con(name), d, "campaign", campaign_id, members, links), llm)


def _has_table(c, t: str) -> bool:
    try:
        c.execute(f"SELECT 1 FROM {t} LIMIT 0")
        return True
    except duckdb.Error:
        return False


@app.get("/live/status")
def live_status(ws: str | None = None) -> dict[str, Any]:
    name, d = _ws_path(ws)
    p = d / "live_status.json"
    if not p.exists():
        raise HTTPException(404, f"workspace {name!r} is not a live workspace")
    return json.loads(p.read_text())


@app.get("/live/alerts")
def live_alerts(ws: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
    name, _ = _ws_path(ws)
    c = con(name)
    if not _has_table(c, "kb_alerts"):
        raise HTTPException(404, "not a live workspace")
    cur = c.execute("""SELECT uid, rule_id, rule_title, technique_id, tactic, severity, ts_first, ts_last, member_count,
                              first_batch, last_batch FROM kb_alerts ORDER BY ts_last DESC LIMIT ?""", [max(1, min(limit, 2000))])
    cols = [x[0] for x in cur.description]
    return [{k: (str(v) if k.startswith("ts_") else v) for k, v in zip(cols, r)} for r in cur.fetchall()]


@app.get("/graph/incidents")
def graph_incident_list(ws: str | None = None) -> dict[str, Any]:
    return _graph("incident_list", ws or default_ws())


@app.get("/graph/chain")
def graph_chain(kind: str, id: str, ws: str | None = None) -> dict[str, Any]:
    return _graph("chain_graph", ws or default_ws(), kind.capitalize(), id)
