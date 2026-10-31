"""Investigation API (dossier §13 API contract). Read endpoints serve precomputed incident JSON
from DuckDB (incident_cache); evidence is re-read from the immutable source by event_id only
(no file paths accepted). Local-only by default (binds 127.0.0.1 via the CLI)."""
from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

import duckdb
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from forgetrace import config
from forgetrace.ingest.evidence import get_raw
from forgetrace.reach.reach import reachability, simulate

STATIC = Path(__file__).parent / "static"
OUT = Path(os.environ.get("FORGETRACE_OUT", config.ROOT / "out"))

app = FastAPI(title="ForgeTrace", version=config.CODE_VERSION)
app.mount("/static", StaticFiles(directory=STATIC), name="static")
_con: duckdb.DuckDBPyConnection | None = None


def con() -> duckdb.DuckDBPyConnection:
    global _con
    if _con is None:
        db = OUT / "forgetrace.duckdb"
        if not db.exists():
            raise HTTPException(503, f"no results at {OUT}; run `make run` first")
        _con = duckdb.connect(str(db), read_only=True)
    return _con.cursor()


@app.middleware("http")
async def security_headers(request, call_next):
    resp = await call_next(request)
    resp.headers["Content-Security-Policy"] = ("default-src 'self'; script-src 'self'; style-src 'self'; "
                                               "img-src 'self' data:; connect-src 'self'; object-src 'none'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


# ----------------------------------------------------------------------------- models
class Health(BaseModel):
    status: str
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


# ----------------------------------------------------------------------------- helpers
def _payload(incident_id: int) -> dict:
    row = con().execute("SELECT json FROM incident_cache WHERE incident_id = ?", [incident_id]).fetchone()
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


# ----------------------------------------------------------------------------- routes
@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/health", response_model=Health)
def health():
    mf = OUT / "files.json"
    digest = json.loads(mf.read_text())["manifest_digest"] if mf.exists() else None
    n = con().execute("SELECT count(*) FROM incident_cache").fetchone()[0]
    return Health(status="ok", manifest_digest=digest, config_hash=config.config_hash(),
                  code_version=config.CODE_VERSION, incidents=n)


@app.get("/incidents", response_model=list[IncidentSummary])
def incidents(sort: Literal["risk", "time"] = "risk", limit: int = 100):
    rows = con().execute("SELECT json FROM incident_cache").fetchall()
    out = []
    for (js,) in rows:
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
def incident(incident_id: int) -> dict[str, Any]:
    return _payload(incident_id)


@app.get("/incidents/{incident_id}/path")
def incident_path(incident_id: int) -> dict[str, Any]:
    p = _payload(incident_id)
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
def incident_reach(incident_id: int) -> dict[str, Any]:
    p = _payload(incident_id)
    inc, gid = _internal(p)
    r = reachability(con(), inc, gid)
    r["disclaimer"] = config.load_yaml(config.CONFIG_DIR / "reach.yml")["disclaimer"].format(
        X=r["critical_reachable"], Y=r["critical_reachable"])
    r["containment_candidates"] = p["inferred"]["containment_candidates"]
    return r


@app.post("/incidents/{incident_id}/simulate", response_model=SimulateResponse)
def incident_simulate(incident_id: int, body: SimulateRequest):
    p = _payload(incident_id)
    inc, gid = _internal(p)
    return simulate(con(), inc, gid, [a.model_dump() for a in body.actions])


@app.get("/events/{event_id}/raw", response_model=RawEvidence)
def event_raw(event_id: int):
    if event_id < 0:
        raise HTTPException(400, "event_id must be a non-negative integer")
    r = get_raw(event_id, OUT, con())
    if r["reason"] in ("unknown file_id", "event_id not found in events or parse_errors"):
        raise HTTPException(404, r["reason"])
    return r


@app.get("/alerts")
def alerts(unlinked: bool = True) -> list[dict[str, Any]]:
    rows = con().execute("SELECT group_ids, tactics, reason FROM abstained").fetchall()
    return [{"group_ids": json.loads(g), "tactics": json.loads(t), "reason": r} for g, t, r in rows]


@app.get("/rules")
def rules() -> list[dict[str, Any]]:
    return json.loads(con().execute("SELECT json FROM rules").fetchone()[0])
