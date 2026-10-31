"""GR-1: graph rows are built from the run without Neo4j; with a server, loads are complete,
idempotent, and every graph edge's evidence points at real Parquet events."""
from __future__ import annotations

import duckdb
import pytest

from forgetrace import store
from forgetrace.graph.loader import build_rows, connect, load, uid

WS = "pytest_graph"


@pytest.fixture(scope="module")
def rows(sample):
    con = store.connect(sample["out"], read_only=True)  # the run's catalog already holds the events view
    r = build_rows(con, WS)
    con.close()
    return r


def test_rows_cover_the_run(rows, sample):
    out = sample["out"]
    con = duckdb.connect(str(out / "forgetrace.duckdb"), read_only=True)
    n_groups = con.execute("SELECT count(*) FROM alert_groups").fetchone()[0]
    n_edges = con.execute("SELECT count(*) FROM edges").fetchone()[0]
    con.close()
    assert len(rows["alert"]) == n_groups and len(rows["leads_to"]) == n_edges
    assert len(rows["incident"]) == len(sample["incidents"])
    assert sum(len(p["inferred"]["primary_path"]["group_ids"]) for p in sample["incidents"]) == len(rows["path_step"])
    assert all(r["uid"].startswith(f"{WS}|") for r in rows["alert"] + rows["user"] + rows["host"])
    assert all(1 <= len(r["sample_event_ids"]) <= 5 for r in rows["logged_on"] + rows["connected"])


def test_connection_scope_excludes_unrelated_external_pairs(rows):
    alert_ips = {r["key"] for r in rows["involves"] if r["label"] == "IP"}
    for c in rows["connected"]:
        internal = c["src_ext"] is False and c["dst_ext"] is False
        assert internal or c["src"] in alert_ips or c["dst"] in alert_ips


@pytest.fixture(scope="module")
def neo4j():
    drv, why = connect()
    if drv is None:
        pytest.skip(why)
    yield drv
    with drv.session() as s:
        s.run("MATCH (n {ws: $ws}) DETACH DELETE n", ws=WS).consume()
    drv.close()


def test_load_is_complete_and_idempotent(neo4j, rows, sample):
    a = load(neo4j, rows, WS, {"workspace": WS})
    b = load(neo4j, rows, WS, {"workspace": WS}, replace=False)  # merge on top: nothing duplicates
    assert a["nodes"] == b["nodes"] and a["relationships"] == b["relationships"]
    assert a["nodes"]["Alert"] == len(rows["alert"]) and a["relationships"]["LEADS_TO"] == len(rows["leads_to"])
    with neo4j.session() as s:
        ev = s.run("MATCH (:Alert {ws: $ws})-[l:LEADS_TO]->() UNWIND l.evidence_event_ids AS e RETURN collect(DISTINCT e) AS ids",
                   ws=WS).single()["ids"]
        steps = s.run("""MATCH (i:Incident {uid: $iu})-[p:PATH_STEP]->(a) RETURN a.group_id AS g ORDER BY p.order""",
                      iu=uid(WS, "incident:1")).value()
    con = duckdb.connect(str(sample["out"] / "forgetrace.duckdb"), read_only=True)
    found = con.execute("SELECT count(*) FROM events WHERE event_id IN (SELECT unnest(?))", [ev]).fetchone()[0]
    con.close()
    assert ev and found == len(ev)  # every graph evidence id is a real raw event
    inc1 = next(p for p in sample["incidents"] if p["incident_id"] == 1)
    assert steps == inc1["inferred"]["primary_path"]["group_ids"]
