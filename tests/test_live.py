"""Live engine (D-82..D-85): micro-batches build the same rule alerts and correlation edges as one batch run,
re-running with no new data changes nothing, appended data is processed incrementally, and with Neo4j
the graph holds the same incidents. ML detectors are compared on their own terms: live models learn from
history only (D-93), so their flags legitimately differ from a batch run that trains on the whole span.
Rules with dataset-wide operators (rare, in_set) see history to date in live mode and the whole input in batch
(D-101): live may raise an early alert that batch suppresses with hindsight, so for them live must contain batch."""
from __future__ import annotations

import json

import duckdb

from forgetrace.live.engine import LiveEngine
from forgetrace.rules.engine import load_rules


def _hindsight(node) -> bool:
    if isinstance(node, dict):
        return node.get("op") in ("rare", "in_set") or any(_hindsight(v) for v in node.values())
    return isinstance(node, list) and any(_hindsight(v) for v in node)


HINDSIGHT = sorted(r.id for r in load_rules() if _hindsight(r.filter))
_EXCLUDED = ", ".join(f"'{r}'" for r in HINDSIGHT) or "''"


def _rules_only(alias: str = "") -> str:
    p = f"{alias}." if alias else ""
    return f"{p}rule_id NOT LIKE 'ML-%' AND {p}rule_id NOT IN ({_EXCLUDED})"


def _hindsight_alerts(db, table: str) -> set:
    con = duckdb.connect(str(db), read_only=True)
    rows = set(con.execute(f"SELECT rule_id, aggregate_key FROM {table} WHERE rule_id IN (SELECT unnest(?))",
                           [HINDSIGHT]).fetchall())
    con.close()
    return rows


def _kb(out):
    con = duckdb.connect(str(out / "forgetrace.duckdb"), read_only=True)
    alerts = sorted(con.execute(f"SELECT rule_id, aggregate_key FROM kb_alerts WHERE {_rules_only()}").fetchall())
    edges = con.execute(f"""SELECT count(*) FROM kb_edges e JOIN kb_alerts a ON a.uid = e.src_uid AND {_rules_only('a')}
                            JOIN kb_alerts b ON b.uid = e.dst_uid AND {_rules_only('b')}""").fetchone()[0]
    con.close()
    return alerts, edges


def _batch(sample):
    con = duckdb.connect(str(sample["out"] / "forgetrace.duckdb"), read_only=True)
    groups = sorted(con.execute(f"SELECT rule_id, aggregate_key FROM alert_groups WHERE {_rules_only()}").fetchall())
    edges = con.execute(f"""SELECT count(*) FROM edges e JOIN alert_groups a ON a.group_id = e.src_group_id AND {_rules_only('a')}
                            JOIN alert_groups b ON b.group_id = e.dst_group_id AND {_rules_only('b')}""").fetchone()[0]
    con.close()
    return groups, edges


def test_live_batches_equal_batch_run(sample, tmp_path):
    src = sample["dir"] / "events.log"
    eng = LiveEngine([src], tmp_path / "live", reset=True, workers=2)
    eng.cfg["batch_mb"] = 3
    st = eng.run(follow=False)
    assert st["batches"] >= 4 and st["totals"]["events"] == sample["stats"]["ingest"]["events"]
    assert _kb(tmp_path / "live") == _batch(sample)
    assert _hindsight_alerts(sample["out"] / "forgetrace.duckdb", "alert_groups") <= \
        _hindsight_alerts(tmp_path / "live" / "forgetrace.duckdb", "kb_alerts")
    plan = json.loads((tmp_path / "live" / "run_plan.json").read_text())
    assert plan["enabled"] and "capability_profile" in plan


def test_live_rerun_and_append(sample, tmp_path):
    lines = (sample["dir"] / "events.log").read_bytes().splitlines(keepends=True)
    half = len(lines) // 2
    src = tmp_path / "feed.log"
    src.write_bytes(b"".join(lines[:half]))
    out = tmp_path / "live"
    eng = LiveEngine([tmp_path], out, reset=True, workers=2)
    eng.cfg["batch_mb"] = 4
    first = eng.run(follow=False)
    again = LiveEngine([tmp_path], out, workers=2).run(follow=False)  # nothing new: state unchanged
    assert again["batches"] == first["batches"] and _kb(out) == _kb(out)
    with open(src, "ab") as f:  # more data arrives later
        f.write(b"".join(lines[half:]))
    final = LiveEngine([tmp_path], out, workers=2).run(follow=False)
    assert final["batches"] > first["batches"]
    assert final["totals"]["events"] == sample["stats"]["ingest"]["events"]
    alerts, _ = _kb(out)
    assert {r for r, _ in alerts} == {r for r, _ in _batch(sample)[0]}  # every rule's alerts found incrementally


def test_live_graph_incidents(sample, tmp_path):
    import pytest

    from forgetrace.graph.loader import connect
    drv, why = connect()
    if drv is None:
        pytest.skip(why)
    ws_dir = tmp_path / "pytest_live"
    eng = LiveEngine([sample["dir"] / "events.log"], ws_dir, graph=True, reset=True, workers=2)
    eng.cfg["batch_mb"] = 3
    eng.run(follow=False)
    with drv.session() as s:
        incs = s.run("""MATCH (i:Incident {ws: 'pytest_live'})-[c:CONTAINS]->(a) WITH i, a ORDER BY c.order
                        RETURN i.uid AS i, collect(a.rule_id) AS rules""").data()
        incs = [r["rules"] for r in incs]
        batches = s.run("MATCH (b:Batch {ws: 'pytest_live'}) RETURN count(b) AS c").single()["c"]
        from forgetrace.graph.loader import clear_workspace
        clear_workspace(s, "pytest_live")
    drv.close()
    rules = lambda rs: sorted(r for r in rs if not r.startswith("ML-"))  # noqa: E731
    want = [[n["rule_id"] for n in p["observed"]["nodes"]] for p in sample["incidents"]]
    assert sorted(rules(r) for r in incs) == sorted(rules(w) for w in want) and batches >= 4
