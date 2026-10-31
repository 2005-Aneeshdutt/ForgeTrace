"""EV-0: frozen interfaces round-trip through JSON and Parquet, and the pipeline emits them."""
from __future__ import annotations

import json
from datetime import datetime

import pyarrow as pa
import pyarrow.parquet as pq
import pytest
from pydantic import ValidationError

from forgetrace import models as m
from forgetrace.eval import groundtruth as g

T0, T1 = datetime(2026, 10, 1, 9, 0, 0), datetime(2026, 10, 1, 9, 5, 0)


def _det(**kw) -> m.Detection:
    base = dict(detection_id="R002:1", detector="rule:R002", score=0.8, technique_id="T1078", tactic="Initial Access",
                member_event_ids=[(1 << 48) | 10], ts_first=T0, ts_last=T1, rule_id="R002", severity=3,
                confidence=0.8, evidence="x",
                reasons=[m.Reason(feature="bytes_out", value=3.2e7, baseline=8.1e5, contribution=0.41,
                                  text="bytes out 38x this host's p99")])
    base.update(kw)
    return m.Detection(**base)


def _group(**kw) -> m.AlertGroup:
    base = dict(group_id="G0001", rule_id="R002", technique_id="T1078", tactic="Initial Access", ts_first=T0,
                ts_last=T1, raw_alert_count=2, detection_ids=["R002:1"], member_event_ids=[(1 << 48) | 10],
                entities={"user": ["dnair"], "host": ["SRV-RDS-01"]}, severity=3, p_malicious=0.7,
                contributions={"m1_pct": 0.3, "rule_sev_conf": 0.5})
    base.update(kw)
    return m.AlertGroup(**base)


def _parquet_roundtrip(tmp_path, rows: list[dict], schema: pa.Schema) -> list[dict]:
    p = tmp_path / "t.parquet"
    pq.write_table(pa.Table.from_pylist(rows, schema=schema), p)
    return pq.read_table(p).to_pylist()


def test_event_pointer_and_roundtrip():
    eid = (2 << 48) | 1234
    e = m.Event(event_id=eid, file_id=2, byte_offset=1234, line_no=7, ts=T0, user="dnair", dataset="d0")
    assert m.Event.model_validate_json(e.model_dump_json()) == e
    with pytest.raises(ValidationError):
        m.Event(event_id=eid + 1, file_id=2, byte_offset=1234, line_no=7, ts=T0)
    assert "dataset" in m.EVENT_SCHEMA.names and "event_id" in m.EVENT_SCHEMA.names


def test_detection_json_and_parquet(tmp_path):
    d = _det()
    assert m.Detection.model_validate_json(d.model_dump_json()) == d
    row = d.model_dump()
    row["reasons"] = [{**r, "value": str(r["value"]), "baseline": str(r["baseline"])} for r in row["reasons"]]
    back = _parquet_roundtrip(tmp_path, [row], m.DETECTION_SCHEMA)[0]
    assert back["member_event_ids"] == d.member_event_ids and back["detector"] == "rule:R002"
    assert back["reasons"][0]["text"] == "bytes out 38x this host's p99"
    for ok in ("m1_ueba", "m2_authgraph", "m3_prov", "rule:R001c"):
        _det(detector=ok)
    with pytest.raises(ValidationError):
        _det(detector="llm")
    with pytest.raises(ValidationError):
        _det(member_event_ids=[])


def test_alert_group_json_and_parquet(tmp_path):
    g = _group()
    assert m.AlertGroup.model_validate_json(g.model_dump_json()) == g
    row = g.model_dump()
    row["entities"] = list(row["entities"].items())
    row["contributions"] = list(row["contributions"].items())
    back = _parquet_roundtrip(tmp_path, [row], m.ALERT_GROUP_SCHEMA)[0]
    assert dict(back["contributions"]) == g.contributions and back["p_malicious"] == 0.7
    assert _group(p_malicious=None).p_malicious is None
    with pytest.raises(ValidationError):
        _group(p_malicious=1.5)


def test_run_plan_roundtrip():
    p = m.RunPlan(dataset="lanl", capability_profile={"outcome": 1.0, "process": 0.0},
                  enabled=["rule:R001", "m2_authgraph"],
                  disabled=[m.DisabledDetector(detector="rule:R003", missing=["command_line"])],
                  blind_spots=["no process telemetry: execution techniques undetectable"])
    assert m.RunPlan.model_validate_json(p.model_dump_json()) == p
    with pytest.raises(ValidationError):
        m.RunPlan(dataset="x", capability_profile={"outcome": 1.2}, enabled=[])


def test_ground_truth_locators_and_roundtrip():
    gt = g.GroundTruth(dataset="lanl", split="test", attacks=[g.Attack(attack_id="RT", name="red team", steps=[
        g.Step(order=1, technique="T1021", tactic="Lateral Movement",
               edges=[g.AuthEdge(t=T0, user="U66@DOM1", src="C17693", dst="C1003")]),
        g.Step(order=2, technique="T1041", tactic="Exfiltration", line_refs=[g.LineRef(file="auth.log", line=3)])])])
    assert g.GroundTruth.model_validate_json(gt.model_dump_json()) == gt
    with pytest.raises(ValidationError):
        g.Step(order=1, technique="T1", tactic="x")


def test_legacy_ground_truth_converts(sample):
    legacy = sample["gt"]
    gt = g.ground_truth_from_legacy(legacy)
    assert [a.attack_id for a in gt.attacks] == [a["attack_id"] for a in legacy["attacks"]]
    assert any(a.is_decoy for a in gt.attacks)
    for a, la in zip(gt.attacks, legacy["attacks"]):
        for s, ls in zip(a.steps, la["steps"]):
            assert s.event_ids == ls["event_ids"] and [r.line for r in s.line_refs] == ls["line_nos"]


def test_pipeline_emits_frozen_columns(sample):
    import duckdb

    con = duckdb.connect(str(sample["out"] / "forgetrace.duckdb"), read_only=True)
    cols = {r[0] for r in con.execute("DESCRIBE detections").fetchall()}
    assert {"detector", "score", "reasons", "member_event_ids", "technique_id", "tactic"} <= cols
    det, score, reasons = con.execute("SELECT detector, score, reasons FROM detections LIMIT 1").fetchone()
    assert det.startswith("rule:") and 0 <= score <= 1 and json.loads(reasons)[0]["text"]
    gcols = {r[0] for r in con.execute("DESCRIBE alert_groups").fetchall()}
    assert {"p_malicious", "contributions"} <= gcols
    assert "dataset" in {r[0] for r in con.execute("DESCRIBE events").fetchall()}
    con.close()
