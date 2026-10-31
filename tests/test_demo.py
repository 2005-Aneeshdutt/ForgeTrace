"""The 5-event demo file must keep demonstrating every stage the Demo page explains."""
from pathlib import Path

from forgetrace import store
from forgetrace.api.walkthrough import build
from forgetrace.pipeline import run

ROOT = Path(__file__).resolve().parents[1]


def test_demo_walkthrough(tmp_path):
    out = tmp_path / "demo"
    stats = run([ROOT / "data/demo/demo_events.log"], out)
    assert stats["ingest"] == {"lines": 5, "events": 5, "errors": 0, "empty": 0}
    w = build(out, store.connect(out, read_only=True))
    lines = w["lines"]
    assert [l["format"] for l in lines] == ["ecs_json", "cef", "ecs_json", "ecs_json", "cef"]  # two parsers
    assert all(l["event_id"] == (1 << 48) | l["byte_offset"] for l in lines)
    assert [bool(l["label"]) for l in lines] == [True, True, False, True, True]  # E3 is benign
    assert lines[3]["label"]["primary_rule"] == "R003" and lines[3]["label"]["also_matched"][0]["rule_id"] == "R004"
    m = {r["field"]: r for r in lines[1]["trace"]["mapping"]}  # CEF suser -> user
    assert m["user"]["source"] == "suser" and m["event_type"]["value"] == "account_create"
    assert len(w["detections"]) == 5 and len(w["groups"]) == 4  # R004 folded
    dropped = [e for e in w["candidate_edges"] if not e["kept"]]
    assert len(dropped) == 1 and dropped[0]["score"] < w["theta_edge"]
    inc = w["incidents"][0]
    assert len(w["incidents"]) == 1 and inc["tactics"] == ["Initial Access", "Persistence", "Execution", "Exfiltration"]
    best = inc["inferred"]["containment_candidates"][0]
    assert (best["action"]["target"], best["before"], best["after"]) == ("dnair", 2, 0)
    assert w["verify"]["verified"] is True
