import math
from datetime import datetime, timedelta

from forgetrace.correlate.correlate import build_incidents, score_edge


def test_dossier_worked_example_score():
    # §12: same_user + same_host, dt = 6 min, forward progression, R = 0.6, F = 0.1 -> s = 0.543
    reasons = [{"type": "same_user", "weight": 0.20}, {"type": "same_host", "weight": 0.15}]
    deg = 501 ** 0.1 - 1  # gives F = 0.1 exactly
    s = score_edge(reasons, 360, 8, 5 + 10, 4, 0.2, deg)
    assert s["terms"]["L"] == 0.32
    assert abs(s["terms"]["T"] - math.exp(-0.2)) < 1e-3
    assert s["terms"]["P"] == 1.0 and abs(s["terms"]["R"] - 0.6) < 1e-9 and abs(s["terms"]["F"] - 0.1) < 1e-4
    assert round(s["score"], 3) == 0.543


def test_progression_and_tau():
    r = [{"type": "same_user", "weight": 0.2}]
    assert score_edge(r, 0, 5, 5, 2, 0.2, 1)["terms"]["P"] == 0.7
    assert score_edge(r, 0, 5, 4, 2, 0.2, 1)["terms"]["P"] == 0.4
    assert score_edge(r, 0, 9, 3, 2, 0.2, 1)["terms"]["P"] == 0.1
    assert score_edge(r, 3600, 1, 2, 2, 0.2, 1)["tau_s"] == 7200
    high = score_edge(r, 0, 1, 2, 2, 0.2, 400)["score"]
    low = score_edge(r, 0, 1, 2, 2, 0.2, 1)["score"]
    assert high < low  # benign-frequency penalty


def _g(i, tactic, ordinal, t):
    ts = datetime(2026, 10, 1) + timedelta(minutes=t)
    return {"group_id": f"G{i}", "tactic": tactic, "tactic_ordinal": ordinal, "technique_id": "T", "severity": 3,
            "confidence": 0.7, "ts_first": ts, "ts_last": ts, "raw_alert_count": 1, "member_event_ids": [i]}


def _e(a, b, s=0.6):
    return {"edge_id": f"{a}:{b}", "src_group_id": a, "dst_group_id": b, "score": s}


def test_multi_tactic_incident_promotion_and_abstention():
    groups = [_g(1, "Credential Access", 8, 0), _g(2, "Persistence", 5, 5),
              _g(3, "Exfiltration", 13, 100), _g(4, "Exfiltration", 13, 110)]
    incs, abst = build_incidents(groups, [_e("G1", "G2"), _e("G3", "G4")])
    assert len(incs) == 1 and incs[0]["group_ids"] == ["G1", "G2"]
    assert incs[0]["primary_path"]["group_ids"] == ["G1", "G2"]
    assert len(abst) == 1 and abst[0]["group_ids"] == ["G3", "G4"] and "distinct tactic" in abst[0]["reason"]


def test_decoy_d1_not_an_incident(sample):
    d1 = next(a for a in sample["gt"]["attacks"] if a["attack_id"] == "D1")
    d1_events = {e for s in d1["steps"] for e in s["event_ids"]}
    for inc in sample["incidents"]:
        members = {x for n in inc["observed"]["nodes"] for x in n["member_event_ids"]}
        assert not (members & d1_events), "D1 decoy was promoted into an incident"


def _reconstructed(sample, attack_id):
    from score import score
    res = score(sample["gt"], sample["out"])
    return next(a for a in res["attacks"] if a["attack_id"] == attack_id), res


def test_a1_reconstruction(sample):
    a, _ = _reconstructed(sample, "A1")
    assert all(s["found"] for s in a["steps"])
    assert a["path"]["in_order"]


def test_a2_reconstruction(sample):
    a, _ = _reconstructed(sample, "A2")
    assert all(s["found"] for s in a["steps"])
    assert a["path"]["in_order"]


def test_no_false_alarm_incidents_on_sample(sample):
    _, res = _reconstructed(sample, "A1")
    assert res["metrics"]["false_alarm_incidents"] == []


def test_every_edge_and_step_is_explained(sample):
    for inc in sample["incidents"]:
        for e in inc["inferred"]["edges"]:
            assert e["reasons"] and e["evidence_event_ids"] and set(e["score_terms"]) == {"L", "T", "P", "R", "F"}
            assert e["kind"] == "inferred" and e["score"] >= 0.45
        for n in inc["observed"]["nodes"]:
            assert n["member_event_ids"] and n["evidence"]
