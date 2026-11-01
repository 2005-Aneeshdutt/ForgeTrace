"""Live simulation: patterns, decisions, guarded explanation and a real engine replay."""
import json
import shutil
import time
from pathlib import Path

import duckdb

from forgetrace import config
from forgetrace.datasets import scenarios
from forgetrace.live.decide import Context, decide
from forgetrace.live.patterns import PatternTracker, describe, signature
from forgetrace.live.predict import Predictor
from forgetrace.live.simulator import Simulator, pattern_facts, sim_config
from forgetrace.report.llm import narrate

ROOT = Path(__file__).resolve().parents[1]


def ev(**k):
    return {"event_type": "auth_fail", "outcome": "failure", "logon_type": "Network", "user": "a", "host": "h", **k}


def test_signature_ignores_identity_and_path():
    assert signature(ev(user="x", host="y", src_ip="1.1.1.1")) == signature(ev(user="p", host="q", src_ip="2.2.2.2"))
    a, b = ev(process="C:\\Tools\\Rclone.exe"), ev(process="/usr/bin/rclone.exe")
    assert signature(a) == signature(b) and "rclone.exe" in describe(signature(a))
    assert signature(ev(src_is_external=True)) != signature(ev(src_is_external=False))


def test_baseline_never_unique_and_first_late_line_is():
    t = PatternTracker(baseline=2)
    assert t.observe(ev(), 1, "t")[1] == "baseline"
    assert t.observe(ev(outcome="success"), 2, "t")[1] == "baseline"
    assert t.observe(ev(), 3, "t")[1] == "known"
    pid, st = t.observe(ev(process="new.exe"), 4, "t")
    assert st == "unique" and t.observe(ev(process="new.exe"), 5, "t") == (pid, "known")
    assert [p["id"] for p in t.unique()] == [pid] and t.unique()[0]["count"] == 2


def test_decision_table():
    c = sim_config()
    assert decide(Context(3, .9, links=2, chain_tactics=4, critical_hosts=["dc"]), c)[0] == "contain"
    assert decide(Context(3, .9, links=2, chain_tactics=2, critical_hosts=["dc"]), c)[0] == "investigate"
    assert decide(Context(2, .5, unique_patterns=1), c)[0] == "investigate"
    assert decide(Context(2, .5, known_seen=9, prior_alerts=1), c)[0] == "investigate"
    assert decide(Context(2, .5, known_seen=9), c)[0] == "monitor"
    assert decide(Context(2, .5, known_seen=500), c)[0] == "ignore"
    assert decide(Context(2, .5, known_seen=500, prior_alerts=9), c)[0] == "ignore"
    assert decide(Context(1, None), c)[0] == "ignore"


def alert(uid, tech, batch, user="u", rule="R1", ts="2026-10-01 01:00:00"):
    return {"uid": uid, "rule_id": rule, "technique_id": tech, "tactic": "x", "title": uid, "first_batch": batch, "ts_first": ts,
            "entities": {"user": [user], "host": [], "src_ip": []}}


def test_prediction_needs_a_later_batch_shared_entity_and_family():
    p = Predictor()
    p.update([alert("a", "T1110", 1), alert("same-batch", "T1078.001", 1)])
    assert p.predictions[0]["status"] == "pending"  # learnt in the same batch: no credit
    p.update([alert("stranger", "T1078", 2, user="other")])
    assert p.predictions[0]["status"] == "pending"
    p.update([alert("b", "T1078.004", 2)])
    assert p.predictions[0]["status"] == "confirmed" and p.predictions[0]["confirmed_by"] == "b"
    q = Predictor()
    q.update([alert("a", "T1110", 1)])
    q.update([alert("late", "T1078", 2, ts="2026-10-02 01:00:00")])
    assert q.predictions[0]["status"] == "not confirmed"  # past expire_minutes of log time
    r = Predictor()
    r.update([alert("m", "T1110", 1, rule="ML-UEBA-user")])
    assert not r.predictions


def test_detection_and_prediction_never_see_the_answer_key():
    for name in ("predict.py", "decide.py", "patterns.py"):
        src = (ROOT / "forgetrace/live" / name).read_text()
        assert "scenarios" not in src.replace("must never import a scenario", "") and "datasets" not in src


def test_scenario_keeps_one_story_and_scores_it():
    pace = sim_config()["scenario"]
    k = scenarios.build("credential-theft", 7, pace)
    assert [s["technique"] for s in k["steps"]][:2] == ["T1110", "T1078"] and k["steps"][0]["event_ids"]
    text = b"".join(x for x, _ in k["lines"])
    assert b"Invoice_2026" not in text  # the other planted attack is not in this log
    a = {"uid": "x", "rule_id": "R002", "technique_id": "T1078", "sample": k["steps"][1]["event_ids"], "decision": "investigate"}
    c = scenarios.score(k, 2, [a], [{"id": "P1", "confirmed_by": "x", "lead_s": 6.0}])
    assert c["steps"][1]["predicted_by"] == "P1" and c["matched"] == 1 and c["steps"][0]["first"] and not c["steps"][0]["detected"]


def test_pattern_narrative_is_guarded(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "ROOT", tmp_path)  # keeps the spend ledger and cache out of the repo
    p = {"id": "ab", "text": "x", "first_ts": "t", "last_ts": "t", "count": 2, "users": ["alice"],
         "hosts": ["HOST-1"], "src_ips": ["8.8.8.8"], "dst_ips": []}
    line = {"event_id": 281474976710656, "display_id": "F01:0", "file": "f", "line_no": 1,
            "raw": "secret-raw-line", "verified": True, "note": None}
    seen = {}

    def transport(msgs):
        seen["body"] = msgs[1]["content"]
        return {"content": json.dumps({"summary": "contacted 9.9.9.9", "steps": [], "uncertainties": []}), "usage": {}, "model": "m"}

    r = narrate(pattern_facts(p, [line], []), transport=transport)
    assert "secret-raw-line" not in seen["body"] and "alice" not in seen["body"] and "8.8.8.8" not in seen["body"]
    assert r["status"] == "rejected"  # an address the facts never held


def test_replay_through_the_real_engine(tmp_path):
    src = tmp_path / "demo.log"
    shutil.copy(ROOT / "data/demo/demo_events.log", src)

    def query(sql):
        c = duckdb.connect(str(tmp_path / "live-sim" / "live_snapshot.duckdb"), read_only=True)
        try:
            return c.execute(sql).fetchall()
        finally:
            c.close()

    s = Simulator(tmp_path, query, lambda: None)
    try:
        s.start(src, 2000)
        end = time.time() + 90
        while s.state not in ("complete", "failed") and time.time() < end:
            time.sleep(.3)
        assert s.state == "complete", s.error
        t = s.tick()
        assert t["lines"] == 5 and t["alerts"] > 0
        assert s.view()["decisions"] and all(d["why"] for d in s.view()["decisions"])
    finally:
        s.stop()
