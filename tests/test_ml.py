"""ML detectors (D-89..D-93): the behaviour model flags an entity that departs from its own baseline with the
features that explain it, the link model flags a burst of out-of-pattern logons one hop at a time, both are
deterministic, stable entities stay quiet, fusion is a noisy-OR, and model flags alone never form an incident."""
from __future__ import annotations

from datetime import datetime, timedelta

import duckdb
import pyarrow as pa

from forgetrace.correlate.correlate import build_incidents
from forgetrace.ml.fusion import fuse
from forgetrace.ml.link import link_detections
from forgetrace.ml.ueba import detections

T0 = datetime(2026, 10, 1)
FILL = {"user": 1.0, "host": 1.0, "event_type": 1.0}


def _events(extra: list[tuple] = ()) -> duckdb.DuckDBPyConnection:
    """20 users, 3 days: each logs on to its own two hosts a few times an hour (small, regular variation)."""
    rows = []
    for u in range(20):
        for hr in range(72):
            for k in range(3 + (hr + u) % 3):
                rows.append((T0 + timedelta(hours=hr, minutes=5 * k + u % 5), f"u{u:02d}", f"H{u:02d}-{k % 2}", "auth_success"))
    rows += list(extra)
    rows.sort()
    con = duckdb.connect()
    con.register("_t", pa.table({"event_id": list(range(len(rows))), "ts": [r[0] for r in rows], "user": [r[1] for r in rows],
                                 "host": [r[2] for r in rows], "event_type": [r[3] for r in rows]}))
    con.execute("CREATE TABLE events AS SELECT * FROM _t")
    return con


BURST_AT = T0 + timedelta(days=2, hours=3)
BURST = [(BURST_AT + timedelta(seconds=10 * i), "u07", "H07-0", "auth_fail") for i in range(120)]


def test_behaviour_model_flags_burst_with_reason_and_technique():
    rows, _, info = detections(_events(BURST), "events", FILL)
    hits = [r for r in rows if r["rule_id"] == "ML-UEBA-user" and "u07" in r["evidence"]
            and r["ts_first"] >= BURST_AT and r["ts_first"] < BURST_AT + timedelta(hours=1)]
    assert hits, info
    h = hits[0]
    assert h["technique_id"] == "T1110" and h["tactic"] == "Credential Access"
    assert h["reasons"][0]["feature"] == "auth_fail" and "usual" in h["reasons"][0]["text"]
    assert h["detector"] == "m1_ueba" and 0 <= h["score"] <= 1
    # members are the events that show the behaviour (the failed logons), not an arbitrary window sample
    con = _events(BURST)
    types = {t for (t,) in con.execute("SELECT event_type FROM events WHERE event_id IN (SELECT unnest(?))",
                                       [h["member_event_ids"]]).fetchall()}
    assert types == {"auth_fail"}


def test_behaviour_model_is_deterministic_and_quiet_on_stable_entities():
    a, _, _ = detections(_events(BURST), "events", FILL)
    b, _, _ = detections(_events(BURST), "events", FILL)
    assert [(r["detection_id"], r["score"]) for r in a] == [(r["detection_id"], r["score"]) for r in b]
    quiet, _, _ = detections(_events(), "events", FILL)
    assert not [r for r in quiet if r["rule_id"] == "ML-UEBA-user"]  # regular behaviour: nothing above its own p95


def test_live_scoring_uses_training_distribution():
    """Live: scoring a handful of ordinary new windows must not flag 'the top 1% of this batch'."""
    from forgetrace.ml.ueba import ml_config, usable_features, window_sql

    con = _events()
    _, models, _ = detections(con, "events", FILL)
    assert models["user"].train_scores is not None
    cfg = ml_config()
    sql = window_sql("events", cfg["ueba"]["entities"]["user"], usable_features(FILL, cfg), 60, latest=True)
    stored = [(r[0], r[1], r[2], r[3], list(r[4]), [float(v) for v in r[5:]]) for r in con.execute(sql).fetchall()[-5:]]
    rows, _, _ = detections(con, None, FILL, models=models, cur_rows={"user": stored}, evidence_view="events",
                            anchor_latest=True)
    assert [r for r in rows if r["rule_id"] == "ML-UEBA-user"] == []


def _logons() -> list[tuple]:
    """Users with their own hosts plus the shared DC; after warm-up u03 reaches three hosts no peer uses."""
    ex = [(T0 + timedelta(hours=hr, minutes=u), f"u{u:02d}", "DC", "auth_success") for u in range(20) for hr in range(0, 72, 6)]
    at = T0 + timedelta(days=2, hours=2)
    ex += [(at + timedelta(minutes=7 * i), "u03", f"H{10 + i:02d}-{i % 2}", "auth_success") for i in range(3)]
    ex += [(T0 + timedelta(days=1, hours=5), "u05", "H11-1", "auth_success")]  # one isolated new link
    return ex


def test_link_model_flags_out_of_pattern_burst_per_hop():
    rows, _, info = link_detections(_events(_logons()), "events", FILL)
    flagged = sorted((r["reasons"][0]["value"], r["evidence"].split(":")[0]) for r in rows)
    srcs = {r["evidence"].split(" -> ")[0].split(": ")[-1] for r in rows}
    assert srcs == {"u03"}, (rows, info)                  # the isolated u05 link is not kept (neighbour filter)
    assert len(rows) == 3 and all(r["technique_id"] == "T1021" for r in rows), flagged
    assert all(r["aggregate_by"] == ["user", "host"] for r in rows)  # one detection per hop
    assert any(r["feature"] == "new_links_same_window" for r in rows[0]["reasons"])


def test_link_model_live_judges_only_new_edges():
    con = _events(_logons())
    _, edges, _ = link_detections(con, "events", FILL)
    rows, _, _ = link_detections(con, "events", FILL, history=edges, min_ts=T0)
    assert rows == []  # everything is already in the history


def test_fusion_noisy_or():
    t = T0
    g = lambda gid, rid, conf, user: {"group_id": gid, "rule_id": rid, "confidence": conf, "ts_first": t,  # noqa: E731
                                      "ts_last": t, "entities": {"user": [user]}}
    groups = [g("G1", "R001", 0.6, "a"), g("G2", "ML-UEBA-user", 0.5, "a"), g("G3", "R009", 0.7, "b")]
    fuse(groups, {"G3": {"ML-LINK-logon": 0.6}})
    assert groups[0]["p_malicious"] == round(1 - 0.4 * 0.5, 4) and set(groups[0]["contributions"]) == {"R001", "ML-UEBA-user"}
    assert groups[2]["p_malicious"] == round(1 - 0.3 * 0.4, 4)  # absorbed model flag still corroborates


def test_model_only_component_is_not_an_incident():
    def grp(i, tactic, rid):
        return {"group_id": f"G{i}", "rule_id": rid, "tactic": tactic, "tactic_ordinal": i, "severity": 2,
                "ts_first": T0 + timedelta(minutes=i), "ts_last": T0 + timedelta(minutes=i), "raw_alert_count": 1, "confidence": 0.5,
                "member_event_ids": [i], "technique_id": "T1078", "entities": {}}
    e = {"edge_id": "E1", "src_group_id": "G1", "dst_group_id": "G2", "score": 0.9}
    incs, abst = build_incidents([grp(1, "Credential Access", "ML-UEBA-user"), grp(2, "Exfiltration", "ML-UEBA-host")], [e])
    assert not incs and "rule detection" in abst[0]["reason"]
    incs, _ = build_incidents([grp(1, "Credential Access", "R001"), grp(2, "Exfiltration", "ML-UEBA-host")], [dict(e)])
    assert len(incs) == 1


def test_model_alert_explanation(sample):
    from forgetrace.report.explain import explain_alert

    con = duckdb.connect(str(sample["out"] / "forgetrace.duckdb"), read_only=True)
    gid = con.execute("SELECT group_id FROM alert_groups WHERE rule_id LIKE 'ML-UEBA-%' ORDER BY group_id LIMIT 1").fetchone()[0]
    x = explain_alert(con, sample["out"], gid)
    con.close()
    w = x["why_flagged"]
    assert x["detector"] == "model" and "Isolation Forest" in w["condition"] and w["model_reasons"]
    assert any(s.startswith("A model flag is a lead") for s in x["how_to_verify"])
    assert x["evidence"] and all(e["verified"] for e in x["evidence"])
