"""EV-1: every metric on a toy ground truth whose answers were computed by hand (see comments)."""
from __future__ import annotations

import json
import math
from datetime import datetime, timedelta

import pytest

from forgetrace.eval import metrics as M
from forgetrace.eval.groundtruth import Attack, GroundTruth, Step
from forgetrace.eval.runview import Det, Incident, RunView
from forgetrace.eval.schema import MetricsFile

T0 = datetime(2026, 10, 1, 9)

# Events 1..10. Attack A = steps {1,2} T1110, {3} T1078, {4} T1021.001. Attack B = {5} T1059.001 (missed),
# {6} T1041. Decoy D = {7} T1136.001. Events 8, 9 are benign but detected.
GT = GroundTruth(dataset="toy", attacks=[
    Attack(attack_id="A", name="A", steps=[Step(order=1, technique="T1110", tactic="Credential Access", event_ids=[1, 2]),
                                           Step(order=2, technique="T1078", tactic="Initial Access", event_ids=[3]),
                                           Step(order=3, technique="T1021.001", tactic="Lateral Movement", event_ids=[4])]),
    Attack(attack_id="B", name="B", steps=[Step(order=1, technique="T1059.001", tactic="Execution", event_ids=[5]),
                                           Step(order=2, technique="T1041", tactic="Exfiltration", event_ids=[6])]),
    Attack(attack_id="D", name="decoy", is_decoy=True,
           steps=[Step(order=1, technique="T1136.001", tactic="Persistence", event_ids=[7])]),
])
STEP_EVENTS = {(a.attack_id, s.order): set(s.event_ids) for a in GT.attacks for s in a.steps}


def _d(i, det, tech, mem, score):
    return Det(f"d{i}", det, tech, mem, score, T0 + timedelta(minutes=i))


DETS = [_d(1, "rule:R001", "T1110", [1, 2], .6), _d(2, "rule:R002", "T1078", [3], .8),
        _d(3, "rule:R008", "T1021", [4], .5), _d(5, "rule:R011", "T1041", [6], .9),
        _d(7, "rule:R006", "T1136.001", [7], .4), _d(8, "rule:R009", "T1071.001", [8], .3),
        _d(9, "rule:R003", "T1059.001", [9], .7)]
LABELS = {1: "T1110", 2: "T1110", 3: "T1078", 4: "T1021", 6: "T1041", 7: "T1136.001", 8: "T1071.001", 9: "T1059.001"}
# I1: A's three steps but path order G1, G3, G2 (steps 1, 3, 2). I2: B step 2 plus two benign groups.
# I3: only the decoy -> a false-alert incident.
INCS = [Incident(1, 80, {"G1": [1, 2], "G2": [3], "G3": [4]}, {"G1": "T1110", "G2": "T1078", "G3": "T1021"},
                 ["G1", "G3", "G2"], ["d1", "d2", "d3"]),
        Incident(2, 50, {"G5": [6], "G8": [8], "G9": [9]}, {"G5": "T1041", "G8": "T1071.001", "G9": "T1059.001"},
                 ["G8", "G9", "G5"], ["d5", "d8", "d9"]),
        Incident(3, 90, {"G7": [7]}, {"G7": "T1136.001"}, ["G7"], ["d7"])]
RV = RunView(DETS, LABELS, INCS, {f"d{i}": f"G{i}" for i in (1, 2, 3, 5, 7, 8, 9)}, days=1.0)


@pytest.fixture(scope="module")
def attacks():
    return M.score_steps(GT, STEP_EVENTS, RV)


def test_step_level(attacks):
    s = M.step_summary(attacks)
    assert s["step_recall"]["value"] == pytest.approx(4 / 5)          # B step 1 has no detection
    assert s["label_acc_exact"]["value"] == pytest.approx(3 / 4)      # T1021 != T1021.001
    assert s["label_acc_parent"]["value"] == pytest.approx(1.0)


def test_attack_level(attacks):
    s = M.step_summary(attacks)
    a = {x.attack_id: x for x in attacks}
    # A: positions s1->0, s2->2, s3->1 => seq [0, 2, 1]: 2 concordant, 1 discordant, tau = (2-1)/3
    assert (a["A"].discordant, a["A"].tau, a["A"].ordered) == (1, pytest.approx(1 / 3), False)
    assert a["B"].ordered and a["B"].tau is None                     # one found step: trivially in order
    assert s["ordered_path_rate"]["value"] == pytest.approx(0.5)
    assert s["mean_kendall_tau"]["value"] == pytest.approx(1 / 3)
    assert s["step_coverage_in_one_incident"]["value"] == pytest.approx((1.0 + 0.5) / 2)
    assert s["decoys_promoted"]["value"] == 1 and a["D"].decoy_in_incidents == [3]


def test_incident_level(attacks):
    s = M.incident_summary(attacks, RV)
    assert s["false_alert_rate"]["value"] == pytest.approx(1 / 3) and s["false_alert_incidents"] == [3]
    assert s["nodes_to_inspect_mean"]["value"] == pytest.approx(7 / 3)
    assert s["nodes_malicious_share"]["value"] == pytest.approx(4 / 7)  # G1, G2, G3, G5
    assert s["purity"]["value"] == pytest.approx(5 / 7)                 # (3 + 1 + 1) / 7
    # truth [A,A,A,B,b8,b9,b7] vs pred [I1,I1,I1,I2,I2,I2,I3]: index 3, expected 18/21, max 4.5 -> 10/17
    assert s["ari"]["value"] == pytest.approx(10 / 17)


def test_ari_edge_cases():
    assert M.ari(list("aabb"), list("xxyy")) == pytest.approx(1.0)
    assert M.ari(list("aabb"), list("xyxy")) == pytest.approx(-0.5)


def test_event_level(attacks):
    e = M.event_level(attacks, RV)
    r008 = e["per_detector"]["rule:R008"]
    assert (r008["precision"], r008["recall"]) == (1.0, pytest.approx(1 / 6))
    t1041 = e["per_technique"]["T1041"]
    assert (t1041["precision"], t1041["recall"], t1041["f1"]) == (1.0, 1.0, 1.0)
    assert e["per_technique"]["T1059.001"]["recall"] == 0.0          # event 9 is benign, event 5 missed


def test_score_level(attacks):
    s = M.score_level(attacks, RV)["all_detectors"]
    # ranked .9T .8T .7F .6T .5T .4F .3F, 4 positives: AP = .25 + .25 + .75*.75*... = .25+.25+.1875+.2
    assert s["auc_pr"] == pytest.approx(0.8875)
    assert s["recall_at_10_per_day"] == 1.0
    assert M.recall_at_budget([(.9, True, 0), (.8, True, 0), (.7, False, 0), (.6, True, 0), (.1, True, 1)], 2) \
        == pytest.approx(3 / 4)                                       # day 0 top-2 = 2, day 1 top-2 = 1
    assert s["alerts_per_day_at_90pct_recall"] == pytest.approx(5.0)  # 4th positive is the 5th alert
    assert M.average_precision([.5, .5], [True, False]) == pytest.approx(0.5)   # ties scored together
    assert M.average_precision([.5], [False]) is None


def test_ranking_and_reach(attacks):
    # risk order I3 (rel 0), I1 (1), I2 (1): DCG = 1/log2 3 + 1/log2 4; IDCG = 1 + 1/log2 3
    exp = (1 / math.log2(3) + 0.5) / (1 + 1 / math.log2(3))
    assert M.incident_ranking(attacks, RV)["ndcg_at_10"]["value"] == pytest.approx(exp)
    assert M.hit_at_k(["h1", "h2", "h3"], {"h3"}, 3) and not M.hit_at_k(["h1", "h2", "h3"], {"h3"}, 2)


def test_kendall():
    assert M.kendall([0, 1, 2]) == (0, 0, 1.0)
    assert M.kendall([2, 1, 0]) == (3, 0, -1.0)
    assert M.kendall([0, 0]) == (0, 1, 0.0)
    assert M.kendall([3]) == (0, 0, None)


def test_bootstrap_ci(attacks):
    real = [a for a in attacks if not a.is_decoy]
    ci = M.bootstrap(real, M.recall_stat, n=500, seed=1)
    assert ci[0] <= M.recall_stat(real) <= ci[1]
    assert ci == M.bootstrap(real, M.recall_stat, n=500, seed=1)        # reproducible
    assert M.bootstrap([], M.recall_stat) is None


def test_na_never_zero():
    assert M.ratio(0, 0)["value"] is None and M.ratio(0, 0)["text"].startswith("N/A")
    empty = RunView([], {}, [], {})
    s = M.incident_summary([], empty)
    assert s["false_alert_rate"]["value"] is None and "no incidents" in s["false_alert_rate"]["text"]


def test_same_host_fallback():
    gt = GroundTruth(dataset="t", attacks=[Attack(attack_id="X", name="x", steps=[
        Step(order=1, technique="T1041", tactic="Exfiltration", event_ids=[100])])])
    near = Det("dn", "m1_ueba", "T1041", [200], 0.9, T0)
    rv = RunView([near], {}, [], {}, ev_meta={100: (T0, "SRV-1"), 200: (T0 + timedelta(seconds=45), "srv-1")})
    r = M.score_steps(gt, {("X", 1): {100}}, rv)[0].steps[0]
    assert r.found and r.found_by == "same_host_60s" and r.label_exact
    rv.ev_meta[200] = (T0 + timedelta(seconds=61), "SRV-1")
    assert not M.score_steps(gt, {("X", 1): {100}}, rv)[0].steps[0].found


def test_cli_on_dev_sample_matches_phase1_scorer(sample, tmp_path):
    from forgetrace.eval.cli import main

    gt = sample["dir"] / "ground_truth.json"
    out = main(["--gt", str(gt), "--run", str(sample["out"]), "--dataset", "d0", "--experiment", "t",
                "--metrics-dir", str(tmp_path), "--boot", "200", "--no-latency"])
    mf = MetricsFile.model_validate(json.loads(out.read_text()))
    assert mf.summary["step_recall"].value == pytest.approx(11 / 11)
    assert mf.summary["label_acc_exact"].value == pytest.approx(9 / 11)
    assert mf.summary["label_acc_parent"].value == pytest.approx(1.0)
    assert mf.summary["ordered_path_rate"].value == pytest.approx(1.0)
    assert mf.summary["false_alert_rate"].value == pytest.approx(0.0)
    assert mf.prd["step_recall"]["pass"] is True and len(mf.git_sha) == 40 and mf.config_hash
