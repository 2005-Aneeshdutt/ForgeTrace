"""firex manifest -> GroundTruth: every labelled event becomes a (file, line) reference; chains and
multi-technique incidents accept any listed technique."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from forgetrace.datasets.firex.adapter import ground_truth
from forgetrace.eval.metrics import techniques_of

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "firex-30G.log.manifest.json"


@pytest.mark.skipif(not MANIFEST.exists(), reason="organisers' manifest not present")
def test_real_manifest_converts_completely():
    m = json.loads(MANIFEST.read_text())
    gt = ground_truth(MANIFEST)
    assert len(gt.attacks) == len(m["incidents"]) == 29
    for inc, a in zip(m["incidents"], gt.attacks):
        refs = a.steps[0].line_refs
        if inc.get("at"):
            assert len(refs) == len(inc["at"]) == inc["events"]
            assert {r.file for r in refs} <= {"firex-30G.log", "firex-30G.win.jsonl"}
        else:
            assert "range_only" in a.steps[0].description and len(refs) >= 2
        assert a.steps[0].t_start <= a.steps[0].t_end
    first = gt.attacks[0].steps[0]  # brute-force-burst, 2026-10-28 14:41:50 +0530 -> 09:11:50 UTC
    assert first.t_start.isoformat() == "2026-10-28T09:11:50"


def test_toy_manifest(tmp_path):
    p = tmp_path / "m.json"
    p.write_text(json.dumps({"log": "build/logs/x.log", "windows_log": "build/logs/x.win.jsonl",
                             "covers": "2026-10-23 08:00:00 .. 2026-10-30 08:00:00 +0530", "incidents": [
        {"id": 7, "class": "medium", "name": "n", "detect": "d", "attack": "T1110.001, T1078", "tactic": "Credential Access",
         "events": 2, "ranges": {}, "from": "2026-10-25 23:50:00", "to": "2026-10-25 00:10:00",
         "at": [[10, 100, 0], [3, 50, 1]]}]}))
    s = ground_truth(p).attacks[0].steps[0]
    assert [(r.file, r.line) for r in s.line_refs] == [("x.log", 10), ("x.win.jsonl", 3)]
    assert s.t_end > s.t_start  # 'to' past midnight rolls to the next day


def test_alternative_and_chain_techniques():
    assert techniques_of("T1110.001, T1078") == ["T1110.001", "T1078"]
    assert techniques_of("T1595.002 -> T1190 -> T1505.003")[1] == "T1190"
    assert techniques_of("T1046") == ["T1046"]
