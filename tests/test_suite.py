"""EV-2: the D0 suite regenerates byte-identically, splits by seed, and actually varies."""
from __future__ import annotations

import hashlib
import json

from gen_suite import TEST, TUNING, draw_params, generate

from forgetrace.eval.groundtruth import GroundTruth


def test_regeneration_is_byte_identical(tmp_path):
    a, b = generate(6, tmp_path / "a"), generate(6, tmp_path / "b")
    assert a["sha256"] == b["sha256"]
    for f in ("events.log", "ground_truth.json"):
        assert hashlib.sha256((tmp_path / "a" / f).read_bytes()).digest() == \
            hashlib.sha256((tmp_path / "b" / f).read_bytes()).digest()
    gt = GroundTruth.model_validate(json.loads((tmp_path / "a" / "ground_truth.json").read_text()))
    assert gt.split == "tuning" and gt.source["sha256"] == a["sha256"]
    lines = (tmp_path / "a" / "events.log").read_bytes().split(b"\n")
    for atk in gt.attacks:
        assert [s.order for s in atk.steps] == list(range(1, len(atk.steps) + 1))
        assert all(s.t_start <= s.t_end for s in atk.steps)
        for s in atk.steps:  # every label points at a real line at the stated byte offset
            for eid, ref in zip(s.event_ids, s.line_refs):
                off = eid & ((1 << 48) - 1)
                assert sum(len(x) + 1 for x in lines[: ref.line - 1]) == off


def test_split_and_variation():
    assert set(TUNING).isdisjoint(TEST) and len(TUNING) == len(TEST) == 10
    ps = [draw_params(s) for s in range(1, 21)]
    assert {p["split"] for p in ps[:10]} == {"tuning"} and {p["split"] for p in ps[10:]} == {"test"}
    assert len({p["a1"]["user"] for p in ps}) > 3 and len({p["a2"]["target"] for p in ps}) > 1
    assert len({p["cef_ratio"] for p in ps}) == 20 and any(p["a1"]["lateral_first"] for p in ps)
    assert any(p["a2"]["c2_first"] for p in ps) and any(p["a3"]["enabled"] for p in ps)
    assert any(p["d2"]["enabled"] for p in ps) and any(p["d3"]["enabled"] for p in ps)
    assert draw_params(3) == draw_params(3)
