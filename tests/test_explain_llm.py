"""Explanations are verifiable (evidence re-read, plain-English conditions, verification steps), and the
LLM narrative only restates them: pseudonymised payload, strict validation, cache, spend caps. Offline:
the HTTP transport is stubbed."""
from __future__ import annotations

import json

import duckdb
import pytest

from forgetrace.report import llm
from forgetrace.report.explain import condition_text, explain_alert, explain_batch_incident


@pytest.fixture()
def facts(sample):
    con = duckdb.connect(str(sample["out"] / "forgetrace.duckdb"), read_only=True)
    gid = con.execute("SELECT group_id FROM alert_groups WHERE rule_id = 'R001c'").fetchone()[0]
    a = explain_alert(con, sample["out"], gid, evidence_lines=3)
    inc = explain_batch_incident(con, sample["out"], 2)
    con.close()
    return a, inc


def test_alert_explanation_is_verifiable(facts):
    a, inc = facts
    assert a["evidence"] and all(e["verified"] and e["line_no"] and e["raw"] for e in a["evidence"])
    assert "auth_fail" in a["why_flagged"]["condition"] and "30m" in a["why_flagged"]["threshold"]
    assert any(s.startswith("Print the cited lines: sed -n") for s in a["how_to_verify"])
    assert a["benign_explanations"] and a["verification_status"].startswith("all cited lines")
    rule_steps = [st for st in inc["steps"] if not st["rule_id"].startswith("ML-")]
    assert len(rule_steps) == 6 and any("linked by" in st["linked_from_previous"] for st in inc["steps"][1:])


def test_condition_text():
    assert condition_text({"all": [{"field": "event_type", "op": "eq", "value": "auth_fail"},
                                   {"not": {"field": "process", "op": "in", "value": ["a.exe", "b.exe"]}}]}) == \
        "event_type is auth_fail AND NOT (process is one of a.exe, b.exe)"


def _stub(reply_fn):
    calls = []

    def send(msgs):
        calls.append(msgs)
        return {"content": json.dumps(reply_fn(json.loads(msgs[1]["content"]))), "usage": {"cost": 0.0001,
                "prompt_tokens": 100, "completion_tokens": 50}, "model": "stub"}
    return send, calls


@pytest.fixture()
def isolated(tmp_path, monkeypatch):
    cfg = dict(llm.llm_config())
    cfg.update(cache_dir=str(tmp_path / "cache"), ledger=str(tmp_path / "ledger.jsonl"))
    monkeypatch.setattr(llm, "llm_config", lambda: cfg)
    monkeypatch.setenv("FORGETRACE_PSEUDO_KEY", "test-key")
    return cfg


def test_payload_is_pseudonymised(facts, isolated):
    _, inc = facts
    payload, ps = llm.build_payload(inc)
    blob = json.dumps(payload)
    assert "jdsouza" not in blob and not llm.IPV4.search(blob) and not llm.EMAIL.search(blob)
    assert ps.restore(ps.token("user", "jdsouza")) == "jdsouza"


def test_valid_reply_is_accepted_cached_and_restored(facts, isolated):
    _, inc = facts

    def good(payload):
        s0 = payload["steps"][0]
        return {"summary": "A brute-force burst was followed by a successful logon.",
                "steps": [{"order": 1, "text": "Repeated failures then a success.", "event_ids": s0["event_ids"][:1],
                           "technique_id": "T1110"}], "uncertainties": []}
    send, calls = _stub(good)
    r1 = llm.narrate(inc, run_id="t", transport=send)
    r2 = llm.narrate(inc, run_id="t", transport=send)
    assert r1["status"] == "ok" and r2["status"] == "cached" and len(calls) == 1
    assert r1["label"] == "AI-written summary of verified evidence"


@pytest.mark.parametrize("bad", [
    lambda p: {"summary": "Attacker 203.0.113.99 exfiltrated data.", "steps": [], "uncertainties": []},
    lambda p: {"summary": "x", "steps": [{"order": 1, "text": "y", "event_ids": [123], "technique_id": "T1110"}],
               "uncertainties": []},
    lambda p: {"summary": "It happened 4242 times.", "steps": [], "uncertainties": []},
    lambda p: {"summary": "x", "steps": [{"order": 1, "text": "y", "event_ids": [], "technique_id": "T9999"}],
               "uncertainties": []},
])
def test_invented_facts_are_rejected(facts, isolated, bad):
    _, inc = facts
    send, _ = _stub(bad)
    r = llm.narrate(inc, run_id="t", transport=send)
    assert r["status"] == "rejected" and r["reason"]


def test_spend_cap(facts, isolated, tmp_path):
    _, inc = facts
    (tmp_path / "ledger.jsonl").write_text(json.dumps({"cost_usd": 5.0, "run_id": "old"}) + "\n")
    send, calls = _stub(lambda p: {})
    assert llm.narrate(inc, transport=send)["status"] == "capped" and not calls


def test_no_key_means_deterministic_only(facts, isolated, monkeypatch):
    a, _ = facts
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    r = llm.narrate(a)
    assert r["status"] == "unavailable" and "OPENROUTER_API_KEY" in r["reason"]


def test_http_only_in_report_and_tools_llm():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    offenders = [str(p) for p in (root / "forgetrace").rglob("*.py")
                 if ("urllib.request" in p.read_text() or "import requests" in p.read_text() or "httpx" in p.read_text())
                 and "report" not in p.parts]
    assert offenders == []
