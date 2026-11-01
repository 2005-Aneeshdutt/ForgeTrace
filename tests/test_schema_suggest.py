"""Schema overlays (D-119): an LLM-drafted mapping for unknown field names is checked by code, and accepted
overlays add aliases without changing how already-mapped fields or named profiles parse."""
from __future__ import annotations

import json

import pytest

import schema_suggest as S
from forgetrace import config
from forgetrace.ingest.parsers import parse_line

FORTI = (b'date=2026-10-24 time=14:00:00 devname="FW1" devid="FG1" logid="0000000013" type="traffic" '
         b'subtype="forward" srcip=10.0.0.5 dstip=198.51.100.7 dstport=443 action="accept" sentbyte=10 rcvdbyte=20')
KNOWN = (b'{"timestamp":"2026-10-23T08:00:00Z","src_ip":"10.0.0.1","dst_ip":"198.51.100.2","user":"bob",'
         b'"actorAddress":"10.9.9.9"}')


def _new_schema_log(path):
    rows = []
    for i in range(60):
        rows.append(json.dumps({"evtWhen": f"2026-10-23T08:{i % 60:02d}:00Z", "actorAddress": f"10.0.1.{i % 200}",
                                "peerAddr": "198.51.100.7", "peerPortNo": 443 + i % 3, "verdictWord": "ALLOW" if i % 4 else "BLOCK",
                                "principalName": f"user{i % 7}", "aiThreatScore": i, "mfaMethod": "push"}))
    path.write_text("\n".join(rows) + "\n")
    return path


class FakeLLM:
    def __init__(self, reply):
        self.reply, self.calls = reply, 0

    def __call__(self, msgs):
        self.calls += 1
        sent = msgs[1]["content"]
        assert "10.0.1." not in sent and "198.51.100.7" not in sent and "user3" not in sent  # values are masked
        return {"content": json.dumps(self.reply), "usage": {"prompt_tokens": 10, "completion_tokens": 10, "cost": 0}}


REPLY = {"fields": {"src_ip": ["actorAddress"], "dst_ip": ["peerAddr"], "dst_port": ["peerPortNo"],
                    "user": ["principalName"], "outcome": ["verdictWord"],
                    "src_port": ["principalName"],          # wrong type -> rejected
                    "not_a_field": ["mfaMethod"]},          # not an envelope field -> rejected
         "timestamp": ["evtWhen"],
         "outcome_words": {"success": ["allow"], "failure": ["block", "nope"]},   # 'nope' not observed -> rejected
         "important_unmapped": [{"key": "mfaMethod", "reason": "authentication factor"}]}


@pytest.fixture
def iso(tmp_path, monkeypatch):
    """Isolated overlay, proposal, cache and ledger locations."""
    monkeypatch.setattr(config, "SCHEMA_DIR", tmp_path / "schemas")
    monkeypatch.setattr(S, "PROPOSAL_DIR", tmp_path / "proposals")
    from forgetrace.report import llm

    base = llm.llm_config()
    monkeypatch.setattr(llm, "llm_config", lambda: {**base, "enabled": True, "cache_dir": str(tmp_path / "cache"),
                                                    "ledger": str(tmp_path / "ledger.jsonl")})
    S._reset_caches()
    yield tmp_path
    S._reset_caches()


def test_unknown_schema_mapped_after_accept(iso):
    log = _new_schema_log(iso / "new.log")
    before = S.fill_rates(log, 100)
    assert before["parsed"] == 0  # no known timestamp key: every line is a parse error today
    fake = FakeLLM(REPLY)
    res = S.suggest(log, 100, transport=fake)
    ov = res["overlay"]
    assert ov["fields"] == {"src_ip": ["actorAddress"], "dst_ip": ["peerAddr"], "dst_port": ["peerPortNo"],
                            "user": ["principalName"], "outcome": ["verdictWord"]}
    assert ov["timestamp"] == ["evtWhen"] and ov["outcome_words"] == {"success": ["allow"], "failure": ["block"]}
    assert any("principalName -> src_port" in r for r in res["rejected"])
    assert any("not_a_field" in r for r in res["rejected"]) and any("'nope'" in r for r in res["rejected"])
    assert res["after"]["parsed"] == 60 and res["after"]["fill"]["src_ip"] == 1.0
    assert not (config.SCHEMA_DIR).exists()  # nothing applied until accepted
    S.suggest(log, 100, transport=fake)  # same schema again: answered from the cache
    assert fake.calls == 1
    S.save_proposal(res)
    S.accept(res["fingerprint"], S.PROPOSAL_DIR)
    ev = parse_line(log.read_bytes().splitlines()[1])
    assert (ev["src_ip"], ev["dst_ip"], ev["dst_port"], ev["user"], ev["outcome"]) == (
        "10.0.1.1", "198.51.100.7", 444, "user1", "success")
    assert "aiThreatScore" not in str(ev)


def test_vendor_verdict_mapping_rejected(iso):
    log = iso / "v.log"
    log.write_text("\n".join(json.dumps({"timestamp": "2026-10-23T08:00:00Z", "riskScore": 5, "actorAddress": "10.0.0.1"})
                             for _ in range(20)) + "\n")
    res = S.suggest(log, 50, transport=FakeLLM({"fields": {"bytes_out": ["riskScore"], "src_ip": ["actorAddress"]}}))
    assert res["overlay"]["fields"] == {"src_ip": ["actorAddress"]}
    assert any("vendor verdict" in r for r in res["rejected"])


def test_overlay_never_changes_existing_parsing(iso):
    """An overlay that names keys already present must not change named profiles or already-mapped fields."""
    want = [parse_line(FORTI), parse_line(KNOWN)]
    config.SCHEMA_DIR.mkdir(parents=True)
    (config.SCHEMA_DIR / "x.yaml").write_text("fields: {src_ip: [actorAddress, devname], host: [srcip]}\n")
    S._reset_caches()
    assert [parse_line(FORTI), parse_line(KNOWN)] == want


def test_offline_lists_unmapped_keys(iso):
    log = _new_schema_log(iso / "new.log")
    res = S.suggest(log, 100, offline=True)
    assert res["llm_status"] == "offline" and "overlay" not in res
    assert {k["key"] for k in res["profile"]["keys"] if k["status"] == "unmapped"} >= {"actorAddress", "evtWhen"}
    assert {k["key"] for k in res["profile"]["keys"] if k["status"] == "vendor_verdict"} == set()


def test_swapped_direction_rejected(iso):
    """Type checks cannot tell source from destination; the key name can (direction_hints, D-120)."""
    log = _new_schema_log(iso / "new.log")
    res = S.suggest(log, 100, transport=FakeLLM({"fields": {"dst_ip": ["actorAddress"], "src_ip": ["peerAddr"],
                                                            "src_port": ["peerPortNo"]}, "timestamp": ["evtWhen"]}))
    assert res["overlay"]["fields"] == {"src_ip": ["actorAddress"], "dst_ip": ["peerAddr"], "dst_port": ["peerPortNo"]}
    assert sum("moved to" in r for r in res["rejected"]) == 3
