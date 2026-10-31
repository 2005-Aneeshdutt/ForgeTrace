import json
import shutil

import pytest

from forgetrace import store
from forgetrace.ingest.evidence import get_raw
from forgetrace.ingest.ingest import ingest, make_event_id, split_event_id
from forgetrace.ingest.parsers import parse_line


def test_event_id_roundtrip():
    for fid, off in [(1, 0), (1, 7651129), (3, (1 << 48) - 1), (31, 123)]:
        eid = make_event_id(fid, off)
        assert eid == (fid << 48) | off
        assert split_event_id(eid) == (fid, off)
    with pytest.raises(ValueError):
        make_event_id(1, 1 << 48)


def test_byte_offsets_point_at_line_start(tmp_path):
    lines = [b'{"@timestamp":"2026-10-01T00:00:00Z","event":{"id":"a","action":"dns_query"},"host":{"name":"H1"}}',
             b"",  # empty line
             b"this is garbage",
             b'CEF:0|V|P|1|sig|name|3|rt=1790812912346 externalId=x1 dvchost=h2 suser=CORP\\\\Bob act=user_logon outcome=failure cn1Label=WinEventId cn1=4625 src=8.8.8.8',
             b'{"@timestamp":"2026-10-01T00:00:01Z","event":{"id":"b","action":"dns_query"},"host":{"name":"H1"}}']
    f = tmp_path / "x.log"
    f.write_bytes(b"\r\n".join(lines[:2]) + b"\n" + b"\n".join(lines[2:]) + b"\n")
    out = tmp_path / "out"
    m = ingest([f], out)
    assert m["stats"] == {"lines": 5, "events": 3, "errors": 1, "empty": 1}
    con = store.connect(out)
    store.create_views(con, out)
    raw = f.read_bytes()
    for eid, off, ln in con.execute("SELECT event_id, byte_offset, line_no FROM events").fetchall():
        assert split_event_id(eid) == (1, off)
        assert off == 0 or raw[off - 1:off] == b"\n"
        r = get_raw(eid, out, con)
        assert r["verified"] and r["line_no"] == ln
    err = con.execute("SELECT line_no, error, preview FROM parse_errors").fetchall()
    assert err[0][0] == 3 and "unknown format" in err[0][1] and err[0][2] == "this is garbage"
    cef = con.execute("SELECT user, host, event_type, src_is_external, source_event_id FROM events WHERE raw_format='cef'").fetchone()
    assert cef == ("bob", "H2", "auth_fail", True, "x1")


def test_evidence_detects_tampering(tmp_path):
    f = tmp_path / "x.log"
    f.write_text('{"@timestamp":"2026-10-01T00:00:00Z","event":{"id":"a","action":"dns_query"},"host":{"name":"H1"}}\n')
    out = tmp_path / "out"
    ingest([f], out)
    con = store.connect(out)
    store.create_views(con, out)
    eid = con.execute("SELECT event_id FROM events").fetchone()[0]
    assert get_raw(eid, out, con)["verified"] is True
    f.write_text(f.read_text().replace('"H1"', '"H9"'))
    r = get_raw(eid, out, con)
    assert r["verified"] is False and "mismatch" in r["reason"]
    assert get_raw(make_event_id(9, 0), out, con)["reason"] == "unknown file_id"


def test_sample_evidence_matches_ground_truth(sample):
    con = store.connect(sample["out"], read_only=True)
    for atk in sample["gt"]["attacks"]:
        for st in atk["steps"]:
            for eid, ln, sid in zip(st["event_ids"], st["line_nos"], st["source_event_ids"]):
                r = get_raw(eid, sample["out"], con)
                assert r["verified"] and r["line_no"] == ln and r["source_event_id"] == sid


def test_parse_line_normalises_ecs():
    ev = parse_line(b'{"@timestamp":"2026-10-01T00:00:00Z","event":{"id":"z","action":"user_logon","outcome":"success"},'
                    b'"host":{"name":"srv-x.corp.local","ip":["::ffff:10.1.2.3"]},"user":{"name":"CORP\\\\Alice"},'
                    b'"winlog":{"event_id":4624,"logon":{"type":"Network"}},"source":{"ip":"203.0.113.9"},'
                    b'"threat":{"technique":{"id":["T1078"]}}}')
    assert ev["host"] == "SRV-X" and ev["user"] == "alice" and ev["host_ip"] == "10.1.2.3"
    assert ev["event_type"] == "auth_success" and ev["src_is_external"] is True
    assert "threat" not in json.dumps(ev)
