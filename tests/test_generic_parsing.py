"""Unseen-format parsing (D-79): syntax detection, alias mapping, timestamps, message patterns, and the
router disabling rules whose inputs a dataset lacks (D-81)."""
from __future__ import annotations

import pytest

from forgetrace.ingest.parsers import csv_header, parse_any_ts, parse_csv, parse_line, sniff

CASES = [
    (b'<34>Oct 23 08:48:26 web01 sshd[2211]: Failed password for invalid user admin from 198.51.100.7 port 51122 ssh2',
     "generic_syslog", {"event_type": "auth_fail", "user": "admin", "src_ip": "198.51.100.7", "outcome": "failure"}),
    (b'Oct 23 08:49:01 web01 sshd[2212]: Accepted publickey for deploy from 10.0.0.9 port 40022 ssh2',
     "generic_syslog", {"event_type": "auth_success", "user": "deploy", "src_ip": "10.0.0.9"}),
    (b'{"TimeCreated":"2026-10-23T03:18:26.1234567Z","EventID":4625,"TargetUserName":"bob",'
     b'"IpAddress":"198.51.100.9","LogonType":3,"Computer":"DC01.corp.example"}',
     "generic_json", {"event_type": "auth_fail", "user": "bob", "host": "DC01", "src_ip": "198.51.100.9", "local_hour": 3}),
    (b'ts=1792745306 src_ip=10.0.0.5 dst_ip=198.51.100.7 dst_port=445 action=allow bytes_sent=1200 user=carol',
     "generic_kv", {"event_type": "net_conn", "source_type": "firewall", "dst_port": 445, "bytes_out": 1200}),
    (b'date=2026-10-24 time=14:00:00 tz="+0530" devname="X" type="traffic" srcip=198.51.100.1 dstip=10.10.20.5 dstport=80',
     "generic_kv", {"event_type": "net_conn", "local_hour": 14, "dst_port": 80}),
    (b'{"time":"2026-10-23 08:50:00","message":"sudo:   alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/cat /etc/shadow"}',
     "generic_json", {"event_type": "proc_start", "user": "alice", "command_line": "/bin/cat /etc/shadow"}),
]


@pytest.mark.parametrize("line,fmt,want", CASES)
def test_generic_lines(line, fmt, want):
    assert sniff(line) == fmt
    ev = parse_line(line)
    assert {k: ev.get(k) for k in want} == want


def test_vendor_verdicts_never_mapped():
    ev = parse_line(b'{"timestamp":"2026-10-23T08:00:00Z","src_ip":"10.0.0.1","dst_ip":"198.51.100.2",'
                    b'"severity":"critical","threat":"Trojan.X","rule_name":"bad"}')
    assert "Trojan" not in str(ev) and "critical" not in str(ev)


def test_csv_with_header():
    hdr = csv_header(b"timestamp,src_ip,dst_ip,dst_port,user,action,result")
    assert hdr == (["timestamp", "src_ip", "dst_ip", "dst_port", "user", "action", "result"], ",")
    ev = parse_line(b"2026-10-23T08:00:00Z,10.0.0.5,10.0.0.9,445,eve,logon,failed", csv_ctx=hdr)
    assert (ev["event_type"], ev["user"], ev["dst_port"]) == ("auth_fail", "eve", 445)
    assert csv_header(b'{"a":1}') is None and csv_header(b"date=1 time=2 x=3") is None
    with pytest.raises(ValueError):
        parse_csv(b"only,two", *hdr)


def test_timestamps():
    assert parse_any_ts("2026-10-23T08:48:26Z")[1] == 0
    assert parse_any_ts("23/Oct/2026:08:48:26 +0530")[1] == 330
    assert parse_any_ts(1792745306)[0] == 1792745306 * 1_000_000
    assert parse_any_ts("1792745306123")[0] == 1792745306123 * 1000


def test_router_disables_rules_without_inputs(tmp_path):
    from forgetrace import store
    from forgetrace.ingest.ingest import ingest
    from forgetrace.rules.engine import load_rules
    from forgetrace.rules.router import plan
    f = tmp_path / "x.log"
    f.write_bytes(b"\n".join(c[0] for c in CASES) + b"\n")
    ingest([f], tmp_path / "o")
    con = store.connect(tmp_path / "o")
    store.create_views(con, tmp_path / "o")
    enabled, rp, info = plan(con, load_rules())
    dis = {d.detector: d.missing for d in rp.disabled}
    assert "rule:R005" in dis and any(m.startswith("field:registry_path") for m in dis["rule:R005"])
    assert "rule:F004" in dis  # too few logins to learn home countries: disabled, not guessed
    assert "rule:R001" in rp.enabled  # auth failures with a source address exist
    assert rp.blind_spots and info["events"] == len(CASES)
