"""End to end on an "unseen" dataset: formats no profile describes (sshd syslog, a CSV export, Windows-style
JSON), dropped into a watched folder in two waves. Nothing is configured for them; the live engine must
parse them, run the rules whose inputs exist, link a brute force to the success that followed it, and
explain the result with verifiable raw lines."""
from __future__ import annotations

import duckdb

from forgetrace.live.engine import LiveEngine
from forgetrace.report.explain import explain_alert


def _wave1() -> tuple[str, str]:
    ssh = [f"Oct 23 09:{m:02d}:{s:02d} bastion sshd[{4000 + m * 60 + s}]: Failed password for root from 198.51.100.66 port {50000 + s} ssh2"
           for m in range(0, 2) for s in range(0, 60, 4)]
    ssh.append("Oct 23 09:02:30 bastion sshd[5000]: Accepted password for root from 198.51.100.66 port 51234 ssh2")
    ssh += [f"Oct 23 10:{m:02d}:00 bastion sshd[{6000 + m}]: Accepted publickey for deploy from 10.0.0.{m + 2} port 40{m:03d} ssh2"
            for m in range(30)]
    csv_rows = ["timestamp,src_ip,dst_ip,dst_port,bytes_sent,action"]
    csv_rows += [f"2026-10-23T09:1{i % 10}:{i:02d}Z,10.0.0.{i % 20 + 2},203.0.113.{i % 50 + 1},443,{800 + i},allow" for i in range(40)]
    return "\n".join(ssh) + "\n", "\n".join(csv_rows) + "\n"


def test_unseen_formats_live_end_to_end(tmp_path, monkeypatch):
    from forgetrace import config
    monkeypatch.setattr(config, "site", lambda: {"home_countries": "auto", "home_countries_share": 0.8,
                                                 "utc_offset_minutes": 0, "night_hours": {"from": 0, "to": 5},
                                                 "default_year": 2026})
    from forgetrace.ingest import parsers
    parsers._alias_index.cache_clear()
    feed = tmp_path / "incoming"
    feed.mkdir()
    ssh, csv_text = _wave1()
    (feed / "auth.log").write_text(ssh)
    out = tmp_path / "live_unseen"
    eng = LiveEngine([feed], out, reset=True, workers=2)
    st1 = eng.run(follow=False)
    # second wave: a new file in a new format appears later
    (feed / "netflow.csv").write_text(csv_text)
    (feed / "win.jsonl").write_text(
        '{"TimeCreated":"2026-10-23T09:40:00Z","EventID":4720,"SubjectUserName":"root","TargetUserName":"backdoor","Computer":"bastion"}\n')
    st2 = LiveEngine([feed], out, workers=2).run(follow=False)
    assert st2["batches"] > st1["batches"] and st2["totals"]["errors"] == 0
    con = duckdb.connect(str(out / "forgetrace.duckdb"), read_only=True)
    fmts = dict(con.execute("SELECT raw_format, count(*) FROM events GROUP BY 1").fetchall())
    assert {"generic_syslog", "generic_csv", "generic_json"} <= set(fmts)
    rules = {r for (r,) in con.execute("SELECT DISTINCT rule_id FROM kb_alerts").fetchall()}
    assert "R001" in rules or "R001c" in rules          # brute force against root from one source
    assert "R006" in rules                               # account created (Windows 4720, generic JSON)
    uid = con.execute("SELECT uid FROM kb_alerts WHERE rule_id IN ('R001c', 'R001') ORDER BY rule_id DESC LIMIT 1").fetchone()[0]
    x = explain_alert(con, out, uid, evidence_lines=3)
    con.close()
    assert x["evidence"] and all(e["verified"] for e in x["evidence"]) and "auth.log" == x["evidence"][0]["file"]
    assert "198.51.100.66" in x["summary"]
