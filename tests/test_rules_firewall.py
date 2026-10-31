"""One positive and one negative FortiGate fixture per firewall rule (F001-F017). Each negative sits just
on the other side of the rule's condition. Addresses are documentation ranges; rules hold no literals."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from tests.conftest import run_rules

IST = timezone(timedelta(hours=5, minutes=30))
T0 = datetime(2026, 10, 24, 14, 0, 0, tzinfo=IST)  # 14:00 local


def fgt(t: float, **kv) -> str:
    ts = T0 + timedelta(seconds=t)
    parts = [f"date={ts:%Y-%m-%d}", f"time={ts:%H:%M:%S}", 'tz="+0530"', 'devname="FGT-TEST"', 'logid="0000000013"']
    for k, v in kv.items():
        parts.append(f"{k}={v}" if isinstance(v, int) else f'{k}="{v}"')
    return " ".join(parts)


def conn(t, src, dst, dport=443, sent=500, sport=40000):
    return fgt(t, type="traffic", subtype="forward", srcip=src, srcport=sport, dstip=dst, dstport=dport, proto=6,
               action="accept", sentbyte=sent, rcvdbyte=200)


def login(t, src, user="admin", ok=False, country="Germany"):
    return fgt(t, type="event", subtype="system", logdesc="Admin login " + ("successful" if ok else "failed"), user=user,
               srcip=src, dstip="10.10.99.1", action="login", srccountry=country, status="success" if ok else "failed")


def vpn(t, user, src, country):
    return fgt(t, type="event", subtype="vpn", logdesc="SSL VPN tunnel up", user=user, srcip=src, dstip="203.0.113.5",
               action="tunnel-up", srccountry=country, status="success")


def dns(t, src, name):
    return fgt(t, type="utm", subtype="dns", srcip=src, dstip="198.51.100.53", dstport=53, action="pass", hostname=name)


def web(t, src, url):
    return fgt(t, type="utm", subtype="ips", srcip=src, dstip="10.10.20.20", dstport=443, action="dropped",
               hostname="portal.example", url=url)


def cfg(t, msg, action="Edit"):
    return fgt(t, type="event", subtype="system", logdesc="Attribute configured", user="ops", srcip="198.51.100.9",
               action=action, srccountry="India", msg=msg)


LONG = "a" * 40
CASES = {
    "F001": ([conn(i // 3, "198.51.100.1", "10.10.20.5", dport=1000 + i) for i in range(120)],
             [conn(i // 3, "198.51.100.1", "10.10.20.5", dport=1000 + i) for i in range(99)]),
    "F002": ([login(i * 600, f"203.0.113.{i + 1}", user=f"u{i}") for i in range(16)],
             [login(i * 600, f"203.0.{i + 1}.7", user=f"u{i}") for i in range(16)]),
    "F003": ([login(i * 30, f"203.0.113.{i + 1}", user="admin") for i in range(10)] + [login(400, "203.0.113.99", ok=True)],
             [login(i * 30, f"203.0.113.{i + 1}", user="admin") for i in range(10)] + [login(400, "198.51.100.99", ok=True)]),
    "F004": ([login(-11 * 3600, "198.51.100.4", user="ops", ok=True, country="Germany")],    # 03:00 local
             [login(0, "198.51.100.4", user="ops", ok=True, country="Germany"),                # 14:00 local
              login(-11 * 3600, "10.10.1.4", user="ops", ok=True, country="India")]),
    "F005": ([vpn(0, "ravi", "198.51.100.10", "India"), vpn(420, "ravi", "203.0.113.10", "Brazil")],
             [vpn(0, "ravi", "198.51.100.10", "India"), vpn(7200, "ravi", "203.0.113.10", "Brazil")]),
    "F006": ([conn(i * 60, "10.10.10.63", f"10.10.20.{i + 1}", dport=445) for i in range(16)],
             [conn(i * 60, "10.10.10.63", f"10.10.20.{i + 1}", dport=445) for i in range(10)]
             + [conn(i * 60, "10.10.10.63", f"198.51.100.{i + 1}", dport=445) for i in range(16)]),
    "F007": ([dns(i * 10, "10.10.10.88", f"{LONG}{i}.tun.example") for i in range(55)],
             [dns(i * 10, "10.10.10.88", f"www{i}.tun.example") for i in range(55)]),
    "F008": ([conn(i * 300, "10.10.10.112", "198.51.100.7", sent=600) for i in range(31)],
             [conn(i * 300, "10.10.10.112", f"198.51.100.{i + 1}", sent=600) for i in range(31)]),
    "F009": ([conn(i * 3600, "10.10.20.31", "198.51.100.8", sent=1_000_000) for i in range(40)],
             [conn(i * 3600, "10.10.20.31", "198.51.100.8", sent=1_000_000) for i in range(20)]),
    "F010": ([cfg(0, "Attribute 'status' of setting 'log disk setting' changed from 'enable' to 'disable'")],
             [cfg(0, "Attribute 'status' of setting 'log disk setting' changed from 'disable' to 'enable'")]),
    "F011": ([cfg(0, "Add system.admin svc_test", action="Add")],
             [cfg(0, "Delete system.admin svc_test", action="Delete")]),
    "F012": ([web(i, "203.0.113.50", "/report?year=2026%27%20union%20select%20password%20from%20users") for i in range(5)],
             [web(i, "203.0.113.50", "/report?year=2026") for i in range(5)]
             + [web(i, "203.0.113.51", "/report?year=2026%27%20union%20select%201") for i in range(4)]),
    "F013": ([web(i, "203.0.113.60", "/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E") for i in range(5)],
             [web(i, "203.0.113.60", "/search?q=scripting+guide") for i in range(5)]),
    "F014": ([web(i, "203.0.113.70", "/view?page=....//....//....//etc/passwd") for i in range(5)],
             [web(i, "203.0.113.70", "/view?page=reports/2026") for i in range(5)]),
    "F015": ([web(i, "203.0.113.80", "/ping?host=10.0.0.1%3Bcat%20/etc/passwd") for i in range(3)],
             [web(i, "203.0.113.80", "/ping?host=10.0.0.1") for i in range(3)]),
    "F016": ([conn(i // 10, f"203.0.{i // 250}.{i % 250 + 1}", "10.10.20.20", dport=80) for i in range(301)],
             [conn(i // 10, f"{11 + i % 200}.{i // 200}.1.1", "10.10.20.20", dport=80) for i in range(301)]),
    "F017": ([conn(i * 5, f"198.51.{i}.53", "203.0.113.5", dport=40000 + i, sent=3000, sport=53) for i in range(51)],
             [conn(i * 5, f"198.51.{i}.53", "203.0.113.5", dport=40000 + i, sent=100, sport=53) for i in range(51)]),
}


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_firewall_rule_positive(tmp_path, rule_id):
    rows = run_rules(tmp_path, CASES[rule_id][0], {rule_id})
    assert any(r == rule_id for r, _ in rows), f"{rule_id} did not fire on its positive fixture"


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_firewall_rule_negative(tmp_path, rule_id):
    rows = run_rules(tmp_path, CASES[rule_id][1], {rule_id})
    assert not any(r == rule_id for r, _ in rows), f"{rule_id} fired on its negative fixture: {rows}"


def test_firewall_rules_never_fire_on_endpoint_data(sample):
    import duckdb
    con = duckdb.connect(str(sample["out"] / "forgetrace.duckdb"), read_only=True)
    assert con.execute("SELECT count(*) FROM detections WHERE rule_id LIKE 'F%'").fetchone()[0] == 0
    con.close()
