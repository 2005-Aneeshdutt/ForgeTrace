"""One positive and one negative fixture per detection rule (synthetic events, no generator)."""
import pytest

from tests.conftest import ecs, run_rules

PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"


def fails(n, step, src="203.0.113.7", user="alice", start=100):
    return [ecs(start + i * step, user=user, action="user_logon", outcome="failure", winlog__event_id=4625,
                winlog__logon__type="RemoteInteractive", source__ip=src) for i in range(n)]


def success(t, src="203.0.113.7", user="alice", host="WS-A-01", ltype="RemoteInteractive"):
    return ecs(t, host=host, user=user, action="user_logon", outcome="success", winlog__event_id=4624,
               winlog__logon__type=ltype, source__ip=src)


def proc(t, name, cmd, parent="explorer.exe", user="alice"):
    return ecs(t, user=user, process__name=name, process__command_line=cmd, process__parent__name=parent)


def conn(t, dst, nbytes, host="WS-A-01", host_ip="10.0.0.5"):
    return ecs(t, host=host, host_ip=host_ip, action="network_connection", source__ip=host_ip,
               destination__ip=dst, destination__port=443, network__bytes=nbytes)


def baseline_logons():
    # early events define the dataset start; pairs seen in warm-up are not "first seen" later
    return [success(0, src="10.0.0.9", host="SRV-X", ltype="Network"),
            success(8 * 3600, src="10.0.0.9", host="SRV-X", ltype="Network")]


CASES = {
    "R001": (fails(25, 20), fails(19, 20) + fails(25, 3600, src="203.0.113.8")),
    "R001c": (fails(6, 30) + [success(400)], fails(6, 30) + [success(400, user="bob")]),
    "R002": ([success(10)], [success(10, src="10.1.1.1")]),
    "R003": ([proc(10, "powershell.exe", "powershell.exe -nop -w hidden -enc SQBFAFgA")],
             [proc(10, "powershell.exe", r"powershell.exe -ExecutionPolicy RemoteSigned -File C:\s\inv.ps1")]),
    "R004": ([proc(10, "powershell.exe", "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA")],
             [proc(10, "powershell.exe", "powershell.exe -enc short")]),
    "R005": ([ecs(10, action="registry_value_set", process__name="evil.exe",
                  registry__path=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\X", registry__data__strings=["a"])],
             [ecs(10, action="registry_value_set", process__name="OneDrive.exe",
                  registry__path=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OneDrive", registry__data__strings=["a"]),
              ecs(11, action="registry_value_set", process__name="evil.exe",
                  registry__path=r"HKCU\Software\Microsoft\Office\16.0\Common\General\RecentFiles", registry__data__strings=["a"])]),
    "R006": ([ecs(10, action="user_account_created", winlog__event_id=4720, user__target__name="newbie")],
             [success(10, src="10.1.1.1")]),
    "R007": ([ecs(10, action="user_added_to_group", winlog__event_id=4732, user__target__name="x", group__name="Administrators")],
             [ecs(10, action="user_added_to_group", winlog__event_id=4732, user__target__name="x", group__name="HR-Staff")]),
    "R008": (baseline_logons() + [success(7 * 3600, src="10.0.0.9", host="SRV-NEW", ltype="RemoteInteractive")],
             baseline_logons() + [success(3600, src="10.0.0.9", host="SRV-EARLY", ltype="Network")]),
    "R009": ([conn(i * 300, "198.51.100.77", 500) for i in range(12)],
             [conn(i * 300, "198.51.100.77", 500) for i in range(12)] + [conn(5, "198.51.100.77", 500, host="WS-B-02", host_ip="10.0.0.6")]),
    "R010": ([proc(10, "WINWORD.EXE", "winword.exe doc.docm", parent="OUTLOOK.EXE"),
              proc(70, "powershell.exe", "powershell.exe -nop", parent="WINWORD.EXE")],
             [proc(10, "WINWORD.EXE", "winword.exe doc.docx", parent="OUTLOOK.EXE"),
              proc(70, "powershell.exe", "powershell.exe -nop", parent="explorer.exe")]),
    "R011": ([conn(10, "198.51.100.5", 150 * 2**20)],
             [conn(10, "10.9.9.9", 150 * 2**20), conn(20, "198.51.100.5", 50 * 2**20)]),
}


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_rule_positive(tmp_path, rule_id):
    rows = run_rules(tmp_path, CASES[rule_id][0], {rule_id})
    assert any(r == rule_id for r, _ in rows), f"{rule_id} did not fire on its positive fixture"


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_rule_negative(tmp_path, rule_id):
    rows = run_rules(tmp_path, CASES[rule_id][1], {rule_id})
    assert not any(r == rule_id for r, _ in rows), f"{rule_id} fired on its negative fixture: {rows}"


def test_every_rule_has_fixtures():
    from forgetrace.rules.engine import load_rules
    from tests.test_rules_firewall import CASES as FW
    assert {r.id for r in load_rules()} == set(CASES) | set(FW)


def test_label_priority_and_also_matched(tmp_path):
    from forgetrace import store
    lines = [proc(10, "powershell.exe", "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA")]
    run_rules(tmp_path, lines, {"R003", "R004"})
    con = store.connect(tmp_path / "out")
    row = con.execute("SELECT primary_rule, primary_technique, also_matched FROM event_labels").fetchall()
    assert row == [("R003", "T1059.001", [{"rule_id": "R004", "technique_id": "T1027"}])]


def test_compiled_sql_snapshot():
    from forgetrace.rules.engine import compile_rule, load_rules
    r = {x.id: x for x in load_rules()}
    assert compile_rule(r["R006"])["filter"] == (
        'SELECT event_id, ts, "host", "user" FROM events WHERE (("event_type" = \'account_create\'))')
    assert "RANGE BETWEEN INTERVAL 600 SECOND PRECEDING" in compile_rule(r["R001"])["threshold"]
