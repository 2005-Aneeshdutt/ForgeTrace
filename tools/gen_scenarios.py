#!/usr/bin/env python3
"""Deterministic development dataset with planted attacks A1, A2 and decoy D1.

Why this exists: the reference generator tools/edr_log_generator.py is not present in the
repository (docs/DECISIONS.md D-04), so the benign background below reimplements the
SimEDR event shape observed in edr_events.json (ECS-like JSON, one object per line).
A configurable share of lines is emitted as CEF to exercise the second parser.

Outputs: data/sample/events.log, data/sample/ground_truth.json, config/assets.yaml.
Vendor tags (threat.*, rule.*, labels.*, event.kind=alert, event.severity>0) are OFF unless
--with-tags is passed. Ground truth is consumed only by tools/score.py.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# --------------------------------------------------------------------------- inventory
DEPTS = {"FIN": 1, "HR": 2, "ENG": 3, "SALES": 4}
USERS = {
    "FIN": ["dnair", "nverma", "rkumar", "pshah"],
    "HR": ["sgupta", "amehta", "kiyer", "tbose"],
    "ENG": ["mkhan", "vrao", "jdsouza", "hsingh"],
    "SALES": ["lpereira", "ochopra", "bdas", "yjoshi"],
}
SERVERS = {
    "SRV-DC-01": ("10.10.0.10", "Windows Server 2022"),
    "SRV-FILE-01": ("10.10.0.20", "Windows Server 2022"),
    "SRV-RDS-01": ("10.10.0.30", "Windows Server 2022"),
    "SRV-DB-01": ("10.10.0.40", "RHEL 9.3"),
    "SRV-DB-02": ("10.10.0.41", "RHEL 9.3"),
    "SRV-BKP-01": ("10.10.0.50", "Windows Server 2022"),
    "SRV-WEB-01": ("10.10.0.60", "RHEL 9.3"),
}
IT_ADMIN = "adm.rsharma"
SVC_BACKUP = "svc_backup"
COMMON_DOMAINS = ["github.com", "office.com", "login.microsoftonline.com", "slack.com", "google.com",
                  "zoom.us", "salesforce.com", "windowsupdate.com", "teams.microsoft.com", "dropbox.com"]
BENIGN_PROCS = [("chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
                ("OUTLOOK.EXE", r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"),
                ("WINWORD.EXE", r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"),
                ("EXCEL.EXE", r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"),
                ("Teams.exe", r"C:\Users\{u}\AppData\Local\Microsoft\Teams\current\Teams.exe"),
                ("OneDrive.exe", r"C:\Users\{u}\AppData\Local\Microsoft\OneDrive\OneDrive.exe"),
                ("explorer.exe", r"C:\Windows\explorer.exe"),
                ("svchost.exe", r"C:\Windows\System32\svchost.exe")]


class Gen:
    def __init__(self, seed: int, start: datetime, days: int, cef_ratio: float, with_tags: bool):
        self.rng = random.Random(seed)
        self.start, self.days, self.cef_ratio, self.with_tags = start, days, cef_ratio, with_tags
        self.end = start + timedelta(days=days)
        self.hosts: dict[str, tuple[str, str]] = dict(SERVERS)
        self.home: dict[str, str] = {}
        for dept, idx in DEPTS.items():
            for i, u in enumerate(USERS[dept]):
                h = f"WS-{dept}-{10 + i:03d}"
                self.hosts[h] = (f"10.10.{idx}.{10 + i}", "Windows 11 Enterprise 23H2")
                self.home[u] = h
        self.hosts["WS-IT-010"] = ("10.10.5.10", "Windows 11 Enterprise 23H2")
        self.home[IT_ADMIN] = "WS-IT-010"
        self.all_users = [u for d in USERS.values() for u in d]
        # Fixed baseline access pairs (user -> servers they log on to normally).
        self.server_access: dict[str, list[str]] = {}
        for u in self.all_users:
            acc = ["SRV-DC-01"]
            if u in USERS["FIN"] + USERS["HR"]:
                acc.append("SRV-FILE-01")
            if u in ("mkhan", "vrao"):
                acc.append("SRV-DB-02")
            if u in ("nverma", "sgupta", "lpereira"):
                acc.append("SRV-RDS-01")
            self.server_access[u] = acc
        self.server_access[IT_ADMIN] = ["SRV-DC-01", "SRV-FILE-01", "SRV-RDS-01", "SRV-DB-01", "SRV-BKP-01"]
        self.ext_pool = [f"{a}.{b}.{c}.{d}" for a, b, c, d in
                         ((20, 33, 196, 187), (52, 96, 10, 4), (13, 107, 42, 14), (142, 250, 72, 46),
                          (151, 101, 1, 69), (104, 18, 32, 7), (40, 126, 31, 2), (34, 117, 59, 81))]
        self.events: list[tuple[datetime, int, dict]] = []  # (ts, seq, event)
        self.seq = 0

    # ------------------------------------------------------------------ primitives
    def uid(self) -> str:
        return str(uuid.UUID(int=self.rng.getrandbits(128), version=4))

    def base(self, ts: datetime, host: str, user: str, dataset: str, action: str, category: str,
             etype: str, outcome: str | None = None) -> dict:
        ip, os_full = self.hosts[host]
        ev = {"@timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z",
              "event": {"id": self.uid(), "kind": "event", "category": [category], "type": [etype],
                        "action": action, "severity": 0, "module": "edr", "dataset": dataset},
              "agent": {"id": hashlib.sha1(host.encode()).hexdigest()[:16], "type": "edr", "name": "SimEDR",
                        "version": "1.0"},
              "observer": {"vendor": "Mitigata", "product": "SimEDR", "version": "1.0"},
              "host": {"name": host, "hostname": host, "ip": [ip],
                       "os": {"type": "linux" if "RHEL" in os_full else "windows", "full": os_full}},
              "user": {"name": user, "domain": "CORP"}}
        if outcome:
            ev["event"]["outcome"] = outcome
        return ev

    def add(self, ts: datetime, ev: dict, tag: tuple[str, str, str] | None = None) -> dict:
        if tag and self.with_tags:
            tid, tname, tactic = tag
            ev["event"]["kind"] = "alert"
            ev["event"]["severity"] = 8
            ev["threat"] = {"framework": "MITRE ATT&CK", "technique": {"id": [tid], "name": [tname]},
                            "tactic": {"name": [tactic]}}
            ev["rule"] = {"id": hashlib.sha1(tid.encode()).hexdigest()[:8], "name": tname}
            ev["labels"] = {"scenario": "planted"}
        self.seq += 1
        self.events.append((ts, self.seq, ev))
        return ev

    def logon(self, ts, host, user, src_ip, ok=True, ltype="Network", logon_id=None, tag=None):
        ev = self.base(ts, host, user, "edr.authentication", "user_logon", "authentication", "start",
                       "success" if ok else "failure")
        ev["winlog"] = {"event_id": 4624 if ok else 4625, "logon": {"type": ltype}}
        if logon_id:
            ev["winlog"]["logon"]["id"] = logon_id
        ev["source"] = {"ip": src_ip}
        return self.add(ts, ev, tag)

    def proc(self, ts, host, user, name, exe, cmd, parent=None, tag=None):
        ev = self.base(ts, host, user, "edr.process", "process_created", "process", "start")
        ev["process"] = {"pid": self.rng.randint(1000, 60000), "name": name, "executable": exe, "command_line": cmd}
        if parent:
            ev["process"]["parent"] = {"name": parent}
        return self.add(ts, ev, tag)

    def netconn(self, ts, host, user, proc, dst_ip, dport, nbytes, domain=None, tag=None):
        ev = self.base(ts, host, user, "edr.network", "network_connection", "network", "connection")
        ev["process"] = {"pid": self.rng.randint(1000, 60000), "name": proc}
        ev["source"] = {"ip": self.hosts[host][0], "port": self.rng.randint(49152, 65535)}
        ev["destination"] = {"ip": dst_ip, "port": dport}
        if domain:
            ev["destination"]["domain"] = domain
        ev["network"] = {"transport": "tcp", "direction": "outbound", "bytes": nbytes}
        return self.add(ts, ev, tag)

    def regset(self, ts, host, user, proc, path, data, tag=None):
        ev = self.base(ts, host, user, "edr.registry", "registry_value_set", "registry", "change")
        ev["registry"] = {"path": path, "data": {"strings": [data]}}
        ev["process"] = {"pid": self.rng.randint(1000, 60000), "name": proc}
        return self.add(ts, ev, tag)

    def iam(self, ts, host, actor, code, action, target, group=None, logon_id=None, tag=None):
        ev = self.base(ts, host, actor, "edr.iam", action, "iam", "creation" if code == 4720 else "change", "success")
        ev["user"]["target"] = {"name": target}
        ev["winlog"] = {"event_id": code}
        if logon_id:
            ev["winlog"]["logon"] = {"id": logon_id}
        if group:
            ev["group"] = {"name": group}
        return self.add(ts, ev, tag)

    # ------------------------------------------------------------------ benign
    def rand_ts(self) -> datetime:
        return self.start + timedelta(seconds=self.rng.uniform(0, self.days * 86400))

    def benign(self, n: int) -> None:
        r = self.rng
        # Morning baseline: every fixed access pair is seen in the first hour (dossier §12 baseline warm-up).
        for u in sorted(self.server_access):
            t = self.start + timedelta(seconds=r.uniform(0, 3600))
            self.logon(t, self.home[u], u, self.hosts[self.home[u]][0], ltype="Interactive")
            for s in self.server_access[u]:
                lt = "RemoteInteractive" if s == "SRV-RDS-01" or u == IT_ADMIN else "Network"
                self.logon(t + timedelta(seconds=r.uniform(5, 600)), s, u, self.hosts[self.home[u]][0], ltype=lt)
        users = self.all_users + [IT_ADMIN]
        for _ in range(n):
            t, u = self.rand_ts(), r.choice(users)
            h = self.home[u]
            k = r.random()
            if k < 0.30:
                name, exe = r.choice(BENIGN_PROCS)
                self.proc(t, h, u, name, exe.format(u=u), f'"{exe.format(u=u)}"', parent="explorer.exe")
            elif k < 0.33:
                self.proc(t, h, u, "powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                          r"powershell.exe -ExecutionPolicy RemoteSigned -File C:\Scripts\inventory.ps1",
                          parent="explorer.exe")
            elif k < 0.55:
                d = r.choice(COMMON_DOMAINS)
                self.netconn(t, h, u, r.choice(["chrome.exe", "Teams.exe", "OUTLOOK.EXE", "OneDrive.exe"]),
                             r.choice(self.ext_pool), 443, r.randint(800, 400_000), domain=d)
            elif k < 0.72:
                ev = self.base(t, h, u, "edr.network", "dns_query", "network", "protocol")
                d = r.choice(COMMON_DOMAINS)
                ev["dns"] = {"question": {"name": d, "type": "A"}, "response_code": "NOERROR",
                             "resolved_ip": [r.choice(self.ext_pool)]}
                ev["process"] = {"pid": r.randint(1000, 60000), "name": "svchost.exe"}
                self.add(t, ev)
            elif k < 0.84:
                ev = self.base(t, h, u, "edr.file", "file_modified", "file", "change")
                fn = r.choice(["report.xlsx", "notes.docx", "budget.xlsx", "deck.pptx"])
                ev["file"] = {"path": f"C:\\Users\\{u}\\Documents\\{fn}", "name": fn, "size": r.randint(1000, 5_000_000)}
                ev["process"] = {"pid": r.randint(1000, 60000), "name": "EXCEL.EXE"}
                self.add(t, ev)
            elif k < 0.90:
                self.regset(t, h, u, "WINWORD.EXE", r"HKCU\Software\Microsoft\Office\16.0\Common\General\RecentFiles",
                            str(r.randint(1000, 99999)))
            elif k < 0.905:
                # Legitimate Run-key write by an allow-listed updater (negative fixture for R005).
                self.regset(t, h, u, "OneDrive.exe", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OneDrive",
                            rf"C:\Users\{u}\AppData\Local\Microsoft\OneDrive\OneDrive.exe /background")
            elif k < 0.98:
                s = r.choice(self.server_access[u])
                lt = "RemoteInteractive" if s == "SRV-RDS-01" or u == IT_ADMIN else "Network"
                self.logon(t, s, u, self.hosts[h][0], ltype=lt)
            else:
                # Isolated typo: a single failed logon (below every brute-force threshold).
                self.logon(t, h, u, self.hosts[h][0], ok=False, ltype="Interactive")
        # Nightly backups: large outbound uploads by the backup service (benign R011 false positive source).
        for d in range(self.days):
            t = self.start + timedelta(days=d, hours=1, minutes=r.randint(0, 30))
            self.netconn(t, "SRV-BKP-01", SVC_BACKUP, "backup-agent.exe", "52.96.10.4", 443,
                         r.randint(120_000_000, 180_000_000), domain="backup.cloudvendor.example")

    # ------------------------------------------------------------------ attacks
    def attacks(self) -> list[dict]:
        r, gt = self.rng, []
        # ---------------- A1: brute force -> valid account -> new user -> admin group -> lateral -> exfil
        attacker = f"185.{r.randint(100, 199)}.{r.randint(1, 254)}.{r.randint(1, 254)}"
        u1 = "jdsouza"  # ENG user: no RDS and no FILE-01 baseline access
        entry, fileserver = "SRV-RDS-01", "SRV-FILE-01"
        t = self.start + timedelta(days=1, hours=2, minutes=r.randint(0, 20))
        steps = []
        ids = [self.logon(t + timedelta(seconds=11 * i + r.uniform(0, 4)), entry, u1, attacker, ok=False,
                          ltype="RemoteInteractive", tag=("T1110", "Brute Force", "Credential Access"))
               for i in range(50)]
        steps.append(("T1110", "Credential Access", "50 failed RDP authentications (4625) from one external IP", ids))
        t += timedelta(seconds=11 * 50 + 120)
        lid = f"0x{r.getrandbits(24):06x}"
        steps.append(("T1078", "Initial Access", "Successful authentication (4624) after the burst",
                      [self.logon(t, entry, u1, attacker, ltype="RemoteInteractive", logon_id=lid,
                                  tag=("T1078", "Valid Accounts", "Initial Access"))]))
        t += timedelta(minutes=6, seconds=r.randint(0, 50))
        newacct = "svc_update" + str(r.randint(10, 99))
        steps.append(("T1136.001", "Persistence", "Local account created (4720)",
                      [self.iam(t, entry, u1, 4720, "user_account_created", newacct, logon_id=lid,
                                tag=("T1136.001", "Local Account", "Persistence"))]))
        t += timedelta(minutes=3, seconds=r.randint(0, 50))
        steps.append(("T1098", "Privilege Escalation", "New account added to Administrators (4732)",
                      [self.iam(t, entry, u1, 4732, "user_added_to_group", newacct, group="Administrators",
                                logon_id=lid, tag=("T1098", "Account Manipulation", "Privilege Escalation"))]))
        t += timedelta(minutes=9, seconds=r.randint(0, 50))
        steps.append(("T1021.002", "Lateral Movement", "Network logon to the file server from the entry host",
                      [self.logon(t, fileserver, u1, self.hosts[entry][0], ltype="Network",
                                  tag=("T1021.002", "SMB/Windows Admin Shares", "Lateral Movement"))]))
        t += timedelta(minutes=12, seconds=r.randint(0, 50))
        steps.append(("T1041", "Exfiltration", "150 MB outbound transfer to the attacker IP",
                      [self.netconn(t, fileserver, u1, "rclone.exe", attacker, 443, 150 * 1024 * 1024,
                                    tag=("T1041", "Exfiltration Over C2 Channel", "Exfiltration"))]))
        gt.append(("A1", steps, False))

        # ---------------- A2: maldoc -> encoded PowerShell -> Run key -> beacons -> RDP to DB server
        u2 = "hsingh"
        h2 = self.home[u2]
        c2 = f"45.{r.randint(10, 250)}.{r.randint(1, 254)}.{r.randint(1, 254)}"
        t = self.start + timedelta(hours=14, minutes=r.randint(0, 40))
        steps = []
        word = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
        steps.append(("T1204.002", "Execution", "winword.exe opens attachment",
                      [self.proc(t, h2, u2, "WINWORD.EXE", word, f'"{word}" /n "C:\\Users\\{u2}\\Downloads\\Invoice_2026.docm"',
                                 parent="OUTLOOK.EXE", tag=("T1204.002", "Malicious File", "Execution"))]))
        t += timedelta(minutes=1, seconds=r.randint(0, 30))
        steps.append(("T1059.001", "Execution", "powershell -nop -w hidden -enc spawned by Word",
                      [self.proc(t, h2, u2, "powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                                 "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
                                 parent="WINWORD.EXE", tag=("T1059.001", "PowerShell", "Execution"))]))
        t += timedelta(minutes=2, seconds=r.randint(0, 30))
        steps.append(("T1547.001", "Persistence", "Run-key write by PowerShell",
                      [self.regset(t, h2, u2, "powershell.exe",
                                   r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WinUpdateSvc",
                                   rf"C:\Users\{u2}\AppData\Roaming\winupd.exe",
                                   tag=("T1547.001", "Registry Run Keys / Startup Folder", "Persistence"))]))
        t += timedelta(minutes=4)
        beacons = []
        for i in range(12):
            t += timedelta(seconds=300 + r.uniform(-8, 8))
            beacons.append(self.netconn(t, h2, u2, "powershell.exe", c2, 443, r.randint(300, 900),
                                        tag=("T1071.001", "Web Protocols", "Command and Control")))
        steps.append(("T1071.001", "Command and Control", "12 low-byte beacons to a rare external IP", beacons))
        t += timedelta(minutes=14, seconds=r.randint(0, 50))
        steps.append(("T1021.001", "Lateral Movement", "RDP logon to the database server",
                      [self.logon(t, "SRV-DB-01", u2, self.hosts[h2][0], ltype="RemoteInteractive",
                                  tag=("T1021.001", "Remote Desktop Protocol", "Lateral Movement"))]))
        gt.append(("A2", steps, False))

        # ---------------- D1: benign IT admin onboarding (must NOT become an incident)
        t = self.start + timedelta(days=1, hours=9, minutes=r.randint(0, 30))
        newhire = "jfernandes"
        dc = "SRV-DC-01"
        steps = [("T1136.001", "Persistence", "IT admin creates a new-hire account (benign)",
                  [self.iam(t, dc, IT_ADMIN, 4720, "user_account_created", newhire)])]
        t += timedelta(minutes=2)
        steps.append(("T1098", "Persistence", "Account added to a normal department group (benign)",
                      [self.iam(t, dc, IT_ADMIN, 4732, "user_added_to_group", newhire, group="HR-Staff")]))
        fails = []
        for _ in range(3):
            t += timedelta(minutes=r.randint(10, 40))
            fails.append(self.logon(t, "WS-HR-011", newhire, self.hosts["WS-HR-011"][0], ok=False, ltype="Interactive"))
        steps.append(("T1110", "Credential Access", "Three typo login failures (benign)", fails))
        gt.append(("D1", steps, True))
        return gt

    # ------------------------------------------------------------------ output
    def to_cef(self, ev: dict) -> str:
        def esc(v) -> str:
            return str(v).replace("\\", "\\\\").replace("=", "\\=").replace("\n", "\\n")

        e = ev["event"]
        ts = datetime.strptime(ev["@timestamp"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
        ext = {"rt": int(ts.timestamp() * 1000), "externalId": e["id"], "cat": e["dataset"],
               "dvchost": ev["host"]["name"], "dvc": ev["host"]["ip"][0], "suser": ev["user"]["name"],
               "sntdom": ev["user"].get("domain"), "act": e["action"], "outcome": e.get("outcome")}
        if "target" in ev["user"]:
            ext["duser"] = ev["user"]["target"]["name"]
        if "source" in ev:
            ext["src"], ext["spt"] = ev["source"].get("ip"), ev["source"].get("port")
        if "destination" in ev:
            ext["dst"], ext["dpt"] = ev["destination"]["ip"], ev["destination"]["port"]
            ext["destinationDnsDomain"] = ev["destination"].get("domain")
        if "network" in ev:
            ext["out"], ext["proto"] = ev["network"]["bytes"], ev["network"]["transport"]
        if "process" in ev:
            ext["sproc"] = ev["process"]["name"]
            ext["cs1Label"], ext["cs1"] = "CommandLine", ev["process"].get("command_line")
            if "parent" in ev["process"]:
                ext["cs6Label"], ext["cs6"] = "ParentProcess", ev["process"]["parent"]["name"]
        if "registry" in ev:
            ext["cs2Label"], ext["cs2"] = "RegistryPath", ev["registry"]["path"]
            ext["cs3Label"], ext["cs3"] = "RegistryValue", ev["registry"]["data"]["strings"][0]
        if "group" in ev:
            ext["cs4Label"], ext["cs4"] = "GroupName", ev["group"]["name"]
        if "winlog" in ev:
            ext["cn1Label"], ext["cn1"] = "WinEventId", ev["winlog"]["event_id"]
            lg = ev["winlog"].get("logon", {})
            ext["cs5Label"], ext["cs5"] = "LogonType", lg.get("type")
            if lg.get("id"):
                ext["cs7Label"], ext["cs7"] = "LogonId", lg["id"]  # non-standard key, mapped in field_map
        if "threat" in ev:  # only with --with-tags; never mapped by field_map
            ext["flexString1Label"], ext["flexString1"] = "MitreTechnique", ev["threat"]["technique"]["id"][0]
        body = " ".join(f"{k}={esc(v)}" for k, v in ext.items() if v is not None)
        sig = e["action"].replace("|", "\\|")
        return f"CEF:0|Mitigata|SimEDR|1.0|{sig}|{sig}|{e['severity']}|{body}"

    def write(self, out: Path, gt_raw: list) -> dict:
        self.events.sort(key=lambda x: (x[0], x[1]))
        id_of = {}
        offset, line_no = 0, 0
        with open(out, "wb") as f:
            for ts, _, ev in self.events:
                line_no += 1
                s = self.to_cef(ev) if self.rng.random() < self.cef_ratio else json.dumps(ev, separators=(",", ":"))
                b = s.encode() + b"\n"
                id_of[id(ev)] = (line_no, offset)
                f.write(b)
                offset += len(b)
        return id_of


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--start", default="2026-10-01T00:00:00Z")
    ap.add_argument("--days", type=int, default=2)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--events", type=int, default=20000)
    ap.add_argument("--cef-ratio", type=float, default=0.1)
    ap.add_argument("--with-tags", action="store_true", help="add vendor threat/rule/labels to planted events")
    ap.add_argument("--out-dir", default=str(ROOT / "data/sample"))
    ap.add_argument("--assets", default=str(ROOT / "config/assets.yaml"))
    a = ap.parse_args()
    start = datetime.strptime(a.start, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    g = Gen(a.seed, start, a.days, a.cef_ratio, a.with_tags)
    g.benign(a.events)
    gt_raw = g.attacks()
    out_dir = Path(a.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    log = out_dir / "events.log"
    pos = g.write(log, gt_raw)
    sha = hashlib.sha256(log.read_bytes()).hexdigest()  # small dev file; fingerprint only
    file_id = 1  # single-file sample: ingest assigns file_id 1 (docs/DECISIONS.md D-12)
    attacks = []
    for aid, steps, decoy in gt_raw:
        out_steps = []
        for i, (tech, tactic, desc, evs) in enumerate(steps, 1):
            locs = [pos[id(e)] for e in evs]
            out_steps.append({"order": i, "technique": tech, "tactic": tactic, "description": desc,
                              "event_ids": [(file_id << 48) | off for _, off in locs],
                              "line_nos": [ln for ln, _ in locs],
                              "source_event_ids": [e["event"]["id"] for e in evs]})
        attacks.append({"attack_id": aid, "decoy": decoy, "steps": out_steps})
    gt = {"dataset": {"file": "events.log", "file_id": file_id, "sha256": sha, "lines": len(g.events),
                      "seed": a.seed, "start": a.start, "days": a.days, "events": a.events,
                      "cef_ratio": a.cef_ratio, "with_tags": a.with_tags},
          "attacks": attacks}
    (out_dir / "ground_truth.json").write_text(json.dumps(gt, indent=1))
    write_assets(Path(a.assets), g)
    print(f"wrote {log} ({len(g.events)} lines, sha256 {sha[:16]}…), ground_truth.json, {a.assets}")


def write_assets(path: Path, g: Gen) -> None:
    """Asset fixture (dossier §13/§14): criticality by hostname regex + configured admin relations."""
    import yaml

    doc = {
        "note": "Generated by tools/gen_scenarios.py. Configured (fixture) relations carry weight 0.7 in reachability.",
        "default_criticality": 0.2,
        "critical_threshold": 0.8,
        "internal_networks": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
        "criticality": [
            {"pattern": "^SRV-DC-", "criticality": 1.0, "type": "dc"},
            {"pattern": "^SRV-DB-", "criticality": 0.9, "type": "data_store"},
            {"pattern": "^SRV-BKP-", "criticality": 0.85, "type": "server"},
            {"pattern": "^SRV-FILE-", "criticality": 0.8, "type": "data_store"},
            {"pattern": "^SRV-", "criticality": 0.6, "type": "server"},
            {"pattern": "^WS-", "criticality": 0.3, "type": "host"},
        ],
        "accounts": [{"account": u, "type": "user", "enabled": True} for u in g.all_users]
        + [{"account": IT_ADMIN, "type": "admin", "enabled": True},
           {"account": SVC_BACKUP, "type": "service", "enabled": True}],
        "groups": {
            "Domain Admins": {"admin_to": ["SRV-DC-01", "SRV-FILE-01", "SRV-DB-01", "SRV-DB-02", "SRV-BKP-01"]},
            "FileServer-Admins": {"admin_to": ["SRV-FILE-01", "SRV-BKP-01"]},
            "DB-Admins": {"admin_to": ["SRV-DB-01", "SRV-DB-02"]},
            "Backup-Operators": {"admin_to": ["SRV-BKP-01", "SRV-FILE-01"]},
        },
        "memberships": [
            {"account": IT_ADMIN, "group": "Domain Admins"},
            {"account": "jdsouza", "group": "FileServer-Admins"},
            {"account": "dnair", "group": "FileServer-Admins"},
            {"account": "hsingh", "group": "DB-Admins"},
            {"account": "mkhan", "group": "DB-Admins"},
            {"account": SVC_BACKUP, "group": "Backup-Operators"},
        ],
        "admin_to": [
            {"account": SVC_BACKUP, "host": "SRV-DC-01"},
            {"account": "hsingh", "host": "SRV-WEB-01"},
        ],
        "privileged_groups": ["Administrators", "Domain Admins", "Enterprise Admins", "Backup Operators"],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(doc, sort_keys=False))


if __name__ == "__main__":
    main()
