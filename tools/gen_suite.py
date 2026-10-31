#!/usr/bin/env python3
"""D0 scenario suite: 20 seeded variants of the dev scenario for tuning (1-10) and test (11-20).

Why this exists: the Phase 1 sample is one seed with fixed victims, hosts, counts and gaps, so a
rule set can be fitted to it exactly. PHASE2 WP EV-2 asks for a suite that varies the benign mix,
attack step ordering, gaps and CEF ratio and includes realistic decoys; evaluation then uses a
time-free split by seed (plan §2 "Statistical hygiene": tune on seeds 1-10, test once on 11-20).

Every random draw comes from rngs seeded by the suite seed, so a seed regenerates byte-identical
files (tests/test_suite.py). Parameters are drawn from their own rng (`seed * 7919 + 1`) so a
change to one parameter's range does not shift the event stream of the others more than needed.
Attacks: A1 brute force -> valid account -> account creation -> admin group -> lateral -> exfil
(victims, targets, counts, gaps vary; 30% of seeds move lateral movement before persistence);
A2 maldoc -> encoded PowerShell -> Run key -> beacons -> RDP (30% of seeds start beaconing before
the Run key); A3 (50% of seeds) external login without brute force -> discovery -> archive ->
upload to cloud storage, whose techniques have no Phase 1 rule (coverage gap kept on purpose).
Decoys: D1 admin onboarding (always), D2 a user's typo burst followed by success (70%),
D3 admin maintenance with an encoded PowerShell deployment and an RDP session (60%).
Ground truth is written in the frozen GroundTruth format; it is read only by forgetrace/eval.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from gen_scenarios import BENIGN_PROCS, COMMON_DOMAINS, IT_ADMIN, SVC_BACKUP, USERS, Gen  # noqa: E402

from forgetrace.eval.groundtruth import Attack, GroundTruth, LineRef, Step  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
TUNING, TEST = range(1, 11), range(11, 21)
BASE_MIX = {"proc": 0.30, "admin_ps": 0.03, "web": 0.22, "dns": 0.17, "file": 0.12, "reg": 0.06,
            "runkey_ok": 0.005, "server_logon": 0.075, "typo": 0.02}
ENTRY_SAFE = {"nverma", "sgupta", "lpereira"}  # users with baseline RDS access (not plausible A1 victims)


def draw_params(seed: int) -> dict:
    r = random.Random(seed * 7919 + 1)
    users = [u for d in USERS.values() for u in d]
    a1_user = r.choice([u for u in users if u not in ENTRY_SAFE])
    a2_user = r.choice([u for u in users if u != a1_user])
    a3_user = r.choice([u for u in users if u not in (a1_user, a2_user)])
    mix = {k: v * r.uniform(0.6, 1.4) for k, v in BASE_MIX.items()}
    tot = sum(mix.values())
    days = r.choice([2, 3])
    return {
        "seed": seed, "split": "tuning" if seed in TUNING else "test", "days": days,
        "events": r.randint(15_000, 40_000), "cef_ratio": round(r.uniform(0.0, 0.3), 3),
        "mix": {k: v / tot for k, v in mix.items()},
        "a1": {"user": a1_user, "target": r.choice(["SRV-FILE-01", "SRV-DB-02", "SRV-BKP-01"]),
               "fails": r.randint(25, 80), "fail_gap_s": round(r.uniform(4, 20), 2), "gap_scale": round(r.uniform(0.5, 2.0), 2),
               "exfil_mb": r.randint(100, 400), "lateral_first": r.random() < 0.3,
               "day": r.randint(1, days - 1), "hour": r.randint(0, 20)},
        "a2": {"user": a2_user, "office": r.choice(["WINWORD.EXE", "EXCEL.EXE"]),
               "beacons": r.randint(8, 20), "beacon_s": r.randint(120, 600),
               "target": r.choice(["SRV-DB-01", "SRV-DB-02", "SRV-FILE-01", "SRV-DC-01"]),
               "c2_first": r.random() < 0.3, "day": r.randint(0, days - 1), "hour": r.randint(7, 18)},
        "a3": {"enabled": r.random() < 0.5, "user": a3_user, "day": r.randint(1, days - 1), "hour": r.randint(0, 22),
               "upload_mb": r.randint(150, 600)},
        "d2": {"enabled": r.random() < 0.7, "fails": r.randint(5, 8), "day": r.randint(0, days - 1)},
        "d3": {"enabled": r.random() < 0.6, "day": r.randint(0, days - 1), "target": r.choice(["SRV-DB-01", "SRV-WEB-01"])},
    }


class SuiteGen(Gen):
    def __init__(self, p: dict, start: datetime):
        super().__init__(p["seed"], start, p["days"], p["cef_ratio"], False)
        self.p = p

    def benign_mix(self, n: int) -> None:
        """Same event shapes as Gen.benign, with per-seed mix weights."""
        r, mix = self.rng, self.p["mix"]
        for u in sorted(self.server_access):
            t = self.start + timedelta(seconds=r.uniform(0, 3600))
            self.logon(t, self.home[u], u, self.hosts[self.home[u]][0], ltype="Interactive")
            for s in self.server_access[u]:
                lt = "RemoteInteractive" if s == "SRV-RDS-01" or u == IT_ADMIN else "Network"
                self.logon(t + timedelta(seconds=r.uniform(5, 600)), s, u, self.hosts[self.home[u]][0], ltype=lt)
        users = self.all_users + [IT_ADMIN]
        kinds, weights = list(mix), list(mix.values())
        for _ in range(n):
            t, u = self.rand_ts(), r.choice(users)
            h = self.home[u]
            k = r.choices(kinds, weights)[0]
            if k == "proc":
                name, exe = r.choice(BENIGN_PROCS)
                self.proc(t, h, u, name, exe.format(u=u), f'"{exe.format(u=u)}"', parent="explorer.exe")
            elif k == "admin_ps":
                self.proc(t, h, u, "powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                          r"powershell.exe -ExecutionPolicy RemoteSigned -File C:\Scripts\inventory.ps1", parent="explorer.exe")
            elif k == "web":
                self.netconn(t, h, u, r.choice(["chrome.exe", "Teams.exe", "OUTLOOK.EXE", "OneDrive.exe"]),
                             r.choice(self.ext_pool), 443, r.randint(800, 400_000), domain=r.choice(COMMON_DOMAINS))
            elif k == "dns":
                ev = self.base(t, h, u, "edr.network", "dns_query", "network", "protocol")
                ev["dns"] = {"question": {"name": r.choice(COMMON_DOMAINS), "type": "A"}, "response_code": "NOERROR",
                             "resolved_ip": [r.choice(self.ext_pool)]}
                ev["process"] = {"pid": r.randint(1000, 60000), "name": "svchost.exe"}
                self.add(t, ev)
            elif k == "file":
                ev = self.base(t, h, u, "edr.file", "file_modified", "file", "change")
                fn = r.choice(["report.xlsx", "notes.docx", "budget.xlsx", "deck.pptx"])
                ev["file"] = {"path": f"C:\\Users\\{u}\\Documents\\{fn}", "name": fn, "size": r.randint(1000, 5_000_000)}
                ev["process"] = {"pid": r.randint(1000, 60000), "name": "EXCEL.EXE"}
                self.add(t, ev)
            elif k == "reg":
                self.regset(t, h, u, "WINWORD.EXE", r"HKCU\Software\Microsoft\Office\16.0\Common\General\RecentFiles",
                            str(r.randint(1000, 99999)))
            elif k == "runkey_ok":
                self.regset(t, h, u, "OneDrive.exe", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OneDrive",
                            rf"C:\Users\{u}\AppData\Local\Microsoft\OneDrive\OneDrive.exe /background")
            elif k == "server_logon":
                s = r.choice(self.server_access[u])
                lt = "RemoteInteractive" if s == "SRV-RDS-01" or u == IT_ADMIN else "Network"
                self.logon(t, s, u, self.hosts[h][0], ltype=lt)
            else:
                self.logon(t, h, u, self.hosts[h][0], ok=False, ltype="Interactive")
        for d in range(self.days):
            t = self.start + timedelta(days=d, hours=1, minutes=r.randint(0, 30))
            self.netconn(t, "SRV-BKP-01", SVC_BACKUP, "backup-agent.exe", "52.96.10.4", 443,
                         r.randint(120_000_000, 180_000_000), domain="backup.cloudvendor.example")

    # ------------------------------------------------------------------ attacks
    def _ext(self, first: int) -> str:
        r = self.rng
        return f"{first}.{r.randint(10, 250)}.{r.randint(1, 254)}.{r.randint(1, 254)}"

    def a1(self) -> list:
        r, p = self.rng, self.p["a1"]
        g = p["gap_scale"]
        attacker, u, entry, target = self._ext(185), p["user"], "SRV-RDS-01", p["target"]
        t = self.start + timedelta(days=p["day"], hours=p["hour"], minutes=r.randint(0, 50))
        fails = [self.logon(t + timedelta(seconds=p["fail_gap_s"] * i + r.uniform(0, 3)), entry, u, attacker, ok=False,
                            ltype="RemoteInteractive") for i in range(p["fails"])]
        t += timedelta(seconds=p["fail_gap_s"] * p["fails"] + 60 * g)
        lid = f"0x{r.getrandbits(24):06x}"
        steps = [("T1110", "Credential Access", f"{p['fails']} failed RDP logons from one external IP", fails),
                 ("T1078", "Initial Access", "successful logon after the burst",
                  [self.logon(t, entry, u, attacker, ltype="RemoteInteractive", logon_id=lid)])]
        newacct = f"svc_{r.choice(['update', 'sync', 'helpdesk', 'patch'])}{r.randint(10, 99)}"

        def persist(t):
            a = ("T1136.001", "Persistence", "local account created",
                 [self.iam(t, entry, u, 4720, "user_account_created", newacct, logon_id=lid)])
            t += timedelta(minutes=3 * g, seconds=r.randint(0, 50))
            b = ("T1098", "Privilege Escalation", "new account added to Administrators",
                 [self.iam(t, entry, u, 4732, "user_added_to_group", newacct, group="Administrators", logon_id=lid)])
            return [a, b], t

        def lateral(t):
            return [("T1021.002", "Lateral Movement", "network logon to a server from the entry host",
                     [self.logon(t, target, u, self.hosts[entry][0], ltype="Network")])], t

        t += timedelta(minutes=6 * g, seconds=r.randint(0, 50))
        first, second = (lateral, persist) if p["lateral_first"] else (persist, lateral)
        s1, t = first(t)
        t += timedelta(minutes=9 * g, seconds=r.randint(0, 50))
        s2, t = second(t)
        steps += s1 + s2
        t += timedelta(minutes=12 * g, seconds=r.randint(0, 50))
        steps.append(("T1041", "Exfiltration", f"{p['exfil_mb']} MB outbound to the attacker IP",
                      [self.netconn(t, target, u, "rclone.exe", attacker, 443, p["exfil_mb"] * 1024 * 1024)]))
        return steps

    def a2(self) -> list:
        r, p = self.rng, self.p["a2"]
        u = p["user"]
        h, c2 = self.home[u], self._ext(45)
        t = self.start + timedelta(days=p["day"], hours=p["hour"], minutes=r.randint(0, 40))
        office = p["office"]
        exe = rf"C:\Program Files\Microsoft Office\root\Office16\{office}"
        doc = "Invoice_2026.docm" if office == "WINWORD.EXE" else "Q3_figures.xlsm"
        steps = [("T1204.002", "Execution", f"{office} opens a macro attachment",
                  [self.proc(t, h, u, office, exe, f'"{exe}" /n "C:\\Users\\{u}\\Downloads\\{doc}"', parent="OUTLOOK.EXE")])]
        t += timedelta(minutes=1, seconds=r.randint(0, 30))
        steps.append(("T1059.001", "Execution", "hidden encoded PowerShell spawned by the Office app",
                      [self.proc(t, h, u, "powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                                 "powershell.exe -nop -w hidden -enc " + hashlib.sha1(str(r.random()).encode()).hexdigest().upper(),
                                 parent=office)]))

        def runkey(t):
            name = r.choice(["WinUpdateSvc", "OneDriveSync", "AdobeHelper"])
            return ("T1547.001", "Persistence", "Run-key write by PowerShell",
                    [self.regset(t, h, u, "powershell.exe", rf"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\{name}",
                                 rf"C:\Users\{u}\AppData\Roaming\{name.lower()}.exe")])

        def beacons(t):
            out = []
            for _ in range(p["beacons"]):
                t += timedelta(seconds=p["beacon_s"] * r.uniform(0.97, 1.03))
                out.append(self.netconn(t, h, u, "powershell.exe", c2, 443, r.randint(300, 900)))
            return ("T1071.001", "Command and Control", f"{p['beacons']} low-byte beacons every ~{p['beacon_s']} s", out), t

        t += timedelta(minutes=2, seconds=r.randint(0, 30))
        if p["c2_first"]:
            b, tb = beacons(t)
            rk = runkey(t + timedelta(seconds=p["beacon_s"] * 1.5))
            steps += [b, rk]  # order by first event time below
            t = tb
        else:
            steps.append(runkey(t))
            b, t = beacons(t + timedelta(minutes=4))
            steps.append(b)
        t += timedelta(minutes=14, seconds=r.randint(0, 50))
        steps.append(("T1021.001", "Lateral Movement", "RDP logon to a server",
                      [self.logon(t, p["target"], u, self.hosts[h][0], ltype="RemoteInteractive")]))
        return steps

    def a3(self) -> list:
        r, p = self.rng, self.p["a3"]
        u, src = p["user"], self._ext(91)
        h = self.home[u]
        t = self.start + timedelta(days=p["day"], hours=p["hour"], minutes=r.randint(0, 50))
        lid = f"0x{r.getrandbits(24):06x}"
        steps = [("T1078", "Initial Access", "remote interactive logon from an external IP with valid credentials",
                  [self.logon(t, h, u, src, ltype="RemoteInteractive", logon_id=lid)])]
        t += timedelta(minutes=2)
        disc = [self.proc(t, h, u, "whoami.exe", r"C:\Windows\System32\whoami.exe", "whoami /all", parent="cmd.exe"),
                self.proc(t + timedelta(seconds=20), h, u, "net.exe", r"C:\Windows\System32\net.exe",
                          'net group "Domain Admins" /domain', parent="cmd.exe")]
        steps.append(("T1069.002", "Discovery", "account and domain-group discovery commands", disc))
        t += timedelta(minutes=5, seconds=r.randint(0, 120))
        steps.append(("T1560.001", "Collection", "documents archived with 7-Zip",
                      [self.proc(t, h, u, "7z.exe", r"C:\Program Files\7-Zip\7z.exe",
                                 rf"7z.exe a -p C:\Users\Public\{r.randint(100, 999)}.7z C:\Users\{u}\Documents", parent="cmd.exe")]))
        t += timedelta(minutes=4, seconds=r.randint(0, 120))
        steps.append(("T1567.002", "Exfiltration", f"{p['upload_mb']} MB upload to a cloud storage service",
                      [self.netconn(t, h, u, "rclone.exe", self._ext(104), 443, p["upload_mb"] * 1024 * 1024,
                                    domain="content.dropboxapi.com")]))
        return steps

    # ------------------------------------------------------------------ decoys
    def d1(self) -> list:
        r = self.rng
        t = self.start + timedelta(days=self.days - 1, hours=9, minutes=r.randint(0, 30))
        hire, dc = f"newhire{r.randint(10, 99)}", "SRV-DC-01"
        steps = [("T1136.001", "Persistence", "IT admin creates a new-hire account (benign)",
                  [self.iam(t, dc, IT_ADMIN, 4720, "user_account_created", hire)])]
        t += timedelta(minutes=2)
        steps.append(("T1098", "Persistence", "account added to a department group (benign)",
                      [self.iam(t, dc, IT_ADMIN, 4732, "user_added_to_group", hire, group="HR-Staff")]))
        return steps

    def d2(self) -> list:
        r, p = self.rng, self.p["d2"]
        u = r.choice(self.all_users)
        h = self.home[u]
        t = self.start + timedelta(days=p["day"], hours=r.randint(8, 17), minutes=r.randint(0, 50))
        fails = [self.logon(t + timedelta(seconds=25 * i), h, u, self.hosts[h][0], ok=False, ltype="Interactive")
                 for i in range(p["fails"])]
        ok = self.logon(t + timedelta(seconds=25 * p["fails"] + 40), h, u, self.hosts[h][0], ltype="Interactive")
        return [("T1110", "Credential Access", f"{p['fails']} typo failures at the user's own desk (benign)", fails),
                ("T1078", "Initial Access", "the same user then logs on successfully (benign)", [ok])]

    def d3(self) -> list:
        r, p = self.rng, self.p["d3"]
        h = self.home[IT_ADMIN]
        t = self.start + timedelta(days=p["day"], hours=r.randint(19, 22), minutes=r.randint(0, 50))
        steps = [("T1021.001", "Lateral Movement", "IT admin RDP session for maintenance (benign)",
                  [self.logon(t, p["target"], IT_ADMIN, self.hosts[h][0], ltype="RemoteInteractive")])]
        t += timedelta(minutes=3)
        steps.append(("T1059.001", "Execution", "encoded PowerShell from the deployment tool (benign)",
                      [self.proc(t, p["target"], IT_ADMIN, "powershell.exe",
                                 r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                                 "powershell.exe -NoProfile -EncodedCommand " + "SQBuAHMAdABhAGwAbAAtAFAAYQBjAGsAYQBnAGUA",
                                 parent="ccmexec.exe")]))
        return steps

    def plant(self) -> list:
        out = [("A1", "brute force to exfiltration", False, self.a1()),
               ("A2", "maldoc to beaconing and RDP", False, self.a2())]
        if self.p["a3"]["enabled"]:
            out.append(("A3", "valid account, discovery, archive, cloud upload", False, self.a3()))
        out.append(("D1", "admin onboarding (decoy)", True, self.d1()))
        if self.p["d2"]["enabled"]:
            out.append(("D2", "typo burst then success (decoy)", True, self.d2()))
        if self.p["d3"]["enabled"]:
            out.append(("D3", "admin maintenance with encoded PowerShell (decoy)", True, self.d3()))
        return out


def generate(seed: int, out_dir: Path, start: str = "2026-10-01T00:00:00Z") -> dict:
    p = draw_params(seed)
    t0 = datetime.strptime(start, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    g = SuiteGen(p, t0)
    g.benign_mix(p["events"])
    planted = g.plant()
    out_dir.mkdir(parents=True, exist_ok=True)
    log = out_dir / "events.log"
    pos = g.write(log, [])
    file_id = 1
    attacks = []
    for aid, name, decoy, steps in planted:
        # ground-truth order = time order of each step's first event (variants reorder steps)
        steps = sorted(steps, key=lambda s: min(ev["@timestamp"] for ev in s[3]))
        out_steps = []
        for i, (tech, tactic, desc, evs) in enumerate(steps, 1):
            ts = sorted(datetime.strptime(e["@timestamp"], "%Y-%m-%dT%H:%M:%S.%fZ") for e in evs)
            out_steps.append(Step(order=i, technique=tech, tactic=tactic, description=desc,
                                  event_ids=[(file_id << 48) | pos[id(e)][1] for e in evs],
                                  line_refs=[LineRef(file="events.log", line=pos[id(e)][0]) for e in evs],
                                  t_start=ts[0], t_end=ts[-1], hosts=sorted({e["host"]["name"] for e in evs}),
                                  users=sorted({e["user"]["name"] for e in evs})))
        attacks.append(Attack(attack_id=aid, name=name, is_decoy=decoy, steps=out_steps))
    sha = hashlib.sha256(log.read_bytes()).hexdigest()
    gt = GroundTruth(dataset="d0", split=p["split"],
                     source={"file": "events.log", "file_id": file_id, "sha256": sha, "lines": len(g.events),
                             "seed": seed, "start": start, "params": p}, attacks=attacks)
    (out_dir / "ground_truth.json").write_text(gt.model_dump_json(indent=1))
    return {"seed": seed, "split": p["split"], "sha256": sha, "lines": len(g.events), "bytes": log.stat().st_size,
            "attacks": [a.attack_id for a in attacks]}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "data/d0"))
    ap.add_argument("--seeds", default="1-20", help="e.g. 1-20 or 3,5,7")
    a = ap.parse_args()
    if "-" in a.seeds:
        lo, hi = map(int, a.seeds.split("-"))
        seeds = list(range(lo, hi + 1))
    else:
        seeds = [int(s) for s in a.seeds.split(",")]
    root = Path(a.out)
    rows = []
    for s in seeds:
        info = generate(s, root / f"seed_{s:02d}")
        rows.append(info)
        print(f"seed {s:2d} [{info['split']:6s}] {info['lines']:6d} lines  attacks={','.join(info['attacks'])}")
    man = root / "suite.json"
    prev = json.loads(man.read_text()) if man.exists() else {"seeds": {}}
    prev["seeds"].update({str(r["seed"]): r for r in rows})
    prev["note"] = "Regenerate with `python tools/gen_suite.py`; files are byte-identical per seed (sha256 below)."
    man.write_text(json.dumps(prev, indent=1, sort_keys=True))


if __name__ == "__main__":
    main()
