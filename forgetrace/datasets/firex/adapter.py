"""firex manifest -> GroundTruth (docs/PHASE2.md DATASETS; frozen GroundTruth interface).

Why this exists: the organisers' generator writes `<log>.manifest.json` beside each firex log with
every planted incident: name, ATT&CK technique(s), tactic, time range, and (`at`) the
[line, byte, stream] of each of its events (stream 0 = firewall log, 1 = Windows JSONL). This turns
it into the GroundTruth that `forgetrace eval` scores. Ground truth only: never imported by the
detection path (tests/test_e2e.py).

Mapping. One manifest incident = one Attack with one Step (the manifest does not say which event
belongs to which stage of a multi-stage chain). `technique` keeps the manifest string, e.g.
"T1110.001, T1078" or "T1595.002 -> T1190 -> ..."; the label is correct if it matches any listed
technique (forgetrace/eval/metrics.py `techniques_of`). Incidents without `at` (the floods) carry
only their first and last line, so they are scored on those two lines (`range_only`).
Manifest times are local (+0530 in `covers`); they are converted to naive UTC like the envelope.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from forgetrace.eval.groundtruth import Attack, GroundTruth, LineRef, Step


def _tz(covers: str) -> timezone:
    m = re.search(r"([+-])(\d{2})(\d{2})\s*$", covers or "")
    if not m:
        return timezone.utc
    sign = 1 if m.group(1) == "+" else -1
    return timezone(sign * timedelta(hours=int(m.group(2)), minutes=int(m.group(3))))


def ground_truth(manifest: Path, firewall_file: str | None = None, windows_file: str | None = None,
                 split: str = "all") -> GroundTruth:
    m = json.loads(Path(manifest).read_text())
    files = {0: firewall_file or Path(m["log"]).name}
    if m.get("windows_log"):
        files[1] = windows_file or Path(m["windows_log"]).name
    tz = _tz(m.get("covers", ""))

    def utc(s: str | None):
        if not s:
            return None
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S").replace(tzinfo=tz).astimezone(timezone.utc).replace(tzinfo=None)

    attacks = []
    for inc in m["incidents"]:
        if inc.get("at"):
            refs = [LineRef(file=files[s], line=ln) for ln, _b, s in inc["at"] if s in files]
            note = None
        else:
            refs = [LineRef(file=files[{"firewall": 0, "windows": 1}[k]], line=r[x])
                    for k, r in inc["ranges"].items() for x in ("first_line", "last_line")]
            note = "range_only: manifest lists no per-event positions; scored on first and last line"
        t0, t1 = utc(inc.get("from")), utc(inc.get("to"))
        if t0 and t1 and t1 < t0:  # 'to' rolled past midnight
            t1 += timedelta(days=1)
        step = Step(order=1, technique=inc["attack"], tactic=inc["tactic"], line_refs=refs, t_start=t0, t_end=t1,
                    description=f"{inc['detect']}" + (f" [{note}]" if note else ""))
        attacks.append(Attack(attack_id=f"F{inc['id']:02d}", name=f"{inc['name']} ({inc['class']})", steps=[step]))
    return GroundTruth(dataset="firex", split=split, attacks=attacks,
                       source={k: m.get(k) for k in ("log", "windows_log", "seed", "bytes", "lines", "covers")})
