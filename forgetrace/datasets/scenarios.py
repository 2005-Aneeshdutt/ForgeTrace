"""Attack simulations for the live demo: real generated logs with an answer key (dossier §9; DECISIONS D-113).

Why this exists: "predicted and actual match" only means something if the actual is known independently of
the system. tools/gen_scenarios.py plants each attack and records its event ids. A scenario keeps background
activity plus one planted story, and paces lines so each step has time to be analysed. The key leaves this
module only through `score()`, after the fact: detection, decisions and prediction never receive it.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from typing import Any

from forgetrace import config

CATALOG = {
    "credential-theft": {
        "plant": "A1",
        "title": "Credential attack to data theft",
        "icon": "key",
        "text": "An outside attacker guesses a password, then tries to stay and move inside.",
    },
    "phishing-c2": {
        "plant": "A2",
        "title": "Phishing to command and control",
        "icon": "mail",
        "text": "A malicious attachment runs on a workstation and an implant takes hold.",
    },
    "benign-admin": {
        "plant": "D1",
        "title": "IT onboarding (safe control)",
        "icon": "user",
        "text": "Legitimate admin work that looks suspicious. A good system should not raise an attack.",
    },
}


def _gen(seed: int):
    if str(config.ROOT) not in sys.path:  # tools/ lives beside the package
        sys.path.insert(0, str(config.ROOT))
    from tools.gen_scenarios import Gen

    g = Gen(seed, datetime(2026, 10, 1, tzinfo=timezone.utc), 2, 0.1, False)
    g.benign(20000)
    return g, g.attacks()


def build(name: str, seed: int, pace: dict) -> dict[str, Any]:
    """Returns {lines: [(bytes, lines per second)], steps: answer key, decoy, starts: line index per step}."""
    g, planted = _gen(seed)
    wanted = next(p for p in planted if p[0] == CATALOG[name]["plant"])
    other = {id(e) for p in planted if p is not wanted for s in p[1] for e in s[3]}
    events = sorted((x for x in g.events if id(x[2]) not in other), key=lambda x: (x[0], x[1]))
    index = {id(x[2]): i for i, x in enumerate(events)}
    spans = [(min(index[id(e)] for e in s[3]), max(index[id(e)] for e in s[3])) for s in wanted[1]]
    end = min(len(events), spans[-1][1] + 1 + pace["tail_lines"])
    rate = [float(pace["fast_eps"])] * end
    for i, (lo, hi) in enumerate(spans):
        rate[lo : hi + 1] = [float(pace["step_eps"])] * (hi + 1 - lo)
        if i:  # the quiet stretch before this step lasts hold_s, however few lines it holds
            prev = spans[i - 1][1] + 1
            count = lo - prev + 1
            rate[prev : lo + 1] = [count / pace["hold_s"]] * count
    rate[spans[-1][1] + 1 : end] = [pace["step_eps"] / 2] * (end - spans[-1][1] - 1)
    lines, offsets, off = [], [], 0
    for i, (_, _, ev) in enumerate(events[:end]):
        s = g.to_cef(ev) if g.rng.random() < g.cef_ratio else json.dumps(ev, separators=(",", ":"))
        b = s.encode() + b"\n"
        lines.append((b, rate[i]))
        offsets.append(off)
        off += len(b)
    steps = [
        {"order": n, "technique": s[0], "tactic": s[1], "description": s[2], "event_ids": [(1 << 48) | offsets[index[id(e)]] for e in s[3]]}
        for n, s in enumerate(wanted[1], 1)
    ]
    return {"lines": lines, "steps": steps, "decoy": wanted[2], "starts": [lo for lo, _ in spans], "bytes": off}


def score(key: dict, reached: int, alerts: list[dict], predictions: list[dict]) -> dict[str, Any]:
    """Compares what the system said with the steps played so far."""
    fam = lambda t: t.split(".")[0]  # noqa: E731
    out, contain = [], 0
    for s in key["steps"][:reached]:
        ids = set(s["event_ids"])
        hit = [a for a in alerts if ids & set(a["sample"]) and not a["rule_id"].startswith("ML-")]
        good = [a for a in hit if fam(a["technique_id"]) == fam(s["technique"])]
        uids = {a["uid"] for a in good}
        contain += sum(a["decision"] == "contain" for a in hit)
        pred = next((p for p in predictions if p.get("confirmed_by") in uids), None)
        out.append(
            {
                **{k: s[k] for k in ("order", "technique", "tactic", "description")},
                "detected": bool(hit),
                "label_ok": bool(good),
                "detected_as": (good or hit)[0]["technique_id"] if hit else None,
                "decision": (good or hit)[0]["decision"] if hit else None,
                "predicted_by": pred["id"] if pred else None,
                "lead_s": pred["lead_s"] if pred else None,
                "first": s["order"] == 1,
            }
        )
    predictable = [x for x in out if not x["first"]]
    return {
        "decoy": key["decoy"],
        "steps": out,
        "total_steps": len(key["steps"]),
        "reached": reached,
        "detected": sum(x["detected"] for x in out),
        "matched": sum(bool(x["predicted_by"]) for x in predictable),
        "predictable": len(predictable),
        "contain": contain,
    }
