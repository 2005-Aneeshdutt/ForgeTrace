"""Log patterns for the live simulation (PRD B-5; dossier §12 long-term dependencies).

Why this exists: an alert says a rule fired, but an analyst also asks "have we ever seen this kind of
log before?". A pattern is the behaviour of a line with its identities removed: event type, outcome,
logon type, process name and direction. Users, hosts, addresses and times are left out, so the same
behaviour from a new user is still a known pattern. Log format is left out too, because one behaviour
can arrive as JSON or CEF. Vendor verdict fields are never read.
"""
from __future__ import annotations

import hashlib
from typing import Any


def signature(e: dict[str, Any]) -> tuple:
    proc = str(e.get("process") or "").lower().replace("\\", "/").rsplit("/", 1)[-1]
    return (e.get("event_type"), e.get("outcome"), e.get("logon_type"), proc or None,
            e.get("src_is_external"), e.get("dst_is_external"))


def pattern_id(sig: tuple) -> str:
    return hashlib.sha256(repr(sig).encode()).hexdigest()[:8]


def describe(sig: tuple) -> str:
    etype, outcome, logon, proc, src_ext, dst_ext = sig
    bits = [str(etype or "unclassified")]
    if outcome and outcome != "unknown":
        bits.append(str(outcome))
    if logon:
        bits.append(f"{logon} logon")
    if proc:
        bits.append(f"by {proc}")
    if src_ext:
        bits.append("from an external address")
    if dst_ext:
        bits.append("to an external address")
    return " · ".join(bits)


def summary(e: dict[str, Any]) -> str:
    """One readable line for the stream."""
    who = f"{e['user']}@{e['host']}" if e.get("user") and e.get("host") else e.get("user") or e.get("host") or ""
    route = f"{e.get('src_ip') or ''} → {e.get('dst_ip')}" if e.get("dst_ip") else str(e.get("src_ip") or "")
    return " ".join(str(x) for x in (e.get("event_type") or "event", who, route, e.get("process") or "") if x)


class PatternTracker:
    """Counts patterns as lines arrive. Lines inside the baseline teach what is normal and are never unique."""

    SAMPLE = 8

    def __init__(self, baseline: int):
        self.baseline, self.lines, self.patterns = baseline, 0, {}
        self.by_event: dict[int, str] = {}

    @property
    def learning(self) -> bool:
        return self.lines < self.baseline

    def observe(self, e: dict[str, Any], event_id: int, ts: str) -> tuple[str, str]:
        """Returns (pattern id, baseline | known | unique). Only a pattern's first late line is unique."""
        learning = self.learning
        self.lines += 1
        sig = signature(e)
        pid = pattern_id(sig)
        self.by_event[event_id] = pid
        p = self.patterns.get(pid)
        if p is None:
            p = self.patterns[pid] = {"id": pid, "text": describe(sig), "unique": not learning, "count": 0,
                                      "first_ts": ts, "last_ts": ts, "first_line": self.lines, "event_ids": [],
                                      "users": set(), "hosts": set(), "src_ips": set(), "dst_ips": set(), "alerts": set()}
            status = "unique" if p["unique"] else "baseline"
        else:
            status = "baseline" if learning else "known"
        p["count"] += 1
        p["last_ts"] = ts
        if len(p["event_ids"]) < self.SAMPLE:
            p["event_ids"].append(event_id)
        for key, val in (("users", e.get("user")), ("hosts", e.get("host")), ("src_ips", e.get("src_ip")), ("dst_ips", e.get("dst_ip"))):
            if val and len(p[key]) < 20:
                p[key].add(val)
        return pid, status

    def public(self, p: dict) -> dict:
        return {k: sorted(v) if isinstance(v, set) else v for k, v in p.items()}

    def unique(self) -> list[dict]:
        return [self.public(p) for p in sorted(self.patterns.values(), key=lambda x: -x["first_line"]) if p["unique"]]
