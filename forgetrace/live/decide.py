"""What to do about a live alert (dossier §12 correlation, §14 containment; DECISIONS D-101).

Why this exists: the live engine links alerts but stops there. This table turns that evidence into one
recommendation, in a fixed order so the same evidence always gives the same answer. It is deterministic,
reads thresholds from config/decision.yml, involves no LLM and never executes anything.
"""
from __future__ import annotations

from dataclasses import dataclass, field

ACTIONS = ("contain", "investigate", "monitor", "ignore")


@dataclass
class Context:
    severity: int
    fused: float | None
    links: int = 0                    # alerts this one was correlated with
    chain_tactics: int = 1            # distinct tactics in its linked chain
    critical_hosts: list[str] = field(default_factory=list)   # critical assets anywhere in the chain
    unique_patterns: int = 0          # never-before-seen log patterns in its events
    known_seen: int = 0               # how often its rarest known pattern has been seen
    prior_alerts: int = 0             # earlier alerts involving the same patterns


def decide(c: Context, cfg: dict) -> tuple[str, list[str]]:
    why: list[str] = []
    routine = c.known_seen >= cfg["routine_min_seen"]  # earlier alerts on everyday behaviour say little about this one
    if c.links:
        why.append(f"correlated with {c.links} earlier alert(s); chain spans {c.chain_tactics} tactic(s)")
    if c.unique_patterns:
        why.append(f"contains {c.unique_patterns} log pattern(s) never seen before")
    if c.known_seen:
        why.append(f"known log pattern, seen {c.known_seen:,} time(s), in {c.prior_alerts} earlier alert(s)")
    if c.fused is not None:
        why.append(f"fused detector score {c.fused:.3f}")
    if c.critical_hosts:
        why.append(f"chain touches critical asset {', '.join(c.critical_hosts[:3])}")
    if c.critical_hosts and c.chain_tactics >= cfg["contain"]["min_chain_tactics"]:
        return "contain", why
    if c.links >= cfg["investigate"]["min_links"] or c.unique_patterns or (c.fused or 0) >= cfg["investigate"]["min_fused"] \
            or (c.prior_alerts and not routine):
        return "investigate", why
    if routine and (c.fused or 0) <= 0.5:
        return "ignore", why + ["single weak signal on routine behaviour"]
    if c.severity >= cfg["monitor"]["min_severity"]:
        return "monitor", why
    return "ignore", why + ["below the monitoring threshold"]
