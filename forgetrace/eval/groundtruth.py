"""Frozen GroundTruth interface (docs/PHASE2.md "FROZEN INTERFACES", WP EV-0).

Why this exists: every dataset (D0 generator, LANL, AIT, OpTC) converts its labels into this one
shape so `forgetrace eval` scores all of them the same way. It lives in the eval package, which
the detection path (ingest, rules, correlate, reach, pipeline, api) must never import
(tests/test_e2e.py::test_ground_truth_not_imported_by_engine).
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field, model_validator

from forgetrace.models import _Model


class LineRef(_Model):
    file: str
    line: int = Field(ge=1)


class AuthEdge(_Model):
    """LANL-style red-team label: a user authenticating from src to dst at time t."""
    t: datetime
    user: str | None = None
    src: str
    dst: str


class Step(_Model):
    order: int = Field(ge=1)
    technique: str
    tactic: str
    event_ids: list[int] = Field(default_factory=list)
    line_refs: list[LineRef] = Field(default_factory=list)
    edges: list[AuthEdge] = Field(default_factory=list)
    t_start: datetime | None = None
    t_end: datetime | None = None
    hosts: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    description: str | None = None

    @model_validator(mode="after")
    def _locator(self) -> "Step":
        if not (self.event_ids or self.line_refs or self.edges):
            raise ValueError("a step needs event_ids, line_refs or edges")
        return self


class Attack(_Model):
    attack_id: str
    name: str
    is_decoy: bool = False
    steps: list[Step] = Field(min_length=1)


class GroundTruth(_Model):
    dataset: str
    split: Literal["tuning", "test", "all"] = "all"
    source: dict = Field(default_factory=dict)
    attacks: list[Attack]


def ground_truth_from_legacy(gt: dict, dataset: str = "d0", events: dict[int, dict] | None = None) -> GroundTruth:
    """Convert a Phase 1 ground_truth.json (`decoy`, `event_ids`, `line_nos`) to GroundTruth.

    `events` (optional) maps event_id -> {ts, host, user}; when given, t_start/t_end/hosts/users
    are filled from the step's events.
    """
    fname = gt.get("dataset", {}).get("file", "events.log")
    attacks = []
    for a in gt["attacks"]:
        steps = []
        for s in a["steps"]:
            evs = [events[e] for e in s["event_ids"] if events and e in events]
            ts = sorted(e["ts"] for e in evs if e.get("ts"))
            steps.append(Step(order=s["order"], technique=s["technique"], tactic=s["tactic"],
                              event_ids=s["event_ids"],
                              line_refs=[LineRef(file=fname, line=n) for n in s.get("line_nos", [])],
                              t_start=ts[0] if ts else None, t_end=ts[-1] if ts else None,
                              hosts=sorted({e["host"] for e in evs if e.get("host")}),
                              users=sorted({e["user"] for e in evs if e.get("user")}),
                              description=s.get("description")))
        attacks.append(Attack(attack_id=a["attack_id"], name=a.get("name", a["attack_id"]),
                              is_decoy=a.get("decoy", a.get("is_decoy", False)), steps=steps))
    return GroundTruth(dataset=dataset, source=gt.get("dataset", {}), attacks=attacks)
