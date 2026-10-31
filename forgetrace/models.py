"""Frozen Phase 2 interfaces (docs/PHASE2.md "FROZEN INTERFACES", WP EV-0).

Why this exists: evaluation, dataset adapters, ML detectors, fusion and the UI are built in
parallel; they meet only through these shapes. Change them only with a line in
docs/DECISIONS.md. Each table-like model has an Arrow schema so the same contract holds for
Parquet files and DuckDB tables. The labels contract lives in the eval package
so that nothing on the detection path can import it.
"""
from __future__ import annotations

import re
from datetime import datetime
import pyarrow as pa
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from forgetrace.ingest.ingest import SCHEMA as _ENVELOPE

DETECTOR_RE = re.compile(r"^(rule:[A-Za-z0-9_.-]+|m1_ueba|m2_authgraph|m3_prov)$")


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --------------------------------------------------------------------------- Event
class Event(_Model):
    """Canonical envelope (dossier §13) + dataset. Every field except the pointer is optional."""
    event_id: int
    file_id: int
    byte_offset: int
    line_no: int
    line_digest: str | None = None
    source_event_id: str | None = None
    dataset: str | None = None
    ts: datetime
    source_type: str | None = None
    raw_format: str | None = None
    event_type: str | None = None
    action: str | None = None
    outcome: str | None = None
    user: str | None = None
    user_domain: str | None = None
    target_user: str | None = None
    host: str | None = None
    host_ip: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_is_external: bool | None = None
    dst_is_external: bool | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    process: str | None = None
    parent_process: str | None = None
    pid: int | None = None
    command_line: str | None = None
    logon_id: str | None = None
    logon_type: str | None = None
    domain_name: str | None = None
    url: str | None = None
    file_path: str | None = None
    file_hash: str | None = None
    registry_path: str | None = None
    registry_value: str | None = None
    group_name: str | None = None
    bytes_out: int | None = None
    bytes_in: int | None = None
    vendor_event_code: str | None = None

    @model_validator(mode="after")
    def _pointer(self) -> "Event":
        if self.event_id != (self.file_id << 48) | self.byte_offset:
            raise ValueError("event_id must equal (file_id << 48) | byte_offset")
        return self


EVENT_SCHEMA = _ENVELOPE


# --------------------------------------------------------------------------- Detection
class Reason(_Model):
    """One explanation term: rule condition, ML feature attribution, or graph evidence."""
    feature: str
    value: float | str | None = None
    baseline: float | str | None = None
    contribution: float | None = None
    text: str


class Detection(_Model):
    detection_id: str
    detector: str
    score: float
    reasons: list[Reason] = Field(default_factory=list)
    technique_id: str
    tactic: str
    member_event_ids: list[int] = Field(min_length=1)
    ts_first: datetime
    ts_last: datetime
    rule_id: str | None = None
    severity: int | None = None
    confidence: float | None = None
    evidence: str | None = None
    duplicate_of: str | None = None

    @field_validator("detector")
    @classmethod
    def _detector(cls, v: str) -> str:
        if not DETECTOR_RE.match(v):
            raise ValueError(f"detector must be rule:<id>, m1_ueba, m2_authgraph or m3_prov, got {v!r}")
        return v


_REASON_T = pa.struct([("feature", pa.string()), ("value", pa.string()), ("baseline", pa.string()),
                       ("contribution", pa.float64()), ("text", pa.string())])
DETECTION_SCHEMA = pa.schema([
    ("detection_id", pa.string()), ("detector", pa.string()), ("score", pa.float64()),
    ("reasons", pa.list_(_REASON_T)), ("technique_id", pa.string()), ("tactic", pa.string()),
    ("member_event_ids", pa.list_(pa.int64())), ("ts_first", pa.timestamp("us")), ("ts_last", pa.timestamp("us")),
    ("rule_id", pa.string()), ("severity", pa.int32()), ("confidence", pa.float64()),
    ("evidence", pa.string()), ("duplicate_of", pa.string()),
])


# --------------------------------------------------------------------------- AlertGroup
class AlertGroup(_Model):
    group_id: str
    rule_id: str
    technique_id: str
    tactic: str
    ts_first: datetime
    ts_last: datetime
    raw_alert_count: int
    detection_ids: list[str]
    member_event_ids: list[int] = Field(min_length=1)
    entities: dict[str, list[str]] = Field(default_factory=dict)
    severity: int | None = None
    p_malicious: float | None = None
    contributions: dict[str, float] = Field(default_factory=dict)

    @field_validator("p_malicious")
    @classmethod
    def _prob(cls, v: float | None) -> float | None:
        if v is not None and not 0.0 <= v <= 1.0:
            raise ValueError("p_malicious must be in [0, 1]")
        return v


ALERT_GROUP_SCHEMA = pa.schema([
    ("group_id", pa.string()), ("rule_id", pa.string()), ("technique_id", pa.string()), ("tactic", pa.string()),
    ("ts_first", pa.timestamp("us")), ("ts_last", pa.timestamp("us")), ("raw_alert_count", pa.int32()),
    ("detection_ids", pa.list_(pa.string())), ("member_event_ids", pa.list_(pa.int64())),
    ("entities", pa.map_(pa.string(), pa.list_(pa.string()))), ("severity", pa.int32()),
    ("p_malicious", pa.float64()), ("contributions", pa.map_(pa.string(), pa.float64())),
])


# --------------------------------------------------------------------------- RunPlan
class DisabledDetector(_Model):
    detector: str
    missing: list[str]


class RunPlan(_Model):
    dataset: str
    capability_profile: dict[str, float]
    enabled: list[str]
    disabled: list[DisabledDetector] = Field(default_factory=list)
    blind_spots: list[str] = Field(default_factory=list)

    @field_validator("capability_profile")
    @classmethod
    def _rates(cls, v: dict[str, float]) -> dict[str, float]:
        bad = [k for k, r in v.items() if not 0.0 <= r <= 1.0]
        if bad:
            raise ValueError(f"fill rates must be in [0, 1]: {bad}")
        return v
