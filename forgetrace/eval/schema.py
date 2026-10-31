"""metrics/<dataset>/<experiment>.json schema (docs/PHASE2.md FROZEN INTERFACES, WP EV-1).

Why this exists: the ablation report, the UI Experiments page and reviewers all read the same
files, so their shape is fixed here and validated on write. A metric value is always a dict with
`value` (number or null) and `text` (human-readable, or "N/A (reason)").
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = "1"

# PRD targets shown on every report (docs/PHASE2.md METRICS).
PRD_TARGETS = {
    "step_recall": {"op": ">", "target": 0.90},
    "label_acc_exact": {"op": ">", "target": 0.85},
    "ordered_path_rate": {"op": "==", "target": 1.0},
    "false_alert_rate": {"op": "<", "target": 0.10},
    "wall_time_s": {"op": "<", "target": 3600},
    "peak_rss_mb": {"op": "<", "target": 8192},
    "p95_path_latency_ms": {"op": "<", "target": 500},
}


class Summary(BaseModel):
    model_config = ConfigDict(extra="forbid")
    value: float | None
    text: str
    ci95: list[float] | None = None
    ci_unit: str | None = None
    per_run: list[float | None] = Field(default_factory=list)
    mean: float | None = None
    sd: float | None = None


class RunEntry(BaseModel):
    model_config = ConfigDict(extra="allow")
    run_dir: str
    ground_truth: str
    ground_truth_sha256: str
    seed: Any = None
    split: str
    metrics: dict[str, Any]


class MetricsFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: str = SCHEMA_VERSION
    dataset: str
    experiment: str
    split: str
    created_at: str
    git_sha: str
    git_dirty: bool
    config_hash: str
    code_version: str
    bootstrap: dict[str, Any]
    summary: dict[str, Summary]
    prd: dict[str, Any]
    system: dict[str, Any]
    runs: list[RunEntry]
    not_computed: dict[str, str] = Field(default_factory=dict)
