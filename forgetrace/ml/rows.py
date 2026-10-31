"""Detection rows for ML detectors in the same stored shape as rule detections (frozen Detection interface)."""
from __future__ import annotations

from forgetrace import config

ML_LABEL_PRIORITY = 95  # a rule's technique label wins over a model's on the same raw event


def ml_detection_row(rule_id: str, title: str, detector: str, technique: str, tactic: str, members: list[int],
                     ts_first, ts_last, evidence: str, score: float, reasons: list[dict], aggregate_by: list[str],
                     severity: int, confidence: float) -> dict:
    att = config.attack()
    tac = att["tactics"][tactic]
    return {"detection_id": f"{rule_id}:{members[0]}", "rule_id": rule_id, "rule_version": 1, "rule_author": "forgetrace-ml",
            "rule_title": title, "technique_id": technique, "technique_name": att["techniques"][technique]["name"],
            "tactic": tactic, "tactic_ordinal": tac["ordinal"], "kill_chain_phase": tac["kill_chain_phase"],
            "severity": severity, "confidence": confidence, "label_priority": ML_LABEL_PRIORITY,
            "ts_first": ts_first, "ts_last": ts_last, "member_event_ids": members, "member_count": len(members),
            "evidence": evidence, "aggregate_by": aggregate_by, "detector": detector, "score": score,
            "reasons": [{k: (str(v) if k in ("value", "baseline") and v is not None else v) for k, v in r.items()} for r in reasons]}
