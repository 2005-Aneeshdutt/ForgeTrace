"""Next-step prediction for live alerts (dossier §10 kill chain, §14 what comes next; DECISIONS D-112).

Why this exists: finding a step is useful, warning about the following one is better. Each rule alert opens a
prediction from config/predict.yml, stamped with the time it was made. A later alert closes it only if it
matches the technique family, shares an account, host or address, and arrived in a later batch, so a prediction
can never be credited for something already known when it was made. This module sees engine alerts only: it
must never import a scenario or its answer key (tests/test_sim.py enforces that).
"""
from __future__ import annotations

import time
from datetime import datetime
from typing import Any

from forgetrace import config


def parent(t: str | None) -> str:
    return (t or "").split(".")[0]


def predict_config() -> dict:
    return config.load_yaml(config.CONFIG_DIR / "predict.yml")


class Predictor:
    def __init__(self, cfg: dict | None = None):
        self.cfg = cfg or predict_config()
        self.predictions: list[dict] = []
        self.seen: set[str] = set()

    @staticmethod
    def _related(a: dict, b: dict) -> bool:
        return any(set(a["entities"].get(k) or []) & set(b["entities"].get(k) or []) for k in ("user", "host", "src_ip"))

    @staticmethod
    def _minutes(a: Any, b: Any) -> float:
        return (datetime.fromisoformat(str(b)) - datetime.fromisoformat(str(a))).total_seconds() / 60

    def update(self, alerts: list[dict]) -> None:
        """Alerts need uid, rule_id, technique_id, tactic, title, entities, first_batch and ts_first."""
        fresh = [a for a in alerts if a["uid"] not in self.seen and not a["rule_id"].startswith("ML-")]
        for a in sorted(fresh, key=lambda x: (x["first_batch"], str(x["ts_first"]))):
            self.seen.add(a["uid"])
            for p in self.predictions:
                if p["status"] == "pending" and self._minutes(p["log_ts"], a["ts_first"]) > self.cfg["expire_minutes"]:
                    p["status"] = "not confirmed"
            for p in self.predictions:
                if p["status"] == "pending" and p["batch"] < a["first_batch"] and self._related(p["source"], a) \
                        and parent(a["technique_id"]) in {o["technique"] for o in p["options"]}:
                    now = time.time()
                    p.update(status="confirmed", confirmed_by=a["uid"], confirmed_at=now, lead_s=round(now - p["made_at"], 1),
                             actual={"technique_id": a["technique_id"], "title": a["title"], "tactic": a["tactic"]},
                             log_lead_min=round(self._minutes(p["log_ts"], a["ts_first"]), 1))
            options = self.cfg["transitions"].get(parent(a["technique_id"]))
            if not options or any(p["status"] == "pending" and p["family"] == parent(a["technique_id"]) and self._related(p["source"], a)
                                  for p in self.predictions):
                continue
            self.predictions.append({"id": f"P{len(self.predictions) + 1}", "family": parent(a["technique_id"]), "from_uid": a["uid"],
                                     "from_technique": a["technique_id"], "from_title": a["title"], "options": options, "status": "pending",
                                     "made_at": time.time(), "log_ts": str(a["ts_first"]), "batch": a["first_batch"],
                                     "entities": {k: (a["entities"].get(k) or [])[:3] for k in ("user", "host")}, "source": a})

    def close(self) -> None:
        for p in self.predictions:
            if p["status"] == "pending":
                p["status"] = "not confirmed"

    def public(self) -> list[dict]:
        return [{k: v for k, v in p.items() if k != "source"} for p in self.predictions]
