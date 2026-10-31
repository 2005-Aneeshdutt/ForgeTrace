"""M1: unsupervised behaviour baselines per entity (UEBA) with SHAP explanations (PHASE2 ML-1/ML-2).

Why this exists: rules only find what someone wrote down; behaviour analysis finds an entity doing something
unusual *for itself*. Without labels the model must be unsupervised and every flag must be checkable by a
person, so:
- each entity (user, host, internal address, active external address) is summarised per window with the
  features in config/ml.yml, computed in DuckDB (no Python loop over events); a feature is used only if the
  fields it needs exist in the data (unseen datasets);
- each value is compared with that entity's own history (median / spread of log counts), so 300 ports is
  normal for a scanner and abnormal for a workstation;
- an Isolation Forest (Liu, Ting & Zhou 2008; scikit-learn) over [log value, entity-relative deviation]
  scores windows; there are no labels, so the operating point is an alert budget (top windows per day,
  above a score percentile), as SOC UEBA products do;
- SHAP TreeExplainer (Lundberg & Lee 2017) attributes each flagged window's score to features; the
  explanation lists the top features that are above the entity's normal, with value and baseline;
- the ATT&CK label is looked up from the top feature in a fixed table (config/ml.yml techniques) - never
  learned, never an LLM. Training is deterministic (fixed random_state).
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import numpy as np
import pyarrow as pa

from forgetrace import config


def ml_config() -> dict:
    return config.load_yaml(config.CONFIG_DIR / "ml.yml")


def usable_features(fill: dict[str, float], cfg: dict) -> dict[str, str]:
    """Feature name -> SQL for the features whose required fields exist in this data."""
    return {k: f["sql"] for k, f in cfg["ueba"]["features"].items() if all(fill.get(r, 0) > 0 for r in f["requires"])}


def window_sql(view: str, ent: dict, feats: dict[str, str], window_minutes: int, extra_where: str = "TRUE",
               latest: bool = False) -> str:
    """One row per (entity, window): entity, win, t0, t1, sample event ids, feature values.
    `latest` samples the window's newest events (live: they belong to the batch being merged)."""
    field = ent["field"]
    order = "DESC" if latest else ""
    where = f'"{field}" IS NOT NULL AND ({ent.get("where", "TRUE")}) AND ({extra_where})'
    having = f"HAVING count(*) >= {int(ent['min_events'])}" if ent.get("min_events") else ""
    cols = ", ".join(f"{sql} AS \"{name}\"" for name, sql in feats.items())
    return (f'SELECT CAST("{field}" AS VARCHAR) AS entity, time_bucket(INTERVAL {int(window_minutes)} MINUTE, ts) AS win, '
            f"min(ts) AS t0, max(ts) AS t1, list(event_id ORDER BY ts {order}, event_id {order})[1:50] AS sample, {cols} "
            f"FROM {view} WHERE {where} GROUP BY 1, 2 {having} ORDER BY 1, 2")


def evidence_ids(con, view: str, ent: dict, feat_cfg: dict, features: list[str], entity: str, win, w: int,
                 limit: int = 50) -> list[tuple[int, Any]]:
    """(event_id, ts) of the events that show the flagged features (config `evidence`), so the analyst reads the
    behaviour itself."""
    out: list[tuple[int, Any]] = []
    for f in features:
        ev = feat_cfg[f].get("evidence") or {}
        q = (f'SELECT event_id, ts FROM {view} WHERE CAST("{ent["field"]}" AS VARCHAR) = ? AND ts >= ? '
             f'AND ts < ? + INTERVAL {int(w)} MINUTE AND ({ent.get("where", "TRUE")}) AND ({ev.get("where", "TRUE")})')
        if ev.get("first_of"):
            q += f' AND {ev["first_of"]} IS NOT NULL QUALIFY row_number() OVER (PARTITION BY {ev["first_of"]} ORDER BY ts, event_id) = 1'
        q += f' ORDER BY {ev.get("order", "ts")}, event_id LIMIT {int(limit)}'
        for r in con.execute(q, [entity, win, win]).fetchall():  # the top reason's events first
            if r not in out and len(out) < limit:
                out.append(r)
    return sorted(out)


class EntityModel:
    """Isolation Forest + per-entity baselines for one entity type."""

    def __init__(self, feats: list[str], cfg: dict):
        self.feats, self.cfg = feats, cfg
        self.model = None
        self.explainer = None
        self.base: dict[str, tuple[np.ndarray, np.ndarray, np.ndarray]] = {}   # entity -> (median, mad, p95) on log1p
        self.glob: tuple[np.ndarray, np.ndarray, np.ndarray] | None = None
        self.train_windows = 0
        self.train_scores: np.ndarray | None = None
        self.train_range: tuple[str, str] | None = None

    @staticmethod
    def _stats(L: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        med = np.median(L, axis=0)
        mad = np.median(np.abs(L - med), axis=0)
        return med, mad, np.percentile(L, 95, axis=0)

    def _baseline(self, ent: str):
        return self.base.get(ent, self.glob)

    def _design(self, ents: list[str], X: np.ndarray) -> np.ndarray:
        L = np.log1p(np.maximum(X, 0))
        Z = np.empty_like(L)
        for i, e in enumerate(ents):
            med, mad, _ = self._baseline(e)
            Z[i] = (L[i] - med) / (mad + 0.5)
        return np.hstack([L, Z])

    def fit(self, ents: list[str], X: np.ndarray, wins: list) -> "EntityModel":
        from sklearn.ensemble import IsolationForest

        L = np.log1p(np.maximum(X, 0))
        self.glob = self._stats(L)
        by: dict[str, list[int]] = {}
        for i, e in enumerate(ents):
            by.setdefault(e, []).append(i)
        mn = int(self.cfg["ueba"]["min_entity_windows"])
        self.base = {e: self._stats(L[idx]) for e, idx in by.items() if len(idx) >= mn}
        self.model = IsolationForest(n_estimators=int(self.cfg["ueba"]["n_estimators"]), random_state=int(self.cfg["random_state"]),
                                     n_jobs=-1).fit(self._design(ents, X))
        self.explainer = None
        self.train_scores = self.score(ents, X)   # the operating point is set against training scores
        self.train_windows = len(ents)
        self.train_range = (str(min(wins)), str(max(wins))) if wins else None
        return self

    def score(self, ents: list[str], X: np.ndarray) -> np.ndarray:
        return -self.model.score_samples(self._design(ents, X))  # higher = more anomalous

    def explain(self, ents: list[str], X: np.ndarray, k: int) -> list[list[dict]]:
        """Top-k features pushing each row towards 'anomalous' that are also above the entity's normal."""
        import shap

        if self.explainer is None:
            self.explainer = shap.TreeExplainer(self.model)
        D = self._design(ents, X)
        sv = np.asarray(self.explainer.shap_values(D))
        F = len(self.feats)
        out = []
        for i, e in enumerate(ents):
            contrib = sv[i, :F] + sv[i, F:]          # value + deviation dims of the same feature
            med, _, p95 = self._baseline(e)
            own = e in self.base
            rows = []
            for j in np.argsort(contrib):            # most negative = most anomalous
                if contrib[j] >= 0 or len(rows) >= k:
                    break
                v = float(X[i, j])
                m, p = float(np.expm1(med[j])), float(np.expm1(p95[j]))
                if v <= max(p, m):                    # only "above the usual range (p95)" is a reason to look
                    continue
                who = "this entity's" if own else "the population's"
                rows.append({"feature": self.feats[j], "value": round(v, 2), "baseline": f"median {m:.1f}, p95 {p:.1f}",
                             "contribution": round(float(-contrib[j]), 4),
                             "text": f"{self.feats[j].replace('_', ' ')} = {v:,.0f} ({who} usual: median {m:,.1f}, p95 {p:,.1f})"})
            out.append(rows)
        return out


def select(scores: np.ndarray, wins: list, cfg: dict, reference: np.ndarray | None = None) -> list[int]:
    """No labels -> an operating point by budget: per day the top `alerts_per_day` windows above the
    `min_score_percentile` of the training scores (`reference`; batch: the scores themselves)."""
    if not len(scores):
        return []
    ref = scores if reference is None or not len(reference) else reference
    cut = np.percentile(ref, float(cfg["ueba"]["min_score_percentile"]))
    by_day: dict[Any, list[int]] = {}
    for i, w in enumerate(wins):
        if scores[i] >= cut:
            by_day.setdefault(w.date() if hasattr(w, "date") else str(w)[:10], []).append(i)
    keep = []
    for idx in by_day.values():
        keep += sorted(idx, key=lambda i: -scores[i])[: int(cfg["ueba"]["alerts_per_day"])]
    return sorted(keep)


def _matrix(rows: list) -> np.ndarray:
    return np.array([[float(v or 0) for v in (r[5] if len(r) == 6 and isinstance(r[5], list) else r[5:])] for r in rows])


def detections(con, view: str | None, fill: dict[str, float], train_view: str | None = None, models: dict | None = None,
               min_win: datetime | None = None, cur_rows: dict | None = None, train_rows: dict | None = None,
               evidence_view: str | None = None, anchor_latest: bool = False) -> tuple[list[dict], dict, dict]:
    """Score entity windows in `view` and return (detection rows, models, run info).
    Batch mode trains on `view` itself. Live mode passes stored windows: `cur_rows` / `train_rows` map entity
    type to rows (entity, win, t0, t1, sample, [features]) and/or fitted `models`.
    `min_win` limits flagged windows to new data (live); `anchor_latest` adds the window's newest event to the
    members so a live flag is tied to the batch that completed it."""
    from forgetrace.ml.rows import ml_detection_row

    cfg = ml_config()
    feats = usable_features(fill, cfg)
    info: dict[str, Any] = {"features": sorted(feats), "entity_types": {}}
    if not cfg.get("enabled") or len(feats) < 2:
        info["skipped"] = "ML disabled or fewer than two usable features"
        return [], models or {}, info
    models = dict(models or {})
    rows: list[dict] = []
    names = list(feats)
    w = int(cfg["window_minutes"])
    for etype, ent in cfg["ueba"]["entities"].items():
        if fill.get(ent["field"], 0) == 0:
            info["entity_types"][etype] = "entity field absent"
            continue
        cur = cur_rows.get(etype, []) if cur_rows is not None else con.execute(window_sql(view, ent, feats, w)).fetchall()
        if not cur:
            continue
        ents, wins, X = [r[0] for r in cur], [r[1] for r in cur], _matrix(cur)
        m = models.get(etype)
        if m is None or list(m.feats) != names:
            tr = (train_rows.get(etype, []) if train_rows is not None else
                  con.execute(window_sql(train_view, ent, feats, w)).fetchall() if train_view else cur)
            if len(tr) < int(cfg["ueba"]["min_windows"]):
                info["entity_types"][etype] = f"only {len(tr)} windows; needs {cfg['ueba']['min_windows']} to train"
                continue
            m = EntityModel(names, cfg).fit([r[0] for r in tr], _matrix(tr), [r[1] for r in tr])
            models[etype] = m
        s = m.score(ents, X)
        pick = [i for i in select(s, wins, cfg, m.train_scores) if min_win is None or wins[i] >= min_win]
        reasons = m.explain([ents[i] for i in pick], X[pick], int(cfg["ueba"]["top_features"])) if pick else []
        ref = m.train_scores if m.train_scores is not None else s
        pct = {i: float((ref < s[i]).mean() * 100) for i in pick}
        n_flag = 0
        flagged = [(i, rs) for i, rs in zip(pick, reasons) if rs]
        if flagged:  # one scan copies the flagged windows' events; per-feature evidence lookups then run on that
            con.register("_ml_picks", pa.table({"entity": [ents[i] for i, _ in flagged], "win": [wins[i] for i, _ in flagged]}))
            con.execute(f"""CREATE OR REPLACE TEMP TABLE _ml_ev AS SELECT e.* FROM {evidence_view or view or "events"} e
                            JOIN _ml_picks p ON CAST(e."{ent['field']}" AS VARCHAR) = p.entity AND e.ts >= p.win
                            AND e.ts < p.win + INTERVAL {w} MINUTE""")
            con.unregister("_ml_picks")
        for i, rs in flagged:
            tech = cfg["techniques"].get(rs[0]["feature"]) or cfg["techniques"]["events"]
            ev_rows = evidence_ids(con, "_ml_ev", ent, cfg["ueba"]["features"],
                                   [r["feature"] for r in rs], ents[i], wins[i], w)
            members = sorted({e for e, _ in ev_rows}) or list(cur[i][4])
            t_first = min((t for _, t in ev_rows), default=cur[i][2])
            t_last = max((t for _, t in ev_rows), default=cur[i][3])
            if anchor_latest and cur[i][4]:
                members = sorted(set(members) | {cur[i][4][0]})
                t_last = cur[i][3]
            top = "; ".join(r["text"] for r in rs)
            ev = (f"behaviour model ({etype}): {ent['field']} {ents[i]} in the {w}-minute window from {wins[i]} is more unusual "
                  f"than {pct[i]:.2f}% of the {len(ref):,} training windows - {top}. Isolation Forest trained on {m.train_windows:,} "
                  f"windows ({m.train_range[0]} .. {m.train_range[1]}).")
            rows.append(ml_detection_row(
                rule_id=f"ML-UEBA-{etype}", title=f"Unusual behaviour for this {etype.replace('_', ' ')} (behaviour model)",
                detector="m1_ueba", technique=tech["technique"], tactic=tech["tactic"], members=members,
                ts_first=t_first, ts_last=t_last, evidence=ev, score=round(pct[i] / 100, 4), reasons=rs,
                aggregate_by=[ent["field"]], severity=int(cfg["ueba"]["severity"]), confidence=float(cfg["ueba"]["prior"])))
            n_flag += 1
        info["entity_types"][etype] = {"windows_scored": len(s), "flagged": n_flag, "trained_on": m.train_windows}
    return rows, models, info


__all__ = ["detections", "EntityModel", "ml_config", "usable_features", "timedelta"]
