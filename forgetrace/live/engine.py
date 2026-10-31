"""Live, incremental analysis into a growing knowledge base (docs/wp/LIVE.md; mentor's requirement).

Why this exists: logs keep arriving (e.g. 2 GB every 5 minutes) and accumulate into terabytes, so a
batch must never re-scan history, yet something arriving now must still be linked to something seen
days ago. The design separates three time scales:

1. Raw events: each micro-batch is ingested in parallel into hot Parquet (event_id = (file_id << 48) |
   byte offset, unchanged). Detection scans only the batch plus `lookback_minutes` of raw history.
2. Rule state: threshold rules whose window exceeds the lookback keep bucketed partial aggregates
   (count / sum / distinct values per key and `bucket_minutes`); first-seen rules keep the set of keys
   already seen. Both are small tables, pruned by window.
3. Knowledge base: alert groups are merged into persistent alerts with stable ids (a window spanning two
   batches extends the same alert); each new alert is correlated with stored alerts of the last
   `correlate_window_hours` (a small table, not raw logs) using the dossier §12 edge score; and the Neo4j
   graph is enriched in place - entity first/last seen and counts accumulate, relationships accumulate,
   and long-range RELATED links / campaigns join alerts that share an uncommon entity at any time gap.
   Raw Parquet older than `hot_days` moves to a cold folder (still used for evidence by event_id); the
   compact knowledge base and graph are kept, so long-term dependencies survive the raw-data horizon.

Per-batch cost is proportional to the batch (+ lookback), not to the history. Batches are applied once:
the graph carries a :Batch marker per batch, and state is saved after each batch.
"""
from __future__ import annotations

import hashlib
import json
import multiprocessing as mp
import shutil
import time
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import duckdb
import pyarrow as pa

from forgetrace import config, store
from forgetrace.correlate.correlate import ENT, _evidence_ids, aggregate, candidate_edges, entity_stats, ip_host_map, prune
from forgetrace.ingest.ingest import default_workers, ingest_batch
from forgetrace.rules.engine import Rule, compile_filter, detect, detection_row, load_rules, parse_duration
from forgetrace.rules.router import plan as route
from forgetrace.stream import _line_end

LOG_SUFFIXES = {".log", ".json", ".jsonl", ".ndjson", ".cef", ".txt", ".csv", ".tsv", ".syslog"}


def live_config() -> dict:
    return config.load_yaml(config.CONFIG_DIR / "live.yml")


def _lit_ts(t: datetime) -> str:
    return f"TIMESTAMP '{t.isoformat(sep=' ')}'"


def _rule_span_s(r: Rule) -> int:
    span = r.threshold.seconds if r.threshold else 0
    if r.followed_by:
        span += parse_duration(r.followed_by.within)
    return span


class LiveEngine:
    def __init__(self, sources: list[Path], out: Path, graph: bool = False, workers: int | None = None,
                 progress=None, reset: bool = False):
        self.cfg = live_config()
        self.sources = [Path(s).resolve() for s in sources]
        self.out = Path(out)
        self.graph = graph
        self.report = progress or (lambda msg: None)
        self.out.mkdir(parents=True, exist_ok=True)
        if reset:
            for p in ("events", "parse_errors", self.cfg["cold_dir"]):
                shutil.rmtree(self.out / p, ignore_errors=True)
            for f in ("forgetrace.duckdb", "forgetrace.duckdb.wal", "live_state.json", "live_status.json"):
                (self.out / f).unlink(missing_ok=True)
            if graph:
                from forgetrace.graph.loader import clear_workspace, connect

                drv, _ = connect()
                if drv is not None:
                    with drv.session() as s:
                        clear_workspace(s, self.out.name)
                    drv.close()
        self.state_path = self.out / "live_state.json"
        self.state = json.loads(self.state_path.read_text()) if self.state_path.exists() else {
            "files": {}, "batches": [], "batch_no": 0, "first_ts": None, "watermark": None, "started": None}
        self.pool = ProcessPoolExecutor(max_workers=workers or default_workers(), mp_context=mp.get_context("spawn"))
        self.ws = self.out.name
        self.con = store.connect(self.out)
        self._init_tables()

    # ------------------------------------------------------------------ state
    def _init_tables(self) -> None:
        c = self.con
        c.execute("""CREATE TABLE IF NOT EXISTS kb_alerts (uid VARCHAR PRIMARY KEY, rule_id VARCHAR, rule_title VARCHAR,
            technique_id VARCHAR, technique_name VARCHAR, tactic VARCHAR, tactic_ordinal INT, kill_chain_phase VARCHAR,
            severity INT, confidence DOUBLE, aggregate_key VARCHAR, ts_first TIMESTAMP, ts_last TIMESTAMP,
            member_count BIGINT, sample_event_ids JSON, entities JSON, evidence JSON, detection_count BIGINT,
            first_batch INT, last_batch INT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS kb_edges (edge_id VARCHAR PRIMARY KEY, src_uid VARCHAR, dst_uid VARCHAR,
            score DOUBLE, score_terms JSON, weighted_terms JSON, reasons JSON, delta_t_s DOUBLE,
            evidence_event_ids JSON, first_batch INT, last_batch INT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS kb_first_seen (rule_id VARCHAR, k VARCHAR, ts TIMESTAMP,
            PRIMARY KEY (rule_id, k))""")
        c.execute("""CREATE TABLE IF NOT EXISTS kb_buckets (rule_id VARCHAR, k VARCHAR, b TIMESTAMP, n BIGINT,
            s DOUBLE, vals VARCHAR[], sample BIGINT[], key_vals VARCHAR[])""")

    def _save(self) -> None:
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.state, indent=1, default=str))
        tmp.replace(self.state_path)
        files = [{"file_id": f["file_id"], "path": p, "size": f["offset"], "mtime": 0, "sha256": None}
                 for p, f in sorted(self.state["files"].items(), key=lambda x: x[1]["file_id"])]
        (self.out / "files.json").write_text(json.dumps({"files": files, "stats": self.state.get("totals", {}),
                                                         "manifest_digest": hashlib.sha256(json.dumps(files).encode()).hexdigest(),
                                                         "mode": "live"}, indent=1))

    def _discover(self) -> list[Path]:
        found = []
        for s in self.sources:
            if s.is_dir():
                found += sorted(p for p in s.rglob("*") if p.is_file() and p.suffix.lower() in LOG_SUFFIXES
                                and not p.name.startswith("."))
            elif s.exists():
                found.append(s)
        return found

    # ------------------------------------------------------------------ one batch
    def step(self, final: bool = False) -> dict | None:
        """Ingest and analyse whatever new complete lines exist (up to batch_mb). None if nothing new."""
        budget = int(self.cfg["batch_mb"]) << 20
        batch_no = self.state["batch_no"] + 1
        t0 = time.perf_counter()
        ingested, files_done = {"lines": 0, "events": 0, "errors": 0, "empty": 0}, []
        for path in self._discover():
            if budget <= 0:
                break
            key = str(path)
            f = self.state["files"].setdefault(key, {"file_id": len(self.state["files"]) + 1, "offset": 0, "lines": 0})
            size = path.stat().st_size
            if size <= f["offset"]:
                continue
            end = _line_end(path, f["offset"], min(f["offset"] + budget, size), size, final)
            if end <= f["offset"]:
                continue
            st = ingest_batch(path, f["file_id"], f["offset"], end, f["lines"], self.out, self.pool, batch_no)
            budget -= end - f["offset"]
            f["offset"], f["lines"] = end, f["lines"] + st["lines"]
            for k in ingested:
                ingested[k] += st[k]
            files_done.append(f["file_id"])
        if not files_done:
            return None
        parts = sorted(str(p) for p in (self.out / "events").glob(f"part-*-b{batch_no:04d}-*.parquet"))
        self.state["batch_no"] = batch_no
        if not parts:  # only empty/unparseable lines
            self._save()
            return {"batch": batch_no, "events": 0, "ingest": ingested}
        bmin, bmax, n = self.con.execute(f"SELECT min(ts), max(ts), count(*) FROM read_parquet({parts!r})").fetchone()
        self.state["batches"].append({"batch": batch_no, "files": parts, "min_ts": str(bmin), "max_ts": str(bmax),
                                      "events": n, "tier": "hot"})
        wm = max(datetime.fromisoformat(self.state["watermark"]), bmax) if self.state["watermark"] else bmax
        self.state["watermark"] = str(wm)
        self.state["first_ts"] = self.state["first_ts"] or str(bmin)
        self.state["started"] = self.state["started"] or datetime.now().astimezone().isoformat(timespec="seconds")
        tot = self.state.setdefault("totals", {"lines": 0, "events": 0, "errors": 0, "empty": 0})
        for k in tot:
            tot[k] += ingested[k]
        ingest_s = time.perf_counter() - t0
        t1 = time.perf_counter()
        res = self._analyse(batch_no, parts, bmin, bmax)
        res.update(batch=batch_no, events=n, ingest=ingested, ingest_s=round(ingest_s, 2),
                   analyse_s=round(time.perf_counter() - t1, 2), batch_min_ts=str(bmin), batch_max_ts=str(bmax))
        self._tier()
        self._save()
        self._status(res)
        self._publish()
        return res

    def _publish(self) -> None:
        """Atomically publish a read-only snapshot of the knowledge base for the API: DuckDB lets one
        process hold the database file, and this engine writes continuously. Raw events are Parquet
        outside the file, so the snapshot stays small."""
        import os

        self.con.execute("CHECKPOINT")
        self.con.close()
        db = self.out / "forgetrace.duckdb"
        tmp = self.out / ".snapshot.tmp"
        shutil.copy2(db, tmp)
        os.replace(tmp, self.out / "live_snapshot.duckdb")
        self.con = store.connect(self.out)

    def _views(self, horizon_start: datetime, bmax: datetime, parts: list[str]) -> None:
        hot = [p for b in self.state["batches"] if b["tier"] == "hot" and datetime.fromisoformat(b["max_ts"]) >= horizon_start
               for p in b["files"]]
        c = self.con
        c.execute(f"CREATE OR REPLACE VIEW events AS SELECT * FROM read_parquet({hot!r}, union_by_name = true) "
                  f"WHERE ts BETWEEN {_lit_ts(horizon_start)} AND {_lit_ts(bmax)}")
        c.execute(f"CREATE OR REPLACE TEMP VIEW batch_events AS SELECT * FROM read_parquet({parts!r}, union_by_name = true)")
        c.execute("CREATE OR REPLACE TEMP TABLE batch_ids AS SELECT event_id FROM batch_events")

    def _all_events_view(self) -> None:
        files = [p for b in self.state["batches"] for p in b["files"]]
        if files:
            self.con.execute(f"CREATE OR REPLACE VIEW events AS SELECT * FROM read_parquet({files!r}, union_by_name = true)")
        pe = sorted(str(p) for p in (self.out / "parse_errors").glob("*.parquet"))
        if pe:
            self.con.execute(f"CREATE OR REPLACE VIEW parse_errors AS SELECT * FROM read_parquet({pe!r}, union_by_name = true)")

    def _analyse(self, batch_no: int, parts: list[str], bmin: datetime, bmax: datetime) -> dict:
        lookback = timedelta(minutes=int(self.cfg["lookback_minutes"]))
        self._views(bmin - lookback, bmax, parts)
        rules = load_rules()
        site_override = self._site_values()
        enabled, run_plan, cap = route(self.con, rules, dataset=self.ws, site_override=site_override)
        (self.out / "run_plan.json").write_text(json.dumps({**run_plan.model_dump(), "data": cap}, indent=1, default=str))
        short = [r for r in enabled if r.type != "baseline" and _rule_span_s(r) <= lookback.total_seconds()]
        long_ = [r for r in enabled if r.type == "threshold" and _rule_span_s(r) > lookback.total_seconds()]
        base = [r for r in enabled if r.type == "baseline"]
        extra = self._long_rules(long_, batch_no, bmax) + self._first_seen(base)
        det = detect(self.con, short, extra_rows=extra)
        # keep only detections that include at least one event of this batch (older ones are already merged)
        self.con.execute("""DELETE FROM detections WHERE detection_id NOT IN (
            SELECT DISTINCT d.detection_id FROM detections d, unnest(d.member_event_ids) u(m)
            JOIN batch_ids b ON b.event_id = u.m)""")
        groups = aggregate(self.con)
        updated = self._merge_alerts(groups, batch_no)
        edges = self._correlate(updated, batch_no)
        out = {"detections_in_batch": self.con.execute("SELECT count(*) FROM detections").fetchone()[0],
               "alerts_updated": len(updated), "edges_added": len(edges),
               "rules": {"short": len(short), "long_window": len(long_), "first_seen": len(base),
                         "disabled": len(run_plan.disabled)},
               "rule_seconds": det["rule_seconds"]}
        if self.graph:
            from forgetrace.live.graph_sync import sync_batch

            out["graph"] = sync_batch(self.con, self.ws, batch_no, updated, edges)
        self._all_events_view()
        return out

    def _site_values(self) -> dict:
        """Learned site values over all hot data (not just the horizon), so they are stable."""
        site = config.site()
        if site.get("home_countries") != "auto":
            return {}
        files = [p for b in self.state["batches"] if b["tier"] == "hot" for p in b["files"]]
        tmp = duckdb.connect()
        tmp.execute(f"CREATE VIEW events AS SELECT * FROM read_parquet({files!r}, union_by_name = true)")
        from forgetrace.rules.router import site_values

        try:
            return {"home_countries": site_values(tmp)["home_countries"]}
        finally:
            tmp.close()

    # ------------------------------------------------------------------ rule state
    def _long_rules(self, rules: list[Rule], batch_no: int, bmax: datetime) -> list[dict]:
        """Threshold rules with windows beyond the lookback, evaluated on bucketed state (D-83)."""
        if not rules:
            return []
        bm = int(self.cfg["bucket_minutes"])
        cap = int(self.cfg["max_bucket_values"])
        rows: list[dict] = []
        for r in rules:
            th = r.threshold
            keys = ", ".join(f'CAST("{k}" AS VARCHAR)' for k in r.group_by)
            nn = " AND ".join(f'"{k}" IS NOT NULL' for k in r.group_by)
            metric_s = f'sum(coalesce("{th.sum}", 0))' if th.sum else "0"
            vals = f'list(DISTINCT CAST("{th.distinct}" AS VARCHAR))[1:{cap}]' if th.distinct else "[]::VARCHAR[]"
            self.con.execute(f"""INSERT INTO kb_buckets SELECT ?, to_json([{keys}])::VARCHAR, time_bucket(INTERVAL {bm} MINUTE, ts),
                    count(*), {metric_s}, {vals}, list(event_id ORDER BY ts, event_id)[1:20], [{keys}]
                FROM batch_events WHERE {compile_filter(r.filter)} AND {nn} GROUP BY ALL""", [r.id])
            win = th.seconds
            metric = "s" if th.sum else "len(dv)" if th.distinct else "n"
            hits = self.con.execute(f"""
                WITH touched AS (SELECT DISTINCT k, b FROM kb_buckets WHERE rule_id = ? AND b >= ?),
                w AS (SELECT t.k, t.b AS at_b, kb.n, kb.s, kb.vals, kb.b AS kb_b, kb.sample, kb.key_vals
                      FROM touched t JOIN kb_buckets kb ON kb.rule_id = ? AND kb.k = t.k
                           AND kb.b > t.b - INTERVAL {win} SECOND AND kb.b <= t.b),
                agg AS (SELECT k, at_b, sum(n) AS n, sum(s) AS s, min(kb_b) AS first_b,
                               flatten(list(sample)) AS sample, any_value(key_vals) AS key_vals,
                               list_distinct(flatten(list(vals))) AS dv
                        FROM w GROUP BY k, at_b)
                SELECT k, max(at_b), max(n), max(s), max(len(dv)), min(first_b), any_value(sample), any_value(key_vals)
                FROM agg WHERE {metric} >= ? GROUP BY k""",
                [r.id, self._batch_bucket_floor(bm), r.id, th.value]).fetchall()
            for k, at_b, n, s, d, first_b, sample, key_vals in hits:
                ids = self.con.execute("""SELECT event_id FROM batch_events WHERE event_id IN (SELECT unnest(?))
                                          ORDER BY ts, event_id""", [sample]).fetchall()
                members = [i for (i,) in ids] or sorted(set(sample))[:20]
                desc = ", ".join(f"{g}={v}" for g, v in zip(r.group_by, key_vals))
                metric = (f"sum {th.sum} = {int(s)}" if th.sum else f"distinct {th.distinct} = {d}" if th.distinct
                          else f"count = {n}")
                ev = (f"{metric} >= {th.value} within {th.window} for {desc} (live bucketed state, {bm}-minute buckets, "
                      f"{n} events in window; members shown are from the current batch)")
                rows.append(detection_row(r, {"members": members, "ts_first": first_b, "ts_last": bmax, "evidence": ev}))
            horizon = max(_rule_span_s(x) for x in rules)
            self.con.execute("DELETE FROM kb_buckets WHERE b < ?", [bmax - timedelta(seconds=horizon)])
        return rows

    def _batch_bucket_floor(self, bm: int) -> datetime:
        bmin = self.con.execute("SELECT min(ts) FROM batch_events").fetchone()[0]
        return bmin - timedelta(minutes=bm)

    def _first_seen(self, rules: list[Rule]) -> list[dict]:
        """Baseline (first-seen) rules on the batch against the persistent set of keys seen (D-83)."""
        rows: list[dict] = []
        first = datetime.fromisoformat(self.state["first_ts"])
        for r in rules:
            keys = r.first_seen.keys
            kexpr = "to_json([" + ", ".join(f'CAST("{k}" AS VARCHAR)' for k in keys) + "])::VARCHAR"
            warm = first + timedelta(seconds=parse_duration(r.first_seen.warmup))
            new = self.con.execute(f"""
                SELECT k, t, eid, vals FROM (
                  SELECT {kexpr} AS k, min(ts) AS t, arg_min(event_id, ts) AS eid,
                         [{", ".join(f'CAST("{k}" AS VARCHAR)' for k in keys)}] AS vals
                  FROM batch_events WHERE {compile_filter(r.filter)} AND {" AND ".join(f'"{k}" IS NOT NULL' for k in keys)}
                  GROUP BY ALL) n
                WHERE NOT EXISTS (SELECT 1 FROM kb_first_seen f WHERE f.rule_id = ? AND f.k = n.k)""", [r.id]).fetchall()
            for k, t, eid, vals in new:
                if t >= warm:
                    pair = ", ".join(f"{a}={b}" for a, b in zip(keys, vals))
                    rows.append(detection_row(r, {"members": [eid], "ts_first": t, "ts_last": t,
                                                  "evidence": f"first-seen ({pair}) after {r.first_seen.warmup} warm-up "
                                                              f"(live: no earlier occurrence in the knowledge base)"}))
            if new:
                self.con.executemany("INSERT OR IGNORE INTO kb_first_seen VALUES (?, ?, ?)", [(r.id, k, t) for k, t, _, _ in new])
        return rows

    # ------------------------------------------------------------------ knowledge base
    def _merge_alerts(self, groups: list[dict], batch_no: int) -> list[dict]:
        if not groups:
            return []
        gap = timedelta(seconds=config.correlation()["agg_gap_s"])
        k_sample = int(self.cfg["sample_event_ids"])
        # count each group's members that belong to this batch (horizon overlap must not double count)
        mem = pa.table({"gi": [i for i, g in enumerate(groups) for _ in g["member_event_ids"]],
                        "eid": [m for g in groups for m in g["member_event_ids"]]})
        self.con.register("_gm", mem)
        new_counts = dict(self.con.execute("SELECT gi, count(*) FROM _gm JOIN batch_ids b ON b.event_id = _gm.eid GROUP BY gi").fetchall())
        self.con.unregister("_gm")
        pairs = sorted({(g["rule_id"], g["aggregate_key"]) for g in groups})
        existing: dict[tuple, list[dict]] = {}
        cols = [r[0] for r in self.con.execute("DESCRIBE kb_alerts").fetchall()]
        self.con.register("_pairs", pa.table({"r": [p[0] for p in pairs], "k": [p[1] for p in pairs]}))
        found = self.con.execute("""SELECT a.* FROM kb_alerts a JOIN _pairs p ON a.rule_id = p.r AND a.aggregate_key = p.k""").fetchall()
        self.con.unregister("_pairs")
        for row in found:
            d = dict(zip(cols, row))
            existing.setdefault((d["rule_id"], d["aggregate_key"]), []).append(d)
        touched: dict[str, dict] = {}
        for i, g in enumerate(groups):
            n_new = new_counts.get(i, 0)
            if not n_new:
                continue
            cands = [e for e in existing.get((g["rule_id"], g["aggregate_key"]), [])
                     if e["ts_last"] >= g["ts_first"] - gap and e["ts_first"] <= g["ts_last"] + gap]
            if cands:
                a = min(cands, key=lambda e: e["ts_first"])
                a["ts_first"], a["ts_last"] = min(a["ts_first"], g["ts_first"]), max(a["ts_last"], g["ts_last"])
                a["member_count"] += n_new
                merged = set(json.loads(a["sample_event_ids"])) | set(g["member_event_ids"][:k_sample])
                a["sample_event_ids"] = json.dumps(sorted(merged)[:k_sample])
                ents = json.loads(a["entities"])
                for key in ENT:
                    ents[key] = sorted(set(ents.get(key, [])) | set(g["entities"].get(key, [])))[:200]
                a["entities"] = json.dumps(ents)
                a["evidence"] = json.dumps((json.loads(a["evidence"]) + g["evidence"])[-10:])
                a["detection_count"] += g["raw_alert_count"]
                a["last_batch"] = batch_no
            else:
                h = hashlib.sha1(f"{g['rule_id']}|{g['aggregate_key']}|{g['ts_first']}|{g['member_event_ids'][0]}".encode())
                a = {"uid": "A" + h.hexdigest()[:14], "rule_id": g["rule_id"], "rule_title": g["rule_title"],
                     "technique_id": g["technique_id"], "technique_name": g["technique_name"], "tactic": g["tactic"],
                     "tactic_ordinal": g["tactic_ordinal"], "kill_chain_phase": g["kill_chain_phase"],
                     "severity": g["severity"], "confidence": g["confidence"], "aggregate_key": g["aggregate_key"],
                     "ts_first": g["ts_first"], "ts_last": g["ts_last"], "member_count": n_new,
                     "sample_event_ids": json.dumps(g["member_event_ids"][:k_sample]),
                     "entities": json.dumps({k: g["entities"].get(k, [])[:200] for k in ENT}),
                     "evidence": json.dumps(g["evidence"][-10:]), "detection_count": g["raw_alert_count"],
                     "first_batch": batch_no, "last_batch": batch_no}
                existing.setdefault((g["rule_id"], g["aggregate_key"]), []).append(a)
            touched[a["uid"]] = a
        if touched:
            rows = list(touched.values())
            self.con.execute("DELETE FROM kb_alerts WHERE uid IN (SELECT unnest(?))", [[r["uid"] for r in rows]])
            self.con.register("_ka", pa.Table.from_pylist([{c: r[c] for c in cols} for r in rows]))
            self.con.execute(f"INSERT INTO kb_alerts SELECT {', '.join(cols)} FROM _ka")
            self.con.unregister("_ka")
        return list(touched.values())

    def _kb_group(self, a: dict) -> dict:
        """A knowledge-base alert in the shape the correlator expects."""
        sample = json.loads(a["sample_event_ids"]) if isinstance(a["sample_event_ids"], str) else a["sample_event_ids"]
        ents = json.loads(a["entities"]) if isinstance(a["entities"], str) else a["entities"]
        return {"group_id": a["uid"], "rule_id": a["rule_id"], "technique_id": a["technique_id"], "tactic": a["tactic"],
                "tactic_ordinal": a["tactic_ordinal"], "severity": a["severity"], "confidence": a["confidence"],
                "ts_first": a["ts_first"], "ts_last": a["ts_last"], "member_event_ids": sample or [0],
                "entities": {k: ents.get(k, []) for k in ENT}, "raw_alert_count": a["detection_count"]}

    def _correlate(self, updated: list[dict], batch_no: int) -> list[dict]:
        """Score edges between updated alerts and stored alerts of the correlation window (dossier §12)."""
        if not updated:
            return []
        window = timedelta(hours=float(self.cfg["correlate_window_hours"]))
        lo = min(a["ts_first"] for a in updated) - window
        cols = [r[0] for r in self.con.execute("DESCRIBE kb_alerts").fetchall()]
        recent = [dict(zip(cols, r)) for r in self.con.execute("SELECT * FROM kb_alerts WHERE ts_last >= ?", [lo]).fetchall()]
        groups = [self._kb_group(a) for a in recent]
        upd = {a["uid"] for a in updated}
        deg = entity_stats(self.con, groups)
        ipmap = ip_host_map(self.con)
        cand = [e for e in candidate_edges(groups, ipmap, deg, self.con) if e["src_group_id"] in upd or e["dst_group_id"] in upd]
        kept = prune(cand)
        gid = {g["group_id"]: g for g in groups}
        _evidence_ids(kept, gid, self.con)
        if kept:
            rows = [{"edge_id": e["edge_id"], "src_uid": e["src_group_id"], "dst_uid": e["dst_group_id"], "score": e["score"],
                     "score_terms": json.dumps(e["score_terms"]), "weighted_terms": json.dumps(e["weighted_terms"]),
                     "reasons": json.dumps(e["reasons"]), "delta_t_s": e["delta_t_s"],
                     "evidence_event_ids": json.dumps(e.get("evidence_event_ids", [])), "first_batch": batch_no,
                     "last_batch": batch_no} for e in kept]
            prev = dict(self.con.execute("SELECT edge_id, first_batch FROM kb_edges WHERE edge_id IN (SELECT unnest(?))",
                                         [[r["edge_id"] for r in rows]]).fetchall())
            for r in rows:
                r["first_batch"] = prev.get(r["edge_id"], batch_no)
            self.con.execute("DELETE FROM kb_edges WHERE edge_id IN (SELECT unnest(?))", [[r["edge_id"] for r in rows]])
            self.con.register("_ke", pa.Table.from_pylist(rows))
            self.con.execute("INSERT INTO kb_edges SELECT * FROM _ke")
            self.con.unregister("_ke")
        return kept

    # ------------------------------------------------------------------ retention + status
    def _tier(self) -> None:
        """Move raw Parquet older than hot_days (event time vs watermark) to the cold folder; optionally
        delete cold data older than cold_days. The knowledge base and graph are never pruned."""
        wm = datetime.fromisoformat(self.state["watermark"])
        hot_cut = wm - timedelta(days=float(self.cfg["hot_days"]))
        cold = self.out / self.cfg["cold_dir"]
        for b in self.state["batches"]:
            if b["tier"] == "hot" and datetime.fromisoformat(b["max_ts"]) < hot_cut:
                cold.mkdir(exist_ok=True)
                moved = []
                for p in b["files"]:
                    dst = cold / Path(p).name
                    shutil.move(p, dst)
                    moved.append(str(dst))
                b["files"], b["tier"] = moved, "cold"
            if b["tier"] == "cold" and self.cfg.get("cold_days") is not None and \
                    datetime.fromisoformat(b["max_ts"]) < wm - timedelta(days=float(self.cfg["cold_days"])):
                for p in b["files"]:
                    Path(p).unlink(missing_ok=True)
                b["files"], b["tier"] = [], "deleted"

    def _status(self, res: dict) -> None:
        kb = self.con.execute("SELECT count(*), count(DISTINCT tactic) FROM kb_alerts").fetchone()
        ed = self.con.execute("SELECT count(*) FROM kb_edges").fetchone()[0]
        tiers: dict[str, int] = {}
        for b in self.state["batches"]:
            tiers[b["tier"]] = tiers.get(b["tier"], 0) + 1
        st = {"state": "running", "workspace": self.ws, "watermark": self.state["watermark"],
              "first_event_ts": self.state["first_ts"], "batches": self.state["batch_no"], "batch_tiers": tiers,
              "totals": self.state.get("totals"), "knowledge_base": {"alerts": kb[0], "tactics": kb[1], "edges": ed},
              "last_batch": res, "updated_at": datetime.now().astimezone().isoformat(timespec="seconds")}
        hist_p = self.out / "live_status.json"
        prev = json.loads(hist_p.read_text()).get("history", []) if hist_p.exists() else []
        keep = ("batch", "events", "ingest_s", "analyse_s", "detections_in_batch", "alerts_updated", "edges_added",
                "batch_min_ts", "batch_max_ts")
        st["history"] = (prev + [{k: res.get(k) for k in keep}])[-500:]
        hist_p.write_text(json.dumps(st, indent=1, default=str))

    def run(self, follow: bool = True, idle_exit: float | None = None) -> dict:
        """Process batches until no new data; with follow, keep polling (stop after idle_exit seconds idle)."""
        idle_since = None
        try:
            while True:
                res = self.step(final=not follow)
                if res is None:
                    if not follow:
                        break
                    idle_since = idle_since or time.perf_counter()
                    if idle_exit is not None and time.perf_counter() - idle_since > idle_exit:
                        break
                    time.sleep(float(self.cfg["poll_seconds"]))
                    continue
                idle_since = None
                self.report(f"batch {res['batch']}: {res['events']:,} events, {res.get('alerts_updated', 0)} alerts updated, "
                            f"{res.get('edges_added', 0)} edges, ingest {res.get('ingest_s', 0)} s + analyse "
                            f"{res.get('analyse_s', 0)} s, watermark {self.state['watermark']}")
        finally:
            self.close()
        return json.loads((self.out / "live_status.json").read_text()) if (self.out / "live_status.json").exists() else {}

    def close(self) -> None:
        try:
            self.pool.shutdown()
        finally:
            self.con.close()


def live_kb_summary(out: Path) -> dict[str, Any]:
    con = duckdb.connect(str(out / "forgetrace.duckdb"), read_only=True)
    try:
        return {"alerts": con.execute("SELECT count(*) FROM kb_alerts").fetchone()[0],
                "edges": con.execute("SELECT count(*) FROM kb_edges").fetchone()[0]}
    finally:
        con.close()
