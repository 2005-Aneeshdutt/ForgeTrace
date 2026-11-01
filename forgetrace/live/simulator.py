"""Live simulation: replays a log file through the real live engine (PRD B-5; dossier §12).

Why this exists: a demo needs logs arriving now, not a finished report. A replay thread appends lines to a
feed file at a chosen rate, and an unmodified `forgetrace live` process follows that file, so detection and
correlation are the same code as production. The replay never looks at labels: it only knows each line's
pattern. After each batch the published knowledge base is read and every alert gets a decision.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections import Counter, deque
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from forgetrace import assets, config
from forgetrace.datasets import scenarios
from forgetrace.ingest.ingest import make_event_id, strip_eol
from forgetrace.ingest.parsers import parse_line
from forgetrace.live.decide import Context, decide
from forgetrace.live.patterns import PatternTracker, summary
from forgetrace.live.predict import Predictor

WS = "live-sim"
TICK_S = 0.1


def sim_config() -> dict:
    return config.load_yaml(config.CONFIG_DIR / "decision.yml")


def _ts(us: int | None) -> str:
    return datetime.fromtimestamp(us / 1e6, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S") if us else ""


class Simulator:
    def __init__(self, out: Path, query: Callable[[str], list], on_reset: Callable[[], None]):
        self.dir, self.query, self.on_reset = out / WS, query, on_reset
        self.lock = threading.Lock()
        self._blank()

    def _blank(self) -> None:
        self.state, self.source, self.error = "idle", None, None
        self.cfg = sim_config()
        self.eps = self.cfg["speed"]["default_eps"]
        self.tracker = PatternTracker(self.cfg["baseline_events"])
        self.tail: deque = deque(maxlen=40)
        self.seq = self.version = self.written = self.total = self.engine_lines = 0
        self.status = Counter()
        self.decisions: dict[str, dict] = {}
        self.feed: deque = deque(maxlen=200)
        self.graph: dict[str, list] = {"nodes": [], "edges": []}
        self.delay_s = None
        self.batches = self.alerts = 0
        self.marks: deque = deque(maxlen=4000)
        self.flagged: set[int] = set()
        self.proc = None
        self.stop_flag = threading.Event()
        self.threads: list[threading.Thread] = []
        self.seen_snapshot = None
        self.started = None
        self.predictor = Predictor()
        self.scenario, self.scenario_name, self.reached, self.card = None, None, 0, None
        self.alert_rows: list[dict] = []

    # ---- control
    def start(self, source: Path | None, eps: int | None, scenario: str | None = None) -> None:
        self.stop()
        self.on_reset()
        shutil.rmtree(self.dir, ignore_errors=True)
        with self.lock:
            runs = self.runs = getattr(self, "runs", -1) + 1
            self._blank()
            self.source, self.state, self.started = source, "running", time.time()
            if scenario:
                pace = self.cfg["scenario"]
                self.scenario = scenarios.build(scenario, pace["seeds"][runs % len(pace["seeds"])], pace)
                self.scenario_name, self.total = scenario, self.scenario["bytes"]
            else:
                self.total = source.stat().st_size
            if eps:
                self.eps = self._clamp(eps)
        feed = self.dir / "feed"
        feed.mkdir(parents=True)
        (feed / "replay.log").touch()
        log = open(self.dir / "engine.log", "ab")
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "forgetrace", "live", "--watch", str(feed), "--out", str(self.dir), "--reset"],
            cwd=config.ROOT,
            stdout=log,
            stderr=log,
            start_new_session=True,
        )
        self.threads = [threading.Thread(target=f, args=(self.stop_flag,), daemon=True) for f in (self._replay, self._follow)]
        for t in self.threads:
            t.start()

    def _clamp(self, eps: int) -> int:
        s = self.cfg["speed"]
        return max(s["min_eps"], min(s["max_eps"], int(eps)))

    def set_speed(self, eps: int) -> None:
        self.eps = self._clamp(eps)

    def stop(self) -> None:
        self.stop_flag.set()
        for t in self.threads:  # a restart must never share the feed with an old replay
            if t is not threading.current_thread():
                t.join(5)
        p, self.proc = self.proc, None
        if p and p.poll() is None:
            os.killpg(p.pid, signal.SIGINT)
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
        if self.state == "running":
            self.state = "stopped"

    # ---- replay: one thread appends lines, streaming the source
    def _plan(self):
        """(line, lines per second); a file replay follows the speed control, a scenario has its own pacing."""
        if self.scenario:
            yield from self.scenario["lines"]
            return
        with open(self.source, "rb") as src:
            for line in src:
                yield line, None

    def _replay(self, stop: threading.Event) -> None:
        offset, done, index = 0, 0, 0
        starts = self.scenario["starts"] if self.scenario else []
        try:
            with open(self.dir / "feed" / "replay.log", "ab") as out:
                due = time.perf_counter()
                for line, rate in self._plan():
                    if stop.is_set():
                        return
                    due += 1 / (rate or self.eps)
                    wait = due - time.perf_counter()
                    if wait > 0.02:
                        out.flush()
                        with self.lock:
                            self.written = done
                            self.marks.append((self.tracker.lines, time.time()))
                        stop.wait(wait)
                    line = line if line.endswith(b"\n") else line + b"\n"
                    self._line(line, offset)
                    out.write(line)
                    offset += len(line)
                    done += len(line)
                    index += 1
                    reached = sum(1 for x in starts if x < index)
                    if reached != self.reached:
                        with self.lock:
                            self.reached, self.version = reached, self.version + 1
                out.flush()
                with self.lock:
                    self.written = done
                    self.marks.append((self.tracker.lines, time.time()))
        except Exception as e:  # shown in the UI; never takes the server down
            self.error, self.state = f"{type(e).__name__}: {e}", "failed"
            return
        self.state = "draining"

    def _line(self, line: bytes, offset: int) -> None:
        content = strip_eol(line)
        event_id = make_event_id(1, offset)  # the feed is the engine's only file, so its file_id is 1
        try:
            e = parse_line(content)
        except Exception:
            self.status["unparsed"] += 1
            return
        ts = _ts(e.get("ts"))
        pid, status = self.tracker.observe(e, event_id, ts)
        self.status[status] += 1
        self.seq += 1
        with self.lock:
            self.tail.append({"seq": self.seq, "ts": ts, "text": summary(e), "status": status, "pattern": pid, "event_id": event_id})
            if status == "unique":
                self.version += 1

    # ---- follow the engine: new snapshot -> decisions
    def _follow(self, stop: threading.Event) -> None:
        snap = self.dir / "live_snapshot.duckdb"
        while not stop.is_set():
            time.sleep(0.5)
            stamp = snap.stat().st_mtime_ns if snap.exists() else None  # published after the status file is written
            if stamp and stamp != self.seen_snapshot:
                self.seen_snapshot = stamp
                st = json.loads((self.dir / "live_status.json").read_text())
                self.batches, self.engine_lines = st.get("batches", 0), (st.get("totals") or {}).get("lines", 0)
                try:
                    self._decide_all()
                    self.error = None
                except Exception as e:  # snapshot swapped mid-read: the next batch retries
                    self.error = f"{type(e).__name__}: {e}"
                self._delay()
            if self.state == "draining" and self.engine_lines >= self.status.total() - self.status["unparsed"]:
                self.state = "complete"
                self._close_run()
                self.stop()
                return
            if self.proc and self.proc.poll() is not None and self.state == "running":
                self.state, self.error = "failed", f"live engine exited with code {self.proc.returncode}; see {WS}/engine.log"
                return

    def _close_run(self) -> None:
        with self.lock:
            self.predictor.close()
            self._score()
            self.version += 1

    def _score(self) -> None:
        if self.scenario:
            self.card = scenarios.score(self.scenario, self.reached, self.alert_rows, self.predictor.public())

    def _delay(self) -> None:
        with self.lock:
            hit = next((t for n, t in self.marks if n >= self.engine_lines), None)
        if hit:
            self.delay_s = round(time.time() - hit, 1)

    def _decide_all(self) -> None:
        rows = self.query("""SELECT uid, rule_id, rule_title, technique_id, tactic, severity, p_malicious, ts_first, ts_last,
                                    member_count, sample_event_ids, entities, kill_chain_phase, first_batch
                             FROM kb_alerts ORDER BY ts_first""")
        edges = self.query("SELECT src_uid, dst_uid, score, delta_t_s, reasons FROM kb_edges")
        cols = (
            "uid",
            "rule_id",
            "title",
            "technique_id",
            "tactic",
            "severity",
            "fused",
            "ts_first",
            "ts_last",
            "events",
            "sample",
            "entities",
            "phase",
            "first_batch",
            "first_batch",
        )
        alerts = {r[0]: dict(zip(cols, r)) for r in rows}
        parent = {u: u for u in alerts}

        def find(x: str) -> str:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        incoming: dict[str, list] = {u: [] for u in alerts}
        for s, d, score, dt, reasons in edges:
            if s in alerts and d in alerts:
                parent[find(s)] = find(d)
                incoming[d].append((s, score, dt, json.loads(reasons or "[]")))
        chains: dict[str, list] = {}
        for u in alerts:
            chains.setdefault(find(u), []).append(u)
        order = sorted(alerts.values(), key=lambda a: str(a["ts_first"]))
        pat_alerts: dict[str, list] = {}
        with self.lock:
            tracker = self.tracker
            for a in order:
                ids = [int(x) for x in json.loads(a["sample"] or "[]")]
                self.flagged.update(ids)
                a["patterns"] = sorted({tracker.by_event[i] for i in ids if i in tracker.by_event})
                for pid in a["patterns"]:
                    tracker.patterns[pid]["alerts"].add(a["uid"])
            for line in self.tail:
                if line["event_id"] in self.flagged:
                    line["status"] = "flagged"
        decided = {}
        for a in order:
            members = [alerts[u] for u in chains[find(a["uid"])]]
            hosts = sorted({h for m in members for h in (json.loads(m["entities"] or "{}").get("host") or [])})
            critical = [h for h in hosts if assets.criticality(h) >= assets.critical_threshold()]
            pats = [tracker.patterns[p] for p in a["patterns"]]
            known = [p for p in pats if not p["unique"]]
            prior = sum(1 for p in a["patterns"] for other in pat_alerts.get(p, []) if other != a["uid"])
            for p in a["patterns"]:
                pat_alerts.setdefault(p, []).append(a["uid"])
            ctx = Context(
                a["severity"],
                a["fused"],
                len(incoming[a["uid"]]),
                len({m["tactic"] for m in members}),
                critical,
                len(pats) - len(known),
                min((p["count"] for p in known), default=0),
                prior,
            )
            action, why = decide(ctx, self.cfg)
            links = [
                {
                    "uid": s,
                    "title": alerts[s]["title"],
                    "technique_id": alerts[s]["technique_id"],
                    "score": round(score, 3),
                    "delta_t_s": dt,
                    "reasons": [r.get("type", "") for r in reasons][:4],
                }
                for s, score, dt, reasons in incoming[a["uid"]]
            ]
            decided[a["uid"]] = {
                "uid": a["uid"],
                "rule_id": a["rule_id"],
                "title": a["title"],
                "technique_id": a["technique_id"],
                "tactic": a["tactic"],
                "phase": a["phase"],
                "severity": a["severity"],
                "fused": a["fused"],
                "ts": str(a["ts_first"])[:19],
                "events": a["events"],
                "decision": action,
                "why": why,
                "links": links,
                "patterns": [{"id": p["id"], "text": p["text"], "unique": p["unique"]} for p in pats],
                "chain": {"alerts": len(members), "tactics": ctx.chain_tactics, "critical": critical},
                "sample": json.loads(a["sample"] or "[]")[:5],
            }
        with self.lock:
            for u, d in decided.items():
                old = self.decisions.get(u)
                if old is None or old["decision"] != d["decision"]:
                    self.feed.appendleft({**d, "from": old["decision"] if old else None, "at": time.strftime("%H:%M:%S")})
            self.decisions = decided
            self.alerts = len(decided)
            self.graph = {
                "nodes": [
                    {k: d[k] for k in ("uid", "title", "technique_id", "tactic", "decision", "severity", "ts")} for d in decided.values()
                ],
                "edges": [
                    {"id": f"{s}>{dd}", "source": s, "target": dd, "score": round(score, 3)}
                    for s, dd, score, _, _ in edges
                    if s in alerts and dd in alerts
                ],
            }
            self.alert_rows = [
                {
                    **a,
                    "entities": json.loads(a["entities"] or "{}"),
                    "sample": [int(x) for x in json.loads(a["sample"] or "[]")],
                    "decision": decided[a["uid"]]["decision"],
                }
                for a in order
            ]
            self.predictor.update(self.alert_rows)
            self.version += 1

    # ---- views
    def tick(self) -> dict:
        with self.lock:
            t = self.tracker
            return {
                "state": self.state,
                "error": self.error,
                "source": self.source.name if self.source else None,
                "eps": self.eps,
                "lines": t.lines,
                "bytes": self.written,
                "total_bytes": self.total,
                "status": dict(self.status),
                "patterns": len(t.patterns),
                "learning": t.learning,
                "baseline": t.baseline,
                "batches": self.batches,
                "alerts": self.alerts,
                "engine_lines": self.engine_lines,
                "delay_s": self.delay_s,
                "version": self.version,
                "tail": list(self.tail)[-18:],
                "counts": dict(Counter(d["decision"] for d in self.decisions.values())),
                "scenario": self.scenario_name,
                "reached": self.reached,
                "total_steps": len(self.scenario["steps"]) if self.scenario else 0,
            }

    def _story(self, preds: list[dict]) -> dict:
        """Alerts joined by predictions that came true, plus open predictions as ghost nodes."""
        used, links, ghosts = [], [], []
        for p in preds:
            for uid in (p["from_uid"], p.get("confirmed_by")):
                if uid and uid not in used:
                    used.append(uid)
            if p.get("confirmed_by"):
                links.append({"id": p["id"], "source": p["from_uid"], "target": p["confirmed_by"]})
            elif p["status"] == "pending":
                ghosts.append(
                    {
                        "id": p["id"],
                        "source": p["from_uid"],
                        "options": [o["technique"] for o in p["options"]],
                        "name": p["options"][0]["name"],
                    }
                )
        by = {u: self.decisions[u] for u in used if u in self.decisions}
        keep = sorted(by.values(), key=lambda d: d["ts"])[-14:]
        ids = {d["uid"] for d in keep}
        return {
            "nodes": [{k: d[k] for k in ("uid", "title", "technique_id", "tactic", "decision")} for d in keep],
            "links": [x for x in links if x["source"] in ids and x["target"] in ids],
            "ghosts": [g for g in ghosts if g["source"] in ids],
        }

    def view(self) -> dict:
        with self.lock:
            self._score()
            preds = self.predictor.public()
            return {
                "version": self.version,
                "unique": self.tracker.unique(),
                "decisions": list(self.feed)[:80],
                "graph": self.graph,
                "predictions": preds[::-1][:40],
                "story": self._story(preds),
                "card": self.card,
            }

    def pattern(self, pid: str) -> dict | None:
        with self.lock:
            p = self.tracker.patterns.get(pid)
            return self.tracker.public(p) if p else None

    def linked(self, uids: list[str]) -> list[dict]:
        with self.lock:
            return [self.decisions[u] for u in uids if u in self.decisions]


def pattern_facts(p: dict, evidence: list[dict], alerts: list[dict]) -> dict[str, Any]:
    """Verified facts about one unique pattern, in the shape forgetrace/report/llm.py narrates."""
    linked = [
        {"rule": a["rule_id"], "title": a["title"], "technique_id": a["technique_id"], "tactic": a["tactic"], "decision": a["decision"]}
        for a in alerts
    ]
    return {
        "kind": "pattern",
        "id": p["id"],
        "headline": f"Never-seen log pattern: {p['text']}",
        "summary": f"This behaviour first appeared after the baseline at {p['first_ts']} UTC and has occurred {p['count']} time(s). "
        f"{len(linked)} alert(s) involve it.",
        "pattern": p["text"],
        "when": {"first": p["first_ts"], "last": p["last_ts"], "timezone": "UTC"},
        "entities": {"user": p["users"], "host": p["hosts"], "src_ip": p["src_ips"], "dst_ip": p["dst_ips"]},
        "linked_alerts": linked,
        "evidence": evidence,
        "uncertainties": ["A new pattern is unusual, not proven malicious", "The baseline only covers the replayed logs before this point"],
    }
