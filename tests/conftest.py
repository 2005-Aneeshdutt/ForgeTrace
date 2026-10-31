import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))


@pytest.fixture(scope="session")
def sample(tmp_path_factory):
    """Generate the dev sample (same args as `make sample`) and run the full pipeline on it."""
    d = tmp_path_factory.mktemp("sample")
    subprocess.run([sys.executable, str(ROOT / "tools/gen_scenarios.py"), "--start", "2026-10-01T00:00:00Z",
                    "--days", "2", "--seed", "7", "--events", "20000", "--cef-ratio", "0.1",
                    "--out-dir", str(d), "--assets", str(d / "assets.yaml")], check=True, capture_output=True)
    from forgetrace.pipeline import run
    out = d / "out"
    stats = run([d / "events.log"], out)
    return {"dir": d, "out": out, "stats": stats, "gt": json.loads((d / "ground_truth.json").read_text()),
            "incidents": json.loads((out / "incidents.json").read_text())}


T0 = datetime(2026, 10, 1, tzinfo=timezone.utc)


def ecs(t, host="WS-A-01", user="alice", **kw):
    """Build one SimEDR/ECS-like event line for rule fixtures."""
    ev = {"@timestamp": (T0 + timedelta(seconds=t)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
          "event": {"id": f"fx-{t}-{len(kw)}", "action": kw.pop("action", "process_created"), "dataset": "edr.x"},
          "host": {"name": host, "ip": [kw.pop("host_ip", "10.0.0.5")]}, "user": {"name": user}}
    if "outcome" in kw:
        ev["event"]["outcome"] = kw.pop("outcome")
    for path, v in kw.items():
        cur = ev
        parts = path.split("__")
        for p in parts[:-1]:
            cur = cur.setdefault(p, {})
        cur[parts[-1]] = v
    return json.dumps(ev)


def run_rules(tmp_path, lines, rule_ids):
    from forgetrace import store
    from forgetrace.ingest.ingest import ingest
    from forgetrace.rules.engine import detect, load_rules
    f = tmp_path / "fx.log"
    f.write_text("\n".join(lines) + "\n")
    out = tmp_path / "out"
    ingest([f], out)
    con = store.connect(out)
    store.create_views(con, out)
    detect(con, [r for r in load_rules() if r.id in rule_ids])
    rows = con.execute("SELECT rule_id, member_event_ids FROM detections").fetchall()
    con.close()
    return rows
