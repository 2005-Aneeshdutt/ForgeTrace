import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from forgetrace.pipeline import run

ROOT = Path(__file__).resolve().parents[1]


def test_end_to_end_sample(sample):
    s = sample["stats"]
    assert s["ingest"]["errors"] == 0 and s["ingest"]["events"] == s["ingest"]["lines"]
    assert s["incidents"] == 2 and s["detections"] > 0
    assert all(i["status"] == "emitted" and len(i["tactics"]) >= 2 for i in sample["incidents"])


def test_rerun_is_deterministic_and_does_not_duplicate(sample, tmp_path):
    out2 = tmp_path / "out2"
    run([sample["dir"] / "events.log"], out2)
    run([sample["dir"] / "events.log"], out2)  # second run into the same dir: no duplicates
    a = (sample["out"] / "incidents.json").read_text()
    b = (out2 / "incidents.json").read_text()
    norm = lambda s: json.dumps(json.loads(s), sort_keys=True)  # noqa: E731
    assert norm(a) == norm(b)


def test_ground_truth_not_imported_by_engine():
    for p in (ROOT / "forgetrace").rglob("*.py"):
        src = p.read_text()
        assert "ground_truth" not in src, f"{p} references ground truth"


def test_ui_never_uses_innerhtml():
    js = (ROOT / "forgetrace/api/static/app.js").read_text()
    assert "innerHTML" not in js.replace("never innerHTML", "") and "insertAdjacentHTML" not in js
    html = (ROOT / "forgetrace/api/static/index.html").read_text()
    assert "http://" not in html and "https://" not in html  # no CDN at runtime


def test_api_live(sample):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    env = dict(os.environ, FORGETRACE_OUT=str(sample["out"]))
    p = subprocess.Popen([sys.executable, "-m", "uvicorn", "forgetrace.api.app:app", "--port", str(port)],
                         cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    get = lambda path: json.loads(urllib.request.urlopen(base + path, timeout=5).read())  # noqa: E731
    try:
        for _ in range(50):
            try:
                get("/health")
                break
            except Exception:
                time.sleep(0.2)
        assert get("/health")["incidents"] == 2
        lst = get("/incidents")
        assert lst[0]["risk_score"] >= lst[1]["risk_score"]
        iid = lst[0]["incident_id"]
        path = get(f"/incidents/{iid}/path")
        assert path["primary"]["steps"]
        eid = path["primary"]["steps"][0]["member_event_ids"][0]
        raw = get(f"/events/{eid}/raw")
        assert raw["verified"] is True and raw["raw"]
        assert get(f"/incidents/{iid}/reach")["reachable"]
        req = urllib.request.Request(base + f"/incidents/{iid}/simulate", method="POST",
                                     headers={"Content-Type": "application/json"},
                                     data=json.dumps({"actions": [{"type": "disable_account", "target": "nobody"}]}).encode())
        sim = json.loads(urllib.request.urlopen(req, timeout=5).read())
        assert sim["before_critical_reachable"] == sim["after_critical_reachable"]
        html = urllib.request.urlopen(base + "/", timeout=5)
        assert "script-src 'self'" in html.headers["Content-Security-Policy"]
    finally:
        p.terminate()
        p.wait(5)
