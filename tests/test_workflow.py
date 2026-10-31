"""Analyst workflow: input folder discovery, uploads into data/input, background analysis runs."""
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

from forgetrace.pipeline import expand_inputs

ROOT = Path(__file__).resolve().parents[1]


def test_expand_inputs_scans_folder(tmp_path):
    (tmp_path / "sub").mkdir()
    for name in ("b.log", "a.json", "sub/c.cef", "README.md", ".hidden.log", "notes.pdf"):
        (tmp_path / name).write_text("x\n")
    got = [p.relative_to(tmp_path).as_posix() for p in expand_inputs([tmp_path])]
    assert got == ["a.json", "b.log", "sub/c.cef"]
    (tmp_path / "empty").mkdir()
    with pytest.raises(ValueError):
        expand_inputs([tmp_path / "empty"])
    with pytest.raises(FileNotFoundError):
        expand_inputs([tmp_path / "missing"])


def _req(base, path, method="GET", data=None, headers=None):
    req = urllib.request.Request(base + path, method=method, data=data, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"null")


def test_upload_and_analyse_input_folder(sample, tmp_path):
    out_root, inbox = tmp_path / "out", tmp_path / "inbox"
    inbox.mkdir()
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    env = dict(os.environ, FORGETRACE_OUT=str(out_root), FORGETRACE_INPUT=str(inbox))
    p = subprocess.Popen([sys.executable, "-m", "uvicorn", "forgetrace.api.app:app", "--port", str(port)],
                         cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(50):
            try:
                if _req(base, "/workspaces")[0] == 200:
                    break
            except OSError:
                time.sleep(0.2)
        ws = {w["name"]: w for w in _req(base, "/workspaces")[1]}
        assert ws["input"]["analysed"] is False and ws["input"]["runnable"] is True
        # empty folder cannot be analysed
        assert _req(base, "/runs", "POST", b'{"workspace":"input"}', {"Content-Type": "application/json"})[0] == 400
        # traversal / bad names rejected, nothing written outside the folder
        for bad in ("../x.log", "x.exe", ".hidden.log", "a/b.log", "README.md"):
            code, _ = _req(base, f"/inputs?filename={urllib.parse.quote(bad)}", "POST", b"data")
            assert code == 400, bad
        assert not (tmp_path / "x.log").exists()
        body = (sample["dir"] / "events.log").read_bytes()
        code, r = _req(base, "/inputs?filename=events.log", "POST", body, {"Content-Type": "application/octet-stream"})
        assert code == 200 and r["size"] == len(body) and (inbox / "events.log").read_bytes() == body
        assert _req(base, "/inputs?filename=events.log", "POST", b"x")[0] == 409  # no silent overwrite
        assert [f["name"] for f in _req(base, "/inputs")[1]["files"]] == ["events.log"]
        code, job = _req(base, "/runs", "POST", b'{"workspace":"input"}', {"Content-Type": "application/json"})
        assert code == 200 and job["state"] == "running"
        for _ in range(150):
            job = _req(base, "/runs/current")[1]
            if job["state"] != "running":
                break
            time.sleep(0.2)
        assert job["state"] == "done", job
        assert job["stats"]["incidents"] == 2
        code, incs = _req(base, "/incidents?ws=input")
        assert code == 200 and len(incs) == 2
        ev = _req(base, f"/incidents/{incs[0]['incident_id']}?ws=input")[1]["observed"]["events"][0]["event_id"]
        assert _req(base, f"/events/{ev}/raw?ws=input")[1]["verified"] is True
        ov = _req(base, "/overview?ws=input")[1]
        assert ov["funnel"]["incidents"] == 2 and ov["files"][0]["name"] == "events.log"
        assert len(_req(base, "/detections?ws=input")[1]) == sample["stats"]["detections"]
        assert _req(base, "/metrics?ws=input")[0] == 404  # no ground truth for uploaded data
        assert _req(base, "/inputs/events.log", "DELETE")[0] == 200 and not (inbox / "events.log").exists()
    finally:
        p.terminate()
        p.wait(5)
