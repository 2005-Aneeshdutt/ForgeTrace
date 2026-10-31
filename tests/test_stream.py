"""SC-4: streaming the dev sample in small batches (also while the file grows) ends with exactly the
events, detections and incidents of a single batch run, and records time to first incident."""
from __future__ import annotations

import json
import threading
import time

import duckdb

from forgetrace.stream import stream


def _events(out):
    con = duckdb.connect()
    rows = con.execute(f"SELECT event_id, line_no, line_digest FROM read_parquet('{out}/events/*.parquet') "
                       "ORDER BY event_id").fetchall()
    con.close()
    return rows


def _detections(out):
    con = duckdb.connect(str(out / "forgetrace.duckdb"), read_only=True)
    d = con.execute("SELECT detection_id, member_event_ids FROM detections ORDER BY detection_id").fetchall()
    con.close()
    return d


def test_stream_equals_batch_run(sample, tmp_path):
    out = tmp_path / "s"
    res = stream(sample["dir"] / "events.log", out, batch_bytes=3 << 20, workers=2)
    assert len(res["batches"]) >= 4
    assert _events(out) == _events(sample["out"])
    assert _detections(out) == _detections(sample["out"])
    norm = lambda p: json.dumps(json.loads(p.read_text()), sort_keys=True)  # noqa: E731
    assert norm(out / "incidents.json") == norm(sample["out"] / "incidents.json")
    assert res["first_incident_s"] is not None and res["first_incident_s"] <= res["wall_time_s"]
    assert [b["bytes_done"] for b in res["batches"]] == sorted(b["bytes_done"] for b in res["batches"])


def test_follow_growing_file(sample, tmp_path):
    src = (sample["dir"] / "events.log").read_bytes()
    live = tmp_path / "live.log"
    live.write_bytes(b"")

    def writer():  # an upload arriving in pieces, cut mid-line on purpose
        for i in range(0, len(src), 2_500_001):
            with open(live, "ab") as f:
                f.write(src[i:i + 2_500_001])
            time.sleep(0.3)

    th = threading.Thread(target=writer)
    th.start()
    out = tmp_path / "f"
    res = stream(live, out, batch_bytes=4 << 20, follow=True, idle_timeout=3.0, workers=2)
    th.join()
    assert res["ingest"]["events"] == sample["stats"]["ingest"]["events"]
    assert [r[1:] for r in _events(out)] == [r[1:] for r in _events(sample["out"])]  # same lines, digests
