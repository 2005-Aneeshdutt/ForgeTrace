"""Parallel byte-range ingest returns exactly the rows of a single sequential pass, for any range
size and worker count, and every event_id seeks back to its own raw line (PHASE2 SC-2 property)."""
from __future__ import annotations

import random

import duckdb

from forgetrace import store
from forgetrace.ingest.evidence import get_raw
from forgetrace.ingest.ingest import ingest, plan_ranges


def _rows(out):
    con = duckdb.connect()
    ev = con.execute(f"SELECT * FROM read_parquet('{out}/events/*.parquet') ORDER BY event_id").fetchall()
    er = con.execute(f"SELECT * FROM read_parquet('{out}/parse_errors/*.parquet') ORDER BY event_id").fetchall()
    return ev, er


def _messy(tmp_path):
    good = b'{"@timestamp":"2026-10-01T00:00:%02dZ","event":{"id":"e%d","action":"dns_query"},"host":{"name":"H1"}}'
    parts = []
    for i in range(400):
        k = i % 9
        if k == 0:
            parts.append(good % (i % 60, i) + b"\r\n")      # CRLF
        elif k == 1:
            parts.append(b"\n")                              # empty line
        elif k == 2:
            parts.append(b"garbage line %d\n" % i)           # parse error
        elif k == 3:
            parts.append(b"x" * 70_000 + b"\n")              # over max_line_bytes (64 KiB)
        else:
            parts.append(good % (i % 60, i) + b"\n")
    a = tmp_path / "a.log"
    a.write_bytes(b"".join(parts) + good % (1, 9999))      # no trailing newline
    b = tmp_path / "b.log"
    b.write_bytes(b"".join(parts[:50]))
    return [a, b]


def test_parallel_equals_sequential_on_messy_input(tmp_path):
    files = _messy(tmp_path)
    seq, par = tmp_path / "seq", tmp_path / "par"
    m1 = ingest(files, seq, workers=1, range_bytes=1 << 40)
    m2 = ingest(files, par, workers=4, range_bytes=50_000)   # dozens of ranges, many cut mid-file
    assert m2["parallel"]["ranges"] > 20 and m2["parallel"]["workers"] == 4
    assert m1["stats"] == m2["stats"] and m1["files"] == m2["files"]
    assert _rows(seq) == _rows(par)


def test_parallel_equals_sequential_on_dev_sample(sample, tmp_path):
    src = sample["dir"] / "events.log"
    seq, par = tmp_path / "seq", tmp_path / "par"
    ingest([src], seq, workers=1, range_bytes=1 << 40)
    ingest([src], par, workers=3, range_bytes=1 << 20)
    assert _rows(seq) == _rows(par)
    con = store.connect(par)
    store.create_views(con, par)
    ids = [r[0] for r in con.execute("SELECT event_id FROM events").fetchall()]
    for eid in random.Random(0).sample(ids, 200):
        r = get_raw(eid, par, con)
        assert r["verified"], r


def test_ranges_start_at_line_starts(tmp_path):
    f = tmp_path / "x.log"
    data = b"".join(b"line-%05d\n" % i for i in range(5000)) + b"tail-no-newline"
    f.write_bytes(data)
    rs = plan_ranges(f, len(data), 997)
    assert rs[0][0] == 0 and rs[-1][1] == len(data)
    assert all(a[1] == b[0] for a, b in zip(rs, rs[1:]))
    assert all(s == 0 or data[s - 1:s] == b"\n" for s, _ in rs)
