"""Evidence retrieval (dossier §11 "Evidence retrieval").

Given an event_id: decode (file_id, byte_offset), seek in the immutable source file listed in
the ingest manifest, read one line (capped at 64 KB), recompute its SHA-256 and compare it with
the digest stored at ingest. Never fabricates: unknown IDs or unreadable files return
verified=False with a reason.
"""
from __future__ import annotations

import json
from pathlib import Path

import duckdb

from forgetrace.ingest.ingest import line_digest, split_event_id, strip_eol

CAP = 64 * 1024


def get_raw(event_id: int, out: Path, con: duckdb.DuckDBPyConnection | None = None) -> dict:
    file_id, offset = split_event_id(int(event_id))
    manifest = json.loads((out / "files.json").read_text())
    entry = next((f for f in manifest["files"] if f["file_id"] == file_id), None)
    res = {"event_id": int(event_id), "display_id": f"F{file_id:02d}:{offset:012d}", "file_id": file_id,
           "byte_offset": offset, "file": None, "line_no": None, "source_event_id": None,
           "raw": None, "stored_digest": None, "digest": None, "verified": False, "reason": None}
    if entry is None:
        res["reason"] = "unknown file_id"
        return res
    res["file"] = Path(entry["path"]).name
    own = con is None
    con = con or duckdb.connect(str(out / "forgetrace.duckdb"), read_only=True)
    try:
        row = con.execute("SELECT line_digest, line_no, source_event_id FROM events WHERE event_id = ?",
                          [int(event_id)]).fetchone()
        if row is None:
            row = con.execute("SELECT line_digest, line_no, NULL FROM parse_errors WHERE event_id = ?",
                              [int(event_id)]).fetchone()
    finally:
        if own:
            con.close()
    if row is None:
        res["reason"] = "event_id not found in events or parse_errors"
        return res
    res["stored_digest"], res["line_no"], res["source_event_id"] = row
    try:
        with open(entry["path"], "rb") as f:
            f.seek(offset)
            content = strip_eol(f.readline(CAP))
    except OSError as e:
        res["reason"] = f"source unreadable: {e}"
        return res
    res["raw"] = content.decode("utf-8", "replace")
    res["digest"] = line_digest(content)
    res["verified"] = res["digest"] == res["stored_digest"]
    res["reason"] = None if res["verified"] else "digest mismatch: source changed since ingest or line > 64 KB"
    return res
