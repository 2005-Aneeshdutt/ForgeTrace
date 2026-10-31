"""Streaming ingestion (dossier §11).

Why this exists: raw text is never held in bulk. Each file is read line by line in binary
mode; for every line we keep its starting byte offset, 1-based line number and SHA-256
digest, normalise it, and append it to Arrow column buffers flushed to Parquet every
`batch_rows` rows. Memory is bounded by the batch size, not by the file size.
Phase 1 is single-process; byte-range parallelism (§11 steps 2-3) is deferred.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from forgetrace import config
from forgetrace.ingest.parsers import ParseError, parse_line

OFFSET_MASK = (1 << 48) - 1

SCHEMA = pa.schema([
    ("event_id", pa.int64()), ("file_id", pa.int16()), ("byte_offset", pa.int64()), ("line_no", pa.int64()),
    ("line_digest", pa.string()), ("source_event_id", pa.string()),
    ("ts", pa.timestamp("us")), ("source_type", pa.string()), ("raw_format", pa.string()),
    ("event_type", pa.string()), ("action", pa.string()), ("outcome", pa.string()),
    ("user", pa.string()), ("user_domain", pa.string()), ("target_user", pa.string()),
    ("host", pa.string()), ("host_ip", pa.string()),
    ("src_ip", pa.string()), ("dst_ip", pa.string()), ("src_is_external", pa.bool_()), ("dst_is_external", pa.bool_()),
    ("src_port", pa.int32()), ("dst_port", pa.int32()), ("protocol", pa.string()),
    ("process", pa.string()), ("parent_process", pa.string()), ("pid", pa.int64()), ("command_line", pa.string()),
    ("logon_id", pa.string()), ("logon_type", pa.string()),
    ("domain_name", pa.string()), ("url", pa.string()), ("file_path", pa.string()), ("file_hash", pa.string()),
    ("registry_path", pa.string()), ("registry_value", pa.string()), ("group_name", pa.string()),
    ("bytes_out", pa.int64()), ("bytes_in", pa.int64()), ("vendor_event_code", pa.string()),
    ("dataset", pa.string()),
])
ERR_SCHEMA = pa.schema([("file_id", pa.int16()), ("byte_offset", pa.int64()), ("line_no", pa.int64()),
                        ("event_id", pa.int64()), ("error", pa.string()), ("preview", pa.string()),
                        ("line_digest", pa.string())])


def make_event_id(file_id: int, byte_offset: int) -> int:
    if not (0 <= byte_offset <= OFFSET_MASK) or not (0 < file_id < 2**15):
        raise ValueError("event_id out of range")
    return (file_id << 48) | byte_offset


def split_event_id(event_id: int) -> tuple[int, int]:
    return event_id >> 48, event_id & OFFSET_MASK


def strip_eol(line: bytes) -> bytes:
    if line.endswith(b"\n"):
        line = line[:-1]
    if line.endswith(b"\r"):
        line = line[:-1]
    return line


def line_digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8 * 1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def ingest(inputs: list[Path], out: Path, batch_rows: int = 200_000, progress=None, dataset: str | None = None) -> dict:
    """progress(bytes_done, bytes_total) is called about every 20k lines (optional); `dataset`
    is stamped on every event (PHASE2 frozen Event interface)."""
    out.mkdir(parents=True, exist_ok=True)
    ev_dir = out / "events"
    ev_dir.mkdir(exist_ok=True)
    for old in ev_dir.glob("*.parquet"):
        old.unlink()
    max_line = config.field_map()["max_line_bytes"]
    names = SCHEMA.names
    files, stats = [], {"lines": 0, "events": 0, "errors": 0, "empty": 0}
    buf: dict[str, list] = {n: [] for n in names}
    errs: dict[str, list] = {n: [] for n in ERR_SCHEMA.names}
    part = 0

    def flush():
        nonlocal part, buf
        if not buf["event_id"]:
            return
        tbl = pa.Table.from_pydict(buf, schema=SCHEMA)
        pq.write_table(tbl, ev_dir / f"part-{part:05d}.parquet", compression="zstd", row_group_size=128_000)
        part += 1
        buf = {n: [] for n in names}

    paths = sorted(Path(p).resolve() for p in inputs)
    total_bytes, done_before = sum(os.path.getsize(p) for p in paths), 0
    for file_id, path in enumerate(paths, start=1):
        st = os.stat(path)
        files.append({"file_id": file_id, "path": str(path), "size": st.st_size, "mtime": st.st_mtime,
                      "sha256": _sha256_file(path)})
        offset, line_no = 0, 0
        with open(path, "rb") as f:
            while True:
                line = f.readline(max_line + 1)
                if not line:
                    break
                start = offset
                offset += len(line)
                line_no += 1
                stats["lines"] += 1
                if progress and stats["lines"] % 20_000 == 0:
                    progress(done_before + offset, total_bytes)
                if len(line) > max_line and not line.endswith(b"\n"):
                    rest = f.readline()  # consume remainder of an oversized line
                    offset += len(rest)
                    content = strip_eol(line)
                    _err(errs, file_id, start, line_no, "line exceeds max_line_bytes", content)
                    stats["errors"] += 1
                    continue
                content = strip_eol(line)
                if not content.strip():
                    stats["empty"] += 1
                    continue
                eid = make_event_id(file_id, start)
                try:
                    ev = parse_line(content)
                except ParseError as e:
                    _err(errs, file_id, start, line_no, str(e), content)
                    stats["errors"] += 1
                    continue
                except Exception as e:  # defensive: never crash on one bad line
                    _err(errs, file_id, start, line_no, f"unexpected: {type(e).__name__}: {e}", content)
                    stats["errors"] += 1
                    continue
                ev.update(event_id=eid, file_id=file_id, byte_offset=start, line_no=line_no,
                          line_digest=line_digest(content), dataset=dataset)
                for n in names:
                    buf[n].append(ev.get(n))
                stats["events"] += 1
                if len(buf["event_id"]) >= batch_rows:
                    flush()
        done_before += st.st_size
    flush()
    if progress:
        progress(total_bytes, total_bytes)
    pq.write_table(pa.Table.from_pydict(errs, schema=ERR_SCHEMA), out / "parse_errors.parquet")
    manifest = {"files": files, "stats": stats,
                "manifest_digest": hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()}
    (out / "files.json").write_text(json.dumps(manifest, indent=1))
    return manifest


def _err(errs, file_id, start, line_no, msg, content):
    errs["file_id"].append(file_id)
    errs["byte_offset"].append(start)
    errs["line_no"].append(line_no)
    errs["event_id"].append(make_event_id(file_id, start))
    errs["error"].append(msg[:500])
    errs["preview"].append(content[:200].decode("utf-8", "replace"))
    errs["line_digest"].append(line_digest(content))
