"""Streaming, parallel ingestion (dossier §11).

Why this exists: raw text is never held in bulk. Files are split into line-aligned byte ranges
that worker processes read line by line in binary mode; for every line we keep its starting byte
offset, 1-based line number and SHA-256 digest, normalise it, and append it to Arrow column
buffers flushed to Parquet every `batch_rows` rows. Memory is bounded by workers x batch size,
not by the file size.
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
    # Firewall/behavioural fields (DECISIONS D-67): copied or derived, never vendor verdicts.
    ("message", pa.string()), ("service", pa.string()), ("log_subtype", pa.string()),
    ("src_country", pa.string()), ("dst_country", pa.string()),
    ("src_subnet24", pa.string()), ("src_subnet16", pa.string()),
    ("domain_base", pa.string()), ("dns_label_max", pa.int32()), ("local_hour", pa.int8()),
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


RANGE_BYTES = 64 * 2**20   # unit of parallel work (dossier §11 step 2: byte-range planning)
WORKER_BATCH_ROWS = 50_000  # rows buffered per worker before a Parquet row group is written


def default_workers() -> int:
    """All cores but one (the parent hashes files and collects results). On an M2 Pro that is 9:
    6 performance + 4 efficiency cores; ranges are handed out dynamically, so faster cores
    simply take more of them."""
    env = os.environ.get("FORGETRACE_WORKERS")
    return max(1, int(env)) if env else max(1, (os.cpu_count() or 2) - 1)


def plan_ranges(path: Path, size: int, range_bytes: int = RANGE_BYTES) -> list[tuple[int, int]]:
    """Split a file into [start, end) byte ranges that each begin at a line start."""
    if size == 0:
        return []
    cuts = [0]
    with open(path, "rb") as f:
        pos = range_bytes
        while pos < size:
            f.seek(pos - 1)
            if f.read(1) != b"\n":
                f.readline()  # move to the start of the next line
            nxt = f.tell()
            if nxt >= size:
                break
            if nxt > cuts[-1]:
                cuts.append(nxt)
            pos = max(nxt, pos) + range_bytes
    cuts.append(size)
    return list(zip(cuts[:-1], cuts[1:]))


def _count_lines(job: tuple[str, int, int]) -> int:
    """Physical lines in [start, end): newline count, plus one for a final unterminated line."""
    path, start, end = job
    n, last = 0, b""
    with open(path, "rb") as f:
        f.seek(start)
        left = end - start
        while left > 0:
            chunk = f.read(min(8 * 2**20, left))
            if not chunk:
                break
            n += chunk.count(b"\n")
            last = chunk[-1:]
            left -= len(chunk)
    return n + (1 if last and last != b"\n" else 0)


def _ingest_range(job: dict) -> dict:
    """Parse one byte range into its own Parquet file (+ parse-error file). Runs in a worker process.
    Line numbers start at job['base_line'] + 1, so results are identical to a sequential pass."""
    file_id, start, end = job["file_id"], job["start"], job["end"]
    max_line, batch_rows, dataset = job["max_line"], job["batch_rows"], job["dataset"]
    names = SCHEMA.names
    stats = {"lines": 0, "events": 0, "errors": 0, "empty": 0}
    buf: dict[str, list] = {n: [] for n in names}
    errs: dict[str, list] = {n: [] for n in ERR_SCHEMA.names}
    writer = None
    ev_path = Path(job["events_path"])

    def flush():
        nonlocal buf, writer
        if not buf["event_id"]:
            return
        tbl = pa.Table.from_pydict(buf, schema=SCHEMA)
        if writer is None:
            writer = pq.ParquetWriter(ev_path, SCHEMA, compression="zstd")
        writer.write_table(tbl, row_group_size=128_000)
        buf = {n: [] for n in names}

    offset, line_no = start, job["base_line"]
    with open(job["path"], "rb") as f:
        f.seek(start)
        while offset < end:
            line = f.readline(max_line + 1)
            if not line:
                break
            lstart = offset
            offset += len(line)
            line_no += 1
            stats["lines"] += 1
            if len(line) > max_line and not line.endswith(b"\n"):
                rest = f.readline()  # consume remainder of an oversized line
                offset += len(rest)
                _err(errs, file_id, lstart, line_no, "line exceeds max_line_bytes", strip_eol(line))
                stats["errors"] += 1
                continue
            content = strip_eol(line)
            if not content.strip():
                stats["empty"] += 1
                continue
            eid = make_event_id(file_id, lstart)
            try:
                ev = parse_line(content)
            except ParseError as e:
                _err(errs, file_id, lstart, line_no, str(e), content)
                stats["errors"] += 1
                continue
            except Exception as e:  # defensive: never crash on one bad line
                _err(errs, file_id, lstart, line_no, f"unexpected: {type(e).__name__}: {e}", content)
                stats["errors"] += 1
                continue
            ev.update(event_id=eid, file_id=file_id, byte_offset=lstart, line_no=line_no,
                      line_digest=line_digest(content), dataset=dataset)
            for n in names:
                buf[n].append(ev.get(n))
            stats["events"] += 1
            if len(buf["event_id"]) >= batch_rows:
                flush()
    flush()
    if writer is not None:
        writer.close()
    if errs["event_id"]:
        pq.write_table(pa.Table.from_pydict(errs, schema=ERR_SCHEMA), job["errors_path"])
    stats["bytes"] = end - start
    stats["range"] = job["range_index"]
    return stats


def ingest(inputs: list[Path], out: Path, batch_rows: int = WORKER_BATCH_ROWS, progress=None,
           dataset: str | None = None, workers: int | None = None, range_bytes: int = RANGE_BYTES) -> dict:
    """Parallel byte-range ingest (dossier §11 steps 2-3; PHASE2 SC-2/SC-5 bounded memory).

    1. Plan ~64 MB ranges per file, each starting at a line boundary.
    2. Count newlines per range in parallel to give every range its first line number.
    3. Parse ranges in a process pool; each writes events/part-<file>-<range>.parquet and,
       if any, parse_errors/part-<file>-<range>.parquet. Memory per worker is bounded by
       `batch_rows`; the parent only holds per-range counters.
    4. Whole-file SHA-256 runs in a parent thread while workers parse.
    Output rows (event_id, byte_offset, line_no, digest, envelope) are identical to the Phase 1
    sequential reader for any worker count (tests/test_parallel_ingest.py).
    progress(bytes_done, bytes_total) is called as ranges finish.
    """
    from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
    import multiprocessing as mp

    out.mkdir(parents=True, exist_ok=True)
    ev_dir, err_dir = out / "events", out / "parse_errors"
    for d in (ev_dir, err_dir):
        d.mkdir(exist_ok=True)
        for old in d.glob("*.parquet"):
            old.unlink()
    legacy_err = out / "parse_errors.parquet"
    if legacy_err.exists():
        legacy_err.unlink()
    max_line = config.field_map()["max_line_bytes"]
    paths = sorted(Path(p).resolve() for p in inputs)
    sizes = [os.path.getsize(p) for p in paths]
    total_bytes = sum(sizes)
    n_workers = workers or default_workers()
    if total_bytes < 2 * range_bytes:
        n_workers = 1  # small inputs: process start-up would cost more than it saves

    ranges = []  # (file_id, path, start, end)
    for file_id, (path, size) in enumerate(zip(paths, sizes), start=1):
        for s, e in plan_ranges(path, size, range_bytes):
            ranges.append((file_id, path, s, e))

    hasher = ThreadPoolExecutor(max_workers=1)
    sha_futs = [hasher.submit(_sha256_file, p) for p in paths]
    pool = ProcessPoolExecutor(max_workers=n_workers, mp_context=mp.get_context("spawn")) if n_workers > 1 else None
    mapper = pool.map if pool else map
    counts = list(mapper(_count_lines, [(str(p), s, e) for _, p, s, e in ranges]))
    jobs, base = [], {}
    for i, ((file_id, path, s, e), c) in enumerate(zip(ranges, counts)):
        jobs.append({"range_index": i, "file_id": file_id, "path": str(path), "start": s, "end": e,
                     "base_line": base.get(file_id, 0), "max_line": max_line, "batch_rows": batch_rows,
                     "dataset": dataset,
                     "events_path": str(ev_dir / f"part-{file_id:03d}-{i:05d}.parquet"),
                     "errors_path": str(err_dir / f"part-{file_id:03d}-{i:05d}.parquet")})
        base[file_id] = base.get(file_id, 0) + c
    stats = {"lines": 0, "events": 0, "errors": 0, "empty": 0}
    done = 0
    try:
        results = (pool.submit(_ingest_range, j) for j in jobs) if pool else None
        if pool:
            from concurrent.futures import as_completed
            futs = list(results)
            for fut in as_completed(futs):
                r = fut.result()
                for k in stats:
                    stats[k] += r[k]
                done += r["bytes"]
                if progress:
                    progress(done, total_bytes)
        else:
            for j in jobs:
                r = _ingest_range(j)
                for k in stats:
                    stats[k] += r[k]
                done += r["bytes"]
                if progress:
                    progress(done, total_bytes)
    finally:
        if pool:
            pool.shutdown()
    if not any(err_dir.glob("*.parquet")):
        pq.write_table(pa.Table.from_pydict({n: [] for n in ERR_SCHEMA.names}, schema=ERR_SCHEMA),
                       err_dir / "part-none.parquet")
    files = []
    for file_id, (path, fut) in enumerate(zip(paths, sha_futs), start=1):
        st = os.stat(path)
        files.append({"file_id": file_id, "path": str(path), "size": st.st_size, "mtime": st.st_mtime,
                      "sha256": fut.result()})
    hasher.shutdown()
    if progress:
        progress(total_bytes, total_bytes)
    manifest = {"files": files, "stats": stats, "parallel": {"workers": n_workers, "ranges": len(jobs),
                                                             "range_bytes": range_bytes},
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


def ingest_batch(path: Path, file_id: int, start: int, end: int, base_line: int, out: Path, pool, batch: int,
                 dataset: str | None = None, range_bytes: int = RANGE_BYTES) -> dict:
    """Ingest one line-aligned byte range [start, end) of a file into an existing workspace (streaming,
    forgetrace/stream.py). Same per-range workers as `ingest`; parts are named by batch so earlier
    batches are never rewritten. Line numbers continue from `base_line`."""
    ev_dir, err_dir = out / "events", out / "parse_errors"
    ev_dir.mkdir(parents=True, exist_ok=True)
    err_dir.mkdir(exist_ok=True)
    max_line = config.field_map()["max_line_bytes"]
    sub = [(s + start, e + start) for s, e in _plan_slice(path, start, end, range_bytes)]
    mapper = pool.map if pool else map
    counts = list(mapper(_count_lines, [(str(path), s, e) for s, e in sub]))
    jobs, base = [], base_line
    for i, ((s, e), c) in enumerate(zip(sub, counts)):
        jobs.append({"range_index": i, "file_id": file_id, "path": str(path), "start": s, "end": e,
                     "base_line": base, "max_line": max_line, "batch_rows": WORKER_BATCH_ROWS, "dataset": dataset,
                     "events_path": str(ev_dir / f"part-{file_id:03d}-b{batch:04d}-{i:05d}.parquet"),
                     "errors_path": str(err_dir / f"part-{file_id:03d}-b{batch:04d}-{i:05d}.parquet")})
        base += c
    stats = {"lines": 0, "events": 0, "errors": 0, "empty": 0}
    for r in mapper(_ingest_range, jobs):
        for k in stats:
            stats[k] += r[k]
    if not any(err_dir.glob("*.parquet")):
        pq.write_table(pa.Table.from_pydict({n: [] for n in ERR_SCHEMA.names}, schema=ERR_SCHEMA),
                       err_dir / "part-none.parquet")
    stats["ranges"] = len(jobs)
    return stats


def _plan_slice(path: Path, start: int, end: int, range_bytes: int) -> list[tuple[int, int]]:
    """Line-aligned sub-ranges of [start, end), relative to start (start and end are line starts)."""
    cuts = [0]
    size = end - start
    with open(path, "rb") as f:
        pos = range_bytes
        while pos < size:
            f.seek(start + pos - 1)
            if f.read(1) != b"\n":
                f.readline()
            nxt = f.tell() - start
            if nxt >= size:
                break
            if nxt > cuts[-1]:
                cuts.append(nxt)
            pos = max(nxt, pos) + range_bytes
    cuts.append(size)
    return list(zip(cuts[:-1], cuts[1:]))
