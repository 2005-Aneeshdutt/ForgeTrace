"""DuckDB catalog over the Parquet raw tier (dossier §10 'store', §11 memory budget)."""
from __future__ import annotations

from pathlib import Path

import duckdb


def connect(out: Path, read_only: bool = False) -> duckdb.DuckDBPyConnection:
    con = duckdb.connect(str(out / "forgetrace.duckdb"), read_only=read_only)
    if not read_only:
        con.execute("SET memory_limit='4GB'")
        con.execute("SET preserve_insertion_order=false")
    return con


def create_views(con: duckdb.DuckDBPyConnection, out: Path) -> None:
    ev = str(out / "events" / "*.parquet").replace("'", "''")
    pe = str(out / "parse_errors.parquet").replace("'", "''")
    con.execute(f"CREATE OR REPLACE VIEW events AS SELECT * FROM read_parquet('{ev}')")
    con.execute(f"CREATE OR REPLACE VIEW parse_errors AS SELECT * FROM read_parquet('{pe}')")
