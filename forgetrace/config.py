"""Config loading and hashing (dossier §10: every stage keyed by a config hash)."""
from __future__ import annotations

import hashlib
from functools import lru_cache
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONFIG_DIR = ROOT / "config"
CODE_VERSION = "phase1-0.1.0"


def load_yaml(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


@lru_cache(maxsize=None)
def field_map() -> dict:
    return load_yaml(CONFIG_DIR / "field_map.yaml")


SCHEMA_DIR = CONFIG_DIR / "schemas"


@lru_cache(maxsize=None)
def field_aliases() -> dict:
    """field_aliases.yaml plus accepted schema overlays in config/schemas/*.yaml (D-119). Overlay names
    are appended after the built-in ones, so an existing mapping always wins; with no overlay files the
    result is exactly field_aliases.yaml."""
    al = load_yaml(CONFIG_DIR / "field_aliases.yaml")
    for p in sorted(SCHEMA_DIR.glob("*.yaml")) if SCHEMA_DIR.is_dir() else ():
        ov = load_yaml(p)
        for canon, names in (ov.get("fields") or {}).items():
            if canon in al["fields"]:
                al["fields"][canon] = al["fields"][canon] + [n for n in names if n not in al["fields"][canon]]
        al["timestamp"] = al["timestamp"] + [n for n in ov.get("timestamp") or [] if n not in al["timestamp"]]
        for canon, ws in (ov.get("outcome_words") or {}).items():
            if canon in al.get("outcome_words", {}):
                al["outcome_words"][canon] = al["outcome_words"][canon] + list(ws)
    return al


@lru_cache(maxsize=None)
def site() -> dict:
    return load_yaml(CONFIG_DIR / "site.yaml")


@lru_cache(maxsize=None)
def correlation() -> dict:
    return load_yaml(CONFIG_DIR / "correlation.yml")


@lru_cache(maxsize=None)
def attack() -> dict:
    return load_yaml(CONFIG_DIR / "attack.yml")


def assets(path: Path | None = None) -> dict | None:
    p = path or CONFIG_DIR / "assets.yaml"
    return load_yaml(p) if p.exists() else None


def config_hash() -> str:
    """SHA-256 over every config file, sorted by path (determinism + provenance)."""
    h = hashlib.sha256()
    for p in sorted(CONFIG_DIR.rglob("*")):
        if p.is_file() and p.suffix in (".yaml", ".yml"):
            h.update(str(p.relative_to(CONFIG_DIR)).encode())
            h.update(p.read_bytes())
    return h.hexdigest()
