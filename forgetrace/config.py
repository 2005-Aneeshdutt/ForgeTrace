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


@lru_cache(maxsize=None)
def field_aliases() -> dict:
    return load_yaml(CONFIG_DIR / "field_aliases.yaml")


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
