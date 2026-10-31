"""Asset fixture access (dossier §13 identity-and-access context). Criticality comes from
hostname regexes in config/assets.yaml; absent fixture -> default criticality, flagged."""
from __future__ import annotations

import re
from functools import lru_cache

from forgetrace import config


@lru_cache(maxsize=1)
def _fixture() -> dict | None:
    return config.assets()


def fixture_present() -> bool:
    return _fixture() is not None


def default_criticality() -> float:
    fx = _fixture()
    return float(fx.get("default_criticality", 0.2)) if fx else 0.2


def critical_threshold() -> float:
    fx = _fixture()
    return float(fx.get("critical_threshold", 0.8)) if fx else 0.8


@lru_cache(maxsize=4096)
def criticality(host: str | None) -> float:
    fx = _fixture()
    if not host or not fx:
        return default_criticality()
    for r in fx.get("criticality", []):
        if re.search(r["pattern"], host):
            return float(r["criticality"])
    return default_criticality()


def asset_type(host: str | None) -> str | None:
    fx = _fixture()
    if not host or not fx:
        return None
    for r in fx.get("criticality", []):
        if re.search(r["pattern"], host):
            return r.get("type")
    return None
