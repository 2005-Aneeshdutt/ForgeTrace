"""Detector router: which rules can run on this data, with what site values (PHASE2 FU-1).

Why this exists: an unseen dataset may lack fields a rule needs (no process telemetry, no auth outcome)
or the site facts a rule refers to (home countries). Running such a rule silently finds nothing and
looks like "no attack"; the router instead measures a capability profile (fill rate of every envelope
field, the event and source types present), enables only rules whose inputs exist, resolves
"@site.<key>" values from config/site.yaml (learning "auto" ones from the data), and records every
disabled rule with its reason as a blind spot in a RunPlan (forgetrace/models.py), so a human sees
exactly what could and could not be detected. Deterministic; no LLM.
"""
from __future__ import annotations

import copy
from typing import Any

import duckdb

from forgetrace import config
from forgetrace.models import DisabledDetector, RunPlan
from forgetrace.rules.engine import ALLOWED_FIELDS, Rule, _walk_fields


def capability_profile(con: duckdb.DuckDBPyConnection) -> tuple[dict[str, float], set[str], set[str], int]:
    cols = [r[0] for r in con.execute("DESCRIBE events").fetchall() if r[0] in ALLOWED_FIELDS]
    n = con.execute("SELECT count(*) FROM events").fetchone()[0]
    if not n:
        return {c: 0.0 for c in cols}, set(), set(), 0
    row = con.execute("SELECT " + ", ".join(f'count("{c}")' for c in cols) + " FROM events").fetchone()
    fill = {c: round(v / n, 6) for c, v in zip(cols, row)}
    etypes = {r[0] for r in con.execute("SELECT DISTINCT event_type FROM events WHERE event_type IS NOT NULL").fetchall()}
    stypes = {r[0] for r in con.execute("SELECT DISTINCT source_type FROM events WHERE source_type IS NOT NULL").fetchall()}
    return fill, etypes, stypes, n


def site_values(con: duckdb.DuckDBPyConnection) -> dict[str, Any]:
    """config/site.yaml with "auto" entries learned from the data (shown in the RunPlan for review)."""
    site = copy.deepcopy(config.site())
    if site.get("home_countries") == "auto":
        share = float(site.get("home_countries_share", 0.8))
        rows = con.execute("""SELECT src_country, count(*) FROM events
                              WHERE event_type IN ('auth_success', 'vpn_login') AND src_country IS NOT NULL
                              GROUP BY 1 ORDER BY 2 DESC, 1""").fetchall()
        total = sum(c for _, c in rows)
        learned, acc = [], 0
        if total >= int(site.get("home_countries_min_logins", 50)):
            for country, c in rows:
                learned.append(country)
                acc += c
                if acc / total >= share:
                    break
        # the label a source uses for private (internal) addresses counts as home
        learned += [r[0] for r in con.execute("""SELECT DISTINCT src_country FROM events
                     WHERE src_is_external = false AND src_country IS NOT NULL""").fetchall() if r[0] not in learned]
        site["home_countries"] = learned if total >= int(site.get("home_countries_min_logins", 50)) else []
        site["_home_countries_learned_from"] = {"successful_logins": total, "share": share}
    return site


def _resolve(node: Any, site: dict, missing: list[str]) -> Any:
    if isinstance(node, dict):
        return {k: _resolve(v, site, missing) for k, v in node.items()}
    if isinstance(node, list):
        return [_resolve(v, site, missing) for v in node]
    if isinstance(node, str) and node.startswith("@site."):
        cur: Any = site
        for part in node[6:].split("."):
            cur = cur.get(part) if isinstance(cur, dict) else None
        if cur in (None, "", [], "auto"):
            missing.append(node)
        return cur
    return node


def required_fields(r: Rule) -> set[str]:
    """Fields a rule cannot work without (filter, grouping, threshold, follower, first-seen keys).
    aggregate_by is display grouping only and may be empty."""
    out: set[str] = set(r.group_by)
    _walk_fields(r.filter, out)
    if r.threshold:
        out |= {f for f in (r.threshold.distinct, r.threshold.sum) if f}
    if r.followed_by:
        _walk_fields(r.followed_by.filter, out)
        out |= set(r.followed_by.join_on) | set(r.followed_by.link) | set(r.followed_by.link.values())
    if r.first_seen:
        out |= set(r.first_seen.keys)
    return out


def _type_needs(node: Any, field: str, out: set) -> None:
    """Sets of acceptable values for `field` that a rule requires via eq/in conditions (outside `not`);
    an `any` contributes the union of its branches."""
    if not isinstance(node, dict) or "not" in node:
        return
    if node.get("field") == field and node.get("op") in ("eq", "in"):
        v = node.get("value")
        out.add(frozenset([v] if node["op"] == "eq" else v))
    for c in node.get("all", []):
        _type_needs(c, field, out)
    if node.get("any"):
        union: set = set()
        for c in node["any"]:
            sub: set = set()
            _type_needs(c, field, sub)
            for alts in sub:
                union |= alts
        if union:
            out.add(frozenset(union))


def plan(con: duckdb.DuckDBPyConnection, rules: list[Rule], dataset: str = "",
         site_override: dict | None = None) -> tuple[list[Rule], RunPlan, dict]:
    fill, etypes, stypes, n = capability_profile(con)
    site = site_values(con)
    if site_override:
        site.update(site_override)
    enabled, disabled, blind = [], [], []
    for r in rules:
        missing: list[str] = []
        fields = sorted(required_fields(r))
        absent = [f for f in fields if fill.get(f, 0.0) == 0.0]
        missing += [f"field:{f}" for f in absent]
        for fld, present in (("event_type", etypes), ("source_type", stypes)):
            needs: set = set()
            _type_needs(r.filter, fld, needs)
            for alts in needs:
                if not (set(alts) & present):
                    missing.append(f"{fld}:{'|'.join(sorted(map(str, alts)))}")
        resolved_filter = _resolve(r.filter, site, missing)
        if missing:
            disabled.append(DisabledDetector(detector=f"rule:{r.id}", missing=sorted(set(missing))))
            blind.append(f"{r.id} {r.technique} ({r.title}): not evaluated - missing {', '.join(sorted(set(missing)))}")
            continue
        enabled.append(r.model_copy(update={"filter": resolved_filter}) if resolved_filter != r.filter else r)
    rp = RunPlan(dataset=dataset or "", capability_profile={k: min(1.0, v) for k, v in fill.items()},
                 enabled=[f"rule:{r.id}" for r in enabled], disabled=disabled, blind_spots=blind)
    info = {"events": n, "event_types": sorted(etypes), "source_types": sorted(stypes),
            "site": {k: v for k, v in site.items()}}
    return enabled, rp, info
