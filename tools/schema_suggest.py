#!/usr/bin/env python3
"""Suggest field mappings for a log schema the alias table does not cover (DECISIONS D-119).

Why this exists: an unseen dataset is parsed through config/field_aliases.yaml (D-79), but a new standard or
vendor can name fields the alias lists do not know (actorAddress, evtTime, ...), and those fields are then
ignored. This tool drafts the missing config; it never runs inside the pipeline.

  suggest FILE   profile a sample of FILE: every raw key, its fill rate and value shapes, and whether the
                 alias table already maps it. Unmapped keys are sent to the LLM (config/llm.yml, OpenRouter)
                 as key names, shapes and masked examples: no IP, host, user or other raw value leaves the
                 machine, except short enum words for low-cardinality keys (e.g. ALLOW / DENY) so outcome
                 words can be proposed. Every proposed mapping is then checked by code: the target must be an
                 envelope field, the key must exist and must not be a vendor verdict (never_map), and the
                 sampled values must fit the target (IPs parse as IPs, ports and byte counts as integers,
                 timestamps as timestamps, >= 90% of non-empty values). The sample is re-parsed with the
                 proposal to show before/after field fill rates. Written to data/schema_proposals/<fp>.yaml.
  accept FP      copy proposal FP to config/schemas/<fp>.yaml, which the parser loads as extra aliases.

Overlays only append alias names after the built-in ones and apply only to lines without a named profile
(generic_*), so already-mapped fields and named formats (fortigate_kv, ECS, CEF) parse exactly as before,
and nothing already ingested is touched. Without an API key or with --offline the tool still profiles the
file and lists the unmapped keys. Replies are cached and spend-capped like the narrative (D-87).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from collections import Counter
from datetime import datetime
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from forgetrace import config  # noqa: E402
from forgetrace.ingest import parsers as P  # noqa: E402
from forgetrace.ingest.ingest import strip_eol  # noqa: E402

PROMPT_VERSION = "schema-2"
PROPOSAL_DIR = ROOT / "data" / "schema_proposals"
MIN_FIT = 0.9
IP_FIELDS = {"src_ip", "dst_ip", "host_ip"}
PORT_FIELDS = {"src_port", "dst_port"}
ENUM_RE = re.compile(r"[A-Za-z][A-Za-z_\- ]{0,19}")
SYSTEM = ("You map log field names to a fixed set of canonical security-log fields. You see only key names, "
          "value shapes (ip, int, ts, hex, text, ...) and, for low-cardinality keys, their enum values. Map a key "
          "only when you are confident of its meaning. Direction matters: src_ip / src_port are the side that "
          "starts the connection or acts (actor, client, initiator, source); dst_ip / dst_port are the side being "
          "reached (peer, server, target, destination). Never map vendor verdicts (threat names, severities, risk "
          "scores, rule names, labels). Reply with JSON: {\"fields\": {canonical_field: [key, ...]}, "
          "\"timestamp\": [key, ...] (only if the event time is not already found), \"outcome_words\": "
          "{\"success\": [word], \"failure\": [word]} (only words from enum_values), \"important_unmapped\": "
          "[{\"key\": str, \"reason\": str}] (keys with security value that fit no canonical field)}.")


def _reset_caches() -> None:
    config.field_aliases.cache_clear()
    P._alias_index.cache_clear()
    P._message_patterns.cache_clear()


def _shape(v) -> str:
    s = str(v).strip()
    if P.norm_ip(s):
        return "ip"
    if re.fullmatch(r"-?\d+", s):
        return "int"
    if re.fullmatch(r"-?\d+\.\d+", s):
        return "float"
    if re.fullmatch(r"[0-9a-fA-F]{16,}", s):
        return "hex"
    if "://" in s:
        return "url"
    if re.fullmatch(r"[\w.+-]+@[\w-]+\.[\w.-]+", s):
        return "email"
    try:
        P.parse_any_ts(s)
        return "ts"
    except (P.ParseError, ValueError, OverflowError):
        pass
    if "/" in s or "\\" in s:
        return "path"
    return "text" if " " in s else "token"


def _known() -> tuple[set, frozenset]:
    al = config.field_aliases()
    fields, never, ts, _ = P._alias_index()
    names = {n for ns in fields.values() for n in ns} | set(ts)
    for k in ("date_fields", "time_fields", "tz_fields"):
        names |= {P._norm_key(x) for x in al.get(k, [])}
    return names, never


def _lines(path: Path, sample: int):
    hdr = None
    with open(path, "rb") as f:
        for i, line in enumerate(f):
            if i >= sample + 1:
                break
            line = strip_eol(line)
            if i == 0:
                hdr = P.csv_header(line)
                if hdr:
                    continue
            if line.strip():
                yield line, hdr


def profile(path: Path, sample: int = 2000) -> dict:
    """Raw keys of the sampled lines with fill, shapes and whether the alias table maps them."""
    names, never = _known()
    keys: dict[str, dict] = {}
    fmts, n, unreadable = Counter(), 0, 0
    for line, hdr in _lines(path, sample):
        try:
            fmt, raw = P._profile_and_raw(line, hdr)
        except P.ParseError:
            unreadable += 1
            continue
        n += 1
        fmts[fmt] += 1
        for k, v in raw.items():
            if v in (None, "") or isinstance(v, dict):
                continue
            v = v[0] if isinstance(v, list) and v else v
            k_ = keys.setdefault(k, {"n": 0, "shapes": Counter(), "values": Counter()})
            k_["n"] += 1
            k_["shapes"][_shape(v)] += 1
            if len(k_["values"]) <= 50:
                k_["values"][str(v)] += 1
    out = []
    for k, d in sorted(keys.items()):
        nk, lk = P._norm_key(k), P._norm_key(k.rsplit(".", 1)[-1])
        status = "vendor_verdict" if (nk in never or lk in never) else "mapped" if (nk in names or lk in names) else "unmapped"
        enum = sorted(d["values"]) if len(d["values"]) <= 12 and all(ENUM_RE.fullmatch(x) for x in d["values"]) else None
        out.append({"key": k, "status": status, "fill": round(d["n"] / max(n, 1), 3), "distinct": len(d["values"]),
                    "shapes": dict(d["shapes"].most_common(3)), "enum_values": enum})
    fp = hashlib.sha256(json.dumps(sorted(P._norm_key(k["key"]) for k in out)).encode()).hexdigest()[:12]
    return {"file": path.name, "fingerprint": fp, "lines": n, "unreadable": unreadable, "formats": dict(fmts),
            "keys": out}


def _payload(prof: dict, before: dict) -> dict:
    return {"canonical_fields": sorted(config.field_aliases()["fields"]),
            "timestamp_found": before["parsed"] > 0,
            "unmapped_keys": [{k: x[k] for k in ("key", "fill", "distinct", "shapes", "enum_values")}
                              for x in prof["keys"] if x["status"] == "unmapped"]}


def ask_llm(payload: dict, transport=None) -> tuple[dict | None, str]:
    """(reply, status) through the narrative's config, key lookup, cache and spend caps."""
    from forgetrace.report.llm import _dotenv, _ledger_total, llm_config

    cfg = llm_config()
    if not cfg.get("enabled"):
        return None, "LLM disabled in config/llm.yml"
    key = hashlib.sha256(json.dumps([payload, PROMPT_VERSION, cfg["model"]], sort_keys=True).encode()).hexdigest()
    cache = ROOT / cfg["cache_dir"] / f"schema-{key}.json"
    if cache.exists():
        return json.loads(cache.read_text()), "cached"
    api_key = os.environ.get(cfg["api_key_env"]) or _dotenv(cfg["api_key_env"])
    if not api_key and transport is None:
        return None, f"set {cfg['api_key_env']} to get LLM suggestions"
    ledger = ROOT / cfg["ledger"]
    total, _ = _ledger_total(ledger, None)
    if total >= cfg["caps_usd"]["lifetime"]:
        return None, f"spend cap reached (lifetime ${total:.3f})"
    from tools.llm.openrouter import LLMError, chat

    send = transport or (lambda msgs: chat(cfg["endpoint"], api_key, cfg["model"], msgs, cfg["temperature"],
                                           cfg["max_tokens"], cfg["timeout_s"]))
    msgs = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": json.dumps(payload)}]
    try:
        r = send(msgs)
    except LLMError as e:
        return None, str(e)
    u = r.get("usage", {})
    cost = u.get("cost")
    if cost is None:
        p = cfg["price_per_million_usd"]
        cost = (u.get("prompt_tokens", 0) * p["input"] + u.get("completion_tokens", 0) * p["output"]) / 1e6
    ledger.parent.mkdir(parents=True, exist_ok=True)
    with open(ledger, "a") as f:
        f.write(json.dumps({"at": datetime.now().astimezone().isoformat(timespec="seconds"), "run_id": None,
                            "model": r.get("model"), "facts": "schema", "prompt_tokens": u.get("prompt_tokens"),
                            "completion_tokens": u.get("completion_tokens"), "cost_usd": round(float(cost), 6)}) + "\n")
    try:
        reply = json.loads(r["content"])
    except ValueError:
        return None, "reply is not JSON"
    if not isinstance(reply, dict):
        return None, "reply is not a JSON object"
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps(reply))
    return reply, "ok"


def _fit(target: str, shapes: dict) -> float:
    tot = sum(shapes.values()) or 1
    if target in IP_FIELDS:
        return shapes.get("ip", 0) / tot
    if target in P._INT_FIELDS:
        return shapes.get("int", 0) / tot
    if target == "timestamp":
        return (shapes.get("ts", 0) + shapes.get("int", 0) + shapes.get("float", 0)) / tot
    return 1.0


def _side(key: str) -> str | None:
    """'src' / 'dst' when the key name carries only that side's hint words (config direction_hints)."""
    hints = config.field_aliases().get("direction_hints") or {}
    words = re.findall(r"[a-z]+", re.sub(r"([a-z])([A-Z])", r"\1 \2", key).lower())
    found = {side for side, ws in hints.items() for w in words if w in ws}
    return found.pop() if len(found) == 1 else None


def validate(reply: dict, prof: dict, path: Path) -> tuple[dict, list[str]]:
    """Keep only mappings that pass the deterministic checks; return (overlay, rejection reasons)."""
    by_key = {k["key"]: k for k in prof["keys"]}
    canon = set(config.field_aliases()["fields"])
    full_shapes = _full_shapes(path, prof)
    overlay: dict = {"fields": {}, "timestamp": [], "outcome_words": {}, "important_unmapped": []}
    rejected, used = [], set()

    def check(target: str, key) -> str | None:
        if not isinstance(key, str) or key not in by_key:
            return f"{key!r} -> {target}: key not in the sample"
        k = by_key[key]
        if k["status"] == "vendor_verdict":
            return f"{key} -> {target}: vendor verdict field (never_map)"
        if k["status"] == "mapped":
            return f"{key} -> {target}: already mapped by field_aliases.yaml"
        if key in used:
            return f"{key} -> {target}: key already mapped to another field"
        side = _side(key)
        if target[:4] in ("src_", "dst_") and side and side != target[:3]:
            return f"{key} -> {target}: the name suggests the {side} side"
        f = _fit(target, full_shapes.get(key, k["shapes"]))
        if f < MIN_FIT:
            return f"{key} -> {target}: only {f:.0%} of values fit {target}"
        if target in PORT_FIELDS and not all(0 <= int(v) <= 65535 for v in _ints(path, prof, key)):
            return f"{key} -> {target}: values outside 0..65535"
        return None

    for target, keys in (reply.get("fields") or {}).items():
        for key in keys if isinstance(keys, list) else [keys]:
            why = f"{key!r} -> {target}: not an envelope field" if target not in canon else check(target, key)
            if why and "the name suggests" in why:  # direction swapped: try the other side's field once
                other = ("dst_" if target.startswith("src_") else "src_") + target[4:]
                if other in canon and not check(other, key):
                    rejected.append(f"{why}; moved to {other}")
                    target, why = other, None
            if why:
                rejected.append(why)
            else:
                used.add(key)
                overlay["fields"].setdefault(target, []).append(key)
    for key in reply.get("timestamp") or []:
        why = check("timestamp", key)
        if why:
            rejected.append(why)
        else:
            used.add(key)
            overlay["timestamp"].append(key)
    seen = {str(v).lower() for k in prof["keys"] if k["enum_values"] for v in k["enum_values"]}
    for canon_o, words in (reply.get("outcome_words") or {}).items():
        if canon_o not in ("success", "failure") or not isinstance(words, list):
            rejected.append(f"outcome_words.{canon_o}: not success/failure")
            continue
        for w in words:
            if str(w).lower() in seen:
                overlay["outcome_words"].setdefault(canon_o, []).append(str(w).lower())
            else:
                rejected.append(f"outcome word {w!r}: not observed in the sample")
    for x in reply.get("important_unmapped") or []:
        if isinstance(x, dict) and x.get("key") in by_key and by_key[x["key"]]["status"] == "unmapped":
            overlay["important_unmapped"].append({"key": x["key"], "reason": str(x.get("reason", ""))[:200]})
    return overlay, rejected


def _full_shapes(path: Path, prof: dict) -> dict:
    """Shapes over every sampled value of unmapped keys (profile shapes keep only the top 3)."""
    want = {k["key"] for k in prof["keys"] if k["status"] == "unmapped"}
    out: dict[str, Counter] = {}
    for line, hdr in _lines(path, prof["lines"] + prof["unreadable"]):
        try:
            _, raw = P._profile_and_raw(line, hdr)
        except P.ParseError:
            continue
        for k in want & raw.keys():
            v = raw[k]
            if v not in (None, "") and not isinstance(v, dict):
                out.setdefault(k, Counter())[_shape(v[0] if isinstance(v, list) and v else v)] += 1
    return {k: dict(c) for k, c in out.items()}


def _ints(path: Path, prof: dict, key: str):
    for line, hdr in _lines(path, prof["lines"] + prof["unreadable"]):
        try:
            _, raw = P._profile_and_raw(line, hdr)
        except P.ParseError:
            continue
        if re.fullmatch(r"-?\d+", str(raw.get(key, "")).strip()):
            yield int(raw[key])


def fill_rates(path: Path, sample: int, overlay: dict | None = None) -> dict:
    """Parse the sample (optionally with `overlay` added to the accepted ones) and count field fill."""
    tmp = None
    if overlay is not None:
        tmp = Path(tempfile.mkdtemp())
        for p in config.SCHEMA_DIR.glob("*.yaml") if config.SCHEMA_DIR.is_dir() else ():
            shutil.copy(p, tmp / p.name)
        (tmp / "_candidate.yaml").write_text(yaml.safe_dump(_overlay_file(overlay, {})))
        saved, config.SCHEMA_DIR = config.SCHEMA_DIR, tmp
    _reset_caches()
    try:
        parsed, errors, fill = 0, 0, Counter()
        for line, hdr in _lines(path, sample):
            try:
                ev = P.parse_line(line, hdr)
            except P.ParseError:
                errors += 1
                continue
            parsed += 1
            fill.update(k for k, v in ev.items() if v is not None and not k.startswith("_"))
        return {"parsed": parsed, "errors": errors,
                "fill": {k: round(c / max(parsed, 1), 3) for k, c in sorted(fill.items())}}
    finally:
        if tmp is not None:
            config.SCHEMA_DIR = saved
            shutil.rmtree(tmp, ignore_errors=True)
        _reset_caches()


def _overlay_file(overlay: dict, prov: dict) -> dict:
    d = {k: overlay[k] for k in ("fields", "timestamp", "outcome_words") if overlay.get(k)}
    if overlay.get("important_unmapped"):
        d["notes_important_unmapped"] = overlay["important_unmapped"]
    return {**({"provenance": prov} if prov else {}), **d}


def suggest(path: Path, sample: int = 2000, offline: bool = False, transport=None) -> dict:
    prof = profile(path, sample)
    generic = sum(c for f, c in prof["formats"].items() if f.startswith("generic_"))
    before = fill_rates(path, sample)
    res = {"fingerprint": prof["fingerprint"], "file": prof["file"], "profile": prof, "before": before}
    unmapped = [k for k in prof["keys"] if k["status"] == "unmapped"]
    if not generic:
        res["status"] = "named profile: every line matches a field_map.yaml profile, overlays do not apply"
        return res
    if not unmapped:
        res["status"] = "nothing to map: every key is mapped or a vendor verdict"
        return res
    reply, status = (None, "offline") if offline else ask_llm(_payload(prof, before), transport)
    res["llm_status"] = status
    if reply is None:
        res["status"] = f"no suggestion ({status}); unmapped keys listed"
        return res
    overlay, rejected = validate(reply, prof, path)
    after = fill_rates(path, sample, overlay)
    from forgetrace.report.llm import llm_config

    res.update(status="proposal", overlay=overlay, rejected=rejected, after=after,
               provenance={"fingerprint": prof["fingerprint"], "file": prof["file"], "model": llm_config()["model"],
                           "prompt_version": PROMPT_VERSION, "sample_lines": prof["lines"],
                           "created": datetime.now().astimezone().isoformat(timespec="seconds"),
                           "parsed_before": before["parsed"], "parsed_after": after["parsed"]})
    return res


def _print(res: dict) -> None:
    prof = res["profile"]
    print(f"file {res['file']}  fingerprint {res['fingerprint']}  lines {prof['lines']}  formats {prof['formats']}")
    for k in prof["keys"]:
        if k["status"] != "mapped":
            print(f"  {k['status']:<14} {k['key']:<32} fill {k['fill']:.2f}  shapes {k['shapes']}")
    print(f"status: {res['status']}")
    if res.get("overlay"):
        ov, b, a = res["overlay"], res["before"], res["after"]
        for t, ks in ov["fields"].items():
            print(f"  map {', '.join(ks)} -> {t}   fill {b['fill'].get(t, 0):.2f} -> {a['fill'].get(t, 0):.2f}")
        for k in ov["timestamp"]:
            print(f"  timestamp <- {k}")
        for c, ws in ov["outcome_words"].items():
            print(f"  outcome {c}: {ws}")
        for x in ov["important_unmapped"]:
            print(f"  note: {x['key']} has no envelope field ({x['reason']})")
        for r in res["rejected"]:
            print(f"  rejected: {r}")
        print(f"  parsed lines {b['parsed']} -> {a['parsed']} of {prof['lines'] + prof['unreadable']}")


def save_proposal(res: dict) -> Path:
    PROPOSAL_DIR.mkdir(parents=True, exist_ok=True)
    p = PROPOSAL_DIR / f"{res['fingerprint']}.yaml"
    p.write_text(yaml.safe_dump({**_overlay_file(res["overlay"], res["provenance"]), "rejected": res["rejected"]},
                                sort_keys=False))
    return p


def accept(fp: str, proposal_dir: Path = PROPOSAL_DIR) -> Path:
    src = proposal_dir / f"{fp}.yaml"
    d = config.load_yaml(src)
    d.pop("rejected", None)
    config.SCHEMA_DIR.mkdir(parents=True, exist_ok=True)
    dst = config.SCHEMA_DIR / f"{fp}.yaml"
    dst.write_text("# Accepted schema overlay (D-119): extra alias names, appended after field_aliases.yaml.\n"
                   + yaml.safe_dump(d, sort_keys=False))
    _reset_caches()
    return dst


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("suggest")
    s.add_argument("file")
    s.add_argument("--sample", type=int, default=2000)
    s.add_argument("--offline", action="store_true", help="profile only; no LLM call")
    s.add_argument("--accept", action="store_true", help="accept the validated proposal immediately")
    s.add_argument("--json", action="store_true")
    a_ = sub.add_parser("accept")
    a_.add_argument("fingerprint")
    a = ap.parse_args()
    if a.cmd == "accept":
        print(f"accepted: {accept(a.fingerprint)}")
        return
    res = suggest(Path(a.file), a.sample, a.offline)
    if a.json:
        print(json.dumps(res, indent=1, default=str))
    else:
        _print(res)
    if res.get("overlay") and any(res["overlay"].get(k) for k in ("fields", "timestamp", "outcome_words")):
        p = save_proposal(res)
        print(f"proposal: {p}")
        if a.accept:
            print(f"accepted: {accept(res['fingerprint'])}")
        else:
            print(f"accept with: python tools/schema_suggest.py accept {res['fingerprint']}")


if __name__ == "__main__":
    main()
