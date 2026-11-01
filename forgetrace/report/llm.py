"""Optional LLM narrative that restates verified facts (docs/PHASE2.md OPENROUTER; mentor: readable reasoning).

Why this exists: an analyst reads a short story faster than a facts table, but an LLM must never add
or decide anything. So: (1) the input is only the deterministic explanation from explain.py, with
every user, host, IP and domain replaced by a stable keyed token (HMAC) before it leaves the machine;
(2) temperature 0 and a fixed JSON schema {summary, steps[{order, text, event_ids, technique_id}],
uncertainties}; (3) the reply is rejected unless every event id and technique it cites appears in the
facts, every step cites at least one event, and every token, IP-like string and multi-digit number in
it also appears in the payload; rejected or unavailable -> the deterministic explanation is shown
instead, with the reason; (4) replies are cached by (facts hash, prompt version, model) and every call
is written to a spend ledger with hard caps. Never imported by the detection path.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
from datetime import datetime
from pathlib import Path
from typing import Any

from forgetrace import config

ENTITY_KEYS = ("user", "target_user", "host", "host_ip", "src_ip", "dst_ip", "domain_name", "user_domain")
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
TOKEN = re.compile(r"\b(?:USR|HST|IP|DOM)_[0-9a-f]{8}\b")
SYSTEM = ("You summarise security findings for a human analyst. Use ONLY the facts provided. Do not add "
          "entities, numbers, times, techniques or claims that are not in the facts. Refer to entities exactly "
          "by the tokens given (e.g. USR_ab12cd34). Every step must cite event_ids from the facts. Reply with JSON: "
          '{"summary": str (<= 120 words), "steps": [{"order": int, "text": str (<= 40 words), '
          '"event_ids": [int], "technique_id": str}], "uncertainties": [str]}.')


def llm_config() -> dict:
    return config.load_yaml(config.CONFIG_DIR / "llm.yml")


def _key() -> bytes:
    env = os.environ.get("FORGETRACE_PSEUDO_KEY")
    if env:
        return env.encode()
    p = config.ROOT / "data" / ".pseudo_key"
    if not p.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(secrets.token_hex(32))
    return p.read_text().strip().encode()


class Pseudonymiser:
    """Stable keyed tokens for entity values; the mapping never leaves the machine."""

    PREFIX = {"user": "USR", "target_user": "USR", "host": "HST", "host_ip": "IP", "src_ip": "IP", "dst_ip": "IP",
              "domain_name": "DOM", "user_domain": "DOM"}

    def __init__(self):
        self.k = _key()
        self.fwd: dict[str, str] = {}
        self.back: dict[str, str] = {}

    def token(self, kind: str, value: str) -> str:
        v = str(value)
        if v not in self.fwd:
            t = f"{self.PREFIX.get(kind, 'ENT')}_{hmac.new(self.k, v.encode(), hashlib.sha256).hexdigest()[:8]}"
            self.fwd[v], self.back[t] = t, v
        return self.fwd[v]

    def collect(self, facts: Any) -> None:
        """Register every entity value found under entity keys anywhere in the facts."""
        if isinstance(facts, dict):
            for k, v in facts.items():
                if k in ENTITY_KEYS:
                    for x in v if isinstance(v, list) else [v]:
                        if x not in (None, ""):
                            self.token(k, x)
                else:
                    self.collect(v)
        elif isinstance(facts, list):
            for x in facts:
                self.collect(x)

    def apply(self, text: str) -> str:
        for v in sorted(self.fwd, key=len, reverse=True):  # longest first so substrings do not clash
            text = text.replace(v, self.fwd[v])
        text = IPV4.sub(lambda m: self.token("src_ip", m.group(0)), text)  # any address not already known
        return EMAIL.sub(lambda m: self.token("user", m.group(0)), text)

    def restore(self, text: str) -> str:
        return TOKEN.sub(lambda m: self.back.get(m.group(0), m.group(0)), text)


def _dotenv(name: str) -> str | None:
    """Read at call time from the repo's git-ignored .env, so pasting a key needs no restart."""
    p = config.ROOT / ".env"
    if not p.exists():
        return None
    for line in p.read_text().splitlines():
        k, _, v = line.partition("=")
        if k.strip() == name:
            return v.strip().strip("'\"") or None
    return None


def build_payload(facts: dict) -> tuple[dict, Pseudonymiser]:
    """Facts the model may see: no raw log lines (they may hold other identifiers), pseudonymised."""
    ps = Pseudonymiser()
    ps.collect(facts)
    slim = {k: v for k, v in facts.items() if k not in ("evidence", "how_to_verify", "facts_hash")}
    if "steps" in slim:
        slim["steps"] = [{k: v for k, v in s.items() if k != "evidence"} | {"event_ids": [e["event_id"] for e in s["evidence"]]}
                         for s in facts["steps"]]
    else:
        slim["event_ids"] = [e["event_id"] for e in facts.get("evidence", [])]
    text = ps.apply(json.dumps(slim, default=str))
    return json.loads(text), ps


def validate(reply: dict, payload: dict) -> list[str]:
    """Reasons to reject a reply (empty = accepted)."""
    errs = []
    blob = json.dumps(payload, default=str)
    ids = {int(x) for x in re.findall(r'"event_ids?":\s*\[?([\d, ]+)', blob) for x in re.findall(r"\d+", x)}
    techs = set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", blob))
    if not isinstance(reply.get("summary"), str) or not isinstance(reply.get("steps"), list):
        return ["reply does not follow the schema"]
    if len(reply["summary"].split()) > 140:
        errs.append("summary longer than 120 words")
    for s in reply["steps"]:
        cited = s.get("event_ids") or []
        if not cited:
            errs.append(f"step {s.get('order')} cites no event")
        bad = [e for e in cited if not isinstance(e, int) or e not in ids]
        if bad:
            errs.append(f"step {s.get('order')} cites unknown event ids {bad[:3]}")
        if s.get("technique_id") and s["technique_id"] not in techs:
            errs.append(f"step {s.get('order')} names technique {s['technique_id']} not in the facts")
    text = json.dumps(reply)
    for t in set(TOKEN.findall(text)):
        if t not in blob:
            errs.append(f"unknown entity token {t}")
    if IPV4.search(text) or EMAIL.search(text):
        errs.append("reply contains a raw address or e-mail")
    for n in set(re.findall(r"\b\d{2,}\b", text)):
        if n not in blob:
            errs.append(f"number {n} not in the facts")
    return errs[:10]


def _ledger_total(ledger: Path, run_id: str | None) -> tuple[float, float]:
    total = run = 0.0
    if ledger.exists():
        for line in ledger.read_text().splitlines():
            try:
                r = json.loads(line)
            except ValueError:
                continue
            total += r.get("cost_usd", 0)
            if run_id and r.get("run_id") == run_id:
                run += r.get("cost_usd", 0)
    return total, run


def narrate(facts: dict, run_id: str | None = None, transport=None) -> dict[str, Any]:
    """{status: ok|cached|unavailable|rejected|capped, narrative?, reason?, model, cost_usd}."""
    cfg = llm_config()
    if facts.get("error"):
        return {"status": "unavailable", "reason": facts["error"]}
    if not cfg.get("enabled"):
        return {"status": "unavailable", "reason": "LLM narrative disabled in config/llm.yml"}
    payload, ps = build_payload(facts)
    key = hashlib.sha256(json.dumps([payload, cfg["prompt_version"], cfg["model"]], sort_keys=True).encode()).hexdigest()
    cache = config.ROOT / cfg["cache_dir"] / f"{key}.json"
    if cache.exists():
        hit = json.loads(cache.read_text())
        return {**hit, "status": "cached", "narrative": _restore(hit.get("narrative"), ps)}
    api_key = os.environ.get(cfg["api_key_env"]) or _dotenv(cfg["api_key_env"])
    if not api_key and transport is None:
        return {"status": "unavailable", "reason": f"set {cfg['api_key_env']} to enable the narrative (deterministic explanation shown)"}
    ledger = config.ROOT / cfg["ledger"]
    total, run = _ledger_total(ledger, run_id)
    caps = cfg["caps_usd"]
    if total >= caps["lifetime"] or run >= caps["per_run"]:
        return {"status": "capped", "reason": f"spend cap reached (lifetime ${total:.3f}, this run ${run:.3f})"}
    import sys

    if str(config.ROOT) not in sys.path:  # tools/ lives beside the package
        sys.path.insert(0, str(config.ROOT))
    from tools.llm.openrouter import LLMError, chat

    send = transport or (lambda msgs: chat(cfg["endpoint"], api_key, cfg["model"], msgs, cfg["temperature"],
                                           cfg["max_tokens"], cfg["timeout_s"]))
    msgs = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": json.dumps(payload)}]
    last_err = None
    for attempt in range(int(cfg["max_attempts"])):
        try:
            r = send(msgs)
        except LLMError as e:
            last_err = str(e)
            continue
        u = r.get("usage", {})
        cost = u.get("cost")
        if cost is None:
            p = cfg["price_per_million_usd"]
            cost = (u.get("prompt_tokens", 0) * p["input"] + u.get("completion_tokens", 0) * p["output"]) / 1e6
        ledger.parent.mkdir(parents=True, exist_ok=True)
        with open(ledger, "a") as f:
            f.write(json.dumps({"at": datetime.now().astimezone().isoformat(timespec="seconds"), "run_id": run_id,
                                "model": r.get("model"), "facts": facts.get("kind"), "id": facts.get("id"),
                                "prompt_tokens": u.get("prompt_tokens"), "completion_tokens": u.get("completion_tokens"),
                                "cost_usd": round(float(cost), 6), "attempt": attempt + 1}) + "\n")
        try:
            reply = json.loads(r["content"])
        except ValueError:
            last_err = "reply is not JSON"
            continue
        errs = validate(reply, payload)
        if errs:
            last_err = "; ".join(errs)
            continue
        entry = {"narrative": reply, "model": r.get("model", cfg["model"]), "prompt_version": cfg["prompt_version"],
                 "facts_hash": facts.get("facts_hash"), "cost_usd": round(float(cost), 6),
                 "label": "AI-written summary of verified evidence"}
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps(entry))
        return {**entry, "status": "ok", "narrative": _restore(reply, ps)}
    return {"status": "rejected", "reason": last_err or "no valid reply"}


def _restore(reply: dict | None, ps: Pseudonymiser) -> dict | None:
    if reply is None:
        return None
    return json.loads(ps.restore(json.dumps(reply)))
