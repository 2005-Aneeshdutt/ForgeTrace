"""Minimal OpenRouter chat-completions client (standard library only; no new dependency).

Why this exists: PHASE2 allows an HTTP client only here and in forgetrace/report/llm.py, never on the
detection path. This module only moves bytes: it sends a JSON request and returns the parsed reply and
usage. Spend caps, caching, pseudonymisation and validation live in forgetrace/report/llm.py.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any


class LLMError(RuntimeError):
    pass


def chat(endpoint: str, api_key: str, model: str, messages: list[dict], temperature: float, max_tokens: int,
         timeout_s: float) -> dict[str, Any]:
    body = json.dumps({"model": model, "messages": messages, "temperature": temperature, "max_tokens": max_tokens,
                       "response_format": {"type": "json_object"}, "usage": {"include": True}}).encode()
    req = urllib.request.Request(endpoint, data=body, method="POST", headers={
        "Authorization": f"Bearer {api_key}", "Content-Type": "application/json",
        "X-Title": "ForgeTrace incident narrative"})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as r:
            data = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raise LLMError(f"HTTP {e.code}: {e.read()[:300].decode(errors='replace')}") from None
    except (urllib.error.URLError, TimeoutError) as e:
        raise LLMError(f"network: {e}") from None
    try:
        content = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        raise LLMError(f"unexpected response: {str(data)[:300]}") from None
    return {"content": content, "usage": data.get("usage") or {}, "model": data.get("model", model)}
