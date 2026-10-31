"""Line parsers and normaliser (dossier §11 steps 4-5, envelope §13).

Each parser turns one raw line into a flat {source_path: value} dict; normalise() then maps
those paths to envelope fields using config/field_map.yaml only. Unknown or malformed lines
raise ParseError so ingest can record them in parse_errors (never dropped silently).
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone

import orjson

from forgetrace import config


class ParseError(ValueError):
    pass


# ----------------------------------------------------------------------------- format detection
def sniff(line: bytes) -> str:
    if line.startswith(b"{"):
        return "ecs_json"
    if line.startswith(b"CEF:"):
        return "cef"
    if line.startswith(b"date="):
        return "fortigate_kv"
    raise ParseError("unknown format")


# ----------------------------------------------------------------------------- JSON
def _flatten(obj, prefix: str, out: dict) -> None:
    for k, v in obj.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            _flatten(v, key + ".", out)
        else:
            out[key] = v


def parse_json(line: bytes) -> dict:
    try:
        obj = orjson.loads(line)
    except orjson.JSONDecodeError as e:
        raise ParseError(f"json: {e}") from None
    if not isinstance(obj, dict):
        raise ParseError("json: not an object")
    out: dict = {}
    _flatten(obj, "", out)
    return out


# ----------------------------------------------------------------------------- CEF
_CEF_EXT = re.compile(r"([A-Za-z0-9_]+)=((?:\\.|[^\\])*?)(?=\s+[A-Za-z0-9_]+=|\s*$)")
_CEF_UNESC = re.compile(r"\\(.)")


def _cef_unescape(s: str) -> str:
    return _CEF_UNESC.sub(lambda m: "\n" if m.group(1) == "n" else m.group(1), s)


def parse_cef(line: bytes, label_fields: dict) -> dict:
    s = line.decode("utf-8", "replace")
    parts, cur, i, n = [], [], 0, len(s)
    while i < n and len(parts) < 7:          # split the 7 header fields on unescaped pipes
        c = s[i]
        if c == "\\" and i + 1 < n:
            cur.append(s[i + 1]); i += 2; continue
        if c == "|":
            parts.append("".join(cur)); cur = []; i += 1; continue
        cur.append(c); i += 1
    if len(parts) < 7 or not parts[0].startswith("CEF:"):
        raise ParseError("cef: header has fewer than 8 fields")
    ext = s[i:]
    out = {"cef.version": parts[0][4:], "cef.vendor": parts[1], "cef.product": parts[2],
           "cef.signature_id": parts[4], "cef.name": parts[5]}
    for m in _CEF_EXT.finditer(ext):
        out[m.group(1)] = _cef_unescape(m.group(2))
    # Resolve custom string/number fields through their labels.
    for k in list(out):
        if k.endswith("Label"):
            base = k[:-5]
            target = label_fields.get(out[k])
            if target and base in out:
                out[f"label:{target}"] = out[base]
    return out


# ----------------------------------------------------------------------------- FortiGate key=value
_KV = re.compile(r'(\w+)=(?:"((?:[^"\\]|\\.)*)"|(\S*))')


def parse_kv(line: bytes) -> dict:
    s = line.decode("utf-8", "replace")
    out = {m.group(1): (m.group(2) if m.group(2) is not None else m.group(3)) for m in _KV.finditer(s)}
    if "date" not in out:
        raise ParseError("kv: no date")
    return out


# ----------------------------------------------------------------------------- normalise
_NETS = None


def _internal_nets():
    global _NETS
    if _NETS is None:
        _NETS = [ipaddress.ip_network(n) for n in config.field_map()["internal_networks"]]
    return _NETS


def norm_ip(v) -> str | None:
    if v is None or v == "":
        return None
    try:
        ip = ipaddress.ip_address(str(v).strip())
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ip)


def is_external(ip: str | None) -> bool | None:
    if ip is None:
        return None
    a = ipaddress.ip_address(ip)
    return not any(a in n for n in _internal_nets())


def norm_user(v) -> str | None:
    """Canonical user: lower-case bare account name; domain kept in user_domain (DECISIONS D-14)."""
    if v is None or v == "":
        return None
    s = str(v).strip().lower()
    if "\\" in s:
        s = s.split("\\", 1)[1]
    if "@" in s:
        s = s.split("@", 1)[0]
    return s or None


def norm_host(v) -> str | None:
    if v is None or v == "":
        return None
    s = str(v).strip()
    try:
        ipaddress.ip_address(s)
        return None  # an IP is not a hostname
    except ValueError:
        pass
    return s.split(".", 1)[0].upper() or None


def parse_ts(raw: dict, spec: dict) -> int:
    """Return UTC epoch microseconds."""
    v = raw.get(spec["field"])
    kind = spec["kind"]
    try:
        if v not in (None, ""):
            if kind == "iso8601":
                s = str(v).replace("Z", "+00:00")
                dt = datetime.fromisoformat(s)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return int(dt.timestamp() * 1_000_000)
            n = int(v)
            if kind == "epoch_ms":
                return n * 1000
            if kind == "epoch_auto":  # s / ms / us / ns by magnitude
                if n > 10**17:
                    return n // 1000
                if n > 10**14:
                    return n
                if n > 10**11:
                    return n * 1000
                return n * 1_000_000
        fb = spec.get("fallback")
        if fb:
            d, t, tz = (raw.get(k) for k in fb)
            dt = datetime.fromisoformat(f"{d}T{t}{tz or '+00:00'}")
            return int(dt.timestamp() * 1_000_000)
    except (ValueError, TypeError) as e:
        raise ParseError(f"timestamp: {e}") from None
    raise ParseError("timestamp: missing")


_INT_FIELDS = {"src_port", "dst_port", "pid", "bytes_out", "bytes_in"}


def _first(raw: dict, paths: list[str]):
    for p in paths:
        v = raw.get(p)
        if isinstance(v, list):
            v = v[0] if v else None
        if v not in (None, ""):
            return v
    return None


def normalise(raw: dict, fmt: str) -> dict:
    fm = config.field_map()
    spec = fm["formats"][fmt]
    ev = {"source_type": spec["source_type"], "raw_format": fmt, "ts": parse_ts(raw, spec["timestamp"])}
    for field, paths in spec["fields"].items():
        v = _first(raw, paths)
        if v is None and fmt == "cef":
            v = raw.get(f"label:{field}")
        ev[field] = v
    if fmt == "cef":
        for target in spec.get("label_fields", {}).values():
            if ev.get(target) is None:
                ev[target] = raw.get(f"label:{target}")
    for k in _INT_FIELDS:
        if ev.get(k) is not None:
            try:
                ev[k] = int(ev[k])
            except (ValueError, TypeError):
                ev[k] = None
    for k in ("vendor_event_code", "logon_id", "source_event_id", "outcome", "action", "logon_type",
              "registry_value", "group_name", "domain_name"):
        if ev.get(k) is not None:
            ev[k] = str(ev[k])
    if ev.get("outcome"):
        ev["outcome"] = ev["outcome"].lower()
    for k in ("user", "target_user"):
        ev[k] = norm_user(ev.get(k))
    ev["host"] = norm_host(ev.get("host"))
    for k in ("src_ip", "dst_ip", "host_ip"):
        ev[k] = norm_ip(ev.get(k))
    ev["src_is_external"] = is_external(ev["src_ip"])
    ev["dst_is_external"] = is_external(ev["dst_ip"])
    if ev.get("command_line"):
        ev["command_line"] = ev["command_line"][: fm["command_line_max"]]
    if ev.get("domain_name"):
        ev["domain_name"] = ev["domain_name"].lower()
    ev["event_type"] = classify(ev)
    ev["outcome"] = {"success": "success", "failure": "failure", "failed": "failure"}.get(ev.get("outcome") or "", "unknown")
    return ev


def classify(ev: dict) -> str | None:
    for r in config.field_map()["event_types"]:
        if all(str(ev.get(k)) in [str(x) for x in vals] for k, vals in r["when"].items()):
            return r["type"]
    return None


def parse_line(line: bytes) -> dict:
    fmt = sniff(line)
    if fmt == "ecs_json":
        raw = parse_json(line)
    elif fmt == "cef":
        raw = parse_cef(line, config.field_map()["formats"]["cef"]["label_fields"])
    else:
        raw = parse_kv(line)
    return normalise(raw, fmt)
