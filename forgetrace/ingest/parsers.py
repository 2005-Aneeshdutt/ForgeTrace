"""Line parsers and normaliser (dossier §11 steps 4-5, envelope §13).

Each line is first classified by syntax (JSON, CEF - also behind a syslog header -, syslog,
key=value, CSV with a header row) and parsed into a flat {source_path: value} dict. A named profile
in config/field_map.yaml is used when its `match` (syntax + required keys) fits; any other line is
mapped generically through config/field_aliases.yaml, so an unseen dataset is parsed without code
changes (DECISIONS D-79). Unknown or malformed lines raise ParseError so ingest can record them in
parse_errors (never dropped silently).
"""
from __future__ import annotations

import csv
import ipaddress
import re
from datetime import datetime, timedelta, timezone
from functools import lru_cache

import orjson

from forgetrace import config


class ParseError(ValueError):
    pass


# ----------------------------------------------------------------------------- format detection
_SYSLOG = re.compile(
    rb"^(?:<(?P<pri>\d{1,3})>)?(?:\d{1,2} )?"
    rb"(?P<ts>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d|\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?)"
    rb" (?P<host>\S+) (?P<prog>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?:? ?(?P<body>.*)$")
_KV = re.compile(r'([\w.@-]+)=(?:"((?:[^"\\]|\\.)*)"|(\S*))')


def syntax_of(line: bytes) -> str:
    """json | cef | syslog | kv | plain (CSV is decided per file from its header, see ingest)."""
    s = line.lstrip()
    if s.startswith(b"{"):
        return "json"
    if s.startswith(b"CEF:"):
        return "cef"
    if _SYSLOG.match(s):
        return "syslog"
    if len(_KV.findall(s[:4096].decode("utf-8", "replace"))) >= 3:
        return "kv"
    return "plain"


def sniff(line: bytes) -> str:
    """Profile (or generic_<syntax>) that will normalise this line; used by ingest and the walkthrough."""
    return _profile_and_raw(line)[0]


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


# ----------------------------------------------------------------------------- key=value / syslog / CSV
def parse_kv(line: bytes) -> dict:
    s = line.decode("utf-8", "replace")
    out = {m.group(1): (m.group(2) if m.group(2) is not None else m.group(3)) for m in _KV.finditer(s)}
    if not out:
        raise ParseError("kv: no key=value pairs")
    return out


def parse_syslog(line: bytes) -> tuple[str, dict]:
    """Syslog header + body; the body is CEF, key=value or free text. Returns (body syntax, fields)."""
    m = _SYSLOG.match(line.lstrip())
    if not m:
        raise ParseError("syslog: header not recognised")
    body = m.group("body")
    hdr = {"syslog.timestamp": m.group("ts").decode(), "syslog.host": m.group("host").decode(),
           "syslog.program": m.group("prog").decode()}
    if m.group("pid"):
        hdr["syslog.pid"] = m.group("pid").decode()
    i = body.find(b"CEF:")
    if 0 <= i <= 64:
        out = parse_cef(body[i:], config.field_map()["formats"]["cef"]["label_fields"])
        return "cef", {**hdr, **out}
    kv = {m2.group(1): (m2.group(2) if m2.group(2) is not None else m2.group(3))
          for m2 in _KV.finditer(body.decode("utf-8", "replace"))}
    if len(kv) >= 2:
        return "kv", {**hdr, **kv, "message": body.decode("utf-8", "replace")}
    return "plain", {**hdr, "message": body.decode("utf-8", "replace")}


def csv_header(first_line: bytes) -> tuple[list[str], str] | None:
    """A file is CSV when its first line is a header: >= 3 identifier-like names split by , ; | or tab."""
    s = first_line.decode("utf-8", "replace").strip().lstrip("\ufeff")
    if not s or s[0] in "{<" or s.startswith("CEF:") or "=" in s:
        return None
    for d in (",", "\t", ";", "|"):
        cols = [c.strip().strip('"') for c in next(csv.reader([s], delimiter=d))]
        if len(cols) >= 3 and all(re.fullmatch(r"[A-Za-z_@][\w .@()-]{0,63}", c) for c in cols):
            return cols, d
    return None


def parse_csv(line: bytes, header: list[str], delim: str) -> dict:
    vals = next(csv.reader([line.decode("utf-8", "replace")], delimiter=delim))
    if len(vals) != len(header):
        raise ParseError(f"csv: {len(vals)} values for {len(header)} columns")
    return {h: v for h, v in zip(header, vals) if v != ""}


# ----------------------------------------------------------------------------- normalise
_NETS = None


def _internal_nets():
    global _NETS
    if _NETS is None:
        _NETS = [ipaddress.ip_network(n) for n in config.field_map()["internal_networks"]]
    return _NETS


def _memo(fn):
    """Memoise a pure normaliser on hashable inputs. IPs, users and hosts repeat millions of times in a
    large file, and ipaddress parsing dominated the per-line profile (docs/wp/SC-1.md). Bounded so a
    file with unbounded cardinality cannot grow it without limit."""
    cached = lru_cache(maxsize=1 << 16)(fn)

    def wrapper(v):
        try:
            return cached(v)
        except TypeError:  # unhashable input: compute directly
            return fn(v)
    wrapper.__wrapped__ = fn
    return wrapper


@_memo
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


@_memo
def is_external(ip: str | None) -> bool | None:
    if ip is None:
        return None
    a = ipaddress.ip_address(ip)
    return not any(a in n for n in _internal_nets())


@_memo
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


@_memo
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


def _offset_min(dt: datetime) -> int | None:
    off = dt.utcoffset()
    return None if off is None else int(off.total_seconds() // 60)


_FRAC = re.compile(r"(\.\d{6})\d+")
_TS_FORMATS = ["%d/%b/%Y:%H:%M:%S %z", "%b %d %H:%M:%S %Y", "%b %d %Y %H:%M:%S", "%m/%d/%Y %H:%M:%S",
               "%m/%d/%Y %I:%M:%S %p", "%Y/%m/%d %H:%M:%S", "%d-%m-%Y %H:%M:%S", "%a %b %d %H:%M:%S %Y",
               "%d %b %Y %H:%M:%S", "%Y%m%d%H%M%S"]


def parse_any_ts(v) -> tuple[int, int | None]:
    """UTC epoch microseconds + the line's own UTC offset (minutes) if it states one. Accepts epoch
    numbers (s/ms/us/ns by magnitude), ISO 8601 (any fraction length, 'Z', space separator), Apache,
    syslog (no year: config/site.yaml default_year or the current year) and common US/EU forms.
    A naive time is taken as site local time (site.yaml utc_offset_minutes)."""
    site = config.site()
    if isinstance(v, (int, float)) or (isinstance(v, str) and re.fullmatch(r"\d{9,19}(\.\d+)?", v.strip())):
        n = int(float(v))
        us = n // 1000 if n > 10**17 else n if n > 10**14 else n * 1000 if n > 10**11 else n * 1_000_000
        return us, None
    s = str(v).strip()
    dt = None
    iso = _FRAC.sub(r"\1", s.replace("Z", "+00:00"))
    if re.match(r"\d{4}-\d\d-\d\d \d", iso):
        iso = iso.replace(" ", "T", 1)
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        for f in _TS_FORMATS:
            try:
                dt = datetime.strptime(s, f)
                break
            except ValueError:
                continue
        if dt is None:
            try:  # syslog without year
                dt = datetime.strptime(f"{site.get('default_year') or datetime.now().year} {s}", "%Y %b %d %H:%M:%S")
            except ValueError:
                raise ParseError(f"timestamp: unrecognised {s[:40]!r}") from None
    own = _offset_min(dt)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone(timedelta(minutes=site.get("utc_offset_minutes") or 0)))
    return int(dt.timestamp() * 1_000_000), own


def _tz_offset(tz) -> int | None:
    m = re.fullmatch(r"\s*([+-])(\d\d):?(\d\d)\s*", str(tz or ""))
    if not m:
        return None
    return (1 if m.group(1) == "+" else -1) * (int(m.group(2)) * 60 + int(m.group(3)))


def parse_ts(raw: dict, spec: dict) -> tuple[int, int | None]:
    """Profile timestamp: UTC epoch microseconds + the line's own UTC offset in minutes (or None)."""
    v = raw.get(spec["field"]) if spec.get("field") else None
    kind = spec["kind"]
    try:
        if v not in (None, ""):
            if kind == "iso8601":
                s = str(v).replace("Z", "+00:00")
                dt = datetime.fromisoformat(s)
                own = _offset_min(dt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return int(dt.timestamp() * 1_000_000), own
            n = int(v)
            if kind == "epoch_ms":
                return n * 1000, None
            if kind == "epoch_auto":  # s / ms / us / ns by magnitude
                if n > 10**17:
                    return n // 1000, None
                if n > 10**14:
                    return n, None
                if n > 10**11:
                    return n * 1000, None
                return n * 1_000_000, None
        fb = spec.get("fallback")
        if fb:
            d, t, tz = (raw.get(k) for k in fb)
            dt = datetime.fromisoformat(f"{d}T{t}{tz or '+00:00'}")
            return int(dt.timestamp() * 1_000_000), _offset_min(dt)
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
    """Map a parsed line to the envelope with a named profile (fmt in field_map formats) or, for
    fmt = generic_<syntax>, through the alias table."""
    fm = config.field_map()
    if fmt.startswith("generic_"):
        return _finish(_generic_fields(raw, fmt), fm)
    spec = fm["formats"][fmt]
    ts, own = parse_ts(raw, spec["timestamp"])
    ev = {"source_type": spec["source_type"], "raw_format": fmt, "ts": ts, "_utc_offset": own}
    for field, paths in spec["fields"].items():
        v = _first(raw, paths)
        if v is None and fmt == "cef":
            v = raw.get(f"label:{field}")
        ev[field] = v
    if fmt == "cef":
        for target in spec.get("label_fields", {}).values():
            if ev.get(target) is None:
                ev[target] = raw.get(f"label:{target}")
    return _finish(ev, fm)


def _norm_key(k: str) -> str:
    return re.sub(r"[._\-\s@]", "", k).lower()


@lru_cache(maxsize=1)
def _alias_index() -> tuple[dict, frozenset, list, dict]:
    al = config.field_aliases()
    fields = {f: [_norm_key(a) for a in names] for f, names in al["fields"].items()}
    never = frozenset(_norm_key(x) for x in al.get("never_map", []))
    words = {canon: {str(w).lower() for w in ws} for canon, ws in al.get("outcome_words", {}).items()}
    return fields, never, [_norm_key(t) for t in al["timestamp"]], words


@lru_cache(maxsize=1)
def _message_patterns() -> tuple:
    return tuple((re.compile(p["regex"]), p.get("set") or {}) for p in config.field_aliases().get("message_patterns", []))


def _generic_fields(raw: dict, fmt: str) -> dict:
    """Alias-based mapping for lines no profile describes (unseen datasets)."""
    al = config.field_aliases()
    fields, never, ts_names, words = _alias_index()
    full, last = {}, {}
    for k, v in raw.items():
        if v in (None, "") or isinstance(v, dict):
            continue
        nk = _norm_key(k)
        lk = _norm_key(k.rsplit(".", 1)[-1])
        if nk in never or lk in never:
            continue
        full.setdefault(nk, v)
        last.setdefault(lk, v)

    def pick(names):
        for n in names:
            if n in full:
                return full[n]
        for n in names:
            if n in last:
                return last[n]
        return None

    ts = own = None
    cands = []
    d = pick([_norm_key(x) for x in al.get("date_fields", [])])
    t = pick([_norm_key(x) for x in al.get("time_fields", [])])
    if d and t:  # split date / time (/ zone) fields first: "time" alone is only a clock
        tz = pick([_norm_key(x) for x in al.get("tz_fields", [])])
        cands.append(f"{d} {t}{tz or ''}".strip())
    for n in ts_names:
        for idx in (full, last):
            if n in idx:
                cands.append(idx[n])
    if "syslog.timestamp" in raw:
        cands.append(raw["syslog.timestamp"])
    for c in cands:
        try:
            ts, own = parse_any_ts(c[0] if isinstance(c, list) and c else c)
            break
        except (ParseError, ValueError, OverflowError):
            continue
    if ts is None:
        raise ParseError("timestamp: no recognised timestamp field")
    ev = {"raw_format": fmt, "ts": ts, "_utc_offset": own}
    for f, names in fields.items():
        v = pick(names)
        ev[f] = (v[0] if v else None) if isinstance(v, list) else v
    msg = raw.get("message") or ev.get("message")
    if msg:
        for pat, fixed in _message_patterns():
            m = pat.search(str(msg))
            if m:
                for k, v in m.groupdict().items():
                    if v is not None and ev.get(k) is None:
                        ev[k] = v
                for k, v in fixed.items():
                    if ev.get(k) is None:
                        ev[k] = v
                break
    if ev.get("outcome") is not None:
        o = str(ev["outcome"]).strip().lower()
        ev["outcome"] = next((c for c, ws in words.items() if o in ws), o)
    present = {k for k, v in ev.items() if v is not None}  # before syslog fallbacks: a program name is not a process
    for r in al.get("source_type_rules", []):
        if set(r.get("all", [])) <= present and (not r.get("any") or present & set(r["any"])):
            ev["source_type"] = r["type"]
            break
    if ev.get("host") is None and raw.get("syslog.host"):
        ev["host"] = raw["syslog.host"]
    if ev.get("service") is None and raw.get("syslog.program"):
        ev["service"] = raw["syslog.program"]
    return ev


def _finish(ev: dict, fm: dict) -> dict:
    """Shared post-processing for profile and generic mappings."""
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
    _derive(ev, fm)
    ev["event_type"] = classify(ev)
    ev["outcome"] = {"success": "success", "failure": "failure", "failed": "failure"}.get(ev.get("outcome") or "", "unknown")
    return ev


@_memo
def subnet(ip: str | None) -> tuple[str | None, str | None]:
    """IPv4 /24 and /16 network of an address (strings like '10.10.20.0/24'); None for IPv6/None."""
    if not ip or ":" in ip:
        return None, None
    a, b, c, _ = ip.split(".")
    return f"{a}.{b}.{c}.0/24", f"{a}.{b}.0.0/16"


@_memo
def domain_parts(name: str | None) -> tuple[str | None, int | None]:
    """Registered-domain approximation (last two labels) and the longest label length, for DNS
    tunnelling (long encoded labels under one domain)."""
    if not name:
        return None, None
    labels = [x for x in name.strip(".").split(".") if x]
    if not labels:
        return None, None
    return ".".join(labels[-2:]), max(len(x) for x in labels)


def _derive(ev: dict, fm: dict) -> None:
    ev["src_subnet24"], ev["src_subnet16"] = subnet(ev.get("src_ip"))
    ev["domain_base"], ev["dns_label_max"] = domain_parts(ev.get("domain_name"))
    own = ev.pop("_utc_offset", None)  # the line's own zone wins; else the site's (config/site.yaml)
    off = own if own is not None else (config.site().get("utc_offset_minutes") or 0)
    ev["local_hour"] = int(((ev["ts"] // 1_000_000 + off * 60) // 3600) % 24)
    for k in ("message", "service", "log_subtype", "src_country", "dst_country"):
        if ev.get(k) is not None:
            ev[k] = str(ev[k])


@lru_cache(maxsize=1)
def _event_type_rules() -> tuple:
    """field_map event_types compiled once: a value list is an exact-match set; a string starting with
    '~' is a case-insensitive regex that must match a non-null value (vendor-neutral wording)."""
    out = []
    for r in config.field_map()["event_types"]:
        conds = []
        for k, vals in r["when"].items():
            if isinstance(vals, str) and vals.startswith("~"):
                conds.append((k, re.compile(vals[1:], re.I)))
            else:
                conds.append((k, frozenset(str(x) for x in vals)))
        out.append((r["type"], tuple(conds)))
    return tuple(out)


def classify(ev: dict) -> str | None:
    for typ, conds in _event_type_rules():
        ok = True
        for k, want in conds:
            v = ev.get(k)
            if isinstance(want, frozenset):
                ok = str(v) in want
            else:
                ok = v is not None and want.search(str(v)) is not None
            if not ok:
                break
        if ok:
            return typ
    return None


@lru_cache(maxsize=1)
def _profiles() -> tuple:
    return tuple((name, spec["match"]) for name, spec in config.field_map()["formats"].items() if spec.get("match"))


def _profile_and_raw(line: bytes, csv_ctx: tuple | None = None) -> tuple[str, dict]:
    """(profile or generic_<syntax>, parsed fields) for one line."""
    if csv_ctx:
        raw, syn = parse_csv(line, *csv_ctx), "csv"
    else:
        syn = syntax_of(line)
        if syn == "json":
            raw = parse_json(line)
        elif syn == "cef":
            raw = parse_cef(line.lstrip(), config.field_map()["formats"]["cef"]["label_fields"])
        elif syn == "syslog":
            syn, raw = parse_syslog(line)
            syn = {"cef": "cef", "kv": "kv"}.get(syn, "syslog")
        elif syn == "kv":
            raw = parse_kv(line)
        else:
            raise ParseError("unknown format")
    for name, m in _profiles():
        if m.get("syntax") == syn and all(k in raw for k in m.get("keys_all", [])):
            return name, raw
    return f"generic_{syn}", raw


def parse_line(line: bytes, csv_ctx: tuple | None = None) -> dict:
    fmt, raw = _profile_and_raw(line, csv_ctx)
    return normalise(raw, fmt)
