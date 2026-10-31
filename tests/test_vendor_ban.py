"""Detection must never use vendor verdict fields (threat.*, rule.*, labels.*, event.kind, event.severity)."""
import re

import pytest
import yaml

from forgetrace import config
from forgetrace.rules.engine import ALLOWED_FIELDS, BANNED_PREFIXES, Rule, load_rules, referenced_fields

BANNED_RE = re.compile(r"threat\.|\brule\.|labels|event\.kind|event\.severity")


def test_rule_files_never_mention_banned_fields():
    for p in sorted((config.CONFIG_DIR / "rules").glob("*.yml")):
        for d in yaml.safe_load(p.read_text()):
            text = yaml.safe_dump({k: v for k, v in d.items() if k not in ("title",)})
            assert not BANNED_RE.search(text), f"{p.name}:{d['id']} references a banned vendor field"


def test_rules_reference_only_envelope_fields():
    for r in load_rules():
        for f in referenced_fields(r):
            assert f in ALLOWED_FIELDS
            assert not f.startswith(BANNED_PREFIXES)


def test_field_map_never_maps_banned_source_fields():
    fm = config.field_map()
    for fmt in fm["formats"].values():
        for paths in fmt["fields"].values():
            for src in paths:
                assert not src.startswith(BANNED_PREFIXES) and not BANNED_RE.search(src), src
    for banned in ("threat", "rule", "labels", "kind", "severity"):
        assert banned not in ALLOWED_FIELDS


def test_rule_using_banned_field_fails_to_load():
    with pytest.raises(Exception):
        Rule(id="RX", version=1, title="bad", author="t", technique="T1110", tactic="Credential Access", severity=2,
             confidence=0.5, label_priority=1, type="match", aggregate_by=["user"],
             filter={"all": [{"field": "threat.technique.id", "op": "eq", "value": "T1110"}]})


def test_vendor_tags_do_not_change_detections(tmp_path):
    """Same seed with --with-tags must yield identical detections (tags are invisible to detection)."""
    import subprocess
    import sys

    from forgetrace import store
    from forgetrace.ingest.ingest import ingest
    from forgetrace.rules.engine import detect

    root = config.ROOT
    res = []
    for tag in ([], ["--with-tags"]):
        d = tmp_path / ("t" if tag else "n")
        subprocess.run([sys.executable, str(root / "tools/gen_scenarios.py"), "--events", "3000", "--out-dir", str(d),
                        "--assets", str(d / "a.yaml")] + tag, check=True, capture_output=True)
        assert ("threat" in (d / "events.log").read_text()) == bool(tag)
        ingest([d / "events.log"], d / "out")
        con = store.connect(d / "out")
        store.create_views(con, d / "out")
        detect(con, load_rules())
        res.append(con.execute("SELECT rule_id, technique_id, member_count FROM detections ORDER BY ALL").fetchall())
    assert res[0] == res[1] and res[0]
