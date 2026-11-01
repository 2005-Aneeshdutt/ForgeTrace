# CLAUDE.md — working rules for ForgeTrace

The dossier has no §25; these rules come from dossier §18 ("Rule for Opus before every work package"), §11–14, and the Phase 1 brief.

- The dossier (`ForgeTrace — Research & Implementation Dossier-2.pdf`) is the architectural authority. Record every threshold or architectural decision as one line in `docs/DECISIONS.md`.
- Every non-trivial algorithm gets a "why this exists" header comment citing the dossier section.
- Update `WORKLOG.md` (completed, metrics, open risks, next tasks) at the end of each work package.
- Never modify the original datasets (`firex-*.log*`, `edr_events.json`). Never read a log file whole; stream line by line.
- `event_id = (file_id << 48) | byte_offset`; every derived row carries raw event IDs.
- Detection must never read `threat.*`, `rule.*`, `labels.*`, `event.kind`, `event.severity` (enforced by `tests/test_vendor_ban.py`).
- No LLM anywhere in detect/label/link/score/decide. The only LLM use is the optional narrative in `forgetrace/report/llm.py` (via `tools/llm/openrouter.py`): it restates verified facts, is validated, cached and spend-capped, and the system works fully offline without it (DECISIONS D-87). The schema helper `tools/schema_suggest.py` may draft field-alias config with the same client; code validates it and a person accepts it before the parser uses it (D-119).
- No hostnames, usernames, IPs, domains, countries or dataset-specific values hardcoded in code or rules; use `config/` (field_map, field_aliases, site, rules, assets). A new unseen dataset must work by editing config only.
- Ground truth is read only by `tools/score.py`.
- Render log-derived strings as text in the UI (`textContent`), never as HTML.
- Report metrics honestly; print N/A with a reason when a metric cannot be computed.

Commands: `make sample`, `make run`, `make score`, `make test`, `make serve`.
