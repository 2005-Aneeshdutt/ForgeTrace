# Drop folder for logs to analyse

Put log files here (or upload them from the dashboard's **Data sources** page), then run

    make analyze        # or click "Analyze input folder" in the dashboard

Every `*.log, *.json, *.jsonl, *.ndjson, *.cef, *.txt` file in this folder (recursively) is ingested,
one file_id per file, into the `input` workspace (`out/input/`). Supported line formats are
auto-detected per line: ECS/SimEDR JSON, ArcSight CEF, FortiGate key=value. Unknown lines go to
`parse_errors` with their byte offset; they are never dropped silently.

Files here are treated as read-only evidence: ForgeTrace never modifies them, and evidence
verification re-reads them by byte offset. Contents of this folder are git-ignored.
