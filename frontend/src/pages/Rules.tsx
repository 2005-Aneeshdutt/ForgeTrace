import { useMemo, useState } from "react";
import { createColumnHelper } from "@tanstack/react-table";
import type { Rule } from "../lib/api";
import { fmtN, fmtTs } from "../lib/format";
import { useCurrentWs, useDetections, useOverview, useRules } from "../lib/hooks";
import { Detector, Drawer, ErrorBox, KV, Kpi, Loading, NotAvailable, Page, Panel, Pill, Section, Select, Sev, Tech } from "../components/ui";
import { DataTable } from "../components/DataTable";

const KW = /\b(SELECT|FROM|WHERE|AND|OR|NOT|IN|ON|AS|GROUP BY|ORDER BY|PARTITION BY|OVER|COUNT|JOIN|LEFT|WITH|RANGE|BETWEEN|PRECEDING|CURRENT ROW|HAVING|DISTINCT|CASE|WHEN|THEN|ELSE|END|TRUE|FALSE|NULL|IS|LIKE|ILIKE|INTERVAL)\b/gi;
// Tokenised into React text nodes, so SQL text is never interpreted as markup.
function Sql({ text }: { text: string }) {
  const out: JSX.Element[] = []; let i = 0, k = 0;
  const re = new RegExp(`('(?:[^']|'')*')|("[^"]*")|${KW.source}|(\\b\\d+\\b)`, "gi");
  for (const m of text.matchAll(re)) {
    if (m.index! > i) out.push(<span key={k++}>{text.slice(i, m.index)}</span>);
    const c = m[1] ? "text-ok" : m[2] ? "text-[#93C5FD]" : m[4] ? "text-warn" : "text-cyan font-semibold";
    out.push(<span key={k++} className={c}>{m[0]}</span>); i = m.index! + m[0].length;
  }
  out.push(<span key={k}>{text.slice(i)}</span>);
  return <pre className="raw rounded border border-line bg-bg p-2.5 text-sub">{out}</pre>;
}

const c = createColumnHelper<Rule & { hits: number; last: string | null; ran: boolean | null }>();

export function Rules() {
  const q = useRules(); const ov = useOverview(); const det = useDetections(); const cur = useCurrentWs();
  const [tac, setTac] = useState(""); const [text, setText] = useState(""); const [sel, setSel] = useState<string | null>(null);
  const rows = useMemo(() => {
    const ran = ov.data?.run.rule_seconds;
    return (q.data ?? []).map((r) => { const d = (det.data ?? []).filter((x) => x.rule_id === r.id); return { ...r, hits: d.length, last: d.map((x) => x.ts_last).sort().pop() ?? null, ran: ran ? r.id in ran : null }; });
  }, [q.data, ov.data, det.data]);
  const shown = rows.filter((r) => (!tac || r.tactic === tac) && (!text || `${r.id} ${r.title} ${r.technique}`.toLowerCase().includes(text.toLowerCase())));
  const models = (ov.data?.detections_by_rule ?? []).filter((r) => r.key.startsWith("ML-"));
  const columns = useMemo(() => [
    c.accessor("id", { header: "Rule", cell: (v) => <span className="mono text-cyan">{v.getValue()}</span> }),
    c.accessor("title", { header: "Name", cell: (v) => <span className="text-ink">{v.getValue()}</span> }),
    c.accessor("severity", { header: "Severity", cell: (v) => <Sev s={v.getValue()} /> }),
    c.accessor("technique", { header: "MITRE", cell: (v) => <Tech id={v.getValue()} /> }),
    c.accessor("tactic", { header: "Tactic", cell: (v) => <span className="whitespace-nowrap">{v.getValue()}</span> }),
    c.accessor("ran", { header: "State", cell: (v) => v.getValue() == null ? <Pill>loaded</Pill> : v.getValue() ? <Pill tone="ok">ran</Pill> : <Pill tone="warn">skipped</Pill> }),
    c.accessor("hits", { header: "Triggers", cell: (v) => <span className="mono">{fmtN(v.getValue())}</span> }),
    c.accessor("last", { header: "Last triggered", cell: (v) => <span className="mono whitespace-nowrap">{fmtTs(v.getValue())}</span> }),
  ], []);
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  const s = rows.find((r) => r.id === sel);
  return (
    <Page title="Rules & Configuration" sub="Rules are YAML files in config/rules. Add or change one there and rerun; no code change is needed.">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-2"><Kpi label="Rules loaded" value={fmtN(rows.length)} /><Kpi label="Ran on this data" value={rows.some((r) => r.ran != null) ? fmtN(rows.filter((r) => r.ran).length) : "N/A"} sub="others lack the required fields" tone="ok" /><Kpi label="Triggered" value={fmtN(rows.filter((r) => r.hits).length)} tone="warn" sub={cur?.name} /><Kpi label="Rule source files" value={fmtN(new Set(rows.map((r) => r.source_file)).size)} /></div>
      <Panel className="h-[520px]" title={`Detection rules · ${shown.length}`}><div className="flex flex-col h-full"><div className="flex gap-2 px-3 py-2 border-b border-line2"><Select label="All tactics" value={tac} onChange={setTac} options={[...new Set(rows.map((r) => r.tactic))].sort()} /><input aria-label="Filter rules" className="field w-52" placeholder="Filter rules" value={text} onChange={(e) => setText(e.target.value)} /></div>
        <div className="flex-1 min-h-0"><DataTable data={shown} columns={columns} onRow={(r) => setSel(r.id)} initialSort={[{ id: "id", desc: false }]} /></div></div></Panel>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        <Panel title="ML detectors in this workspace" body="overflow-auto">{models.length ? <table className="tbl"><thead><tr>{["", "Model", "Name", "Detections"].map((h) => <th key={h}>{h}</th>)}</tr></thead><tbody>{models.map((m) => <tr key={m.key + m.technique}><td><Detector rule={m.key} /></td><td className="mono text-2xs">{m.key}</td><td>{m.title}</td><td className="mono">{m.count}</td></tr>)}</tbody></table> : <div className="p-3 text-xs text-mute">No ML detections in this workspace.</div>}</Panel>
        <div className="space-y-2"><NotAvailable title="Edit, validate and enable or disable rules here" why="The API serves rules read-only, so this page does not offer a save it cannot honour." /><NotAvailable title="Test a rule against sample events" why="No test endpoint exists. Rerun an analysis after editing the YAML file." /></div>
      </div>
      {s && <Drawer title={`${s.id} · ${s.title}`} width={640} onClose={() => setSel(null)} badge={<Sev s={s.severity} />}>
        <KV rows={[["Technique", <Tech id={s.technique} />], ["Tactic", s.tactic], ["Type", s.type], ["Confidence", s.confidence], ["Author", s.author], ["Label priority", s.label_priority], ["Definition", <span className="mono text-2xs">config/rules/{s.source_file}</span>], ["Triggers", s.hits], ["Last triggered", fmtTs(s.last)]]} />
        {Object.entries(s.sql).map(([k, v]) => <Section key={k} title={`Compiled DuckDB SQL · ${k}`}><Sql text={v} /></Section>)}
      </Drawer>}
    </Page>
  );
}
