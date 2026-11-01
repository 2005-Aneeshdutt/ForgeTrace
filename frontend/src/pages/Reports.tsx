import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Check, Download, Printer, X } from "lucide-react";
import { api, useTelemetry, withWs } from "../lib/api";
import type { Explanation, Incident, Metrics, Overview, Reach, SimResult } from "../lib/api";
import { countBy, download, fmtBytes, fmtDur, fmtN, fmtTs, pad, uniq } from "../lib/format";
import { useAllIncidents, useCurrentWs, useDetections, useExplainIncident, useIncident, useMetrics, useOverview, useReach, useSelectedIncident, useWs } from "../lib/hooks";
import { Empty, ErrorBox, EvLink, Kpi, Loading, NotAvailable, Page, Panel, Pill, Tech } from "../components/ui";
import { HBars } from "../components/charts";
import { IncidentGraph } from "../components/IncidentGraph";
import type { CyHandle } from "../components/CyGraph";
import { IncidentPicker } from "../components/IncidentPicker";
import { incidentName, orderedSteps } from "../lib/derive";

function markdown(inc: Incident, x: Explanation | undefined, r: Reach | undefined, sim: SimResult | null | undefined, ws: string) {
  const steps = orderedSteps(inc); const L: string[] = [];
  L.push(`# ${pad(inc.incident_id)}: ${incidentName(inc)}`, "", `Workspace: ${ws} · Risk ${inc.risk_score.toFixed(1)} · Severity ${inc.severity} · Config ${inc.config_hash.slice(0, 12)}`, "", "## Summary", "", x?.headline ?? "", "", x?.summary ?? "", "");
  L.push(`Merged ${inc.raw_alert_count_total} alerts covering ${inc.member_event_count} raw events, ${fmtTs(inc.ts_first)} to ${fmtTs(inc.ts_last)} UTC.`, "", "## Attack timeline", "", "| # | Time (UTC) | Tactic | Kill chain | Technique | Detection | First event |", "|---|---|---|---|---|---|---|");
  steps.forEach((n, i) => L.push(`| ${i + 1} | ${fmtTs(n.ts_first)} | ${n.tactic} | ${n.kill_chain_phase ?? "Unknown"} | ${n.technique_id} ${n.technique_name} | ${n.rule_title.replace(/\|/g, "/")} | ${n.member_event_ids[0]} |`));
  L.push("", "## Affected entities", "", ...inc.entity_keys.map((e) => `- ${e}`), "", "## Asset reachability (potential, not proof of compromise)", "");
  r?.reachable.filter((a) => a.critical).forEach((a) => L.push(`- ${a.explanation}`));
  if (r && !r.reachable.some((a) => a.critical)) L.push("No critical asset is modelled as reachable.");
  L.push("", "## Containment simulation (no system was changed)", "");
  if (sim) L.push(`disable_account(${sim.actions.map((a) => a.target).join(", ")}): critical assets in reach ${sim.before_critical_reachable} to ${sim.after_critical_reachable}. ${sim.caveat}`);
  else L.push("No single account action reduces modelled critical reach.");
  L.push("", "## Evidence references", "", ...steps.flatMap((n) => [`- ${n.group_id} ${n.rule_id}: ${n.member_event_ids.slice(0, 5).join(", ")}${n.member_count > 5 ? ` (+${n.member_count - 5} more)` : ""}`]), "", "## Uncertainties", "", ...inc.uncertainty.map((u) => `- ${u}`), "");
  return L.join("\n");
}
const esc = (s: string) => s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]!));
function htmlDoc(md: string, png: string | null, title: string) {
  const body = md.split("\n").map((l) => (l.startsWith("# ") ? `<h1>${esc(l.slice(2))}</h1>` : l.startsWith("## ") ? `<h2>${esc(l.slice(3))}</h2>` : l.startsWith("- ") ? `<li>${esc(l.slice(2))}</li>` : l.startsWith("|") ? (l.startsWith("|---") ? "" : `<div class=r>${l.split("|").slice(1, -1).map((c) => `<span>${esc(c.trim())}</span>`).join("")}</div>`) : l ? `<p>${esc(l)}</p>` : "")).join("\n");
  return `<!doctype html><html><head><meta charset="utf-8"><title>${esc(title)}</title><style>body{font:14px system-ui;max-width:900px;margin:32px auto;color:#111}h2{margin-top:24px;border-bottom:1px solid #ddd}.r{display:grid;grid-template-columns:30px 150px 1fr 1fr 1.4fr 1.6fr 1fr;gap:6px;font-size:12px;border-bottom:1px solid #eee;padding:3px 0}img{max-width:100%}</style></head><body>${png ? `<img src="${png}" alt="Attack graph">` : ""}${body}</body></html>`;
}

function ReportTab() {
  const { id } = useSelectedIncident(); const q = useIncident(id); const ex = useExplainIncident(id); const r = useReach(id); const ws = useWs()!;
  const graph = useRef<CyHandle>(null);
  const best = q.data?.inferred.containment_candidates.filter((c) => c.reduction > 0).sort((a, b) => b.reduction - a.reduction)[0];
  const sim = useQuery({ queryKey: ["report-sim", ws, id, best?.action.target], enabled: !!best, queryFn: () => api<SimResult>(withWs(`/incidents/${id}/simulate`, ws), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ actions: [best!.action] }) }) });
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  const inc = q.data;
  if (!inc) return <Empty title="No incident selected" />;
  const md = markdown(inc, ex.data, r.data, sim.data, ws); const steps = orderedSteps(inc); const name = `kairos-${pad(inc.incident_id).toLowerCase()}`;
  const crit = r.data?.reachable.filter((a) => a.critical) ?? [];
  return <div className="space-y-3">
    <div className="flex items-center gap-2 flex-wrap no-print"><IncidentPicker /><span className="flex-1" />
      <button className="btn" onClick={() => download(`${name}.md`, md, "text/markdown")}><Download size={12} />Markdown</button>
      <button className="btn" onClick={() => download(`${name}.html`, htmlDoc(md, graph.current?.png() ?? null, pad(inc.incident_id)), "text/html")}><Download size={12} />HTML</button>
      <button className="btn btn-primary" onClick={() => window.print()}><Printer size={12} />Print / PDF</button></div>
    <article className="panel p-5 space-y-4 max-w-[980px] mx-auto w-full">
      <header className="border-b border-line pb-3"><div className="label">Incident report · generated from stored evidence</div><h2 className="text-lg font-semibold mt-0.5">{pad(inc.incident_id)}: {incidentName(inc)}</h2><div className="text-xs text-mute">Risk {inc.risk_score.toFixed(1)} · {inc.severity} · {fmtTs(inc.ts_first)} to {fmtTs(inc.ts_last)} UTC · {inc.raw_alert_count_total} alerts merged · config {inc.config_hash.slice(0, 12)}</div></header>
      <section><h3 className="label mb-1">Summary</h3><p className="text-sm">{ex.data?.headline}</p><p className="text-xs text-sub mt-1">{ex.data?.summary}</p></section>
      <section><h3 className="label mb-1">Attack graph</h3><div className="h-64 rounded overflow-hidden border border-line2"><IncidentGraph ref={graph} id={inc.incident_id} /></div></section>
      <section><h3 className="label mb-1">Timeline, ATT&CK and Kill Chain</h3><table className="tbl"><thead><tr>{["#", "Time UTC", "Tactic", "Kill chain", "Technique", "Evidence"].map((h) => <th key={h}>{h}</th>)}</tr></thead><tbody>{steps.map((n, i) => <tr key={n.group_id}><td className="mono">{i + 1}</td><td className="mono whitespace-nowrap">{fmtTs(n.ts_first)}</td><td>{n.tactic}</td><td>{n.kill_chain_phase ?? "Unknown"}</td><td><Tech id={n.technique_id} /> <span className="text-2xs">{n.technique_name}</span></td><td><EvLink id={n.member_event_ids[0]} /></td></tr>)}</tbody></table></section>
      <div className="grid md:grid-cols-2 gap-4">
        <section><h3 className="label mb-1">Affected entities</h3><div className="flex flex-wrap gap-1">{inc.entity_keys.map((e) => <Pill key={e}>{e}</Pill>)}</div></section>
        <section><h3 className="label mb-1">Asset reachability</h3><div className="text-2xs text-mute mb-1">Potential, not proof of compromise.</div>{crit.length ? <ul className="text-xs text-sub list-disc pl-4 space-y-0.5">{crit.map((a) => <li key={a.asset}>{a.explanation}</li>)}</ul> : <div className="text-xs text-mute">No critical asset reachable.</div>}</section>
      </div>
      <section><h3 className="label mb-1">Containment simulation</h3>{sim.data ? <p className="text-xs text-sub">Simulated disable_account({sim.data.actions.map((a) => a.target).join(", ")}): critical assets in reach {sim.data.before_critical_reachable} → {sim.data.after_critical_reachable}. No system was changed. {sim.data.caveat}</p> : <p className="text-xs text-mute">No single account action reduces modelled critical reach.</p>}</section>
      <section><h3 className="label mb-1">Uncertainties</h3><ul className="text-xs text-sub list-disc pl-4 space-y-0.5">{inc.uncertainty.map((u, i) => <li key={i}>{u}</li>)}</ul></section>
    </article>
  </div>;
}

// PRD section 4 targets, shown beside the measured value.
const TARGETS: [string, string, string, string][] = [["step_recall", "Detection (planted steps found)", "> 70%", "> 90%"], ["label_accuracy_subtechnique", "Correct labels (sub-technique)", "> 60%", "> 85%"], ["label_accuracy_parent", "Correct labels (parent)", "> 60%", "> 85%"], ["attacks_in_correct_order", "Attack path rebuilt in order", "Half", "All"], ["false_alarm_share", "False alarms (lower is better)", "< 30%", "< 10%"]];

function Evaluation({ m }: { m: Metrics }) {
  const t = m.metrics as Record<string, { text?: string; value?: number }>;
  return <div className="space-y-3">
    <Panel title="Evaluation against planted attacks" body="overflow-auto"><table className="tbl"><thead><tr>{["Measure", "Measured", "Good", "Great"].map((h) => <th key={h}>{h}</th>)}</tr></thead><tbody>
      {TARGETS.map(([k, n, g, gr]) => <tr key={k}><td className="text-ink">{n}</td><td className="mono text-cyan">{t[k]?.text ?? "N/A"}</td><td className="mono">{g}</td><td className="mono">{gr}</td></tr>)}</tbody></table>
      <div className="text-2xs text-mute px-3 py-2">The sample's generator, ground truth and rules share an author, so these figures are optimistic. Applies only to workspaces with ground truth.</div></Panel>
    <Panel title="Per-attack ground truth" body="overflow-auto"><table className="tbl"><thead><tr>{["Attack", "Step", "Expected", "Predicted", "Found", "Label", "Rules"].map((h) => <th key={h}>{h}</th>)}</tr></thead><tbody>
      {m.attacks.flatMap((a) => (a.steps ?? []).map((s) => <tr key={`${a.attack_id}${s.order}`}><td className="mono">{a.attack_id}</td><td className="mono">{s.order}</td><td className="mono">{s.gt_technique}</td><td className="mono">{s.predicted ?? "—"}</td><td>{s.found ? <Check size={13} className="text-ok" /> : <X size={13} className="text-crit" />}</td><td>{s.sub_ok ? <Pill tone="ok">exact</Pill> : s.parent_ok ? <Pill tone="warn">parent</Pill> : <Pill tone="crit">wrong</Pill>}</td><td className="mono text-2xs truncate max-w-64">{s.rules.join(", ")}</td></tr>))}</tbody></table>
      {m.attacks.filter((a) => a.decoy).map((a) => <div key={a.attack_id} className="flex items-center gap-2 px-3 py-2 text-xs text-sub border-t border-line2"><span className="mono">{a.attack_id}</span>Decoy activity {a.rejected ? <Pill tone="ok">correctly rejected</Pill> : <Pill tone="crit">raised as an incident</Pill>}</div>)}</Panel>
  </div>;
}

function Analytics({ o }: { o: Overview }) {
  const det = useDetections().data ?? []; const all = useAllIncidents(); const cur = useCurrentWs(); const metrics = useMetrics(!!cur?.has_metrics); const calls = useTelemetry((s) => s.calls);
  const sevs = useMemo(() => countBy(all.data, (i) => i.severity).map((s) => ({ key: s.key, value: s.count })), [all.data]);
  const tech = useMemo(() => countBy(det, (d) => d.technique_id).sort((a, b) => b.count - a.count).slice(0, 10).map((t) => ({ key: t.key, value: t.count })), [det]);
  const inv = calls.filter((c) => /^\/incidents\/:id$/.test(c.path)); const avg = inv.length ? inv.reduce((a, c) => a + c.ms, 0) / inv.length : null;
  const r = o.run; const s = r.stages?.ingest_s; const bytes = r.dataset?.files.reduce((a, f) => a + f.size, 0) ?? 0; const days = uniq(all.data.map((i) => i.ts_first.slice(0, 10)));
  return <div className="space-y-3">
    <div className="grid grid-cols-2 md:grid-cols-5 gap-2"><Kpi label="Ingest throughput" value={s ? `${(bytes / 2 ** 20 / s).toFixed(1)} MB/s` : "N/A"} sub={s ? undefined : r.ingest_reused ? "ingest re-used; not re-timed" : undefined} tone="cyan" /><Kpi label="Run time" value={fmtDur(r.wall_time_s ?? r.analysis_wall_time_s)} sub={r.wall_time_s == null && r.analysis_wall_time_s != null ? `analysis only · ${fmtBytes(bytes)}` : fmtBytes(bytes)} /><Kpi label="Peak memory" value={fmtBytes(r.peak_rss_bytes)} sub="main process" /><Kpi label="Open incident" value={avg != null ? `${Math.round(avg)} ms` : "N/A"} sub={`measured here · ${inv.length} calls`} tone={avg != null && avg < 500 ? "ok" : undefined} /><Kpi label="Incident days" value={fmtN(days.length)} sub="single run; no trend history" /></div>
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
      <Panel title="Severity distribution" body="p-2">{sevs.length ? <HBars data={sevs} colors={(k) => (k === "critical" || k === "high" ? "#EF4444" : k === "medium" ? "#F59E0B" : "#64748B")} /> : <Empty title="No incidents" />}</Panel>
      <Panel title="Top MITRE techniques" body="p-2"><HBars data={tech} color="#26D9D0" /></Panel>
      <Panel title="Detections by tactic" body="p-2"><HBars data={o.detections_by_tactic.map((t) => ({ key: t.key, value: t.count }))} color="#F59E0B" /></Panel>
    </div>
    {metrics.data ? <Evaluation m={metrics.data} /> : <NotAvailable title="Model performance and false-positive rate" why="Measured only where ground truth exists. This workspace has none." cmd="make score" />}
  </div>;
}

export function Reports() {
  const [tab, setTab] = useState<"report" | "analytics">("report"); const o = useOverview();
  useEffect(() => undefined, []);
  return <Page title="Reports & Analytics" sub="Reports contain only stored evidence for the selected incident.">
    <div className="flex border-b border-line2 no-print">{([["report", "Incident report"], ["analytics", "Analytics & evaluation"]] as const).map(([k, t]) => <button key={k} className={`tab ${tab === k ? "tab-on" : ""}`} onClick={() => setTab(k)}>{t}</button>)}</div>
    {tab === "report" ? <ReportTab /> : o.data ? <Analytics o={o.data} /> : <Loading />}
  </Page>;
}
