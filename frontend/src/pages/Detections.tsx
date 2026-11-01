import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { createColumnHelper } from "@tanstack/react-table";
import { RotateCcw } from "lucide-react";
import { api, withWs } from "../lib/api";
import type { Detection, Explanation, GroupNode, Incident } from "../lib/api";
import { detectorLabel, fmtDay, fmtN, fmtP, fmtTs, isModel, sevName, short, tsMs, uniq } from "../lib/format";
import { useAllIncidents, useDetections, useMetrics, useCurrentWs, useWs } from "../lib/hooks";
import { useStore } from "../lib/store";
import { Callout, Detector, Drawer, ErrorBox, EvLink, IncLink, KV, Kpi, Loading, NotAvailable, Page, Panel, Pill, Section, Select, Sev, Tech } from "../components/ui";
import { DataTable } from "../components/DataTable";
import { HBars, Trend } from "../components/charts";
import { ExplanationView } from "../components/Explanation";
import { KILL_CHAIN } from "../lib/derive";

const c = createColumnHelper<Detection>();
const FUTURE = [["GCN + GRU", "Sequence graph model named in the brief. Not in this repository."], ["Linear encoder + MLP", "Named in the brief. Not in this repository."]];

export function findGroup(all: Incident[], det: Detection): { inc: Incident; node: GroupNode } | null {
  for (const inc of all) for (const node of inc.observed.nodes) if (node.detection_ids.includes(det.detection_id) || node.also_matched.some((a) => a.detection_id === det.detection_id)) return { inc, node };
  return null;
}
// tactic -> phase as the backend assigned it in this workspace; a tactic it never labelled stays Unknown.
export function phaseMap(all: Incident[]) {
  const m = new Map<string, string>();
  for (const i of all) for (const n of i.observed.nodes) if (n.kill_chain_phase) m.set(n.tactic, n.kill_chain_phase);
  return m;
}

function DetectionDrawer({ d, all, onClose }: { d: Detection; all: Incident[]; onClose: () => void }) {
  const ws = useWs(); const go = useStore((s) => s.go); const hit = findGroup(all, d); const pm = phaseMap(all);
  const ex = useQuery({ queryKey: ["explain-alert", ws, hit?.node.group_id], enabled: !!hit, queryFn: () => api<Explanation>(withWs(`/explain/alert/${hit!.node.group_id}`, ws!)) });
  const ents: [string, string[]][] = [["Users", d.users], ["Hosts", d.hosts], ["Source IPs", d.src_ips], ["Destination IPs", d.dst_ips]];
  return (
    <Drawer title={d.rule_title} width={620} onClose={onClose} badge={<Sev s={d.severity} />}>
      <KV rows={[["Detection ID", <span className="mono text-2xs break-all">{d.detection_id}</span>], ["Model", <span className="flex items-center gap-1.5"><Detector rule={d.rule_id} />{detectorLabel(d.rule_id)} · <span className="mono text-2xs">{d.rule_id}</span></span>],
        ["Confidence", fmtP(d.confidence)], ["ATT&CK", <span>{d.technique_id} {d.technique_name} ({d.tactic})</span>], ["Kill chain", hit?.node.kill_chain_phase ?? pm.get(d.tactic) ?? "Unknown"], ["Window", `${fmtTs(d.ts_first)} to ${fmtTs(d.ts_last)}`], ["Events", fmtN(d.member_count)],
        ["Incident", d.incident_id ? <IncLink id={d.incident_id} /> : "Not linked to an incident"], ...(d.duplicate_of ? [["Duplicate of", <span className="mono text-2xs">{d.duplicate_of}</span>] as [string, JSX.Element]] : [])]} />
      <Section title="Explanation"><p className="text-xs text-sub">{d.evidence}</p></Section>
      <Section title="Associated entities"><div className="space-y-1">{ents.filter(([, v]) => v.length).map(([k, v]) => <div key={k} className="text-xs"><span className="text-mute">{k}: </span><span className="mono text-2xs">{v.slice(0, 12).join(", ")}{v.length > 12 ? ` +${v.length - 12} more` : ""}</span></div>)}</div></Section>
      {hit?.node.contributions && <Section title="Detector contributions (priors agreeing on this entity)"><div className="space-y-1">{Object.entries(hit.node.contributions).sort((a, b) => b[1] - a[1]).map(([k, v]) => <div key={k} className="grid grid-cols-[110px_1fr_40px] items-center gap-2 text-2xs"><span className="mono truncate text-sub">{k}</span><div className="bar"><i style={{ width: `${v * 100}%`, background: isModel(k) ? "#26D9D0" : "#94A3B8" }} /></div><span className="mono text-mute text-right">{v.toFixed(2)}</span></div>)}</div></Section>}
      <Section title={`Evidence references (${d.member_event_ids.length}${d.member_count > d.member_event_ids.length ? ` of ${fmtN(d.member_count)}` : ""})`}><div className="flex flex-wrap gap-x-2">{d.member_event_ids.slice(0, 20).map((e) => <EvLink key={e} id={e} />)}</div></Section>
      {d.incident_id && <button className="btn btn-primary" onClick={() => go("incidents", d.incident_id)}>Open incident</button>}
      {hit ? (ex.isLoading ? <Loading label="Loading explanation" /> : ex.error ? <ErrorBox error={ex.error} /> : ex.data && <div className="border-t border-line pt-3"><ExplanationView x={ex.data} kind="alert" id={hit.node.group_id} /></div>)
        : <Callout tone="cyan">This detection was not merged into an incident, so it has no alert-level explanation. Open the raw events above to review it.</Callout>}
    </Drawer>
  );
}

export function Detections() {
  const q = useDetections(); const all = useAllIncidents(); const { detFilter: f, setDetFilter } = useStore(); const cur = useCurrentWs(); const metrics = useMetrics(!!cur?.has_metrics);
  const param = useStore((s) => s.param);
  const [sel, setSel] = useState<Detection | null>(null);
  const data = q.data ?? [];
  const set = (k: keyof typeof f) => (v: string) => setDetFilter({ ...f, [k]: v || undefined });
  const opts = useMemo(() => ({ tech: uniq(data.map((d) => d.technique_id)).sort(), days: uniq(data.map((d) => fmtDay(d.ts_first))).sort(), tactics: uniq(data.map((d) => d.tactic)).sort(), rules: uniq(data.map((d) => d.rule_id)).sort() }), [data]);
  const rows = useMemo(() => data.filter((d) => {
    if (f.model && !(f.model === "rule" ? !isModel(d.rule_id) : d.rule_id.startsWith(f.model))) return false;
    if (f.severity && sevName(d.severity) !== f.severity) return false;
    if (f.technique && !d.technique_id.startsWith(f.technique)) return false;
    if (f.tactic && d.tactic !== f.tactic) return false;
    if (f.day && fmtDay(d.ts_first) !== f.day) return false;
    if (f.entity && ![...d.users, ...d.hosts, ...d.src_ips, ...d.dst_ips].some((e) => e.toLowerCase().includes(f.entity!.toLowerCase()))) return false;
    if (f.text && !`${d.rule_id} ${d.rule_title} ${d.detection_id}`.toLowerCase().includes(f.text.toLowerCase())) return false;
    return true;
  }), [data, f]);
  const trend = useMemo(() => {
    if (!rows.length) return [];
    const ts = rows.map((d) => tsMs(d.ts_first)); const lo = Math.min(...ts), hi = Math.max(...ts);
    const step = Math.max(3_600_000, Math.ceil((hi - lo) / 40 / 3_600_000) * 3_600_000);
    const b = new Map<number, number>();
    for (let t = lo - (lo % step); t <= hi; t += step) b.set(t, 0);
    ts.forEach((t) => b.set(t - (t % step), (b.get(t - (t % step)) ?? 0) + 1));
    return [...b].map(([t, n]) => ({ key: new Date(t).toISOString().slice(5, 16).replace("T", " "), value: n }));
  }, [rows]);
  const fam = useMemo(() => { const m = new Map<string, number>(); rows.forEach((d) => { const k = detectorLabel(d.rule_id); m.set(k, (m.get(k) ?? 0) + 1); }); return [...m].map(([key, value]) => ({ key, value })); }, [rows]);
  const columns = useMemo(() => [
    c.accessor("ts_first", { header: "Timestamp", cell: (v) => <span className="mono whitespace-nowrap">{fmtTs(v.getValue())}</span> }),
    c.accessor((d) => d.member_event_ids[0], { id: "event", header: "Event ID", enableSorting: false, cell: (v) => v.getValue() != null ? <EvLink id={v.getValue()} /> : "—" }),
    c.accessor((d) => d.users[0] ?? d.src_ips[0] ?? "", { id: "src", header: "Source", cell: (v) => { const d = v.row.original; const n = d.users.length + d.src_ips.length; return <span className="mono text-2xs" title={[...d.users, ...d.src_ips].join(", ")}>{short(v.getValue() || "—", 18)}{n > 1 ? ` +${n - 1}` : ""}</span>; } }),
    c.accessor((d) => d.hosts[0] ?? d.dst_ips[0] ?? "", { id: "dst", header: "Destination", cell: (v) => <span className="mono text-2xs">{short(v.getValue() || "—", 18)}</span> }),
    c.accessor("tactic", { header: "Category", cell: (v) => <span className="whitespace-nowrap">{v.getValue()}</span> }),
    c.accessor("rule_id", { header: "Detector", cell: (v) => <span className="flex items-center gap-1.5 whitespace-nowrap"><Detector rule={v.getValue()} /><span className="mono text-2xs">{v.getValue()}</span></span> }),
    c.accessor("severity", { header: "Severity", cell: (v) => <Sev s={v.getValue()} /> }),
    c.accessor("confidence", { header: "Confidence", cell: (v) => <span className="mono">{fmtP(v.getValue())}</span> }),
    c.accessor("technique_id", { header: "MITRE", cell: (v) => <Tech id={v.getValue()} /> }),
    c.accessor((d) => d.incident_id ?? -1, { id: "status", header: "Status", cell: (v) => { const d = v.row.original; return d.incident_id ? <IncLink id={d.incident_id} /> : d.duplicate_of ? <Pill>duplicate</Pill> : <Pill>unlinked</Pill>; } }),
  ], []);
  if (q.isLoading) return <Loading label="Loading detections" />;
  if (q.error) return <ErrorBox error={q.error} />;
  const m = metrics.data?.metrics as Record<string, { text?: string }> | undefined;
  const active = Object.values(f).some(Boolean);
  void param; void KILL_CHAIN;
  return (
    <Page title="Detection Engine" sub="YAML rules and unsupervised models. Every row links to the original log lines.">
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-2">
        <Kpi label="Total detections" value={fmtN(data.length)} sub={active ? `${fmtN(rows.length)} match filters` : undefined} /><Kpi label="Critical" value={fmtN(data.filter((d) => d.severity === 4).length)} tone={data.some((d) => d.severity === 4) ? "crit" : undefined} /><Kpi label="High severity" value={fmtN(data.filter((d) => d.severity === 3).length)} tone="warn" />
        <Kpi label="From ML models" value={fmtN(data.filter((d) => isModel(d.rule_id)).length)} tone="cyan" sub="Isolation Forest, Adamic-Adar" /><Kpi label="From rules" value={fmtN(data.filter((d) => !isModel(d.rule_id)).length)} sub={`${opts.rules.filter((r) => !isModel(r)).length} rules fired`} />
        <Kpi label="Step recall" value={m?.step_recall?.text?.split(" = ")[1] ?? "N/A"} tone={m ? "ok" : undefined} sub={m ? m.step_recall?.text?.split(" = ")[0] + " planted steps" : "no ground truth here"} />
      </div>
      <div className="grid grid-cols-1 xl:grid-cols-[1fr_360px_300px] gap-3">
        <Panel title="Detections over log time" body="p-2">{trend.length ? <Trend data={trend} color="#F59E0B" height={118} name="detections" /> : <div className="h-[118px]" />}</Panel>
        <Panel title="By detector" body="p-2"><HBars data={fam} h={118} onClick={(k) => set("model")(k.startsWith("Isolation") ? "ML-UEBA" : k.startsWith("Adamic") ? "ML-LINK" : "rule")} colors={(k) => (k === "YAML rule" ? "#64748B" : "#26D9D0")} /></Panel>
        <Panel title="Model roadmap" body="p-2 space-y-1.5 overflow-auto max-h-[150px]">{FUTURE.map(([t, w]) => <NotAvailable key={t} title={t} why={w} />)}</Panel>
      </div>
      <Panel className="h-[560px]" title={`Detections · ${fmtN(rows.length)}`} actions={active && <button className="btn btn-ghost !h-6 normal-case tracking-normal" onClick={() => setDetFilter({})}><RotateCcw size={11} />Clear filters</button>}>
        <div className="flex flex-col h-full">
          <div className="flex items-center gap-2 flex-wrap px-3 py-2 border-b border-line2">
            <Select label="All detectors" value={f.model ?? ""} onChange={set("model")} options={[["rule", "YAML rules"], ["ML-UEBA", "Isolation Forest"], ["ML-LINK", "Adamic-Adar"]]} />
            <Select label="All severities" value={f.severity ?? ""} onChange={set("severity")} options={["critical", "high", "medium", "low"]} />
            <Select label="All tactics" value={f.tactic ?? ""} onChange={set("tactic")} options={opts.tactics} />
            <Select label="All techniques" value={f.technique ?? ""} onChange={set("technique")} options={opts.tech} />
            <Select label="All days" value={f.day ?? ""} onChange={set("day")} options={opts.days} />
            <input aria-label="Filter by entity" className="field w-40" placeholder="Entity (user, host, IP)" value={f.entity ?? ""} onChange={(e) => set("entity")(e.target.value)} />
            <input aria-label="Filter by rule" className="field w-36" placeholder="Rule or text" value={f.text ?? ""} onChange={(e) => set("text")(e.target.value)} />
          </div>
          <div className="flex-1 min-h-0"><DataTable data={rows} columns={columns} onRow={setSel} selected={(r) => r === sel} initialSort={[{ id: "ts_first", desc: false }]} empty="No detection matches these filters" /></div>
        </div>
      </Panel>
      {sel && <DetectionDrawer d={sel} all={all.data} onClose={() => setSel(null)} />}
    </Page>
  );
}
