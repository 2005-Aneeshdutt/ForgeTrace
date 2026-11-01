import { useMemo } from "react";
import { fmtBytes, fmtDur, fmtN, fmtTime } from "../lib/format";
import { useAllIncidents, useCurrentWs, useDetections, useGraphStatus, useIncidents, useInputs, useJob, useOverview } from "../lib/hooks";
import { useStore } from "../lib/store";
import type { Route } from "../lib/store";
import { Detector, Empty, ErrorBox, IncLink, Kpi, Loading, Page, Panel, Pill, Sev, Tech } from "../components/ui";
import { HBars } from "../components/charts";
import { incidentName } from "../lib/derive";

const curve = (x1: number, y1: number, x2: number, y2: number) => { const m = (x1 + x2) / 2; return `M${x1},${y1} C${m},${y1} ${m},${y2} ${x2},${y2}`; };

// Dot rings of the engine core, spaced evenly around the centre.
const CORE_DOTS = [34, 50, 66, 82].flatMap((r, ri) => Array.from({ length: 12 + ri * 8 }, (_, i) => {
  const a = (i / (12 + ri * 8)) * Math.PI * 2;
  return { x: Math.cos(a) * r, y: Math.sin(a) * r, o: 0.9 - ri * 0.17 };
}));

function FlowMap({ sources, active, outputs, totals }: { sources: { key: string; count: number }[]; active: boolean; outputs: { label: string; value: number | string; route: Route; tone: string; sub?: string }[]; totals: { events: number; detections: number } }) {
  const go = useStore((s) => s.go);
  const W = 1180, H = 372, cx = 590, cy = 186;
  const sy = (i: number) => (sources.length < 2 ? cy : 30 + (i * (H - 60)) / (sources.length - 1));
  const oy = (i: number) => (outputs.length < 2 ? cy : 52 + (i * (H - 104)) / (outputs.length - 1));
  const max = Math.max(1, ...sources.map((s) => s.count));
  const w = (n: number) => 1 + 4.5 * (Math.log1p(n) / Math.log1p(max));
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-auto block" role="img" aria-label="Data flow from log sources through the engine to outputs">
      <defs>
        <radialGradient id="core"><stop offset="0" stopColor="#26D9D0" stopOpacity=".2" /><stop offset=".62" stopColor="#12B8A6" stopOpacity=".05" /><stop offset="1" stopColor="#12B8A6" stopOpacity="0" /></radialGradient>
        <filter id="glow" x="-20%" y="-60%" width="140%" height="220%"><feGaussianBlur stdDeviation="2.4" /></filter>
        <linearGradient id="inL" x1="0" x2="1"><stop offset="0" stopColor="#64748B" stopOpacity=".5" /><stop offset="1" stopColor="#26D9D0" stopOpacity=".85" /></linearGradient>
      </defs>
      <circle cx={cx} cy={cy} r="176" fill="url(#core)" />
      {sources.map((s, i) => {
        const d = curve(204, sy(i), cx - 112, cy + (i - (sources.length - 1) / 2) * 7);
        return <g key={s.key} className="cursor-pointer" onClick={() => go("ingest")}>
          <path d={d} fill="none" stroke="#26D9D0" strokeOpacity=".2" strokeWidth={w(s.count) + 2} filter="url(#glow)" />
          <path d={d} fill="none" stroke="url(#inL)" strokeOpacity=".55" strokeWidth={w(s.count)} />
          <path d={d} fill="none" stroke="#B9FFFA" strokeWidth={1.3} strokeLinecap="round" className={`flow-line ${active ? "" : "idle"}`} />
          <circle cx={204} cy={sy(i)} r="4" fill="#0B1220" stroke="#94A3B8" strokeWidth="1.4" />
          <text x={192} y={sy(i) - 1} textAnchor="end" fontSize="12" fill="#E5E7EB">{s.key}</text>
          <text x={192} y={sy(i) + 12} textAnchor="end" fontSize="10" fill="#64748B" className="mono">{fmtN(s.count)}</text>
        </g>;
      })}
      {outputs.map((o, i) => {
        const d = curve(cx + 112, cy + (i - (outputs.length - 1) / 2) * 12, 964, oy(i));
        return <g key={o.label} className="cursor-pointer" onClick={() => go(o.route)}>
          <path d={d} fill="none" stroke={o.tone} strokeOpacity=".26" strokeWidth="6" filter="url(#glow)" />
          <path d={d} fill="none" stroke={o.tone} strokeOpacity=".65" strokeWidth="2.4" />
          <path d={d} fill="none" stroke="#fff" strokeOpacity=".85" strokeWidth={1.2} strokeLinecap="round" className={`flow-line ${active ? "" : "idle"}`} />
          <circle cx={964} cy={oy(i)} r="10" fill="#0B1220" stroke={o.tone} strokeWidth="1.5" /><circle cx={964} cy={oy(i)} r="3" fill={o.tone} />
          <text x={984} y={oy(i) - 2} fontSize="21" fontWeight="600" fill="#E5E7EB" className="mono">{o.value}</text>
          <text x={984} y={oy(i) + 15} fontSize="11.5" fill="#94A3B8">{o.label}</text>
          {o.sub && <text x={984} y={oy(i) + 29} fontSize="9.5" fill="#64748B">{o.sub}</text>}
        </g>;
      })}
      <g transform={`translate(${cx} ${cy})`}>
        <circle r="112" fill="#070B14" fillOpacity=".78" stroke="#26D9D0" strokeOpacity=".2" />
        <g className={`spin-slow ${active ? "spin-fast" : ""}`}><circle r="104" fill="none" stroke="#26D9D0" strokeOpacity=".55" strokeWidth="1.5" strokeDasharray="120 40 60 433" /></g>
        <g className="spin-rev">{CORE_DOTS.map((d, i) => <circle key={i} cx={d.x} cy={d.y} r="1.5" fill="#26D9D0" opacity={d.o * 0.5} />)}</g>
        <text textAnchor="middle" y="-12" fontSize="29" fontWeight="600" fill="#F8FAFC" className="mono">{fmtN(totals.events)}</text>
        <text textAnchor="middle" y="7" fontSize="11" fill="#94A3B8">events analysed</text>
        <line x1="-34" x2="34" y1="20" y2="20" stroke="#253247" />
        <text textAnchor="middle" y="41" fontSize="17" fontWeight="600" fill="#26D9D0" className="mono">{fmtN(totals.detections)}</text>
        <text textAnchor="middle" y="56" fontSize="10" fill="#64748B">detections</text>
      </g>
    </svg>
  );
}

export function CommandCentre() {
  const ov = useOverview(); const inc = useIncidents(); const det = useDetections(); const all = useAllIncidents();
  const job = useJob().data; const inputs = useInputs().data; const graph = useGraphStatus().data; const cur = useCurrentWs();
  const go = useStore((s) => s.go);
  const o = ov.data;
  const x = useMemo(() => {
    const entities = new Set(all.data.flatMap((i) => i.entity_keys));
    const crit = new Set(all.data.flatMap((i) => i.inferred.reachability.reachable.filter((r) => r.critical).map((r) => r.asset)));
    const total = Math.max(0, ...all.data.map((i) => i.inferred.reachability.total_critical_assets));
    const paths = all.data.filter((i) => i.inferred.primary_path.group_ids.length > 1).length;
    return { entities: entities.size, crit: crit.size, total, paths };
  }, [all.data]);
  if (ov.isLoading) return <Loading label="Loading workspace" />;
  if (ov.error) return <ErrorBox error={ov.error} />;
  if (!o) return null;
  const run = o.run; const list = inc.data ?? [];
  const ingestS = run.stages?.ingest_s; const events = o.funnel.events ?? 0;
  const eps = ingestS ? events / ingestS : null;
  // Incident severity bands come from the risk score: high / medium / low (config/correlation.yml severity_bands).
  const bySev = (s: string) => list.filter((i) => i.severity === s).length;
  const highCount = bySev("high");
  const sorted = [...o.events_by_type].sort((a, b) => b.count - a.count);
  const sources = sorted.length > 7 ? [...sorted.slice(0, 6), { key: `+${sorted.length - 6} more types`, count: sorted.slice(6).reduce((a, b) => a + b.count, 0) }] : sorted;
  const running = job?.state === "running";
  const outputs = [
    { label: "Suspicious detections", value: fmtN(o.funnel.detections), route: "detections" as Route, tone: "#F59E0B", sub: `${fmtN(o.funnel.alert_groups)} alert groups` },
    { label: "Correlated incidents", value: fmtN(o.funnel.incidents), route: "incidents" as Route, tone: "#EF4444", sub: `${fmtN(o.funnel.unlinked)} components left unlinked` },
    { label: "Attack paths rebuilt", value: fmtN(x.paths), route: "graph" as Route, tone: "#26D9D0" },
    { label: "Critical assets potentially reachable", value: fmtN(x.crit), route: "reach" as Route, tone: "#12B8A6", sub: x.total ? `of ${x.total} configured critical assets` : undefined },
  ];
  const stages: [string, string, Route][] = [
    ["Ingest", `${fmtN(run.ingest?.lines)} lines`, "ingest"], ["Parse", `${o.events_by_format.map((f) => f.key).join(", ") || "—"}`, "ingest"], ["Normalise", `${fmtN(run.ingest?.events)} events · ${fmtN(run.ingest?.errors)} errors`, "ingest"],
    ["ML detection", `${fmtDur(run.stages?.ml_s)}`, "detections"], ["Rule detection", `${Object.keys(run.rule_seconds ?? {}).length} rules ran`, "rules"], ["Graph correlation", `${fmtN(run.kept_edges)} of ${fmtN(run.candidate_edges)} edges kept`, "graph"], ["Incidents", `${fmtN(run.incidents)} reconstructed`, "incidents"],
  ];
  const st = run.stages ?? {}; // detect_s includes ml_s, so rules are shown net of it
  const stageRows = [["ingest", st.ingest_s], ["rules", st.detect_s != null ? st.detect_s - (st.ml_s ?? 0) : undefined], ["ml", st.ml_s], ["correlate", st.correlate_s], ["reach & cache", st.reach_and_cache_s]].filter(([, v]) => v != null).map(([k, v]) => ({ key: k as string, value: Number((v as number).toFixed(3)) }));
  const feed = [...(det.data ?? [])].sort((a, b) => b.ts_first.localeCompare(a.ts_first)).slice(0, 8);
  return (
    <Page title="Command Centre" sub={`Workspace ${o.workspace}${o.time_span[0] ? ` · log time ${o.time_span[0].slice(0, 16)} to ${o.time_span[1]?.slice(0, 16)} UTC` : ""}`}
      actions={running ? <Pill tone="cyan">Processing: {job?.stage}</Pill> : <Pill>Last run {run.finished_at?.slice(0, 16).replace("T", " ") ?? "—"}</Pill>}>
      <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-7 gap-2">
        <Kpi label="Events processed" value={fmtN(events)} sub={`${fmtBytes(run.dataset?.files.reduce((a, f) => a + f.size, 0))} of logs`} onClick={() => go("ingest")} />
        <Kpi label="Events / second" value={eps ? fmtN(Math.round(eps)) : "N/A"} sub={eps ? "average of last ingest" : run.ingest_reused ? "ingest re-used; not re-timed" : "average of last ingest"} tone="cyan" />
        <Kpi label="Total detections" value={fmtN(o.funnel.detections)} sub={`${fmtN(o.funnel.alert_groups)} groups`} onClick={() => go("detections")} tone="warn" />
        <Kpi label="Active incidents" value={fmtN(list.filter((i) => i.status === "emitted").length)} sub="status: emitted" onClick={() => go("incidents")} />
        <Kpi label="High-severity incidents" value={fmtN(highCount)} sub={`${bySev("medium")} medium · ${bySev("low")} low`} tone={highCount ? "crit" : undefined} onClick={() => go("incidents")} />
        <Kpi label="Graph entities" value={all.loading ? "…" : fmtN(x.entities)} sub="distinct, across incidents" onClick={() => go("graph")} />
        <Kpi label="Critical assets reachable" value={all.loading ? "…" : fmtN(x.crit)} sub="potential, not proof" tone={x.crit ? "warn" : undefined} onClick={() => go("reach")} />
      </div>
      <Panel className="overflow-hidden" title="Intelligence pipeline" actions={<span className="normal-case tracking-normal font-normal text-mute">{running ? "Run in progress" : "Line width is log-scaled event count by type"}</span>}>
        <div className="grid-bg px-3 pt-3"><FlowMap sources={sources} active={running} outputs={outputs} totals={{ events, detections: o.funnel.detections ?? 0 }} /></div>
        <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-7 border-t border-line2">
          {stages.map(([t, v, r], i) => <button key={t} onClick={() => go(r)} className="text-left px-3 py-2 border-r last:border-r-0 border-line2 hover:bg-cyan/[.06] transition-colors min-w-0">
            <div className="flex items-center gap-1.5"><span className="mono text-2xs text-cyan">{String(i + 1).padStart(2, "0")}</span><span className="text-xs font-medium truncate">{t}</span></div><div className="text-2xs text-mute truncate" title={v}>{v}</div></button>)}
        </div>
      </Panel>
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-3">
        <Panel title="Recent incidents" actions={<button className="link text-2xs normal-case tracking-normal" onClick={() => go("incidents")}>View all</button>} className="h-[248px]" body="overflow-auto">
          {list.length ? list.slice(0, 8).map((i) => <div key={i.incident_id} onClick={() => go("incidents", i.incident_id)} className="flex items-center gap-2.5 px-3 py-2 border-b border-line2 cursor-pointer hover:bg-cyan/[.05]">
            <IncLink id={i.incident_id} /><span className="text-xs text-sub truncate flex-1">{incidentName(i)}</span><span className="mono text-xs text-ink">{i.risk_score.toFixed(1)}</span><Sev s={i.severity} /></div>) : <Empty title="No incidents" text="Correlation found no linked attack here." />}
        </Panel>
        <Panel title="Latest detections (by log time)" actions={<button className="link text-2xs normal-case tracking-normal" onClick={() => go("detections")}>View all</button>} className="h-[248px]" body="overflow-auto">
          {feed.length ? feed.map((d) => <div key={d.detection_id} onClick={() => d.incident_id ? go("incidents", d.incident_id) : go("detections")} className="flex items-center gap-2 px-3 py-1.5 border-b border-line2 cursor-pointer hover:bg-cyan/[.05]">
            <span className="mono text-2xs text-mute">{fmtTime(d.ts_first)}</span><Detector rule={d.rule_id} /><span className="text-xs text-sub truncate flex-1" title={d.rule_title}>{d.rule_title}</span><Tech id={d.technique_id} /></div>) : <Empty title="No detections" />}
        </Panel>
        <div className="grid grid-rows-[auto_1fr] gap-3 h-[248px] min-h-0">
          <Panel title="Status" body="p-3 text-xs grid grid-cols-2 gap-x-4 gap-y-1">
            <span className="text-mute">Ingestion</span><span className="text-right capitalize">{job?.state ?? "—"}</span>
            <span className="text-mute">Waiting in input folder</span><span className="text-right mono">{inputs?.files.length ?? "—"}</span>
            <span className="text-mute">Parse errors</span><span className={`text-right mono ${run.ingest?.errors ? "text-warn" : ""}`}>{fmtN(run.ingest?.errors)}</span>
            <span className="text-mute">Peak memory</span><span className="text-right mono">{fmtBytes(run.peak_rss_bytes)}</span>
            <span className="text-mute">Graph store (optional)</span><span className={`text-right ${graph?.available ? "text-ok" : "text-mute"}`}>{graph?.available ? "connected" : "offline"}</span>
            <span className="text-mute">Workspace type</span><span className="text-right">{cur?.live ? "live" : "batch"}</span>
          </Panel>
          <Panel title="Stage time, last run (seconds)" body="px-2 py-1 overflow-auto">{stageRows.length ? <HBars data={stageRows} unit="s" /> : <Empty title="No timings" />}</Panel>
        </div>
      </div>
    </Page>
  );
}
