import { useMemo, useState } from "react";
import { createColumnHelper } from "@tanstack/react-table";
import { ArrowLeft, FileText, FlaskConical, GitBranch, Link2, Network, Target } from "lucide-react";
import type { IncidentSummary } from "../lib/api";
import { entKind, entName, fmtN, fmtPct, fmtTime, fmtTs, pad, uniq } from "../lib/format";
import { useDetections, useExplainIncident, useIncident, useIncidents, useUnlinked } from "../lib/hooks";
import { useStore } from "../lib/store";
import { Bar, Callout, Detector, EvLink, ErrorBox, GoBtn, Kpi, Loading, NotAvailable, Page, Panel, Pill, Select, Sev, Tech, riskTone } from "../components/ui";
import { DataTable } from "../components/DataTable";
import { ExplanationView } from "../components/Explanation";
import { IncidentGraph } from "../components/IncidentGraph";
import { KILL_CHAIN, incidentName, orderedSteps } from "../lib/derive";

const c = createColumnHelper<IncidentSummary>();

function Queue() {
  const q = useIncidents(); const un = useUnlinked(); const go = useStore((s) => s.go);
  const [sev, setSev] = useState(""); const [tac, setTac] = useState(""); const [host, setHost] = useState(""); const [user, setUser] = useState(""); const [status, setStatus] = useState(""); const [day, setDay] = useState("");
  const data = q.data ?? [];
  const opts = useMemo(() => ({ tac: uniq(data.flatMap((i) => i.tactics)).sort(), hosts: uniq(data.flatMap((i) => i.top_entities.filter((e) => e.startsWith("host:")).map(entName))).sort(), users: uniq(data.flatMap((i) => i.top_entities.filter((e) => e.startsWith("user:")).map(entName))).sort(), st: uniq(data.map((i) => i.status)), days: uniq(data.map((i) => i.ts_first.slice(0, 10))).sort() }), [data]);
  const rows = data.filter((i) => (!sev || i.severity === sev) && (!tac || i.tactics.includes(tac)) && (!status || i.status === status) && (!day || i.ts_first.startsWith(day)) && (!host || i.top_entities.includes(`host:${host}`)) && (!user || i.top_entities.includes(`user:${user}`)));
  const columns = useMemo(() => [
    c.accessor("incident_id", { header: "Incident", cell: (v) => <span className="mono text-cyan">{pad(v.getValue())}</span> }),
    c.accessor((i) => incidentName(i), { id: "name", header: "Name", cell: (v) => <span className="text-ink whitespace-nowrap">{v.getValue()}</span> }),
    c.accessor("ts_first", { header: "First observed", cell: (v) => <span className="mono whitespace-nowrap">{fmtTs(v.getValue())}</span> }),
    c.accessor("ts_last", { header: "Last observed", cell: (v) => <span className="mono whitespace-nowrap">{fmtTs(v.getValue())}</span> }),
    c.accessor("severity", { header: "Severity", cell: (v) => <Sev s={v.getValue()} /> }),
    c.accessor("risk_score", { header: "Risk", cell: (v) => <div className="w-20"><div className="mono text-ink">{v.getValue().toFixed(1)}</div><Bar value={v.getValue() / 100} tone={riskTone(v.getValue())} /></div> }),
    c.accessor("raw_alert_count_total", { header: "Alerts merged", cell: (v) => <span className="mono">{fmtN(v.getValue())}</span> }),
    c.accessor((i) => i.top_entities.length, { id: "ents", header: "Entities", cell: (v) => <span className="mono text-2xs" title={v.row.original.top_entities.join(", ")}>{v.row.original.top_entities.slice(0, 2).map(entName).join(", ")}{v.getValue() > 2 ? ` +${v.getValue() - 2}` : ""}</span> }),
    c.accessor("tactic_count", { header: "Tactics", cell: (v) => <span className="mono" title={v.row.original.tactics.join(" → ")}>{v.getValue()}</span> }),
    c.accessor("status", { header: "Status", cell: (v) => <Pill tone="warn">{v.getValue()}</Pill> }),
  ], []);
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  return (
    <Page title="Incident Management" sub="Sorted by risk, so the worst incident is on top. Alerts merged shows how much noise each incident absorbed.">
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-2">
        <Kpi label="Total incidents" value={fmtN(data.length)} /><Kpi label="High severity" value={fmtN(data.filter((i) => i.severity === "high").length)} tone={data.some((i) => i.severity === "high") ? "crit" : undefined} /><Kpi label="Medium severity" value={fmtN(data.filter((i) => i.severity === "medium").length)} tone="warn" />
        <Kpi label="Investigating" value="N/A" sub="no case workflow in backend" /><Kpi label="Resolved" value="N/A" sub="no case workflow in backend" /><Kpi label="Alerts merged" value={fmtN(data.reduce((a, i) => a + i.raw_alert_count_total, 0))} tone="cyan" sub={un.data ? `${un.data.length} groups left unlinked` : undefined} />
      </div>
      <Panel className="flex-1 min-h-[420px]" title={`Queue · ${rows.length}`}>
        <div className="flex flex-col h-full">
          <div className="flex items-center gap-2 flex-wrap px-3 py-2 border-b border-line2">
            <Select label="All severities" value={sev} onChange={setSev} options={["high", "medium", "low"]} /><Select label="All statuses" value={status} onChange={setStatus} options={opts.st} /><Select label="All days" value={day} onChange={setDay} options={opts.days} />
            <Select label="All tactics" value={tac} onChange={setTac} options={opts.tac} /><Select label="All hosts" value={host} onChange={setHost} options={opts.hosts} /><Select label="All users" value={user} onChange={setUser} options={opts.users} />
          </div>
          <div className="flex-1 min-h-0"><DataTable data={rows} columns={columns} onRow={(i) => go("incidents", i.incident_id)} empty="No incident matches these filters" /></div>
        </div>
      </Panel>
      {!!un.data?.length && <Panel title={`Linked groups left out of incidents · ${un.data.length}`} className="max-h-56" body="overflow-auto"><table className="tbl"><thead><tr>{["Tactics", "Why not an incident", "Rules", "Users / hosts"].map((h) => <th key={h}>{h}</th>)}</tr></thead>
        <tbody>{un.data.map((u, i) => <tr key={i}><td>{u.tactics.join(", ")}</td><td>{u.reason}</td><td className="mono text-2xs">{uniq(u.groups.map((g) => g.rule_id)).join(", ")}</td><td className="mono text-2xs">{uniq(u.groups.flatMap((g) => [...g.users, ...g.hosts])).slice(0, 4).join(", ")}</td></tr>)}</tbody></table></Panel>}
    </Page>
  );
}

function Workspace({ id }: { id: number }) {
  const q = useIncident(id); const ex = useExplainIncident(id); const det = useDetections(); const go = useStore((s) => s.go);
  const [tab, setTab] = useState<"story" | "detections" | "uncertainty">("story");
  const inc = q.data;
  const steps = useMemo(() => (inc ? orderedSteps(inc) : []), [inc]);
  if (q.isLoading) return <Loading label="Opening incident" />;
  if (q.error) return <ErrorBox error={q.error} />;
  if (!inc) return null;
  const rel = (det.data ?? []).filter((d) => d.incident_id === id);
  const reachCrit = inc.inferred.reachability.critical_reachable;
  const stages = new Set(inc.observed.nodes.map((n) => n.kill_chain_phase));
  const ents = inc.entity_keys;
  return (
    <Page title={`${pad(id)} · ${incidentName(inc)}`} sub={`${fmtTs(inc.ts_first)} to ${fmtTs(inc.ts_last)} UTC`}
      actions={<div className="flex gap-1.5 flex-wrap"><button className="btn btn-ghost" onClick={() => go("incidents")}><ArrowLeft size={12} />Queue</button><GoBtn to="graph" primary><GitBranch size={12} />Attack graph</GoBtn><GoBtn to="killchain"><Link2 size={12} />Kill chain</GoBtn><GoBtn to="reach"><Target size={12} />Reachability</GoBtn><GoBtn to="simulate"><FlaskConical size={12} />Simulate</GoBtn><GoBtn to="reports"><FileText size={12} />Report</GoBtn></div>}>
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-2">
        <Kpi label="Risk score" value={inc.risk_score.toFixed(1)} tone={inc.risk_score >= 80 ? "crit" : "warn"} sub={Object.entries(inc.risk_terms).map(([k, v]) => `${k} ${v.toFixed(2)}`).join(" · ")} /><Kpi label="Severity" value={<span className="capitalize">{inc.severity}</span>} sub={`status: ${inc.status}`} />
        <Kpi label="Attack steps" value={fmtN(steps.length)} sub={`${inc.tactics.length} tactics`} /><Kpi label="Alerts merged" value={fmtN(inc.raw_alert_count_total)} sub={`${fmtN(inc.member_event_count)} raw events`} tone="cyan" />
        <Kpi label="Affected entities" value={fmtN(ents.length)} sub={`${ents.filter((e) => e.startsWith("user:")).length} users · ${ents.filter((e) => e.startsWith("host:")).length} hosts`} /><Kpi label="Critical assets reachable" value={fmtN(reachCrit)} tone={reachCrit ? "warn" : undefined} sub="potential, not proof" onClick={() => go("reach")} />
      </div>
      <Panel body="px-3 py-2.5">
        <div className="flex items-center gap-1 overflow-x-auto">{inc.inferred.primary_path.stages.map((s, i) => <span key={i} className="flex items-center gap-1 shrink-0">{i > 0 && <span className="text-mute">→</span>}<Pill tone="cyan">{s}</Pill></span>)}<span className="flex-1" /><span className="text-2xs text-mute shrink-0 ml-2">Kill chain coverage {KILL_CHAIN.filter((k) => stages.has(k)).length}/{KILL_CHAIN.length}</span></div>
      </Panel>
      <div className="grid grid-cols-1 xl:grid-cols-[1fr_1fr] gap-3">
        <Panel title="Attack timeline" className="h-[420px]" body="overflow-auto p-3">
          <ol className="relative border-l border-line ml-1.5 space-y-2.5">
            {steps.map((n, i) => <li key={n.group_id} className="pl-4 relative">
              <i className="absolute -left-[5px] top-1.5 w-[9px] h-[9px] rounded-full border-2 border-bg" style={{ background: n.severity >= 3 ? "#EF4444" : "#F59E0B" }} />
              <div className="flex items-center gap-2"><span className="mono text-2xs text-mute">{fmtTime(n.ts_first)}</span><Detector rule={n.rule_id} /><Tech id={n.technique_id} /><span className="text-2xs text-cyan">{n.tactic}</span><span className="flex-1" /><EvLink id={n.member_event_ids[0]} label={`${fmtN(n.member_count)} events`} /></div>
              <div className="text-xs text-ink">{i + 1}. {n.rule_title}</div><div className="text-2xs text-mute truncate" title={n.evidence[0]}>{n.evidence[0]}</div>
            </li>)}
          </ol>
        </Panel>
        <Panel title="Attack graph preview" className="h-[420px]" actions={<button className="link text-2xs normal-case tracking-normal" onClick={() => go("graph")}>Open explorer</button>}><IncidentGraph id={id} /></Panel>
      </div>
      <Panel>
        <div className="flex border-b border-line2 px-1">{([["story", "Explanation"], ["detections", `Related detections (${rel.length})`], ["uncertainty", "Entities & uncertainty"]] as const).map(([k, t]) => <button key={k} onClick={() => setTab(k)} className={`tab ${tab === k ? "tab-on" : ""}`}>{t}</button>)}</div>
        <div className="p-3">
          {tab === "story" && (ex.isLoading ? <Loading /> : ex.error ? <ErrorBox error={ex.error} /> : ex.data && <ExplanationView x={ex.data} kind="incident" id={String(id)} />)}
          {tab === "detections" && <table className="tbl"><thead><tr>{["Time", "", "Detection", "Technique", "Tactic", "Severity", "Events"].map((h) => <th key={h}>{h}</th>)}</tr></thead><tbody>{rel.map((d) => <tr key={d.detection_id}><td className="mono whitespace-nowrap">{fmtTs(d.ts_first)}</td><td><Detector rule={d.rule_id} /></td><td>{d.rule_title}</td><td><Tech id={d.technique_id} /></td><td>{d.tactic}</td><td><Sev s={d.severity} /></td><td><EvLink id={d.member_event_ids[0]} label={fmtN(d.member_count)} /></td></tr>)}</tbody></table>}
          {tab === "uncertainty" && <div className="grid md:grid-cols-2 gap-4">
            <div><div className="label mb-1.5 flex items-center gap-1"><Network size={11} />Entities</div><div className="flex flex-wrap gap-1">{ents.map((e) => <Pill key={e} title={entKind(e)}>{e}</Pill>)}</div></div>
            <div className="space-y-2"><div className="label">What remains uncertain</div><ul className="list-disc pl-4 text-xs text-sub space-y-0.5">{inc.uncertainty.map((u, i) => <li key={i}>{u}</li>)}</ul><Callout tone="cyan">{inc.inferred.note}</Callout>
              <NotAvailable title="Acknowledge, assign, resolve" why="The API has no case workflow, so incident status cannot be changed here." /><div className="text-2xs text-mute">Mean link score {fmtPct(inc.inferred.edges.reduce((a, e) => a + e.score, 0) / Math.max(1, inc.inferred.edges.length))}</div></div>
          </div>}
        </div>
      </Panel>
    </Page>
  );
}

export function Incidents() {
  const param = useStore((s) => s.param); const setIncident = useStore((s) => s.setIncident);
  const id = param && /^\d+$/.test(param) ? Number(param) : null;
  useMemo(() => { if (id != null) setIncident(id); }, [id, setIncident]);
  return id != null ? <Workspace key={id} id={id} /> : <Queue />;
}
