import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import type { ElementDefinition } from "cytoscape";
import { Crosshair, Expand, Pause, Play, Route as RouteIcon, Search, Share2, Workflow } from "lucide-react";
import { api, withWs } from "../lib/api";
import type { Explanation, GraphStatus, GroupNode, InferredEdge, KgEdge, KgGraph, KgNode } from "../lib/api";
import { fmtDur, fmtN, fmtP, fmtTime, fmtTs, pad, short } from "../lib/format";
import { useCurrentWs, useExplainIncident, useGraphStatus, useIncident, useReach, useSelectedIncident, useWs } from "../lib/hooks";
import { useStore } from "../lib/store";
import { Basis, Bar, Callout, Detector, Empty, ErrorBox, EvLink, KV, Loading, NotAvailable, Pill, Section, Sev, Tech } from "../components/ui";
import { CyGraph, cardImage } from "../components/CyGraph";
import type { CyHandle } from "../components/CyGraph";
import { C, TYPE_LABEL, entityColor, entityElements, stepElements } from "../components/IncidentGraph";
import { IncidentPicker } from "../components/IncidentPicker";
import { buildEntityGraph, orderedSteps } from "../lib/derive";
import type { GEntity, GRelation } from "../lib/derive";
import { ExplanationView } from "../components/Explanation";

const Legend = () => <div className="flex items-center gap-3 text-2xs text-mute flex-wrap">
  {[[C.red, "Implicated"], [C.amber, "Suspicious / in incident"], [C.cyan, "Context"]].map(([c, t]) => <span key={t} className="flex items-center gap-1"><i className="w-2 h-2 rounded-sm" style={{ background: c }} />{t}</span>)}
  <span className="flex items-center gap-1"><i className="w-4 border-t border-sub" />Observed</span><span className="flex items-center gap-1"><i className="w-4 border-t border-dashed border-warn" />Inferred / configured</span>
</div>;

function EvIds({ ids, total }: { ids: number[]; total?: number }) {
  return <div className="flex flex-wrap gap-x-2">{ids.slice(0, 10).map((e) => <EvLink key={e} id={e} />)}{(total ?? ids.length) > 10 && <span className="text-2xs text-mute">+{fmtN((total ?? ids.length) - 10)} more</span>}</div>;
}
function EntityInspect({ e, onExpand }: { e: GEntity; onExpand: () => void }) {
  const { setDetFilter, go, setSimTargets } = useStore();
  return <div className="space-y-2.5">
    <KV rows={[["Entity", <span className="mono text-2xs break-all">{e.id}</span>], ["Type", TYPE_LABEL[e.type]], ["First seen", fmtTs(e.first)], ["Last seen", fmtTs(e.last)], ["State", e.compromised ? `Implicated (weight ${e.compromised.weight})` : e.incident ? "In incident" : "Context from reachability"], ["Techniques", [...e.techniques].length ? <span className="flex flex-wrap gap-1.5">{[...e.techniques].map((t) => <Tech key={t} id={t} />)}</span> : "—"], ["Detectors", [...e.rules].join(", ") || "—"]]} />
    {e.compromised && <Callout>{e.compromised.reason}</Callout>}
    {e.reach && <Callout tone="cyan">{e.reach.explanation}. Potential reachability, not proof of compromise.</Callout>}
    {e.events.length > 0 && <Section title={`Associated events (${e.events.length})`}><EvIds ids={[...new Set(e.events)]} /></Section>}
    <div className="flex gap-1.5 flex-wrap"><button className="btn" onClick={onExpand}><Expand size={12} />Expand neighbours</button>
      <button className="btn" onClick={() => { setDetFilter({ entity: e.name }); go("detections"); }}>Detections</button>
      {e.type === "user" && <button className="btn" onClick={() => { setSimTargets([e.id.slice(5)]); go("simulate"); }}>Simulate disable</button>}</div>
  </div>;
}
function RelationInspect({ r, g }: { r: GRelation; g: Map<string, GEntity> }) {
  return <div className="space-y-2.5"><KV rows={[["Relationship", <span className="mono text-cyan">{r.relation}</span>], ["Source", g.get(r.src)?.name], ["Destination", g.get(r.dst)?.name], ["Classification", <Basis kind={r.basis} />], ["First", fmtTs(r.first)], ["Last", fmtTs(r.last)], ...(r.weight != null ? [["Weight", r.weight] as [string, number]] : [])]} />
    <Section title="Why this relationship exists"><p className="text-xs text-sub">{r.text || "Configured in config/assets.yaml."}</p></Section>
    {r.events.length ? <Section title={`Supporting events (${r.events.length})`}><EvIds ids={r.events} /></Section> : <div className="text-2xs text-mute">No log events: this link comes from configuration.</div>}</div>;
}
function StepInspect({ n }: { n: GroupNode }) {
  return <div className="space-y-2.5"><div className="flex items-center gap-1.5"><Detector rule={n.rule_id} /><Sev s={n.severity} /><Tech id={n.technique_id} /></div><div className="text-xs">{n.rule_title}</div>
    <KV rows={[["Tactic", n.tactic], ["Kill chain", n.kill_chain_phase ?? "Unknown"], ["Window", `${fmtTime(n.ts_first)} to ${fmtTime(n.ts_last)}`], ["Events", fmtN(n.member_count)], ["Alerts merged", n.raw_alert_count], ["Fused score", fmtP(n.p_malicious)]]} />
    <Section title="Evidence">{n.evidence.map((t, i) => <p key={i} className="text-xs text-sub mb-1">{t}</p>)}</Section><Section title="Raw events"><EvIds ids={n.member_event_ids} total={n.member_count} /></Section></div>;
}
function LinkInspect({ e, nodes }: { e: InferredEdge; nodes: GroupNode[] }) {
  const t = (g: string) => nodes.find((n) => n.group_id === g)?.technique_id ?? g;
  return <div className="space-y-2.5"><KV rows={[["Link", <span className="mono">{t(e.src_group_id)} → {t(e.dst_group_id)}</span>], ["Classification", <Basis kind={e.kind} />], ["Score", <span className="mono">{e.score.toFixed(3)}</span>], ["Gap", fmtDur(e.delta_t_s)]]} />
    <Section title="Why linked">{e.reasons.map((r, i) => <div key={i} className="text-xs text-sub flex justify-between gap-2"><span>{r.type.replace(/_/g, " ")} {r.entity_key && <span className="mono text-2xs">{r.entity_key}</span>}</span><span className="mono text-2xs">{r.weight}</span></div>)}</Section>
    <Section title="Score terms"><div className="space-y-1">{Object.entries(e.score_terms).map(([k, v]) => <div key={k} className="grid grid-cols-[16px_1fr_40px] items-center gap-2 text-2xs"><span className="mono text-mute">{k}</span><Bar value={v} /><span className="mono text-right text-mute">{v.toFixed(2)}</span></div>)}</div></Section>
    <Section title="Supporting events"><EvIds ids={e.evidence_event_ids} /></Section></div>;
}

function Incidents() {
  const { id } = useSelectedIncident();
  const q = useIncident(id); const r = useReach(id); const ex = useExplainIncident(id);
  const inc = q.data;
  const cy = useRef<CyHandle>(null);
  const [view, setView] = useState<"steps" | "entities">("entities");
  const [potential, setPotential] = useState(false); const [off, setOff] = useState<Set<string>>(new Set()); const [tech, setTech] = useState(""); const [search, setSearch] = useState("");
  const [sel, setSel] = useState<{ id: string; kind: "node" | "edge" } | null>(null);
  const [cursor, setCursor] = useState<number | null>(null); const [playing, setPlaying] = useState(false);
  const steps = useMemo(() => (inc ? orderedSteps(inc) : []), [inc]);
  const g = useMemo(() => (inc ? buildEntityGraph(inc, r.data, { potential }) : null), [inc, r.data, potential]);
  const cut = cursor == null ? undefined : steps[cursor]?.ts_last;
  const els: ElementDefinition[] = useMemo(() => {
    if (!inc || !g) return [];
    if (view === "steps") return stepElements(inc, cut);
    const relIn = (id: string) => { const x = g.relations.get(id)!; return (!cut || (x.first != null && x.first <= cut)) && (!tech || x.techniques.has(tech)); };
    const live = new Set<string>();
    for (const x of g.relations.values()) if (relIn(x.id)) { live.add(x.src); live.add(x.dst); }
    return entityElements(g, (e) => !off.has(e.type) && (live.has(e.id) || (!cut && !tech)), relIn);
  }, [inc, g, view, off, tech, cut]);
  useEffect(() => { setCursor(null); setPlaying(false); setSel(null); }, [id]);
  useEffect(() => {
    if (!playing) return;
    const t = setInterval(() => setCursor((c) => { const n = (c ?? -1) + 1; if (n >= steps.length - 1) { setPlaying(false); return null; } return n; }), 1100);
    return () => clearInterval(t);
  }, [playing, steps.length]);
  useEffect(() => { const t = search.trim().toLowerCase(); const c = cy.current?.cy(); if (!c) return; if (!t) cy.current?.highlight(null); else cy.current?.highlight(c.nodes().filter((n) => n.id().toLowerCase().includes(t)).map((n) => n.id())); }, [search, els]);
  const expand = () => { const c = cy.current?.cy(); if (sel && c) { setPotential(true); cy.current?.highlight(c.getElementById(sel.id).closedNeighborhood().map((x) => x.id())); } };
  const showPath = () => { if (!inc) return; if (view !== "steps") setView("steps"); setTimeout(() => cy.current?.highlight([...inc.inferred.primary_path.group_ids, ...inc.inferred.primary_path.edge_ids]), 80); };
  if (q.isLoading) return <Loading label="Building graph" />;
  if (q.error) return <ErrorBox error={q.error} />;
  if (!inc || !g) return <Empty title="No incident selected" text="This workspace has no incidents to graph." />;
  const techs = [...new Set(inc.observed.nodes.map((n) => n.technique_id))];
  const types = [...new Set([...g.entities.values()].map((e) => e.type))];
  const selNode = sel?.kind === "node" ? (view === "entities" ? g.entities.get(sel.id) : undefined) : undefined;
  const selStep = sel?.kind === "node" && view === "steps" ? inc.observed.nodes.find((n) => n.group_id === sel.id) : undefined;
  const selRel = sel?.kind === "edge" && view === "entities" ? g.relations.get(sel.id) : undefined;
  const selLink = sel?.kind === "edge" && view === "steps" ? inc.inferred.edges.find((e) => e.edge_id === sel.id) : undefined;
  return (
    <div className="flex-1 min-h-0 grid grid-cols-[232px_1fr_312px] grid-rows-[1fr_128px] gap-2 px-2 pb-2">
      <div className="panel row-span-2 overflow-auto p-2.5 space-y-3">
        <div className="space-y-1.5"><IncidentPicker /><div className="flex items-center gap-1.5"><Sev s={inc.severity} /><span className="mono text-xs">risk {inc.risk_score.toFixed(1)}</span></div>
          <div className="text-2xs text-mute">{fmtN(inc.member_event_count)} events · {inc.raw_alert_count_total} alerts merged · {g.entities.size} entities</div></div>
        <div><div className="label mb-1">View</div><div className="grid grid-cols-2 gap-1">
          <button className={`btn ${view === "entities" ? "btn-primary" : ""}`} onClick={() => { setView("entities"); setSel(null); }}><Share2 size={12} />Entities</button>
          <button className={`btn ${view === "steps" ? "btn-primary" : ""}`} onClick={() => { setView("steps"); setSel(null); }}><Workflow size={12} />Steps</button></div></div>
        <div className="relative"><Search size={11} className="absolute left-2 top-2 text-mute" /><input aria-label="Search nodes" className="field w-full !pl-6" placeholder="Search nodes" value={search} onChange={(e) => setSearch(e.target.value)} /></div>
        <button className="btn w-full" onClick={showPath}><RouteIcon size={12} />Highlight attack path</button>
        {view === "entities" && <>
          <div><div className="label mb-1">Entity types</div>{types.map((t) => <label key={t} className="flex items-center gap-2 text-xs text-sub h-5 cursor-pointer"><input type="checkbox" className="accent-[#26D9D0]" checked={!off.has(t)} onChange={() => { const s = new Set(off); s.has(t) ? s.delete(t) : s.add(t); setOff(s); }} />{TYPE_LABEL[t]}<span className="ml-auto mono text-2xs text-mute">{[...g.entities.values()].filter((e) => e.type === t).length}</span></label>)}</div>
          <label className="flex items-center gap-2 text-xs text-sub cursor-pointer"><input type="checkbox" className="accent-[#26D9D0]" checked={potential} onChange={(e) => setPotential(e.target.checked)} />Show potential reach paths</label>
          <div><div className="label mb-1">Technique</div><select aria-label="Filter by technique" className="field w-full" value={tech} onChange={(e) => setTech(e.target.value)}><option value="">All techniques</option>{techs.map((t) => <option key={t}>{t}</option>)}</select></div>
          {g.sampled && <Callout>Showing {fmtN(inc.observed.events.length)} of {fmtN(inc.member_event_count)} member events embedded in the incident record.</Callout>}
          <div><div className="label mb-1">Entities</div><div className="space-y-px max-h-52 overflow-auto">{[...g.entities.values()].filter((e) => e.incident).sort((a, b) => Number(!!b.compromised) - Number(!!a.compromised)).map((e) => <button key={e.id} onClick={() => setSel({ id: e.id, kind: "node" })} className={`w-full flex items-center gap-1.5 px-1 h-5 text-left text-2xs rounded hover:bg-cyan/10 ${sel?.id === e.id ? "bg-cyan/10" : ""}`}><i className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: entityColor(e) }} /><span className="mono truncate text-sub">{e.name}</span></button>)}</div></div>
        </>}
      </div>
      <div className="panel overflow-hidden relative min-h-0">
        <CyGraph ref={cy} key={view} elements={els} layout="preset" selected={sel?.id} onSelect={(i, k) => { setSel(i && k ? { id: i, kind: k } : null); if (!i) cy.current?.highlight(null); }} />
        <div className="absolute top-2 left-2 right-2 flex justify-between pointer-events-none"><div className="pointer-events-auto bg-bg/80 rounded px-2 py-1"><Legend /></div></div>
      </div>
      <div className="row-span-2 flex flex-col gap-2 min-h-0">
        <div className="panel flex flex-col h-[42%] min-h-0"><div className="flex items-center gap-1.5 h-8 px-2.5 border-b border-line2 shrink-0"><i className="w-2 h-2 rounded-full bg-crit" /><i className="w-2 h-2 rounded-full bg-warn" /><i className="w-2 h-2 rounded-full bg-ok" /><span className="label ml-1 text-cyan">Investigation terminal</span></div>
          <div className="flex-1 overflow-auto bg-bg px-2.5 py-1.5 mono text-2xs leading-[17px]">
            {ex.data?.steps?.map((s, i) => <div key={i} className="mb-1.5"><span className="text-mute">{fmtTime(s.when)} </span><span className={s.rule_id.startsWith("ML-") ? "text-cyan" : "text-warn"}>[{s.rule_id}]</span> <span className="text-ink">{s.what}</span><div className="text-mute pl-2">{s.linked_from_previous}</div></div>) ?? <span className="text-mute">Loading…</span>}
            {ex.data && <div className="text-ok">[DONE] {ex.data.headline}</div>}
          </div></div>
        <div className="panel flex-1 min-h-0 flex flex-col"><div className="panel-h">{selRel || selLink ? "Relationship" : selNode || selStep ? "Selection" : "Inspector"}</div>
          <div className="flex-1 overflow-auto p-2.5">
            {selNode && <EntityInspect e={selNode} onExpand={expand} />}{selRel && <RelationInspect r={selRel} g={g.entities} />}{selStep && <StepInspect n={selStep} />}{selLink && <LinkInspect e={selLink} nodes={inc.observed.nodes} />}
            {!sel && <div className="text-xs text-mute">Select a node or edge. Every edge shows its supporting events and why it exists.</div>}
          </div></div>
      </div>
      <div className="panel flex flex-col min-h-0 min-w-0">
        <div className="flex items-center gap-2 h-8 px-2.5 border-b border-line2 shrink-0"><button aria-label={playing ? "Pause replay" : "Replay attack"} className="btn btn-primary !h-6" onClick={() => { if (!playing && cursor == null) setCursor(0); setPlaying(!playing); }}>{playing ? <Pause size={11} /> : <Play size={11} />}{playing ? "Pause" : "Replay"}</button>
          <span className="label">Attack timeline</span><span className="flex-1" /><button className="link text-2xs" onClick={() => { setCursor(null); setPlaying(false); }}>{cursor != null ? "Show all" : ""}</button></div>
        <div className="flex-1 overflow-x-auto flex items-stretch gap-1.5 p-2">
          {steps.map((n, i) => <button key={n.group_id} onClick={() => { setPlaying(false); setCursor(i); }} className={`shrink-0 w-[150px] text-left rounded border px-2 py-1 transition-colors ${cursor === i ? "border-cyan bg-cyan/10" : cursor != null && i > cursor ? "border-line2 opacity-40" : n.severity >= 3 ? "border-crit/40 bg-crit/[.05]" : "border-warn/30 bg-warn/[.04]"}`}>
            <div className="mono text-2xs text-mute">{fmtTime(n.ts_first)}</div><div className="mono text-2xs text-ink truncate">{n.technique_id}</div><div className="text-2xs text-sub truncate">{n.tactic}</div></button>)}
        </div>
      </div>
    </div>
  );
}

// ---- optional Neo4j knowledge graph: alerts, entities and long-range links
const KG_COLOR: Record<string, string> = { Alert: C.amber, Incident: C.red, Campaign: C.red, User: C.cyan, Host: "#94A3B8", IP: C.amber };
const kgName = (n: KgNode) => String(n.props.name ?? n.props.addr ?? n.props.rule_id ?? n.id);
function kgElements(d: KgGraph): ElementDefinition[] {
  const ids = new Set(d.nodes.map((n) => n.id)); const out: ElementDefinition[] = [];
  for (const n of d.nodes) { const color = KG_COLOR[n.label] ?? C.grey; out.push({ group: "nodes", data: { id: n.id, w: 164, h: 58, color, img: cardImage({ kind: n.label, title: kgName(n), sub: n.label === "Alert" ? `${n.props.technique_id ?? ""} ${n.props.tactic ?? ""}` : undefined, color, w: 164, h: 58 }) } }); }
  d.edges.forEach((e: KgEdge, i) => { if (ids.has(e.from) && ids.has(e.to)) out.push({ group: "edges", data: { id: `k${i}`, source: e.from, target: e.to, color: e.type === "LEADS_TO" ? C.cyan : e.type === "RELATED" ? C.amber : "#475569", label: e.type === "INVOLVES" ? "" : e.type, style: e.type === "RELATED" ? "dashed" : "solid" } }); });
  return out;
}
function Knowledge() {
  const st = useGraphStatus(); const ws = useWs()!; const [key, setKey] = useState<{ kind: string; id: string } | null>(null); const [text, setText] = useState(""); const [sel, setSel] = useState<string | null>(null);
  const on = !!st.data?.available;
  const inc = useQuery({ queryKey: ["kg-inc", ws], enabled: on, queryFn: () => api<{ incidents: { id: string; steps?: number; tactics?: string[] }[] }>(withWs("/graph/incidents", ws)) });
  const camp = useQuery({ queryKey: ["kg-camp", ws], enabled: on, queryFn: () => api<{ campaigns: { id: string; alerts?: number }[] }>(withWs("/graph/campaigns", ws)) });
  const g = useQuery({ queryKey: ["kg", ws, key], enabled: on && !!key, queryFn: () => api<KgGraph>(key!.kind === "explore" ? withWs(`/graph/neighbors?key=${encodeURIComponent(key!.id)}`, ws) : withWs(`/graph/chain?kind=${key!.kind}&id=${encodeURIComponent(key!.id)}`, ws)) });
  const ex = useQuery({ queryKey: ["kg-ex", ws, sel], enabled: !!sel && !!g.data?.nodes.find((n) => n.id === sel && n.label === "Alert"), queryFn: () => { const n = g.data!.nodes.find((x) => x.id === sel)!; return api<Explanation>(withWs(`/explain/alert/${encodeURIComponent(String(n.props.group_id ?? n.id))}`, ws)); } });
  const els = useMemo(() => (g.data ? kgElements(g.data) : []), [g.data]);
  if (st.isLoading) return <Loading />;
  if (!on) return <div className="p-4"><NotAvailableKg s={st.data} /></div>;
  return <div className="flex-1 min-h-0 grid grid-cols-[240px_1fr_320px] gap-2 px-2 pb-2">
    <div className="panel overflow-auto p-2.5 space-y-3"><input aria-label="Explore entity" className="field w-full" placeholder="user:name, host:name, ip:addr" value={text} onChange={(e) => setText(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter" && text.trim()) setKey({ kind: "explore", id: text.trim() }); }} />
      <div><div className="label mb-1">Incidents ({inc.data?.incidents.length ?? 0})</div>{inc.data?.incidents.map((i) => <button key={i.id} onClick={() => setKey({ kind: "incident", id: i.id })} className="block w-full text-left mono text-2xs text-sub truncate py-1 hover:text-cyan">{i.id}</button>)}</div>
      <div><div className="label mb-1">Campaigns ({camp.data?.campaigns.length ?? 0})</div>{camp.data?.campaigns.map((i) => <button key={i.id} onClick={() => setKey({ kind: "campaign", id: i.id })} className="block w-full text-left mono text-2xs text-sub truncate py-1 hover:text-cyan">{i.id}</button>)}</div></div>
    <div className="panel overflow-hidden">{g.error ? <ErrorBox error={g.error} /> : els.length ? <CyGraph elements={els} onSelect={(i) => setSel(i)} selected={sel} /> : <Empty title="Pick an incident or campaign" text="The knowledge graph is read from Neo4j." />}</div>
    <div className="panel overflow-auto p-2.5">{ex.data ? <ExplanationView x={ex.data} kind="alert" id={ex.data.id} /> : sel ? <KV rows={Object.entries(g.data?.nodes.find((n) => n.id === sel)?.props ?? {}).slice(0, 12).map(([k, v]) => [k, short(String(v), 80)])} /> : <div className="text-xs text-mute">Select a node.</div>}</div>
  </div>;
}
const NotAvailableKg = ({ s }: { s?: GraphStatus }) => <NotAvailable title="Neo4j knowledge graph is offline" why={`Optional. Attack graphs above work without it. ${short(s?.reason ?? "", 120)}`} cmd="make graph-up && make run GRAPH=1" />;

export function GraphExplorer() {
  const param = useStore((s) => s.param); const go = useStore((s) => s.go); const cur = useCurrentWs(); const incident = useStore((s) => s.incident);
  const kg = param === "kg" || !!cur?.live;
  return (
    <div className="fade-in flex flex-col h-full min-h-[620px]">
      <div className="flex items-center gap-3 px-3 h-11 shrink-0"><h1 className="text-[15px] font-semibold tracking-tight flex items-center gap-2"><Crosshair size={14} className="text-cyan" />Attack Graph Explorer</h1>{incident != null && !kg && <Pill tone="cyan">{pad(incident)}</Pill>}<span className="flex-1" />
        <div className="flex border-b border-line2">{!cur?.live && <button className={`tab ${!kg ? "tab-on" : ""}`} onClick={() => go("graph")}>Incident graph</button>}<button className={`tab ${kg ? "tab-on" : ""}`} onClick={() => go("graph", "kg")}>Knowledge graph</button></div></div>
      {kg ? <Knowledge /> : <Incidents />}
    </div>
  );
}
