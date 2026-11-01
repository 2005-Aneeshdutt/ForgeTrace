import { useEffect, useMemo, useRef, useState } from "react";
import { Activity, Bell, ChevronDown, Check as CheckIcon, Waves, Boxes, BrainCircuit, CircuitBoard, FileBarChart, FlaskConical, GitBranch, Grid3x3, HeartPulse, LayoutDashboard, Link2, PlayCircle, Radar, Radio, Search, Settings2, ShieldAlert, Upload } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { api } from "./lib/api";
import type { Workspace } from "./lib/api";
import { fmtN, pad } from "./lib/format";
import { useCurrentWs, useDetections, useIncidents, useJob, useJobWatcher, useWorkspaces } from "./lib/hooks";
import { syncRoute, useStore } from "./lib/store";
import type { Route } from "./lib/store";
import { Empty, GoBtn, Loading, PageBoundary } from "./components/ui";
import { EvidenceDrawer } from "./components/EvidenceDrawer";
import { CommandCentre } from "./pages/CommandCentre";
import { Ingestion } from "./pages/Ingestion";
import { LiveSim } from "./pages/LiveSim";
import { Detections } from "./pages/Detections";
import { Incidents } from "./pages/Incidents";
import { GraphExplorer } from "./pages/GraphExplorer";
import { Attack } from "./pages/Attack";
import { KillChain } from "./pages/KillChain";
import { Reachability } from "./pages/Reachability";
import { Decision } from "./pages/Decision";
import { Simulator } from "./pages/Simulator";
import { Reports } from "./pages/Reports";
import { Rules } from "./pages/Rules";
import { Health } from "./pages/Health";
import { Walkthrough } from "./pages/Walkthrough";

const NAV: [Route, string, typeof Activity][] = [
  ["command", "Command Centre", LayoutDashboard], ["live", "Live Simulation", Waves], ["ingest", "Live Ingestion", Upload], ["detections", "Detection Engine", Radar], ["incidents", "Incident Management", ShieldAlert],
  ["graph", "Attack Graph Explorer", GitBranch], ["attack", "MITRE ATT&CK", Grid3x3], ["killchain", "Cyber Kill Chain", Link2], ["reach", "Asset Reachability", Boxes],
  ["decision", "Decision Intelligence", BrainCircuit], ["simulate", "Response Simulator", FlaskConical], ["reports", "Reports & Analytics", FileBarChart], ["rules", "Rules & Configuration", Settings2], ["health", "System Health", HeartPulse],
];
const PAGES: Record<Route, () => JSX.Element | null> = { command: CommandCentre, live: LiveSim, ingest: Ingestion, detections: Detections, incidents: Incidents, graph: GraphExplorer, attack: Attack, killchain: KillChain, reach: Reachability, decision: Decision, simulate: Simulator, reports: Reports, rules: Rules, health: Health, walkthrough: Walkthrough };
const NEEDS_BATCH: Route[] = ["detections", "incidents", "attack", "killchain", "reach", "decision", "simulate", "reports"];

export const Logo = ({ size = 26 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 32 32" fill="none" aria-hidden><rect x=".75" y=".75" width="30.5" height="30.5" rx="6" fill="#0B1220" stroke="#26D9D0" strokeOpacity=".6" strokeWidth="1.2" />
    <path d="M11 8v16M22 8l-8 8 8 8" stroke="#26D9D0" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" /><circle cx="14" cy="16" r="1.9" fill="#E5E7EB" /></svg>
);

function Sidebar() {
  const route = useStore((s) => s.route);
  const go = useStore((s) => s.go);
  const inc = useIncidents().data;
  return (
    <nav aria-label="Main" className="no-print w-[208px] shrink-0 bg-bg2 border-r border-line2 flex flex-col">
      <div className="h-12 flex items-center gap-2.5 px-3.5 border-b border-line2 shrink-0"><Logo /><span className="font-semibold text-[14px] tracking-tight">Kai<span className="text-cyan">ros</span></span></div>
      <div className="flex-1 overflow-auto py-2 px-2 space-y-px">
        {NAV.map(([r, t, Ic]) => (
          <button key={r} onClick={() => go(r)} aria-current={route === r ? "page" : undefined} className={`w-full flex items-center gap-2.5 h-[30px] px-2 rounded text-[12px] border transition-colors ${route === r ? "bg-cyan/10 border-cyan/30 text-cyan" : "border-transparent text-sub hover:text-ink hover:bg-raised/60"}`}>
            <Ic size={14} className="shrink-0" /><span className="truncate">{t}</span>
            {r === "incidents" && !!inc?.length && <span className="ml-auto mono text-2xs text-mute">{inc.length}</span>}
          </button>))}
      </div>
      <div className="border-t border-line2 p-2"><button onClick={() => go("walkthrough")} className={`w-full flex items-center gap-2.5 h-[30px] px-2 rounded text-[12px] border ${route === "walkthrough" ? "bg-cyan/10 border-cyan/30 text-cyan" : "border-transparent text-sub hover:text-ink"}`}><PlayCircle size={14} />Pipeline walkthrough</button></div>
    </nav>
  );
}

function GlobalSearch() {
  const [q, setQ] = useState(""); const [open, setOpen] = useState(false);
  const inc = useIncidents().data ?? []; const det = useDetections().data ?? [];
  const { go, setDetFilter } = useStore();
  const hits = useMemo(() => {
    const t = q.trim().toLowerCase();
    if (t.length < 2) return [];
    const out: { label: string; sub: string; run: () => void }[] = [];
    for (const i of inc) if (`${pad(i.incident_id)} ${i.tactics.join(" ")} ${i.techniques.join(" ")} ${i.top_entities.join(" ")}`.toLowerCase().includes(t)) out.push({ label: pad(i.incident_id), sub: `${i.severity} · ${i.top_entities.slice(0, 3).join(", ")}`, run: () => go("incidents", i.incident_id) });
    const ents = new Set<string>();
    for (const d of det) for (const e of [...d.users, ...d.hosts, ...d.src_ips, ...d.dst_ips]) if (e.toLowerCase().includes(t)) ents.add(e);
    for (const e of [...ents].slice(0, 6)) out.push({ label: e, sub: "entity · open matching detections", run: () => { setDetFilter({ entity: e }); go("detections"); } });
    for (const d of det.filter((x) => `${x.rule_id} ${x.rule_title} ${x.technique_id} ${x.technique_name}`.toLowerCase().includes(t)).slice(0, 6)) out.push({ label: `${d.rule_id} · ${d.technique_id}`, sub: d.rule_title, run: () => { setDetFilter({ text: d.rule_id }); go("detections"); } });
    return out.slice(0, 12);
  }, [q, inc, det, go, setDetFilter]);
  return (
    <div className="relative w-56">
      <Search size={12} className="absolute left-2 top-[8px] text-mute" />
      <input aria-label="Global search" className="field w-full !pl-6" placeholder="Search incidents, entities, rules" value={q} onChange={(e) => { setQ(e.target.value); setOpen(true); }} onFocus={() => setOpen(true)} onBlur={() => setTimeout(() => setOpen(false), 160)} />
      {open && q.trim().length >= 2 && (
        <div className="absolute z-50 top-8 left-0 right-0 min-w-72 panel !bg-raised shadow-xl max-h-80 overflow-auto">
          {hits.length ? hits.map((h, i) => <button key={i} onClick={() => { h.run(); setOpen(false); setQ(""); }} className="block w-full text-left px-2.5 py-1.5 hover:bg-cyan/10"><div className="mono text-xs text-ink truncate">{h.label}</div><div className="text-2xs text-mute truncate">{h.sub}</div></button>)
            : <div className="px-2.5 py-2 text-xs text-mute">No match in this workspace</div>}
        </div>)}
    </div>
  );
}

function Notifications() {
  const { notices, unread, markRead, go } = useStore();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => { const f = (e: MouseEvent) => { if (!ref.current?.contains(e.target as Node)) setOpen(false); }; document.addEventListener("mousedown", f); return () => document.removeEventListener("mousedown", f); }, []);
  return (
    <div className="relative" ref={ref}>
      <button aria-label="Notifications" className="btn btn-ghost !px-1.5 relative" onClick={() => { setOpen(!open); markRead(); }}><Bell size={14} />{unread > 0 && <i className="absolute top-1 right-1 w-1.5 h-1.5 rounded-full bg-crit" />}</button>
      {open && <div className="absolute z-50 right-0 top-8 w-80 panel !bg-raised shadow-xl max-h-96 overflow-auto">
        <div className="panel-h">Run events this session</div>
        {notices.length ? notices.map((n) => <button key={n.id} className="block w-full text-left px-3 py-2 border-b border-line2 hover:bg-cyan/10" onClick={() => { if (n.route) go(n.route, n.param); setOpen(false); }}><div className={`text-xs ${n.level === "crit" ? "text-crit" : n.level === "ok" ? "text-ok" : "text-ink"}`}>{n.text}</div><div className="text-2xs text-mute">{new Date(n.at).toLocaleTimeString()}</div></button>)
          : <div className="px-3 py-4 text-xs text-mute">Nothing yet. Finished or failed analyses appear here.</div>}
      </div>}
    </div>
  );
}

function ApiStatus() {
  const q = useQuery({ queryKey: ["ping"], queryFn: () => api<Workspace[]>("/workspaces"), refetchInterval: 10_000, retry: false });
  const ok = q.isSuccess && !q.isError;
  return <span className={`inline-flex items-center gap-1.5 h-6 px-2 rounded-full border text-2xs font-semibold tracking-wide ${q.isLoading ? "text-sub border-line" : ok ? "text-ok border-ok/40 bg-ok/10" : "text-crit border-crit/40 bg-crit/10"}`}><i className={`w-1.5 h-1.5 rounded-full bg-current ${ok ? "pulse" : ""}`} />{q.isLoading ? "CONNECTING" : ok ? "API ONLINE" : "API OFFLINE"}</span>;
}

function WorkspaceMenu({ wss, ws, setWs }: { wss: Workspace[]; ws: string | null; setWs: (w: string) => void }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => { const f = (e: MouseEvent) => { if (!ref.current?.contains(e.target as Node)) setOpen(false); }; document.addEventListener("mousedown", f); return () => document.removeEventListener("mousedown", f); }, []);
  return (
    <div className="relative" ref={ref}>
      <button aria-label="Workspace" aria-haspopup="listbox" aria-expanded={open} className="field inline-flex items-center gap-2 min-w-28 hover:border-cyan/60" onClick={() => setOpen(!open)}><span className="mono flex-1 text-left truncate max-w-32">{ws ?? "—"}</span><ChevronDown size={12} className="text-mute" /></button>
      {open && <div role="listbox" className="absolute z-50 top-8 left-0 min-w-56 panel !bg-raised shadow-xl py-1">
        {wss.map((w) => <button key={w.name} role="option" aria-selected={w.name === ws} data-ws={w.name} onClick={() => { setWs(w.name); setOpen(false); }} className={`w-full flex items-center gap-2 px-2.5 h-8 text-left hover:bg-cyan/10 ${w.name === ws ? "text-cyan" : "text-ink"}`}>
          <CheckIcon size={12} className={w.name === ws ? "" : "opacity-0"} /><span className="mono text-xs flex-1">{w.name}</span><span className="text-2xs text-mute">{w.live ? "live" : w.analysed ? `${fmtN(w.events)} events` : "empty"}</span></button>)}
      </div>}
    </div>
  );
}

function Topbar() {
  const wss = useWorkspaces().data ?? [];
  const cur = useCurrentWs();
  const { ws, setWs, go } = useStore();
  const job = useJob().data;
  const running = job?.state === "running";
  return (
    <header className="no-print h-12 shrink-0 flex items-center gap-2.5 px-3 border-b border-line2 bg-bg2/80 backdrop-blur">
      <label className="flex items-center gap-1.5"><span className="label">Workspace</span>
        <WorkspaceMenu wss={wss} ws={ws} setWs={setWs} /></label>
      <span className="hidden xl:flex items-center gap-1.5 min-w-0 text-2xs text-mute"><CircuitBoard size={12} className="shrink-0" /><span className="mono truncate max-w-44" title={cur?.files.join(", ")}>{cur?.files.length ? cur.files.join(", ") : cur?.source ?? "no dataset"}</span>{cur?.events != null && <span className="mono text-sub">· {fmtN(cur.events)} events</span>}</span>
      <span className="flex-1" />
      <GlobalSearch />
      <button onClick={() => go("ingest")} className={`inline-flex items-center gap-1.5 h-6 px-2 rounded-full border text-2xs font-semibold tracking-wide ${running ? "text-cyan border-cyan/40 bg-cyan/10" : "text-sub border-line"}`}>
        <Radio size={11} className={running ? "pulse" : ""} />{running ? `${job!.stage} ${Math.round((job!.progress ?? 0) * 100)}%` : "INGEST IDLE"}</button>
      <ApiStatus /><Notifications />
    </header>
  );
}

// Default workspace is whichever analysed one holds the most events; nothing is assumed by name.
function useWorkspaceDefault() {
  const wss = useWorkspaces().data;
  const { ws, setWs } = useStore();
  useEffect(() => {
    if (!wss?.length || wss.some((w) => w.name === ws)) return;
    const best = [...wss].filter((w) => w.analysed).sort((a, b) => (b.events ?? 0) - (a.events ?? 0))[0] ?? wss[0];
    setWs(best.name);
  }, [wss, ws, setWs]);
}

export default function App() {
  useEffect(() => { syncRoute(); window.addEventListener("hashchange", syncRoute); return () => window.removeEventListener("hashchange", syncRoute); }, []);
  useWorkspaceDefault();
  useJobWatcher();
  const route = useStore((s) => s.route);
  const param = useStore((s) => s.param);
  const wsq = useWorkspaces();
  const cur = useCurrentWs();
  const P = PAGES[route];
  const main = useRef<HTMLElement>(null);
  useEffect(() => { main.current?.scrollTo(0, 0); }, [route]);
  let body: JSX.Element;
  if (route === "live") body = <PageBoundary name="live"><LiveSim /></PageBoundary>;
  else if (wsq.isLoading || !cur) body = wsq.isError ? <Empty title="Cannot reach the Kairos API" text="Start it with: make serve" /> : <Loading />;
  else if (!cur.analysed && route !== "ingest" && route !== "rules" && route !== "health" && route !== "walkthrough") body = <Empty title={`Workspace "${cur.name}" has no results yet`} text="Upload logs and run an analysis, or pick another workspace in the top bar." action={<GoBtn to="ingest" primary>Open Live Ingestion</GoBtn>} />;
  else if (cur.live && NEEDS_BATCH.includes(route)) body = <Empty title="This is a live workspace" text="Live workspaces publish a knowledge base rather than batch incidents. Use Live Ingestion for its alerts and the Knowledge graph tab for its incidents and campaigns." action={<span className="flex gap-2"><GoBtn to="ingest" primary>Open Live Ingestion</GoBtn><GoBtn to="graph" param="kg">Knowledge graph</GoBtn></span>} />;
  else body = <PageBoundary name={`${cur.name}:${route}:${param}`}><P key={`${cur.name}:${route}`} /></PageBoundary>;
  return (
    <div className="h-full flex bg-bg print-root">
      <Sidebar />
      <div className="flex-1 min-w-0 flex flex-col print-root"><Topbar /><main ref={main} className="flex-1 min-h-0 overflow-auto print-root">{body}</main></div>
      <EvidenceDrawer />
    </div>
  );
}
