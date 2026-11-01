import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Check, CircleStop, Clock, Crosshair, Fingerprint, KeyRound, Lock, Mail, Play, ShieldCheck, Sparkles, UserCheck, X } from "lucide-react";
import type { ElementDefinition } from "cytoscape";
import { api, withWs } from "../lib/api";
import type { EvidenceLine, Explanation } from "../lib/api";
import { fmtN, fmtP, short } from "../lib/format";
import { Callout, Detector, Drawer, Empty, ErrorBox, EvLink, KV, Kpi, Loading, Page, Panel, Pill, Section, Tech } from "../components/ui";
import { CyGraph, cardImage } from "../components/CyGraph";
import { layered } from "../components/IncidentGraph";
import { ExplanationView } from "../components/Explanation";

const SIM_WS = "live-sim";
type Decision = "contain" | "investigate" | "monitor" | "ignore";
interface Option { technique: string; name: string; why: string }
interface Prediction { id: string; from_technique: string; from_title: string; options: Option[]; status: string; lead_s?: number; log_lead_min?: number; confirmed_by?: string; actual?: { technique_id: string; title: string; tactic: string }; entities: { user: string[]; host: string[] } }
interface StepCard { order: number; technique: string; tactic: string; description: string; detected: boolean; label_ok: boolean; detected_as: string | null; decision: Decision | null; predicted_by: string | null; lead_s: number | null; first: boolean }
interface Card { decoy: boolean; steps: StepCard[]; total_steps: number; reached: number; detected: number; matched: number; predictable: number; contain: number }
interface Story { nodes: { uid: string; title: string; technique_id: string; tactic: string; decision: Decision }[]; links: { id: string; source: string; target: string }[]; ghosts: { id: string; source: string; options: string[]; name: string }[] }
interface Scenario { id: string; title: string; text: string; icon: string }
interface Line { seq: number; ts: string; text: string; status: string; pattern: string; event_id: number }
interface Tick { state: string; error: string | null; source: string | null; eps: number; lines: number; bytes: number; total_bytes: number; status: Record<string, number>; patterns: number; learning: boolean; baseline: number; batches: number; alerts: number; engine_lines: number; delay_s: number | null; version: number; tail: Line[]; counts: Record<string, number>; scenario: string | null; reached: number; total_steps: number }
interface Pattern { id: string; text: string; count: number; first_ts: string; last_ts: string; event_ids: number[]; alerts: string[]; users: string[]; hosts: string[] }
interface Dec { uid: string; rule_id: string; title: string; technique_id: string; tactic: string; phase: string; severity: number; fused: number | null; ts: string; events: number; decision: Decision; from: Decision | null; at: string; why: string[]; links: { uid: string; title: string; technique_id: string; score: number; delta_t_s: number; reasons: string[] }[]; patterns: { id: string; text: string; unique: boolean }[]; chain: { alerts: number; tactics: number; critical: string[] }; sample: number[] }
interface View { version: number; unique: Pattern[]; decisions: Dec[]; graph: { nodes: { uid: string; title: string; technique_id: string; tactic: string; decision: Decision; severity: number; ts: string }[]; edges: { id: string; source: string; target: string; score: number }[] }; predictions: Prediction[]; story: Story; card: Card | null }
type Conn = "connecting" | "connected" | "reconnecting";

const ACT: Record<Decision, { label: string; color: string; tone: "crit" | "warn" | "cyan" | "mute" }> = {
  contain: { label: "Recommend containment", color: "#EF4444", tone: "crit" }, investigate: { label: "Investigate", color: "#F59E0B", tone: "warn" },
  monitor: { label: "Monitor", color: "#26D9D0", tone: "cyan" }, ignore: { label: "Ignore", color: "#64748B", tone: "mute" },
};
const LINE: Record<string, [string, string]> = { baseline: ["text-mute", "learn"], known: ["text-sub", "known"], unique: ["text-[#C4B5FD]", "UNIQUE"], flagged: ["text-[#FCA5A5]", "ALERT"] };
const BLANK: View = { version: -1, unique: [], decisions: [], graph: { nodes: [], edges: [] }, predictions: [], story: { nodes: [], links: [], ghosts: [] }, card: null };
const ICON: Record<string, typeof Mail> = { key: KeyRound, mail: Mail, user: UserCheck };

function useSimStream() {
  const [tick, setTick] = useState<Tick | null>(null); const [view, setView] = useState<View>(BLANK); const [conn, setConn] = useState<Conn>("connecting");
  useEffect(() => {
    const es = new EventSource("/sim/stream");
    es.onopen = () => setConn("connected");
    es.onerror = () => setConn("reconnecting"); // EventSource retries by itself
    es.addEventListener("tick", (e) => setTick(JSON.parse((e as MessageEvent).data)));
    es.addEventListener("view", (e) => setView(JSON.parse((e as MessageEvent).data)));
    return () => es.close();
  }, []);
  return { tick, view, conn };
}

function Stream({ tick }: { tick: Tick }) {
  return <div className="h-full bg-bg px-3 py-2 mono text-2xs leading-[19px] overflow-hidden flex flex-col justify-end">
    {tick.tail.length ? tick.tail.map((l) => { const [c, tag] = LINE[l.status] ?? LINE.known; return <div key={l.seq} className={`flex gap-2 ${l.status === "unique" ? "bg-[#7C3AED]/15 -mx-1 px-1 rounded-sm" : l.status === "flagged" ? "bg-crit/10 -mx-1 px-1 rounded-sm" : ""}`}><span className="text-mute shrink-0">{l.ts.slice(5)}</span><span className={`w-12 shrink-0 font-semibold ${c}`}>{tag}</span><span className={`truncate ${c}`} title={l.text}>{l.text}</span></div>; })
      : <span className="text-mute">Press Start to replay logs through the live engine.</span>}
  </div>;
}

function ChainGraph({ view, onPick, selected }: { view: View; onPick: (uid: string) => void; selected: string | null }) {
  const els = useMemo<ElementDefinition[]>(() => {
    const linked = new Set(view.graph.edges.flatMap((e) => [e.source, e.target]));
    const nodes = view.graph.nodes.filter((n) => linked.has(n.uid));
    const pos = layered(nodes.map((n) => n.uid), view.graph.edges.map((e) => [e.source, e.target]), 196, 66);
    return [...nodes.map((n) => { const color = ACT[n.decision].color; return { group: "nodes" as const, position: pos.get(n.uid), data: { id: n.uid, w: 172, h: 56, color, img: cardImage({ kind: n.tactic, title: n.technique_id, sub: ACT[n.decision].label, color, w: 172, h: 56 }) } }; }),
      ...view.graph.edges.filter((e) => linked.has(e.source)).map((e) => ({ group: "edges" as const, data: { id: e.id, source: e.source, target: e.target, color: "#26D9D0", label: e.score.toFixed(2), style: "dashed" } }))];
  }, [view.graph]);
  return els.length ? <CyGraph elements={els} layout="preset" selected={selected} onSelect={(id, k) => { if (id && k === "node") onPick(id); }} /> : <Empty title="No correlated alerts yet" text="Links appear when a new alert shares an account, host or address with an earlier one." />;
}

// Reads as a story: alerts snake in time order, and an open prediction sits after its source as a dashed ghost.
function StoryGraph({ story, onPick, selected }: { story: Story; onPick: (uid: string) => void; selected: string | null }) {
  const els = useMemo<ElementDefinition[]>(() => {
    const cols = 3, place = (i: number) => ({ x: (Math.floor(i / cols) % 2 ? cols - 1 - (i % cols) : i % cols) * 226, y: Math.floor(i / cols) * 108 });
    const out: ElementDefinition[] = story.nodes.map((n, i) => { const color = ACT[n.decision].color; return { group: "nodes", position: place(i), data: { id: n.uid, w: 198, h: 72, color, img: cardImage({ kind: `${i + 1} · ${n.tactic}`, title: n.technique_id, sub: short(n.title, 38), color, w: 198, h: 72 }) } }; });
    story.links.forEach((l) => out.push({ group: "edges", data: { id: l.id, source: l.source, target: l.target, color: "#22C55E", label: "", style: "solid", hot: true } }));
    story.ghosts.forEach((g, i) => { const id = `ghost-${g.id}`; out.push({ group: "nodes", position: place(story.nodes.length + i), data: { id, w: 198, h: 72, color: "#A78BFA", img: cardImage({ kind: "Predicted next", title: g.options.join(" / "), sub: g.name, color: "#A78BFA", w: 198, h: 72 }) } }); out.push({ group: "edges", data: { id: `${id}-e`, source: g.source, target: id, color: "#A78BFA", label: "", style: "dashed" } }); });
    return out;
  }, [story]);
  return els.length ? <CyGraph elements={els} layout="preset" selected={selected} onSelect={(id, k) => { if (id && k === "node" && !id.startsWith("ghost-")) onPick(id); }} /> : <Empty title="Waiting for the first detection" text="Each detection adds a card. Kairos then draws what it expects next as a dashed purple card." />;
}

function Forecast({ view, tick }: { view: View; tick: Tick }) {
  const pending = view.predictions.find((p) => p.status === "pending");
  const hit = view.predictions.find((p) => p.status === "confirmed");
  if (!pending && !hit) return null;
  return <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
    <div className={`rounded border px-3 py-2 ${pending && tick.state !== "complete" ? "border-[#A78BFA]/50 bg-[#7C3AED]/10" : "border-line2 bg-panel"}`}>
      <div className="label flex items-center gap-1.5 !text-[#C4B5FD]"><Crosshair size={11} className={pending ? "pulse" : ""} />Kairos predicts next</div>
      {pending ? <><div className="text-sm font-medium mt-0.5">{pending.options.map((o) => o.name).join(" or ")}</div><div className="text-xs text-sub">{pending.options[0].why}. <span className="text-mute">After {pending.from_technique}{pending.entities.host[0] ? ` on ${pending.entities.host[0]}` : ""}{pending.entities.user[0] ? `, account ${pending.entities.user[0]}` : ""}.</span></div></> : <div className="text-xs text-mute mt-0.5">No open prediction.</div>}
    </div>
    <div className={`rounded border px-3 py-2 ${hit ? "border-ok/40 bg-ok/[.07]" : "border-line2 bg-panel"}`}>
      <div className="label flex items-center gap-1.5 !text-ok"><Check size={11} />Latest prediction that came true</div>
      {hit && <><div className="text-sm font-medium mt-0.5">{hit.actual?.technique_id} · {hit.actual?.title}</div><div className="text-xs text-sub">Predicted {hit.lead_s} s before it was detected, after {hit.from_technique}.</div></>}
    </div>
  </div>;
}

function Verdict({ s, live, decoy }: { s: StepCard; live: boolean; decoy: boolean }) {
  if (!s.detected && decoy) return <Pill tone="ok"><Check size={10} />Correctly not flagged</Pill>;
  if (!s.detected) return live ? <Pill tone="mute"><Clock size={10} />Analysing</Pill> : <Pill tone="crit"><X size={10} />Not detected</Pill>;
  if (decoy) return <Pill tone="warn">Flagged, not escalated: {s.decision}</Pill>;
  if (s.predicted_by) return <Pill tone="ok"><Check size={10} />Predicted, then happened · {s.lead_s} s ahead</Pill>;
  if (s.first) return <Pill tone="cyan">First signal</Pill>;
  return <Pill tone="warn">Detected, not predicted in time</Pill>;
}

function Scorecard({ card, predictions, live }: { card: Card; predictions: Prediction[]; live: boolean }) {
  const pred = (s: StepCard) => predictions.find((p) => p.id === s.predicted_by);
  return <Panel title="Predicted vs actual" actions={<span className="normal-case tracking-normal font-normal text-mute">Actual comes from the scenario's answer key, which Kairos never sees</span>} body="overflow-auto">
    <table className="tbl"><thead><tr>{["Step", "What actually happened", "Kairos predicted", "Kairos detected", "Result"].map((h) => <th key={h}>{h}</th>)}</tr></thead><tbody>
      {card.steps.map((s) => <tr key={s.order} className="fade-in"><td className="mono">{s.order}</td><td className="text-ink">{s.description}<span className="mono text-2xs text-mute ml-1.5">{s.technique}</span></td>
        <td className="mono text-2xs">{pred(s)?.options.map((o) => o.technique).join(" / ") ?? "—"}</td><td className="mono text-2xs">{s.detected_as ?? "—"}</td><td className="whitespace-nowrap"><Verdict s={s} live={live} decoy={card.decoy} /></td></tr>)}
      {Array.from({ length: card.total_steps - card.reached }, (_, i) => <tr key={`h${i}`}><td className="mono text-mute">{card.reached + i + 1}</td><td colSpan={4} className="text-mute"><span className="inline-flex items-center gap-1.5"><Lock size={10} />Has not happened yet</span></td></tr>)}
    </tbody></table>
  </Panel>;
}

function ExplainDrawer({ p, onClose }: { p: Pattern; onClose: () => void }) {
  const q = useQuery({ queryKey: ["sim-explain", p.id], retry: false, staleTime: Infinity, queryFn: () => api<Explanation & { pattern: string; linked_alerts: { rule: string; title: string; technique_id: string; decision: Decision }[]; evidence: EvidenceLine[] }>(`/sim/patterns/${p.id}/explain`, { method: "POST" }) });
  const n = q.data?.narrative;
  return <Drawer title="Pattern explanation" onClose={onClose} badge={<Pill tone="cyan">Decisions are not made by AI</Pill>}>
    <div className="mono text-xs text-[#C4B5FD]">{p.text}</div>
    <KV rows={[["First seen", `${p.first_ts} UTC`], ["Occurrences", fmtN(p.count)], ["Hosts", p.hosts.join(", ") || "—"], ["Users", p.users.join(", ") || "—"]]} />
    {q.isLoading && <Loading label="Generating through OpenRouter" />}{q.error && <ErrorBox error={q.error} />}
    {n?.narrative && <div className="rounded border border-cyan/30 bg-cyan/[.05] p-2.5 space-y-1.5"><Pill tone="cyan">{n.label ?? "AI-written summary of verified evidence"}</Pill><p className="text-xs">{n.narrative.summary}</p><ol className="list-decimal pl-4 text-xs text-sub">{n.narrative.steps?.map((s, i) => <li key={i}>{s.text}</li>)}</ol><div className="text-2xs text-mute">{n.model} · {n.status}</div></div>}
    {n && !n.narrative && <Callout>AI explanation not shown: {n.reason ?? n.status}. The verified facts below are complete without it.</Callout>}
    {q.data && <><Section title="Verified facts"><p className="text-xs text-sub">{q.data.summary}</p></Section>
      {q.data.linked_alerts.length > 0 && <Section title="Alerts involving this pattern"><div className="space-y-1">{q.data.linked_alerts.map((a, i) => <div key={i} className="flex items-center gap-2 text-xs"><Tech id={a.technique_id} /><span className="text-sub truncate flex-1">{a.title}</span><Pill tone={ACT[a.decision].tone}>{ACT[a.decision].label}</Pill></div>)}</div></Section>}
      <Section title="Raw evidence, hash-verified"><div className="flex flex-wrap gap-x-2">{q.data.evidence.map((e) => <EvLink key={e.event_id} id={e.event_id} ws={SIM_WS} label={e.display_id} />)}</div></Section></>}
  </Drawer>;
}

function DecisionDrawer({ d, onClose }: { d: Dec; onClose: () => void }) {
  const q = useQuery({ queryKey: ["sim-alert", d.uid], queryFn: () => api<Explanation>(withWs(`/explain/alert/${encodeURIComponent(d.uid)}`, SIM_WS)) });
  return <Drawer title={d.title} width={620} onClose={onClose} badge={<Pill tone={ACT[d.decision].tone}>{ACT[d.decision].label}</Pill>}>
    <Section title="Why this decision"><ul className="list-disc pl-4 text-xs text-sub space-y-0.5">{d.why.map((w, i) => <li key={i}>{w}</li>)}</ul><div className="text-2xs text-mute mt-1">Same evidence always gives the same answer. This is a recommendation; nothing is executed.</div></Section>
    <KV rows={[["Technique", <span>{d.technique_id} ({d.tactic})</span>], ["Kill chain", d.phase ?? "Unknown"], ["Log time", `${d.ts} UTC`], ["Events", fmtN(d.events)], ["Fused score", `${fmtP(d.fused)} (uncalibrated)`], ["Chain", `${d.chain.alerts} alerts · ${d.chain.tactics} tactics`], ["Critical assets", d.chain.critical.join(", ") || "None"]]} />
    {d.links.length > 0 && <Section title="Correlated with earlier alerts"><div className="space-y-1">{d.links.map((l) => <div key={l.uid} className="rounded border border-line2 bg-bg px-2 py-1 text-xs"><div className="flex gap-2"><Tech id={l.technique_id} /><span className="truncate flex-1">{l.title}</span><span className="mono text-2xs text-cyan">{l.score.toFixed(2)}</span></div><div className="text-2xs text-mute">{l.reasons.join(", ").replace(/_/g, " ")} · {Math.round(l.delta_t_s / 60)} min earlier</div></div>)}</div></Section>}
    {d.patterns.length > 0 && <Section title="Log patterns"><div className="space-y-0.5">{d.patterns.map((p) => <div key={p.id} className="flex items-center gap-2 text-2xs"><Pill tone={p.unique ? "cyan" : "mute"}>{p.unique ? "never seen" : "seen before"}</Pill><span className="mono text-sub truncate">{p.text}</span></div>)}</div></Section>}
    <Section title="Evidence"><div className="flex flex-wrap gap-x-2">{d.sample.map((e) => <EvLink key={e} id={e} ws={SIM_WS} />)}</div></Section>
    {q.data && <div className="border-t border-line pt-3"><ExplanationViewFor x={q.data} uid={d.uid} /></div>}
  </Drawer>;
}
const ExplanationViewFor = ({ x, uid }: { x: Explanation; uid: string }) => <ExplanationView x={x} kind="alert" id={uid} />;

export function LiveSim() {
  const { tick, view, conn } = useSimStream();
  const src = useQuery({ queryKey: ["sim-sources"], queryFn: () => api<{ sources: { name: string; size: number }[]; speed: { default_eps: number; min_eps: number; max_eps: number }; scenarios: Scenario[] }>("/sim/sources") });
  const [source, setSource] = useState(""); const [eps, setEps] = useState<number | null>(null); const [err, setErr] = useState<unknown>(null);
  const [pat, setPat] = useState<Pattern | null>(null); const [dec, setDec] = useState<Dec | null>(null);
  const timer = useRef<number>();
  const pick = (u: string) => setDec(view.decisions.find((d) => d.uid === u) ?? null);
  const sources = src.data?.sources ?? [];
  const chosen = source || [...sources].sort((a, b) => b.size - a.size)[0]?.name || "";
  const speed = eps ?? tick?.eps ?? src.data?.speed.default_eps ?? 0;
  const running = tick?.state === "running" || tick?.state === "draining";
  const launch = async (scenario: string) => { setErr(null); try { await post("/sim/start", { scenario }); } catch (e) { setErr(e); } };
  const post = (path: string, body?: object) => api(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
  const start = async () => { setErr(null); try { await post("/sim/start", { source: chosen, eps: speed }); } catch (e) { setErr(e); } };
  const stop = async () => { try { await post("/sim/stop"); } catch (e) { setErr(e); } };
  const changeSpeed = (v: number) => { setEps(v); clearTimeout(timer.current); if (running) timer.current = window.setTimeout(() => { post("/sim/speed", { eps: v }).catch(setErr); }, 200); };
  if (!tick) return <Loading label="Connecting to the live stream" />;
  const pct = tick.total_bytes ? tick.bytes / tick.total_bytes : 0;
  return (
    <Page title="Live Simulation" sub="Pick an attack. Logs arrive line by line through the real detection engine, and Kairos has to call the next step before it happens."
      actions={<span className="flex items-center gap-2"><Pill tone={conn === "connected" ? "ok" : "warn"}>Stream {conn}</Pill><Pill tone={running ? "cyan" : tick.state === "failed" ? "crit" : "mute"}>{tick.state}</Pill></span>}>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
        {src.data?.scenarios.map((c) => { const Ic = ICON[c.icon] ?? Crosshair; const on = tick.scenario === c.id && running; return <div key={c.id} className={`panel p-3 flex gap-3 items-start transition-colors ${on ? "!border-cyan/50 bg-cyan/[.05]" : ""}`}>
          <span className={`w-8 h-8 rounded grid place-items-center shrink-0 ${c.icon === "user" ? "bg-ok/10 text-ok" : "bg-crit/10 text-crit"}`}><Ic size={15} /></span>
          <div className="min-w-0 flex-1"><div className="text-sm font-medium">{c.title}</div><div className="text-2xs text-mute">{c.text}</div></div>
          <button className="btn btn-primary shrink-0" disabled={running} onClick={() => launch(c.id)}>{on ? "Running" : <><Play size={12} />Simulate</>}</button></div>; })}
      </div>
      <div className="panel flex items-center gap-3 flex-wrap px-3 py-2">
        {tick.scenario && running ? <span className="text-xs text-sub flex items-center gap-1.5"><Clock size={12} className="text-cyan" />{tick.reached ? `Attack step ${tick.reached} of ${tick.total_steps} is unfolding` : "Normal activity, attack not started"}</span>
          : <><span className="label">Or replay a file</span><select aria-label="Replay source" className="field" value={chosen} disabled={running} onChange={(e) => setSource(e.target.value)}>{sources.map((s) => <option key={s.name} value={s.name}>{s.name}</option>)}</select>
            <button className="btn" disabled={!chosen || running} onClick={start}><Play size={12} />Start replay</button>
            <label className="flex items-center gap-2 text-xs text-sub">Speed<input aria-label="Replay speed" type="range" className="accent-[#26D9D0] w-28" min={src.data?.speed.min_eps} max={src.data?.speed.max_eps} step={20} value={speed} onChange={(e) => changeSpeed(Number(e.target.value))} /><span className="mono text-2xs w-20">{fmtN(speed)} lines/s</span></label></>}
        {running && <button className="btn" onClick={stop}><CircleStop size={12} />Stop</button>}
        <div className="flex-1 min-w-32"><div className="bar"><i style={{ width: `${pct * 100}%`, background: "#26D9D0" }} /></div></div><span className="mono text-2xs text-mute">{Math.round(pct * 100)}%</span>
      </div>
      {!!err && <ErrorBox error={err} />}{tick.error && tick.state === "failed" && <ErrorBox error={tick.error} />}
      <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-8 gap-2">
        <Kpi label="Lines received" value={fmtN(tick.lines)} sub={tick.learning && tick.lines ? `learning normal: ${Math.round(tick.lines / tick.baseline * 100)}%` : `${fmtN(tick.engine_lines)} analysed`} tone="cyan" />
        <Kpi label="Known patterns" value={fmtN(tick.patterns - view.unique.length)} sub={`${fmtN(tick.status.known)} matching lines`} /><Kpi label="Unique patterns" value={fmtN(view.unique.length)} sub="never seen before" tone={view.unique.length ? "warn" : undefined} />
        <Kpi label="Alerts" value={fmtN(tick.alerts)} sub={`${tick.batches} batches`} /><Kpi label="Contain" value={fmtN(tick.counts.contain ?? 0)} tone={tick.counts.contain ? "crit" : undefined} sub="recommended" /><Kpi label="Investigate" value={fmtN(tick.counts.investigate ?? 0)} tone={tick.counts.investigate ? "warn" : undefined} sub={`${tick.counts.monitor ?? 0} monitor · ${tick.counts.ignore ?? 0} ignore`} />
        <Kpi label="Predictions confirmed" value={view.card ? `${view.card.matched} / ${view.card.predictable}` : fmtN(view.predictions.filter((p) => p.status === "confirmed").length)} sub={`${view.predictions.filter((p) => p.status === "pending").length} open`} tone={view.card?.matched ? "ok" : undefined} />
        <Kpi label="Detection delay" value={tick.delay_s != null ? `${tick.delay_s} s` : "—"} sub="line written to analysed" tone={tick.delay_s != null && tick.delay_s < 5 ? "ok" : undefined} />
      </div>
      <Forecast view={view} tick={tick} />
      {tick.state === "complete" && view.card && <Callout tone="cyan"><ShieldCheck size={12} className="inline mr-1" />{view.card.decoy ? (view.card.contain ? `Control failed: ${view.card.contain} containment recommendation(s) on legitimate work.` : "Control passed: legitimate admin work raised no containment recommendation.") : `Scenario finished: ${view.card.detected} of ${view.card.total_steps} steps detected, ${view.card.matched} of ${view.card.predictable} predictable steps predicted ahead of time.`}</Callout>}
      <div className="grid grid-cols-1 xl:grid-cols-[1fr_1.25fr_300px] gap-3">
        <Panel title="Incoming logs" className="h-[372px]" actions={<span className="flex gap-2 normal-case tracking-normal font-normal"><span className="text-mute">learn</span><span className="text-sub">known</span><span className="text-[#C4B5FD]">unique</span><span className="text-[#FCA5A5]">alert</span></span>}><Stream tick={tick} /></Panel>
        <Panel title={tick.scenario ? "Attack story, building live" : "Correlation with earlier alerts"} className="h-[372px] overflow-hidden">{tick.scenario ? <StoryGraph story={view.story} onPick={pick} selected={dec?.uid ?? null} /> : <ChainGraph view={view} onPick={pick} selected={dec?.uid ?? null} />}</Panel>
        <Panel title={<span className="flex items-center gap-1.5"><Fingerprint size={12} className="text-[#C4B5FD]" />Unique logs · {view.unique.length}</span>} className="h-[372px]" body="overflow-auto">
          {view.unique.length ? view.unique.map((p) => <div key={p.id} className="px-3 py-2 border-b border-line2 fade-in">
            <div className="mono text-2xs text-[#C4B5FD] break-words">{p.text}</div>
            <div className="flex items-center gap-2 text-2xs text-mute mt-0.5 whitespace-nowrap"><span>{p.first_ts.slice(5, 16)}</span><span>×{fmtN(p.count)}</span>{p.alerts.length > 0 && <span className="text-[#FCA5A5]">{p.alerts.length} alert{p.alerts.length > 1 ? "s" : ""}</span>}</div>
            <button className="btn !h-6 w-full mt-1.5 whitespace-nowrap" onClick={() => setPat(p)}><Sparkles size={11} />Generate explanation</button>
          </div>) : <Empty title={tick.learning && tick.lines ? "Learning normal behaviour" : "No unique logs yet"} text={`Patterns first seen after the first ${fmtN(tick.baseline)} lines appear here.`} />}
        </Panel>
      </div>
      {view.card && <Scorecard card={view.card} predictions={view.predictions} live={running} />}
      <Panel title={`Decisions · newest first`} className="h-[300px]" actions={<span className="normal-case tracking-normal font-normal text-mute">Deterministic rules in config/decision.yml. No AI decides, and nothing is executed.</span>} body="overflow-auto">
        {view.decisions.length ? <table className="tbl"><thead><tr>{["Log time", "Decision", "", "Alert", "Technique", "Why"].map((h) => <th key={h}>{h}</th>)}</tr></thead><tbody>
          {view.decisions.map((d, i) => <tr key={`${d.uid}${i}`} className="click fade-in" onClick={() => setDec(d)}><td className="mono whitespace-nowrap">{d.ts.slice(5)}</td><td className="whitespace-nowrap"><Pill tone={ACT[d.decision].tone}>{ACT[d.decision].label}</Pill>{d.from && <span className="text-2xs text-mute ml-1.5">was {d.from}</span>}</td><td><Detector rule={d.rule_id} /></td><td className="max-w-72 truncate text-ink" title={d.title}>{short(d.title, 56)}</td><td><Tech id={d.technique_id} /></td><td className="max-w-96 truncate" title={d.why.join("; ")}>{d.why[0] ?? ""}</td></tr>)}
        </tbody></table> : <Empty title="No decisions yet" text="Each alert from the engine gets one decision here." />}
      </Panel>
      {pat && <ExplainDrawer p={pat} onClose={() => setPat(null)} />}{dec && <DecisionDrawer d={dec} onClose={() => setDec(null)} />}
    </Page>
  );
}
