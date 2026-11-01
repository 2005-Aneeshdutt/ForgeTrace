import { useState } from "react";
import { CheckCircle2, Sparkles, XCircle } from "lucide-react";
import { api, withWs } from "../lib/api";
import type { EvidenceLine, Explanation } from "../lib/api";
import { fmtN, fmtP, fmtTs } from "../lib/format";
import { useWs } from "../lib/hooks";
import { Callout, Detector, ErrorBox, EvLink, KV, Loading, Pill, Section } from "./ui";

export function EvidenceList({ ev }: { ev: EvidenceLine[] }) {
  return <div className="space-y-1">{ev.map((l) => (
    <div key={l.event_id} className="rounded border border-line2 bg-bg px-2 py-1">
      <div className="flex items-center gap-2"><EvLink id={l.event_id} label={l.display_id} />
        <span className="text-2xs text-mute truncate">{l.file}:{l.line_no}</span><span className="flex-1" />
        {l.verified ? <span title="SHA-256 re-verified"><CheckCircle2 size={11} className="text-ok" /></span> : <span title={l.note ?? "not verified"}><XCircle size={11} className="text-crit" /></span>}
      </div>
      <div className="mono text-2xs text-sub truncate">{l.raw}</div>
    </div>))}</div>;
}

const List = ({ title, items }: { title: string; items?: string[] }) => (items?.length ? <Section title={title}><ul className="space-y-0.5 text-xs text-sub list-disc pl-4">{items.map((x, i) => <li key={i}>{x}</li>)}</ul></Section> : null);

export function ExplanationView({ x, kind, id }: { x: Explanation; kind: string; id: string }) {
  const ws = useWs();
  const [ai, setAi] = useState<Explanation["narrative"] | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);
  if (x.error) return <Callout>{x.error}</Callout>;
  const w = x.why_flagged;
  const run = async () => {
    setBusy(true); setErr(null);
    try { setAi((await api<Explanation>(withWs(`/explain/${kind}/${encodeURIComponent(id)}?llm=true`, ws!))).narrative); } catch (e) { setErr(e); }
    setBusy(false);
  };
  return (
    <div className="space-y-3">
      <div><div className="text-sm font-medium">{x.headline}</div><p className="text-xs text-sub mt-1">{x.summary}</p></div>
      {x.data_quality?.map((d, i) => <Callout key={i}>{d}</Callout>)}
      <div className="flex items-center gap-2">
        <button className="btn" disabled={busy} onClick={run} title="Optional: restates these facts through OpenRouter; validated and cached"><Sparkles size={12} />AI summary</button>
        {x.verification_status && <Pill tone="ok">{x.verification_status}</Pill>}
      </div>
      {busy && <Loading label="Requesting summary" />}{!!err && <ErrorBox error={err} />}
      {ai && (ai.narrative
        ? <div className="rounded border border-cyan/30 bg-cyan/[.05] p-2.5 space-y-1"><Pill tone="cyan">{ai.label ?? "AI-written summary of verified evidence"}</Pill><p className="text-xs">{ai.narrative.summary}</p>
            <ol className="list-decimal pl-4 text-xs text-sub">{ai.narrative.steps?.map((s, i) => <li key={i}>{s.text}</li>)}</ol></div>
        : <Callout tone="cyan">AI summary not shown: {ai.reason ?? ai.status}. The explanation here is complete without it.</Callout>)}
      {w && <Section title="Why it was flagged"><KV rows={[
        ["Detector", <span className="flex items-center gap-1.5"><Detector rule={w.rule} /><span className="mono text-2xs">{w.rule}</span></span>],
        ...(w.type ? [["Type", w.type] as [string, string]] : []),
        ["Technique", `${w.technique.id} ${w.technique.name ?? ""} (${w.technique.tactic})`],
        ["Condition", <span className="mono text-2xs">{w.condition}</span>],
        ...(w.threshold ? [["Threshold", w.threshold] as [string, string]] : []),
        ...(w.followed_by ? [["Then", w.followed_by] as [string, string]] : []),
        ...(w.model_reasons?.length ? [["Model reasons", <div>{w.model_reasons.map((r, i) => <div key={i}>{r}</div>)}</div>] as [string, JSX.Element]] : []),
        ...(w.observed?.length ? [["Observed", <div>{w.observed.map((r, i) => <div key={i}>{r}</div>)}</div>] as [string, JSX.Element]] : []),
        ...(w.technique_basis ? [["Technique from", w.technique_basis] as [string, string]] : []),
        ...(w.fused_probability != null ? [["Fused score", `${fmtP(w.fused_probability)} (noisy-OR of agreeing detector priors, not a calibrated probability)`] as [string, string]] : []),
      ]} /></Section>}
      {x.steps && <Section title="Steps, in order"><ol className="space-y-2">{x.steps.map((s) => (
        <li key={s.order} className="text-xs"><div><span className="mono text-cyan mr-1.5">{s.order}.</span><strong className="font-medium">{s.what}</strong></div>
          <div className="text-2xs text-mute">{s.technique} · {s.tactic} · {fmtTs(s.when)} · {fmtN(s.events)} event(s)</div><div className="text-2xs text-sub mb-1">{s.linked_from_previous}</div><EvidenceList ev={s.evidence.slice(0, 2)} /></li>))}</ol></Section>}
      {x.evidence && <Section title="Evidence: raw lines, re-read and hash-checked"><EvidenceList ev={x.evidence} /></Section>}
      <List title="How to verify by hand" items={x.how_to_verify} /><List title="What else it could be" items={x.benign_explanations} /><List title="Uncertainties" items={x.uncertainties} />
    </div>
  );
}
