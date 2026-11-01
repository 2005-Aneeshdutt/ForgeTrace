import { useMemo } from "react";
import { fmtN, fmtP, pad } from "../lib/format";
import { useIncident, useSelectedIncident } from "../lib/hooks";
import { useStore } from "../lib/store";
import { Callout, Empty, ErrorBox, Kpi, Loading, NotAvailable, Page, Panel, Pill, Section } from "../components/ui";
import { IncidentPicker } from "../components/IncidentPicker";

const NM = <span className="text-mute whitespace-nowrap">Not modelled</span>;

export function Decision() {
  const { id } = useSelectedIncident(); const q = useIncident(id); const { go, setSimTargets } = useStore();
  const inc = q.data;
  const fused = useMemo(() => Math.max(0, ...(inc?.observed.nodes.map((n) => n.p_malicious ?? 0) ?? [0])), [inc]);
  const prior = useMemo(() => { const m = new Map<string, number>(); inc?.observed.nodes.forEach((n) => Object.entries(n.contributions ?? {}).forEach(([k, v]) => m.set(k, Math.max(m.get(k) ?? 0, v)))); return [...m].sort((a, b) => b[1] - a[1]); }, [inc]);
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  if (!inc) return <Empty title="No incident selected" />;
  const cands = [...inc.inferred.containment_candidates].sort((a, b) => b.reduction - a.reduction);
  const best = cands[0]?.reduction > 0 ? cands[0] : null;
  const r = inc.inferred.reachability;
  const sim = (t: string[]) => { setSimTargets(t); go("simulate"); };
  return (
    <Page title="Decision Intelligence" sub={`${pad(inc.incident_id)} · Decision support built only from modelled reachability. Nothing is executed.`} actions={<IncidentPicker />}>
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-2"><Kpi label="Severity" value={<span className="capitalize">{inc.severity}</span>} sub={`risk ${inc.risk_score.toFixed(1)}`} tone="crit" /><Kpi label="Fused detector score" value={fmtP(fused)} sub="noisy-OR, not calibrated" tone="warn" /><Kpi label="Affected entities" value={fmtN(inc.entity_keys.length)} /><Kpi label="Critical assets reachable" value={`${r.critical_reachable} / ${r.total_critical_assets}`} tone="warn" sub="potential" /><Kpi label="Evidence" value={fmtN(inc.member_event_count)} sub="raw events cited" /><Kpi label="Open uncertainties" value={fmtN(inc.uncertainty.length)} /></div>
      <div className="grid grid-cols-1 xl:grid-cols-[1fr_380px] gap-3">
        <Panel title="Response actions compared" body="overflow-auto"><table className="tbl"><thead><tr>{["Action", "Critical reach", "Reduction", "Disruption", "Cost", "Reversible", "Evidence", ""].map((h) => <th key={h}>{h}</th>)}</tr></thead>
          <tbody>{cands.slice(0, 10).map((c) => <tr key={c.action.target}><td><span className="mono text-ink text-2xs">disable_account({c.action.target})</span></td><td className="mono whitespace-nowrap">{c.before} → {c.after}</td><td className={`mono ${c.reduction > 0 ? "text-ok" : ""}`}>{c.reduction ? `−${c.reduction}` : "0"}</td><td>{NM}</td><td>{NM}</td><td>{NM}</td><td>{NM}</td><td><button className="btn !h-6" onClick={() => sim([c.action.target])}>Simulate</button></td></tr>)}
            {["Isolate host", "Block IP", "Revoke session", "Collect more evidence"].map((a) => <tr key={a} className="opacity-60"><td>{a}</td><td colSpan={7} className="text-2xs text-mute">The backend does not model this action yet.</td></tr>)}</tbody></table></Panel>
        <Panel title="Recommendation" body="p-3 space-y-3">
          {best ? <><div className="rounded border border-cyan/40 bg-cyan/[.07] p-2.5"><div className="label text-cyan">Largest modelled reduction</div><div className="mono text-sm mt-0.5">disable_account({best.action.target})</div><div className="text-xs text-sub mt-1">Reduces critical assets in reach from {best.before} to {best.after}. Ranked only on this one number; cost and disruption are not modelled.</div></div>
            <button className="btn btn-primary w-full" onClick={() => sim([best.action.target])}>Open in simulator</button>
            {cands[1]?.reduction > 0 && <Section title="Alternatives"><ul className="text-xs text-sub space-y-0.5">{cands.slice(1, 4).filter((c) => c.reduction > 0).map((c) => <li key={c.action.target} className="mono text-2xs">{c.action.target}: {c.before} → {c.after}</li>)}</ul></Section>}</>
            : <Callout tone="cyan">No single account action lowers modelled critical reach for this incident, so nothing is recommended.</Callout>}
          <Section title="Uncertainties"><ul className="list-disc pl-4 text-xs text-sub space-y-0.5">{inc.uncertainty.slice(0, 4).map((u, i) => <li key={i}>{u}</li>)}</ul></Section>
          <div className="flex items-center gap-2 text-2xs text-mute">Analyst approval <Pill>No workflow in backend</Pill></div>
        </Panel>
      </div>
      <Panel title="Decision reasoning" body="p-3 grid grid-cols-1 md:grid-cols-2 gap-2.5">
        <div className="rounded border border-line bg-bg2/60 px-3 py-2.5 md:row-span-2"><div className="flex items-center gap-1.5 text-xs font-medium mb-1.5">Evidence fusion<Pill tone="ok">Implemented as noisy-OR</Pill></div><div className="space-y-1">{prior.slice(0, 7).map(([k, v]) => <div key={k} className="grid grid-cols-[120px_1fr_36px] items-center gap-2 text-2xs"><span className="mono truncate text-sub">{k}</span><div className="bar"><i style={{ width: `${v * 100}%`, background: "#26D9D0" }} /></div><span className="mono text-right text-mute">{v.toFixed(2)}</span></div>)}</div><div className="text-2xs text-mute mt-1.5">Detector priors combined per entity. This is not a full Bayesian model and the score is not a calibrated probability.</div></div>
        <NotAvailable title="Causal inference" why="No causal model exists in the repository, so no causal scores are shown." /><NotAvailable title="Value of information" why="Collecting more evidence is not scored." /><NotAvailable title="Multi-objective optimisation" why="Only critical-reach reduction is computed; there is no trade-off model." />
      </Panel>
    </Page>
  );
}
