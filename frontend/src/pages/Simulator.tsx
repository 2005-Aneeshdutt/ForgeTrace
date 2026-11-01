import { useEffect, useMemo, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { FlaskConical, Loader2 } from "lucide-react";
import { api, withWs } from "../lib/api";
import type { SimResult } from "../lib/api";
import { entName, fmtN, pad } from "../lib/format";
import { useReach, useSelectedIncident, useWs } from "../lib/hooks";
import { useStore } from "../lib/store";
import { Basis, Callout, Empty, ErrorBox, EvLink, Kpi, Loading, NotAvailable, Page, Panel, Pill, Section } from "../components/ui";
import { CyGraph } from "../components/CyGraph";
import { C, reachElements } from "../components/IncidentGraph";
import { IncidentPicker } from "../components/IncidentPicker";
import { canon } from "../lib/derive";

export function Simulator() {
  const { id } = useSelectedIncident(); const q = useReach(id); const ws = useWs(); const { simTargets, setSimTargets } = useStore();
  const [res, setRes] = useState<SimResult | null>(null);
  const run = useMutation({ mutationFn: (t: string[]) => api<SimResult>(withWs(`/incidents/${id}/simulate`, ws!), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ actions: t.map((target) => ({ type: "disable_account", target })) }) }), onSuccess: setRes });
  const r = q.data; const cands = useMemo(() => [...(r?.containment_candidates ?? [])].sort((a, b) => b.reduction - a.reduction), [r]);
  useEffect(() => { setRes(null); }, [id]);
  useEffect(() => { if (simTargets.length && id != null) run.mutate(simTargets); }, []); // eslint-disable-line
  const before = useMemo(() => (r ? reachElements(r.reachable, r) : []), [r]);
  const after = useMemo(() => {
    if (!r || !res) return [];
    const removed = new Set(res.actions.map((a) => canon(`account:${a.target}`)));
    const gone = new Set(res.no_longer_reachable_critical.map((a) => canon(`host:${a}`)));
    const still = new Set(res.still_reachable_critical.map((a) => canon(`host:${a.asset}`)));
    return reachElements(r.reachable, r, (n) => removed.has(n) ? { color: C.green, sub: "disabled in simulation" } : gone.has(n) ? { color: C.green, sub: "no longer reachable" } : still.has(n) ? { color: C.red, sub: "still reachable" } : null, (s, d) => removed.has(s) || removed.has(d));
  }, [r, res]);
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  if (!r) return <Empty title="No incident selected" />;
  const toggle = (t: string) => { setSimTargets(simTargets.includes(t) ? simTargets.filter((x) => x !== t) : [...simTargets, t]); };
  return (
    <Page title="Response Simulator" sub={`${id != null ? pad(id) : ""} · What-if analysis on the reachability model.`} actions={<IncidentPicker />}>
      <Callout tone="cyan"><FlaskConical size={12} className="inline mr-1" /><strong className="font-semibold">Simulation only.</strong> No account, host or network is changed. Kairos has no connection to your systems.</Callout>
      <div className="grid grid-cols-1 xl:grid-cols-[300px_1fr] gap-3">
        <Panel title="Actions" className="xl:h-[566px]" body="flex flex-col min-h-0 h-full">
          <div className="flex-1 min-h-0 overflow-auto p-2 space-y-0.5"><div className="label px-1 mb-1">Disable account</div>
            {cands.length ? cands.map((c) => <label key={c.action.target} className={`flex items-center gap-2 px-1.5 h-7 rounded cursor-pointer text-xs ${simTargets.includes(c.action.target) ? "bg-cyan/10" : "hover:bg-raised"}`}><input type="checkbox" className="accent-[#26D9D0]" checked={simTargets.includes(c.action.target)} onChange={() => toggle(c.action.target)} /><span className="mono truncate flex-1 text-2xs">{c.action.target}</span><span className={`mono text-2xs ${c.reduction ? "text-ok" : "text-mute"}`}>{c.before}→{c.after}</span></label>) : <div className="text-xs text-mute px-1">No candidates for this incident.</div>}
            <div className="pt-2 space-y-1"><NotAvailable title="Isolate host" why="The API accepts only disable_account." /><NotAvailable title="Block IP" why="The API accepts only disable_account." /><NotAvailable title="Revoke session" why="The API accepts only disable_account." /></div></div>
          <div className="p-2 border-t border-line2"><button className="btn btn-primary w-full" disabled={!simTargets.length || run.isPending} onClick={() => run.mutate(simTargets)}>{run.isPending && <Loader2 size={12} className="animate-spin" />}Run simulation ({simTargets.length})</button></div>
        </Panel>
        <div className="flex flex-col gap-3 min-w-0">
          {run.error && <ErrorBox error={run.error} />}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2"><Kpi label="Critical reachable, before" value={res?.before_critical_reachable ?? r.critical_reachable} tone="warn" /><Kpi label="After simulation" value={res ? res.after_critical_reachable : "—"} tone={res ? "ok" : undefined} /><Kpi label="Assets no longer reachable" value={res ? res.no_longer_reachable_critical.length : "—"} /><Kpi label="Relationships removed" value={res ? fmtN(res.removed_relationships.length) : "—"} /></div>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 h-[476px]">
            <Panel title="Before" className="overflow-hidden">{before.length ? <CyGraph elements={before} layout="preset" /> : <Empty title="No reachable assets" />}</Panel>
            <Panel title="After (simulated)" className="overflow-hidden">{res ? <CyGraph elements={after} layout="preset" /> : <Empty title="Choose an action and run it" text="Results come from POST /incidents/{id}/simulate." />}</Panel>
          </div>
        </div>
      </div>
      {res && <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        <Panel title="Critical assets still exposed" body="p-3 space-y-2">{res.still_reachable_critical.length ? res.still_reachable_critical.map((a) => <div key={a.asset} className="text-xs"><div className="mono text-[#FCA5A5]">{a.asset}</div><div className="text-2xs text-sub">{a.explanation}</div><div className="flex flex-wrap gap-x-2">{a.supporting_event_ids.slice(0, 4).map((e) => <EvLink key={e} id={e} />)}</div></div>) : <div className="text-xs text-ok">No critical asset stays reachable in the model.</div>}
          {res.no_longer_reachable_critical.length > 0 && <Section title="No longer reachable"><div className="flex gap-1 flex-wrap">{res.no_longer_reachable_critical.map((a) => <Pill key={a} tone="ok">{a}</Pill>)}</div></Section>}
          <div className="text-2xs text-mute">Non-critical assets are not re-scored by the API, so they keep their original colour in the After graph. An asset still marked reachable may use a path not drawn there; its explanation above names it.</div></Panel>
        <Panel title={`Removed relationships · ${res.removed_relationships.length}`} className="max-h-72" body="overflow-auto p-2 space-y-1">{res.removed_relationships.slice(0, 40).map((e, i) => <div key={i} className="flex items-center gap-1.5 text-2xs"><span className="mono truncate">{entName(e.src)}</span><span className="mono text-cyan">{e.relation}</span><span className="mono truncate">{entName(e.dst)}</span><span className="flex-1" /><Basis kind={e.kind} /></div>)}<div className="text-2xs text-mute pt-1">{res.caveat} {res.disclaimer}</div></Panel>
      </div>}
    </Page>
  );
}
