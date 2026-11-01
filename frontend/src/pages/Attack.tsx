import { useMemo } from "react";
import { fmtN, uniq } from "../lib/format";
import { useAllIncidents, useDetections, useOverview, useRules, useCurrentWs } from "../lib/hooks";
import { useStore } from "../lib/store";
import { Callout, Detector, EvLink, IncLink, KV, Kpi, Loading, Page, Panel, Pill, Section } from "../components/ui";
import { HBars } from "../components/charts";
import { TACTICS } from "../lib/derive";

interface Cell { id: string; name: string; tactic: string; count: number; incidents: Set<number>; covered: boolean }

export function Attack() {
  const det = useDetections(); const rules = useRules(); const all = useAllIncidents(); const ov = useOverview(); useCurrentWs();
  const { param, go, setDetFilter } = useStore();
  const cells = useMemo(() => {
    const m = new Map<string, Cell>();
    const key = (id: string, t: string) => `${t}|${id}`;
    for (const r of rules.data ?? []) if (r.technique && !m.has(key(r.technique, r.tactic))) m.set(key(r.technique, r.tactic), { id: r.technique, name: "", tactic: r.tactic, count: 0, incidents: new Set(), covered: true });
    for (const d of det.data ?? []) {
      const k = key(d.technique_id, d.tactic); const c = m.get(k) ?? { id: d.technique_id, name: "", tactic: d.tactic, count: 0, incidents: new Set(), covered: false };
      c.count++; c.name = d.technique_name || c.name; if (d.incident_id) c.incidents.add(d.incident_id); m.set(k, c);
    }
    for (const i of all.data) for (const n of i.observed.nodes) { const c = m.get(key(n.technique_id, n.tactic)); if (c) { c.name ||= n.technique_name; if (!c.count) c.incidents.add(i.incident_id); } else m.set(key(n.technique_id, n.tactic), { id: n.technique_id, name: n.technique_name, tactic: n.tactic, count: 0, incidents: new Set([i.incident_id]), covered: false }); }
    return [...m.values()];
  }, [rules.data, det.data, all.data]);
  if (det.isLoading || rules.isLoading) return <Loading />;
  const seen = cells.filter((c) => c.count > 0 || c.incidents.size > 0);
  const sel = cells.filter((c) => c.id === param);
  const maxN = Math.max(1, ...cells.map((c) => c.count));
  const dets = (det.data ?? []).filter((d) => d.technique_id === param);
  const nodes = all.data.flatMap((i) => i.observed.nodes.filter((n) => n.technique_id === param).map((n) => ({ n, inc: i.incident_id })));
  const tacticsSeen = uniq(seen.map((c) => c.tactic));
  const covered = all.data.filter((i) => i.techniques.length).length;
  const columns = TACTICS.filter((t) => cells.some((c) => c.tactic === t) );
  const absent = TACTICS.filter((t) => !columns.includes(t));
  const ents = uniq(dets.flatMap((d) => [...d.hosts, ...d.users]));
  return (
    <Page title="MITRE ATT&CK Explorer" sub="Columns are tactics. Red has supporting evidence, amber was only corroborated inside an incident, grey is covered by a rule but not observed.">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-2"><Kpi label="Tactics observed" value={`${tacticsSeen.length} / ${TACTICS.length}`} tone="cyan" /><Kpi label="Techniques detected" value={fmtN(uniq(seen.map((c) => c.id)).length)} tone="crit" sub={`${uniq(cells.map((c) => c.id)).length} covered in total`} /><Kpi label="Detections mapped" value={fmtN(det.data?.length)} /><Kpi label="Incident coverage" value={`${covered} / ${all.data.length}`} sub="incidents with mapped techniques" /></div>
      <Panel title="Matrix" actions={<span className="flex items-center gap-3 normal-case tracking-normal font-normal">{[["#EF4444", "Detected"], ["#F59E0B", "Corroborated"], ["#334155", "Not observed"]].map(([c, t]) => <span key={t} className="flex items-center gap-1 text-mute"><i className="w-2 h-2 rounded-sm" style={{ background: c }} />{t}</span>)}</span>}>
        <div className="overflow-x-auto p-2"><div className="grid gap-1.5 min-w-[880px]" style={{ gridTemplateColumns: `repeat(${columns.length}, minmax(112px,1fr))` }}>
          {columns.map((t) => { const col = cells.filter((c) => c.tactic === t).sort((a, b) => b.count - a.count || a.id.localeCompare(b.id));
            return <div key={t} className="min-w-0"><div className="text-2xs font-semibold text-sub text-center px-1 py-1.5 border-b-2 mb-1.5 h-11 grid place-items-center leading-tight" style={{ borderColor: col.some((c) => c.count) ? "#EF4444" : "#253247" }}>{t}</div>
              <div className="space-y-1">{col.map((c) => { const hit = c.count > 0, rel = !hit && c.incidents.size > 0;
                return <button key={c.id} onClick={() => go("attack", c.id)} title={c.name} className={`relative overflow-hidden w-full rounded-sm border px-1.5 py-1 text-left transition-colors ${param === c.id ? "ring-1 ring-cyan" : ""} ${hit ? "border-crit/60 bg-crit/15 hover:bg-crit/25" : rel ? "border-warn/50 bg-warn/10" : "border-line2 bg-bg2 hover:border-line"}`}>
                  <div className="flex justify-between gap-1"><span className={`mono text-2xs ${hit ? "text-[#FCA5A5]" : rel ? "text-warn" : "text-mute"}`}>{c.id}</span>{c.count > 0 && <span className="mono text-2xs text-ink">{c.count}</span>}</div>
                  {c.name && <div className="text-2xs text-sub truncate">{c.name}</div>}{hit && <i className="absolute left-0 bottom-0 h-px bg-crit" style={{ width: `${(c.count / maxN) * 100}%` }} />}</button>; })}</div></div>; })}
        </div>
        {absent.length > 0 && <div className="text-2xs text-mute px-1 pt-2">No rule covers: {absent.join(", ")}.</div>}</div>
      </Panel>
      <div className="grid grid-cols-1 xl:grid-cols-[1fr_380px] gap-3">
        <Panel title={param ? `Technique ${param}` : "Technique detail"} body="p-3 space-y-3">
          {!param && <div className="text-xs text-mute">Select a technique cell to see its evidence.</div>}
          {param && !sel.length && <Callout>{param} is not present in this workspace.</Callout>}
          {sel.length > 0 && <><KV rows={[["Name", sel[0].name || "No detections name this technique yet"], ["Tactic", sel.map((c) => c.tactic).join(", ")], ["Detections", fmtN(dets.length)], ["Detection sources", <span className="flex gap-1 flex-wrap">{uniq(dets.map((d) => d.rule_id)).map((r) => <span key={r} className="flex items-center gap-1"><Detector rule={r} /><span className="mono text-2xs">{r}</span></span>)}</span>], ["Incidents", <span className="flex gap-2">{uniq(nodes.map((n) => n.inc)).map((i) => <IncLink key={i} id={i} />)}</span>], ["Entities", <span className="mono text-2xs">{ents.slice(0, 10).join(", ") || "—"}</span>]]} />
            <Section title="Why flagged"><ul className="list-disc pl-4 text-xs text-sub space-y-0.5">{uniq(dets.map((d) => d.rule_title)).slice(0, 6).map((t) => <li key={t}>{t}</li>)}</ul></Section>
            <Section title="Evidence references"><div className="flex flex-wrap gap-x-2">{uniq(dets.flatMap((d) => d.member_event_ids.slice(0, 3))).slice(0, 14).map((e) => <EvLink key={e} id={e} />)}</div></Section>
            <button className="btn btn-primary" onClick={() => { setDetFilter({ technique: param! }); go("detections"); }}>View related detections</button></>}
          <div className="flex items-center gap-1.5"><Pill>Technique table</Pill><span className="text-2xs text-mute">IDs come from config/attack.yml. No LLM touches a mapping.</span></div>
        </Panel>
        <Panel title="Detections by tactic" body="p-2"><HBars data={(ov.data?.detections_by_tactic ?? []).map((t) => ({ key: t.key, value: t.count }))} color="#EF4444" /></Panel>
      </div>
    </Page>
  );
}
