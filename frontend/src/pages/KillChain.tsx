import { useMemo, useState } from "react";
import { AlertTriangle, Check, Minus } from "lucide-react";
import { fmtN, fmtTime, fmtTs, pad } from "../lib/format";
import { useIncident, useSelectedIncident } from "../lib/hooks";
import { Callout, Detector, Empty, ErrorBox, EvLink, Loading, Page, Panel, Pill, Tech } from "../components/ui";
import { IncidentPicker } from "../components/IncidentPicker";
import { KILL_CHAIN, ambiguousTechniques, orderedSteps } from "../lib/derive";

export function KillChain() {
  const { id } = useSelectedIncident(); const q = useIncident(id); const [stage, setStage] = useState<string | null>(null);
  const steps = useMemo(() => (q.data ? orderedSteps(q.data) : []), [q.data]);
  const amb = useMemo(() => ambiguousTechniques(steps), [steps]);
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  if (!q.data) return <Empty title="No incident selected" />;
  const by = (s: string) => steps.filter((n) => n.kill_chain_phase === s);
  const unknown = steps.filter((n) => !n.kill_chain_phase || !KILL_CHAIN.includes(n.kill_chain_phase));
  const shown = (stage ? (stage === "Unknown" ? unknown : by(stage)) : steps);
  const covered = KILL_CHAIN.filter((s) => by(s).length).length;
  return (
    <Page title="Cyber Kill Chain" sub={`${pad(q.data.incident_id)} · ${covered} of ${KILL_CHAIN.length} stages have evidence. Stage comes from the tactic mapping in config/attack.yml.`} actions={<IncidentPicker />}>
      <Panel body="px-4 py-5"><div className="grid grid-cols-7 gap-0 min-w-[760px]">
        {KILL_CHAIN.map((s, i) => { const n = by(s).length; const on = n > 0; return (
          <button key={s} onClick={() => setStage(stage === s ? null : s)} className="relative flex flex-col items-center gap-1.5 group px-1">
            {i < 6 && <i className={`absolute top-[19px] left-1/2 w-full h-px ${on && by(KILL_CHAIN[i + 1]).length ? "bg-crit shadow-[0_0_6px_#EF4444]" : "bg-line"}`} />}
            <span className={`relative z-[1] w-10 h-10 rounded-full grid place-items-center border-2 transition-all ${stage === s ? "ring-2 ring-cyan ring-offset-2 ring-offset-panel" : ""} ${on ? "border-crit bg-crit/15 text-crit shadow-[0_0_14px_rgba(239,68,68,.4)]" : "border-line bg-bg2 text-mute"}`}>{on ? <span className="mono text-sm font-semibold text-[#FECACA]">{n}</span> : <Minus size={14} />}</span>
            <span className={`text-xs text-center leading-tight ${on ? "text-ink font-medium" : "text-mute"}`}>{s}</span><span className="text-2xs text-mute">{on ? `${n} step${n > 1 ? "s" : ""}` : "Not observed"}</span>
          </button>); })}
      </div></Panel>
      {amb.size > 0 && <Callout><AlertTriangle size={12} className="inline mr-1" />Ambiguous mapping: {[...amb].join(", ")} appears in more than one stage in this incident, because ATT&CK techniques can serve several tactics. Both placements are shown as observed.</Callout>}
      <Callout tone="cyan">ATT&CK and the Kill Chain are separate frameworks. Kairos maps tactic to stage through a documented table, so a stage here is a mapping, not an extra detection. {unknown.length > 0 && <button className="link ml-1" onClick={() => setStage("Unknown")}>{unknown.length} step(s) have no stage</button>}</Callout>
      <Panel title={`Events ${stage ? `· ${stage}` : "· all stages, in attack order"}`} actions={stage && <button className="link text-2xs normal-case tracking-normal" onClick={() => setStage(null)}>Show all</button>} body="overflow-auto">
        {!shown.length ? <Empty title={`No evidence for ${stage}`} text="Shown as not observed rather than assumed." /> : <table className="tbl"><thead><tr>{["Time", "Stage", "Description", "Entity", "Event", "Technique", "Evidence"].map((h) => <th key={h}>{h}</th>)}</tr></thead>
          <tbody>{shown.map((n) => { const ent = n.entities.host?.[0] ?? n.entities.user?.[0] ?? "—"; return <tr key={n.group_id}><td className="mono whitespace-nowrap" title={fmtTs(n.ts_first)}>{fmtTime(n.ts_first)}</td><td className="whitespace-nowrap"><Pill tone={n.severity >= 3 ? "crit" : "warn"}>{n.kill_chain_phase ?? "Unknown"}</Pill></td>
            <td><span className="flex items-center gap-1.5"><Detector rule={n.rule_id} /><span className="text-ink">{n.rule_title}</span></span></td><td className="mono text-2xs">{ent}</td><td><EvLink id={n.member_event_ids[0]} label={`${fmtN(n.member_count)} events`} /></td>
            <td><span className="flex items-center gap-1.5"><Tech id={n.technique_id} />{amb.has(n.technique_id) && <span title="Placed in several stages here"><AlertTriangle size={10} className="text-warn" /></span>}</span></td><td><span className="inline-flex items-center gap-1 text-2xs text-ok"><Check size={11} />raw lines cited</span></td></tr>; })}</tbody></table>}
      </Panel>
    </Page>
  );
}
