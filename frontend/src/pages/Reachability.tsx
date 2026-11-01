import { useMemo, useState } from "react";
import { createColumnHelper } from "@tanstack/react-table";
import type { ReachRow } from "../lib/api";
import { entName, fmtN, pad, uniq } from "../lib/format";
import { useReach, useSelectedIncident } from "../lib/hooks";
import { useStore } from "../lib/store";
import { Bar, Basis, Callout, Drawer, Empty, ErrorBox, EvLink, KV, Kpi, Loading, Page, Panel, Pill, Section, Select } from "../components/ui";
import { DataTable } from "../components/DataTable";
import { CyGraph } from "../components/CyGraph";
import { reachElements } from "../components/IncidentGraph";
import { IncidentPicker } from "../components/IncidentPicker";
import { canon } from "../lib/derive";

const c = createColumnHelper<ReachRow>();
const kinds = (r: ReachRow) => uniq(r.path_edges.map((e) => e.kind));

export function Reachability() {
  const { id } = useSelectedIncident(); const q = useReach(id); const { go, setSimTargets } = useStore();
  const [crit, setCrit] = useState(""); const [hops, setHops] = useState(""); const [min, setMin] = useState(0); const [start, setStart] = useState(""); const [ev, setEv] = useState(""); const [sel, setSel] = useState<ReachRow | null>(null);
  const r = q.data; const rows = useMemo(() => (r?.reachable ?? []).filter((x) => (!crit || (crit === "critical") === x.critical) && (!hops || x.hops <= Number(hops)) && x.reach >= min && (!start || x.start === start) && (!ev || kinds(x).includes(ev))), [r, crit, hops, min, start, ev]);
  const els = useMemo(() => (r ? reachElements(rows, r) : []), [rows, r]);
  const columns = useMemo(() => [
    c.accessor("asset", { header: "Asset", cell: (v) => <span className="mono text-ink whitespace-nowrap">{v.getValue()}</span> }),
    c.accessor((x) => (x.critical ? "critical" : "standard"), { id: "crit", header: "Class", cell: (v) => <Pill tone={v.getValue() === "critical" ? "warn" : "mute"}>{v.getValue()}</Pill> }),
        c.accessor("reach", { header: "Reach", cell: (v) => <div className="w-16"><div className="mono">{v.getValue().toFixed(2)}</div><Bar value={v.getValue()} /></div> }),
    c.accessor("hops", { header: "Hops", cell: (v) => <span className="mono">{v.getValue()}</span> }),
    c.accessor((x) => uniq(x.path_edges.map((e) => e.relation)).join(" → "), { id: "rel", header: "Relationship", cell: (v) => <span className="mono text-2xs whitespace-nowrap">{v.getValue()}</span> }),
    c.accessor((x) => kinds(x).join(), { id: "basis", header: "Evidence", enableSorting: false, cell: (v) => <span className="flex gap-1">{kinds(v.row.original).map((k) => <Basis key={k} kind={k} />)}</span> }),
  ], []);
  if (q.isLoading) return <Loading label="Computing reachability" />;
  if (q.error) return <ErrorBox error={q.error} />;
  if (!r) return <Empty title="No incident selected" />;
  const others = sel ? uniq(r.reachable.filter((x) => x.asset === sel.asset).map((x) => x.start)) : [];
  const accounts = sel ? sel.path.filter((p) => p.startsWith("account:")) : [];
  return (
    <Page title="Asset Reachability" sub={`${id != null ? pad(id) : ""} · ${r.mode}, hop limit ${r.hop_limit}, minimum reach ${r.min_reach}`} actions={<IncidentPicker />}>
      <Callout>Reachability is a model of what an attacker could try next from implicated entities. It is never proof that an asset was compromised.</Callout>
      <div className="grid grid-cols-2 md:grid-cols-5 gap-2"><Kpi label="Implicated starts" value={fmtN(r.compromised.length)} tone="crit" /><Kpi label="Reachable assets" value={fmtN(r.reachable.length)} sub={`${rows.length} after filters`} /><Kpi label="Critical reachable" value={`${r.critical_reachable} / ${r.total_critical_assets}`} tone="warn" /><Kpi label="Direct (1 hop)" value={fmtN(r.reachable.filter((x) => x.hops === 1).length)} /><Kpi label="Model graph" value={`${r.graph.nodes} · ${r.graph.edges}`} sub="nodes · edges" /></div>
      <div className="flex items-center gap-2 flex-wrap">
        <Select label="All assets" value={crit} onChange={setCrit} options={["critical", "standard"]} /><Select label="Any evidence" value={ev} onChange={setEv} options={uniq((r.reachable).flatMap(kinds))} /><Select label="Any hops" value={hops} onChange={setHops} options={uniq(r.reachable.map((x) => x.hops)).sort().map((h) => [String(h), `≤ ${h} hops`])} /><Select label="All starts" value={start} onChange={setStart} options={uniq(r.reachable.map((x) => x.start)).sort()} />
        <label className="flex items-center gap-2 text-xs text-sub">Min reach<input aria-label="Minimum reach" type="range" min={0} max={1} step={0.05} value={min} onChange={(e) => setMin(Number(e.target.value))} className="accent-[#26D9D0] w-24" /><span className="mono text-2xs">{min.toFixed(2)}</span></label>
      </div>
      <div className="grid grid-cols-1 xl:grid-cols-[1.1fr_1fr] gap-3">
        <Panel title="Exposure paths, left to right by hop" className="h-[440px] overflow-hidden">{els.length ? <CyGraph elements={els} layout="preset" selected={sel ? canon(`host:${sel.asset}`) : null} onSelect={(n) => { const row = r.reachable.find((x) => canon(`host:${x.asset}`) === n); setSel(row ?? null); }} /> : <Empty title="Nothing reachable under these filters" />}</Panel>
        <Panel title={`Assets · ${rows.length}`} className="h-[440px]"><DataTable data={rows} columns={columns} onRow={setSel} selected={(x) => x === sel} empty="No asset matches" /></Panel>
      </div>
      {sel && <Drawer title={sel.asset} onClose={() => setSel(null)} badge={<Pill tone={sel.critical ? "warn" : "mute"}>{sel.critical ? "Critical asset" : "Asset"}</Pill>}>
        <KV rows={[["Criticality", sel.criticality], ["Reach", sel.reach], ["Hops", sel.hops], ["Start", <span className="mono text-2xs">{sel.start}</span>], ["Other starts", others.map(entName).join(", ")]]} />
        <Section title="Why it is reachable"><p className="text-xs text-sub">{sel.explanation}</p></Section>
        <Section title="Supporting path"><div className="space-y-1.5">{sel.path_edges.map((e, i) => <div key={i} className="rounded border border-line2 bg-bg px-2 py-1.5"><div className="flex items-center gap-1.5 text-2xs flex-wrap"><span className="mono">{entName(e.src)}</span><span className="mono text-cyan">{e.relation}</span><span className="mono">{entName(e.dst)}</span><span className="flex-1" /><Basis kind={e.kind} /></div>
          <div className="text-2xs text-mute mt-0.5">{e.evidence.text}</div><div className="flex flex-wrap gap-x-2">{e.evidence.event_ids?.slice(0, 5).map((x) => <EvLink key={x} id={x} />)}</div></div>)}</div></Section>
        {accounts.length > 0 && <button className="btn btn-primary" onClick={() => { setSimTargets(accounts.map(entName)); go("simulate"); }}>Simulate disabling {accounts.map(entName).join(", ")}</button>}
      </Drawer>}
    </Page>
  );
}
