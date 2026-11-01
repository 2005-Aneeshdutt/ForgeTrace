import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronLeft, ChevronRight, Play } from "lucide-react";
import { api } from "../lib/api";
import { useWorkspaces } from "../lib/hooks";
import { useStore } from "../lib/store";
import { Empty, ErrorBox, Loading, Page, Panel, Pill } from "../components/ui";

type W = Record<string, any>;
const prim = (v: unknown) => v == null || typeof v !== "object";
const show = (v: unknown) => (v == null ? "—" : typeof v === "object" ? JSON.stringify(v) : String(v));

// Generic renderer: walkthrough sections are plain stored outputs, so they are displayed as they are.
function Auto({ data }: { data: unknown }) {
  if (Array.isArray(data)) {
    if (!data.length) return <div className="text-xs text-mute p-3">Empty at this stage.</div>;
    if (prim(data[0])) return <div className="flex flex-wrap gap-1 p-3">{data.map((d, i) => <Pill key={i}>{show(d)}</Pill>)}</div>;
    const cols = [...new Set(data.flatMap((r) => Object.keys(r as object)))].filter((c) => data.some((r) => prim((r as W)[c]) || Array.isArray((r as W)[c]))).slice(0, 9);
    return <div className="overflow-auto"><table className="tbl"><thead><tr>{cols.map((c) => <th key={c}>{c.replace(/_/g, " ")}</th>)}</tr></thead><tbody>{data.map((r, i) => <tr key={i}>{cols.map((c) => <td key={c} className="mono text-2xs max-w-72 truncate" title={show((r as W)[c])}>{show((r as W)[c])}</td>)}</tr>)}</tbody></table></div>;
  }
  if (data && typeof data === "object") {
    return <div className="p-3 grid gap-x-4 gap-y-1 grid-cols-[auto_1fr] text-xs">{Object.entries(data).map(([k, v]) => [<span key={k} className="text-mute">{k.replace(/_/g, " ")}</span>, <span key={`${k}v`} className="mono text-2xs break-all">{show(v)}</span>])}</div>;
  }
  return <div className="p-3 mono text-xs">{show(data)}</div>;
}

const STEPS: [string, string, string[]][] = [
  ["Ingest", "Each raw line is read by byte offset, hashed and given a stable event id.", ["files", "lines"]],
  ["Normalise & store", "Vendor fields become one envelope, written to Parquet and queried through DuckDB.", ["storage"]],
  ["Detect", "YAML rules run as SQL. Models add behaviour and link flags.", ["rules", "detections"]],
  ["Aggregate", "Detections of the same technique on the same entity collapse into one alert group.", ["groups"]],
  ["Correlate", "Candidate links share an entity. Each is scored and kept only above the threshold.", ["shared_entities", "candidate_edges", "theta_edge", "weights"]],
  ["Incident", "Kept links form incidents. Components that fail the checks stay unlinked.", ["incidents", "abstained"]],
  ["Verify", "Every number traces back to raw lines whose hashes are re-checked.", ["verify", "stats"]],
];

export function Walkthrough() {
  const wss = useWorkspaces().data ?? []; const demo = wss.find((w) => w.name === "demo"); const qc = useQueryClient(); const [i, setI] = useState(0); const go = useStore((s) => s.go); const setWs = useStore((s) => s.setWs);
  const q = useQuery({ queryKey: ["walkthrough"], enabled: !!demo?.analysed, queryFn: () => api<W>("/walkthrough?ws=demo") });
  const run = useMutation({ mutationFn: () => api("/runs", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ workspace: "demo" }) }), onSuccess: () => qc.invalidateQueries() });
  if (!demo?.analysed) return <Empty title="Run the demo pipeline first" text="A five-event file passes through every stage, and this page shows each stage's stored output." action={<button className="btn btn-primary" disabled={run.isPending} onClick={() => run.mutate()}><Play size={12} />Run demo pipeline</button>} />;
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  const [, text, keys] = STEPS[i];
  return (
    <Page title="Pipeline walkthrough" sub="One tiny dataset through every stage, showing real stored output." actions={<button className="btn" onClick={() => { setWs("demo"); go("incidents"); }}>Open demo incident</button>}>
      <div className="flex gap-1 flex-wrap">{STEPS.map(([t], n) => <button key={t} onClick={() => setI(n)} className={`btn ${n === i ? "btn-primary" : ""}`}><span className="mono">{n + 1}</span>{t}</button>)}</div>
      <p className="text-sm text-sub">{text}</p>
      {keys.filter((k) => q.data?.[k] != null).map((k) => <Panel key={k} title={k.replace(/_/g, " ")} className="max-h-[420px]" body="overflow-auto"><Auto data={k === "lines" ? q.data![k].map(({ trace: _t, envelope: _e, label: _l, ...r }: W) => r) : q.data![k]} /></Panel>)}
      <div className="flex justify-between"><button className="btn" disabled={i === 0} onClick={() => setI(i - 1)}><ChevronLeft size={12} />Previous</button><button className="btn btn-primary" disabled={i === STEPS.length - 1} onClick={() => setI(i + 1)}>Next<ChevronRight size={12} /></button></div>
    </Page>
  );
}
