import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Check, CircleDashed, FileUp, Loader2, Play, Trash2, UploadCloud, X } from "lucide-react";
import { api, withWs } from "../lib/api";
import { fmtBytes, fmtDur, fmtN, fmtPct, fmtTs } from "../lib/format";
import { useCurrentWs, useInputs, useJob, useLiveAlerts, useLiveStatus, useOverview, useWorkspaces } from "../lib/hooks";
import { useStore } from "../lib/store";
import { Bar, Callout, Detector, Drawer as Drawerless, Empty, ErrorBox, Kpi, Loading, NotAvailable, Page, Panel, Pill, Tech } from "../components/ui";
import { ExplanationView } from "../components/Explanation";
import { useQuery } from "@tanstack/react-query";
import type { Explanation } from "../lib/api";

interface Up { name: string; size: number; pct: number; state: "uploading" | "done" | "failed" | "conflict"; msg?: string; file: File }

// The backend's real stages. Parsing, normalising and Parquet writing happen inside one "ingest" stage,
// so they are shown together rather than as invented separate progress bars.
const STAGES: { id: string; title: string; note: string; time?: string[] }[] = [
  { id: "ingest", title: "Ingest", note: "parse · normalise · store Parquet", time: ["ingest_s"] },
  { id: "detect", title: "Rules", note: "YAML rules in DuckDB", time: ["detect_s"] },
  { id: "ml", title: "ML", note: "Isolation Forest · Adamic-Adar", time: ["ml_s"] },
  { id: "correlate", title: "Correlate", note: "scored incident edges", time: ["correlate_s"] },
  { id: "reach", title: "Reachability", note: "asset exposure · cache", time: ["reach_and_cache_s"] },
  { id: "graph", title: "Graph", note: "Neo4j load, when enabled" },
];

export function Ingestion() {
  const inputs = useInputs(); const qc = useQueryClient(); const job = useJob().data; const wss = useWorkspaces().data ?? [];
  const ov = useOverview(); const cur = useCurrentWs();
  const { runLog, log, setWs, go } = useStore();
  const [ups, setUps] = useState<Up[]>([]); const [over, setOver] = useState(false); const [target, setTarget] = useState("input");
  const pick = useRef<HTMLInputElement>(null);
  const term = useRef<HTMLDivElement>(null);
  const running = job?.state === "running";
  useEffect(() => { term.current?.scrollTo(0, term.current.scrollHeight); }, [runLog.length]);

  const upload = useCallback((file: File, overwrite = false) => {
    const mark = (p: Partial<Up>) => setUps((u) => u.map((x) => (x.file === file ? { ...x, ...p } : x)));
    setUps((u) => [{ name: file.name, size: file.size, pct: 0, state: "uploading" as const, file }, ...u.filter((x) => x.file !== file)]);
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `/inputs?filename=${encodeURIComponent(file.name)}${overwrite ? "&overwrite=true" : ""}`);
    xhr.setRequestHeader("Content-Type", "application/octet-stream");
    xhr.upload.onprogress = (e) => { if (e.lengthComputable) mark({ pct: e.loaded / e.total }); };
    xhr.onload = () => {
      let msg = xhr.statusText;
      try { msg = JSON.parse(xhr.responseText).detail ?? msg; } catch { /* keep status text */ }
      if (xhr.status >= 200 && xhr.status < 300) { mark({ pct: 1, state: "done" }); log({ tag: "UPLOAD", tone: "ok", text: `${file.name} stored in the input folder (${fmtBytes(file.size)})` }); qc.invalidateQueries({ queryKey: ["inputs"] }); }
      else if (xhr.status === 409 && !overwrite && /already exists/.test(msg)) mark({ state: "conflict", msg });
      else { mark({ state: "failed", msg }); log({ tag: "UPLOAD", tone: "crit", text: `${file.name}: ${msg}` }); }
    };
    xhr.onerror = () => mark({ state: "failed", msg: "connection lost" });
    xhr.send(file);
  }, [log, qc]);

  const start = useMutation({
    mutationFn: () => api("/runs", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ workspace: target }) }),
    onSuccess: () => { log({ tag: "RUN", text: `Analysis of workspace "${target}" accepted by the server` }); qc.invalidateQueries({ queryKey: ["job"] }); },
    onError: (e) => log({ tag: "RUN", tone: "crit", text: String((e as Error).message) }),
  });
  const del = useMutation({ mutationFn: (n: string) => api(`/inputs/${encodeURIComponent(n)}`, { method: "DELETE" }), onSuccess: () => qc.invalidateQueries({ queryKey: ["inputs"] }) });

  // Time spent per stage as seen by this browser while the run was active.
  const measured = useMemo(() => {
    const m: Record<string, number> = {};
    const stg = runLog.filter((l) => l.stage);
    stg.forEach((l, i) => { const n = stg[i + 1]; if (l.stage !== "done" && n) { const k = l.stage!.split(":")[0]; m[k] = (m[k] ?? 0) + (n.at - l.at) / 1000; } });
    return m;
  }, [runLog]);
  const stageNow = job?.stage?.split(":")[0];
  const idx = STAGES.findIndex((s) => s.id === stageNow);
  const stateOf = (i: number) => {
    if (running) return stageNow === "queued" ? "pending" : i < idx ? "done" : i === idx ? "active" : "pending";
    if (job?.state === "done") return STAGES[i].id === "graph" ? "skip" : "done";
    if (job?.state === "failed") return "pending";
    return "idle";
  };
  const allowed = inputs.data?.allowed_suffixes ?? [];
  const sameRun = job?.state === "done" && job.workspace === ov.data?.workspace; // never show another workspace's timings
  const run = sameRun ? ov.data?.run : undefined;
  return (
    <Page title="Live Ingestion" sub="Upload progress and processing progress are tracked separately. Status is polled from the API while a run is active.">
      <div className="grid grid-cols-1 xl:grid-cols-[380px_1fr] gap-3">
        <Panel title="1 · Upload logs" body="p-3 space-y-2.5">
          <div onDragOver={(e) => { e.preventDefault(); setOver(true); }} onDragLeave={() => setOver(false)} onDrop={(e) => { e.preventDefault(); setOver(false); [...e.dataTransfer.files].forEach((f) => upload(f)); }} onClick={() => pick.current?.click()}
            className={`rounded-md border border-dashed h-28 grid place-items-center text-center cursor-pointer transition-colors ${over ? "border-cyan bg-cyan/10" : "border-line hover:border-cyan/60 bg-bg2"}`}>
            <div><UploadCloud size={22} className="mx-auto text-cyan" /><div className="text-xs mt-1">Drop log files or click to browse</div><div className="text-2xs text-mute">{allowed.join(" ")} · up to {fmtBytes(inputs.data?.max_upload_bytes)} each</div></div>
            <input ref={pick} type="file" multiple hidden accept={allowed.join(",")} onChange={(e) => { [...(e.target.files ?? [])].forEach((f) => upload(f)); e.target.value = ""; }} />
          </div>
          <p className="text-2xs text-mute">JSON, CEF, syslog, key=value and CSV are detected per line, so there is no format setting.</p>
          {ups.map((u) => <div key={u.name + u.size} className="rounded border border-line2 bg-bg2 px-2 py-1.5">
            <div className="flex items-center gap-2 text-xs"><FileUp size={12} className="text-mute shrink-0" /><span className="mono truncate flex-1">{u.name}</span><span className="text-2xs text-mute">{fmtBytes(u.size)}</span>
              <span className={`text-2xs ${u.state === "done" ? "text-ok" : u.state === "failed" ? "text-crit" : u.state === "conflict" ? "text-warn" : "text-cyan"}`}>{u.state === "uploading" ? `${Math.round(u.pct * 100)}%` : u.state}</span></div>
            <div className="mt-1"><Bar value={u.pct} tone={u.state === "failed" ? "#EF4444" : u.state === "done" ? "#22C55E" : "#26D9D0"} /></div>
            {u.msg && <div className="text-2xs text-mute mt-1">{u.msg}</div>}
            {u.state === "conflict" && <button className="btn mt-1" onClick={() => upload(u.file, true)}>Replace existing file</button>}
          </div>)}
          <div><div className="label mb-1">Input folder · {inputs.data?.folder}</div>
            {inputs.data?.files.length ? <div className="space-y-1 max-h-32 overflow-auto">{inputs.data.files.map((f) => <div key={f.name} className="flex items-center gap-2 text-xs px-1"><span className="mono truncate flex-1" title={f.name}>{f.name}</span><span className="text-2xs text-mute">{fmtBytes(f.size)}</span>
              <button aria-label={`Delete ${f.name}`} className="text-mute hover:text-crit" disabled={del.isPending} onClick={() => del.mutate(f.name)}><Trash2 size={12} /></button></div>)}</div> : <div className="text-2xs text-mute">Empty</div>}
            {del.error && <ErrorBox error={del.error} />}
          </div>
        </Panel>
        <div className="flex flex-col gap-3 min-w-0">
          <Panel title="2 · Process" actions={job?.elapsed_s != null && <span className="mono normal-case tracking-normal font-normal">{fmtDur(job.elapsed_s)}</span>} body="p-3 space-y-3">
            <div className="flex items-center gap-2 flex-wrap">
              <label className="label" htmlFor="target">Analyse</label>
              <select id="target" className="field" value={target} onChange={(e) => setTarget(e.target.value)} disabled={running}>{wss.filter((w) => w.runnable).map((w) => <option key={w.name} value={w.name}>{w.name} · {w.source}</option>)}</select>
              <button className="btn btn-primary" disabled={running || start.isPending} onClick={() => start.mutate()}>{running ? <Loader2 size={12} className="animate-spin" /> : <Play size={12} />}{running ? "Running" : "Start analysis"}</button>
              <button className="btn" disabled title="The API has no way to stop a run; it finishes on its own"><X size={12} />Cancel</button>
              <span className="text-2xs text-mute">Cancel needs backend support.</span>
              <span className="flex-1" />
              {job?.state === "done" && <button className="btn" onClick={() => { setWs(job.workspace!); go("incidents"); }}>Open results</button>}
            </div>
            {start.error && <ErrorBox error={start.error} />}
            {job?.state === "failed" && <Callout tone="crit">Run failed: {job.error}</Callout>}
            <div><div className="flex justify-between text-2xs text-mute mb-1"><span>Processing progress</span><span className="mono">{running ? `${job!.stage} · ${Math.round((job!.progress ?? 0) * 100)}%` : job?.state === "done" ? `complete · ${job.workspace}` : "idle"}</span></div>
              <Bar value={running ? job!.progress ?? 0 : job?.state === "done" ? 1 : 0} tone={job?.state === "failed" ? "#EF4444" : "#26D9D0"} /></div>
            <div className="grid grid-cols-3 lg:grid-cols-6 gap-1.5">
              {STAGES.map((s, i) => { const st = stateOf(i); const server = s.id === "detect" ? Math.max(0, (run?.stages?.detect_s ?? 0) - (run?.stages?.ml_s ?? 0)) : s.time?.reduce((a, k) => a + (run?.stages?.[k] ?? 0), 0);
                return <div key={s.id} className={`rounded border px-2 py-1.5 min-w-0 transition-colors ${st === "active" ? "border-cyan/60 bg-cyan/10" : st === "done" ? "border-ok/30 bg-ok/[.05]" : "border-line2 bg-bg2"}`}>
                  <div className="flex items-center gap-1.5 text-xs font-medium">{st === "active" ? <Loader2 size={11} className="animate-spin text-cyan" /> : st === "done" ? <Check size={11} className="text-ok" /> : <CircleDashed size={11} className="text-mute" />}{s.title}</div>
                  <div className="text-2xs text-mute truncate" title={s.note}>{s.note}</div>
                  <div className="mono text-2xs text-sub mt-0.5">{st === "skip" ? "not requested" : st === "active" ? (measured[s.id] != null ? fmtDur(measured[s.id]) : "running") : server ? fmtDur(server) : measured[s.id] != null ? fmtDur(measured[s.id]) : "—"}</div></div>; })}
            </div>
          </Panel>
          <Panel title="Processing log" className="h-[196px]" actions={<span className="normal-case tracking-normal font-normal text-mute">Real events from this session</span>}>
            <div ref={term} className="h-full overflow-auto bg-bg px-3 py-2 mono text-2xs leading-[18px]">
              {runLog.length ? runLog.map((l, i) => <div key={i} className="flex gap-2"><span className="text-mute shrink-0">{new Date(l.at).toLocaleTimeString()}</span><span className={`shrink-0 ${l.tone === "crit" ? "text-crit" : l.tone === "ok" ? "text-ok" : "text-cyan"}`}>[{l.tag}]</span><span className="text-sub break-words min-w-0">{l.text}</span></div>)
                : <span className="text-mute">Waiting for an upload or a run…</span>}
            </div>
          </Panel>
        </div>
      </div>
      {ov.data && !cur?.live && <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-8 gap-2">
        {(() => { const r = ov.data.run; const bytes = r.dataset?.files.reduce((a, f) => a + f.size, 0) ?? 0; const s = r.stages?.ingest_s; return <>
          <Kpi label="Events / second" value={s ? fmtN(Math.round((r.ingest?.events ?? 0) / s)) : "N/A"} sub={`last run · ${ov.data.workspace}`} tone="cyan" />
          <Kpi label="MB / second" value={s ? (bytes / 2 ** 20 / s).toFixed(1) : "N/A"} sub="ingest average" />
          <Kpi label="Total records" value={fmtN(r.ingest?.lines)} sub={`${fmtBytes(bytes)} read`} />
          <Kpi label="Valid records" value={fmtN(r.ingest?.events)} sub={fmtPct(r.ingest ? r.ingest.events / Math.max(1, r.ingest.lines) : null)} tone="ok" />
          <Kpi label="Parse errors" value={fmtN(r.ingest?.errors)} tone={r.ingest?.errors ? "warn" : undefined} sub="kept with byte offset" />
          <Kpi label="Peak memory" value={fmtBytes(r.peak_rss_bytes)} sub="main process, whole run" />
          <Kpi label="Ingest workers" value={fmtN(r.ingest_parallel?.workers)} sub={`${fmtN(r.ingest_parallel?.ranges)} byte ranges`} />
          <Kpi label="Run wall time" value={fmtDur(r.wall_time_s)} sub={r.finished_at?.slice(0, 16).replace("T", " ")} />
        </>; })()}
      </div>}
      {!cur?.live && <NotAvailable title="Live CPU, live memory and DuckDB spill while a run is active" why="The API only reports these as totals after a run. The figures above are last-run values, not live gauges." />}
      <LiveSection />
    </Page>
  );
}

function LiveSection() {
  const cur = useCurrentWs(); const ws = cur?.name ?? ""; const live = !!cur?.live;
  const st = useLiveStatus(live); const al = useLiveAlerts(live);
  const [sel, setSel] = useState<string | null>(null);
  const ex = useQuery({ queryKey: ["explain-alert", ws, sel], enabled: !!sel, queryFn: () => api<Explanation>(withWs(`/explain/alert/${encodeURIComponent(sel!)}`, ws)) });
  if (!live) return <Panel title="Live mode" body="p-3"><div className="text-xs text-sub">Live mode follows a folder and keeps enriching a knowledge base. It is started from the command line; its workspace then appears in the top bar and updates here every 5 seconds.</div><code className="mono text-2xs text-cyan block mt-1.5">make live GRAPH=1 RESET=1</code></Panel>;
  if (st.isLoading) return <Loading />;
  if (st.error) return <ErrorBox error={st.error} />;
  const s = st.data!; const kb = s.knowledge_base ?? {}; const hist = [...(s.history ?? [])].slice(-15).reverse();
  return <>
    <div className="grid grid-cols-2 lg:grid-cols-5 gap-2">
      <Kpi label="Batches processed" value={fmtN(s.batches)} sub={`last: ${fmtN(s.last_batch?.events)} events`} tone="cyan" /><Kpi label="Events ingested" value={fmtN(s.totals?.events)} sub={`${fmtN(s.totals?.errors)} parse errors`} />
      <Kpi label="Knowledge-base alerts" value={fmtN(kb.alerts)} sub={`${fmtN(kb.tactics)} tactics`} tone="warn" /><Kpi label="Correlation edges" value={fmtN(kb.edges)} sub="stored, any batch" /><Kpi label="Latest event" value={<span className="text-sm">{fmtTs(s.watermark)}</span>} sub={Object.entries(s.batch_tiers ?? {}).map(([k, v]) => `${k}: ${v}`).join(" · ")} />
    </div>
    <div className="grid grid-cols-1 xl:grid-cols-2 gap-3">
      <Panel title="Recent batches" actions={<Pill tone="ok">refreshes every 5 s</Pill>} className="max-h-80" body="overflow-auto"><table className="tbl"><thead><tr>{["Batch", "Events", "Ingest s", "Analyse s", "Detections", "Edges+"].map((c) => <th key={c}>{c}</th>)}</tr></thead>
        <tbody>{hist.map((b) => <tr key={b.batch}><td className="mono">{b.batch}</td><td className="mono">{fmtN(b.events)}</td><td className="mono">{b.ingest_s}</td><td className="mono">{b.analyse_s}</td><td className="mono">{fmtN(b.detections_in_batch)}</td><td className="mono">{fmtN(b.edges_added)}</td></tr>)}</tbody></table></Panel>
      <Panel title="Knowledge-base alerts, latest first" className="max-h-80" body="overflow-auto">{al.data?.length ? <table className="tbl"><thead><tr>{["Last seen", "", "Detection", "Technique", "Fused"].map((c) => <th key={c}>{c}</th>)}</tr></thead>
        <tbody>{al.data.map((a) => <tr key={a.uid} className="click" onClick={() => setSel(a.uid)}><td className="mono whitespace-nowrap">{fmtTs(a.ts_last)}</td><td><Detector rule={a.rule_id} /></td><td className="max-w-44 truncate" title={a.rule_title}>{a.rule_title}</td><td><Tech id={a.technique_id} /></td><td className="mono">{a.p_malicious?.toFixed(3) ?? "—"}</td></tr>)}</tbody></table> : <Empty title="No alerts yet" text="ML models stay silent during warm-up." />}</Panel>
    </div>
    {sel && <Drawerless title={`Alert ${sel}`} onClose={() => setSel(null)}>{ex.isLoading ? <Loading /> : ex.error ? <ErrorBox error={ex.error} /> : ex.data && <ExplanationView x={ex.data} kind="alert" id={sel} />}</Drawerless>}
  </>;
}
