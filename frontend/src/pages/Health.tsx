import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, useTelemetry, withWs } from "../lib/api";
import type { GraphStatus } from "../lib/api";
import { fmtBytes, fmtDur, fmtN, fmtTs } from "../lib/format";
import { useCurrentWs, useGraphStatus, useInputs, useJob, useOverview, useWs } from "../lib/hooks";
import { Empty, Kpi, NotAvailable, Page, Panel, Pill } from "../components/ui";
import { HBars } from "../components/charts";

const Row = ({ name, ok, text }: { name: string; ok: boolean | null; text: string }) => <div className="flex items-center gap-2 px-3 py-1.5 border-b border-line2 text-xs"><i className={`w-1.5 h-1.5 rounded-full ${ok == null ? "bg-mute" : ok ? "bg-ok" : "bg-crit"}`} /><span className="flex-1">{name}</span><span className="text-2xs text-mute truncate max-w-[60%]" title={text}>{text}</span></div>;

export function Health() {
  const ws = useWs(); const cur = useCurrentWs(); const job = useJob().data; const ov = useOverview(); const inputs = useInputs().data; const g: GraphStatus | undefined = useGraphStatus().data;
  const h = useQuery({ queryKey: ["health", ws], enabled: !!ws && !!cur?.analysed && !cur.live, queryFn: () => api<{ status: string; config_hash: string; code_version: string; manifest_digest: string | null }>(withWs("/health", ws!)), refetchInterval: 10_000 });
  const { calls, errors } = useTelemetry();
  const by = useMemo(() => { const m = new Map<string, number[]>(); calls.forEach((c) => m.set(c.path, [...(m.get(c.path) ?? []), c.ms])); return [...m].map(([k, v]) => ({ key: k, value: Math.round(v.reduce((a, b) => a + b, 0) / v.length), n: v.length })).sort((a, b) => b.value - a.value).slice(0, 10); }, [calls]);
  const r = ov.data?.run; const recent = calls.slice(-120);
  const slowest = Object.entries(r?.rule_seconds ?? {}).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([key, v]) => ({ key, value: Number((v * 1000).toFixed(1)) }));
  const failRate = calls.length ? calls.filter((c) => c.status === 0 || c.status >= 500).length / calls.length : 0;
  return (
    <Page title="System Health" sub="Service state from the API, plus latency this browser actually measured in this session.">
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-2"><Kpi label="API" value={calls.at(-1)?.status === 0 ? "Down" : "Up"} tone={calls.at(-1)?.status === 0 ? "crit" : "ok"} sub={h.data?.code_version} /><Kpi label="Active jobs" value={job?.state === "running" ? 1 : 0} sub={job?.state ?? "—"} /><Kpi label="Peak memory" value={fmtBytes(r?.peak_rss_bytes)} sub="last run, main process" /><Kpi label="Parser failures" value={fmtN(r?.ingest?.errors)} tone={r?.ingest?.errors ? "warn" : undefined} sub={`${fmtN(r?.ingest?.lines)} lines`} /><Kpi label="Avg API latency" value={calls.length ? `${Math.round(calls.reduce((a, c) => a + c.ms, 0) / calls.length)} ms` : "—"} sub={`${calls.length} calls measured`} tone="cyan" /><Kpi label="Failed calls" value={`${(failRate * 100).toFixed(1)}%`} tone={failRate ? "crit" : "ok"} sub="this session" /></div>
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-3">
        <Panel title="Services" body="overflow-auto">
          <Row name="FastAPI" ok={calls.at(-1)?.status !== 0} text={h.data ? `${h.data.status} · config ${h.data.config_hash.slice(0, 10)}` : "running"} />
          <Row name="DuckDB workspace" ok={cur?.analysed ?? null} text={cur?.name ?? "—"} />
          <Row name="Parquet events" ok={!!r?.ingest} text={r?.ingest ? `${fmtN(r.ingest.events)} rows · ${fmtBytes(r.dataset?.files.reduce((a, f) => a + f.size, 0))} source` : "none"} />
          <Row name="Input folder" ok={!!inputs} text={inputs ? `${inputs.folder} · ${inputs.files.length} file(s)` : "—"} />
          <Row name="Neo4j graph store (optional)" ok={g?.available ? true : null} text={g?.available ? g.uri ?? "connected" : "not running"} />
          <Row name="Live stream (SSE)" ok={null} text="Not provided by the API; status is polled" />
        </Panel>
        <Panel title="Mean API latency, this session (ms)" body="p-2 overflow-auto">{by.length ? <HBars data={by} unit="ms" /> : <Empty title="No calls yet" />}</Panel>
        <Panel title="DuckDB rule time, last run (ms)" body="p-2 overflow-auto">{slowest.length ? <HBars data={slowest} unit="ms" color="#12B8A6" /> : <Empty title="No run data" />}</Panel>
      </div>
      <Panel title={`API call timeline · last ${recent.length} calls`} body="p-3"><div className="flex items-end gap-px h-14">{recent.map((c, i) => <i key={i} title={`${c.path} · ${Math.round(c.ms)} ms · HTTP ${c.status}`} className="flex-1 max-w-2 rounded-t-sm" style={{ height: `${Math.min(100, 8 + Math.log1p(c.ms) * 14)}%`, background: c.status === 0 || c.status >= 500 ? "#EF4444" : c.status >= 400 ? "#F59E0B" : "#12B8A6" }} />)}</div><div className="flex gap-3 text-2xs text-mute mt-1.5"><span>Height is log latency</span><span className="text-[#12B8A6]">OK</span><span className="text-warn">4xx</span><span className="text-crit">Failed</span></div></Panel>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        <Panel title={`Error log · ${errors.length}`} className="max-h-64" body="overflow-auto">{errors.length ? <table className="tbl"><tbody>{[...errors].reverse().map((e, i) => <tr key={i}><td className="mono">{new Date(e.at).toLocaleTimeString()}</td><td className="mono">{e.path}</td><td><Pill tone="crit">HTTP {e.status || "none"}</Pill></td></tr>)}</tbody></table> : <Empty title="No server errors this session" />}</Panel>
        <Panel title={`Parser failures · ${ov.data?.parse_errors.length ?? 0}`} className="max-h-64" body="overflow-auto">{ov.data?.parse_errors.length ? <table className="tbl"><tbody>{ov.data.parse_errors.map((e, i) => <tr key={i}><td className="mono">{e.file_id}:{e.line_no}</td><td>{e.error}</td><td className="mono text-2xs truncate max-w-64">{e.preview}</td></tr>)}</tbody></table> : <Empty title="No parser failures" />}</Panel>
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3"><NotAvailable title="Live CPU, memory and per-query DuckDB timing" why="The API exposes run totals only, so nothing here is a live gauge." /><div className="panel px-3 py-2 text-2xs text-mute">Last run finished {fmtTs(r?.finished_at)} in {fmtDur(r?.wall_time_s)}. {r?.peak_rss_note}</div></div>
    </Page>
  );
}
