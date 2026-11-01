import { useEffect, useMemo, useRef } from "react";
import { useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, withWs } from "./api";
import type { Detection, Explanation, GraphStatus, Incident, IncidentSummary, Inputs, Job, LiveAlert, LiveStatus, Metrics, Overview, Reach, Rule, Workspace } from "./api";
import { useStore } from "./store";

export const useWs = () => useStore((s) => s.ws);

export function useWorkspaces() {
  return useQuery({ queryKey: ["workspaces"], queryFn: () => api<Workspace[]>("/workspaces"), refetchInterval: 15_000 });
}
export function useCurrentWs() {
  const ws = useWs();
  const q = useWorkspaces();
  return useMemo(() => q.data?.find((w) => w.name === ws), [q.data, ws]);
}

const wsQuery = <T,>(key: string, path: string, ws: string | null, enabled = true) => ({
  queryKey: [key, ws, path], enabled: !!ws && enabled, queryFn: () => api<T>(withWs(path, ws!)),
});

const useBatch = () => { const w = useCurrentWs(); return !!w?.analysed && !w.live; };

export const useOverview = () => { const ws = useWs(); return useQuery(wsQuery<Overview>("overview", "/overview", ws, useBatch())); };
export const useIncidents = () => { const ws = useWs(); return useQuery(wsQuery<IncidentSummary[]>("incidents", "/incidents", ws, useBatch())); };
export const useDetections = () => { const ws = useWs(); return useQuery(wsQuery<Detection[]>("detections", "/detections?limit=5000", ws, useBatch())); };
export const useUnlinked = () => { const ws = useWs(); return useQuery(wsQuery<{ group_ids: string[]; tactics: string[]; reason: string; groups: { group_id: string; rule_id: string; technique_id: string; tactic: string; ts_first: string; users: string[]; hosts: string[] }[] }[]>("alerts", "/alerts", ws, useBatch())); };
export const useIncident = (id: number | null) => { const ws = useWs(); return useQuery({ ...wsQuery<Incident>("incident", `/incidents/${id}`, ws, id != null), staleTime: 60_000 }); };
export const useReach = (id: number | null) => { const ws = useWs(); return useQuery({ ...wsQuery<Reach>("reach", `/incidents/${id}/reach`, ws, id != null), staleTime: 60_000 }); };
export const useExplainIncident = (id: number | null) => { const ws = useWs(); return useQuery({ ...wsQuery<Explanation>("explain", `/explain/incident/${id}`, ws, id != null), staleTime: 60_000 }); };
export const useMetrics = (on: boolean) => { const ws = useWs(); return useQuery(wsQuery<Metrics>("metrics", "/metrics", ws, on)); };
export const useRules = () => useQuery({ queryKey: ["rules"], queryFn: () => api<Rule[]>("/rules"), staleTime: 60_000 });
export const useInputs = () => useQuery({ queryKey: ["inputs"], queryFn: () => api<Inputs>("/inputs") });
export const useGraphStatus = () => useQuery({ queryKey: ["graph-status"], queryFn: () => api<GraphStatus>("/graph/status"), refetchInterval: 30_000 });
export const useLiveStatus = (on: boolean) => { const ws = useWs(); return useQuery({ ...wsQuery<LiveStatus>("live", "/live/status", ws, on), refetchInterval: 5_000 }); };
export const useLiveAlerts = (on: boolean) => { const ws = useWs(); return useQuery({ ...wsQuery<LiveAlert[]>("live-alerts", "/live/alerts?limit=100", ws, on), refetchInterval: 5_000 }); };

// Full records for every incident in the workspace (aggregate KPIs, MITRE and analytics pages).
export function useAllIncidents() {
  const ws = useWs();
  const list = useIncidents();
  const qs = useQueries({ queries: (list.data ?? []).map((i) => ({ ...wsQuery<Incident>("incident", `/incidents/${i.incident_id}`, ws), staleTime: 60_000 })) });
  const data = useMemo(() => qs.flatMap((q) => (q.data ? [q.data] : [])), [qs.map((q) => q.dataUpdatedAt).join()]); // eslint-disable-line
  return { data, loading: list.isLoading || qs.some((q) => q.isLoading) };
}

// Run state is global on the server; polled faster while a run is active.
export function useJob() {
  return useQuery({
    queryKey: ["job"], queryFn: () => api<Job>("/runs/current"),
    refetchInterval: (q) => (q.state.data?.state === "running" ? 600 : 4_000),
  });
}

// Selected incident: URL param wins, then the stored selection, then the highest-risk incident.
export function useSelectedIncident(fromParam = false) {
  const { incident, param, setIncident } = useStore();
  const list = useIncidents();
  const urlId = fromParam && param && /^\d+$/.test(param) ? Number(param) : null;
  const known = (id: number | null) => id != null && !!list.data?.some((i) => i.incident_id === id);
  const id = urlId ?? (known(incident) ? incident : list.data?.[0]?.incident_id ?? null);
  useEffect(() => { if (id != null && id !== incident) setIncident(id); }, [id, incident, setIncident]);
  return { id, list };
}

// Reports job transitions once, wherever the user is: refreshes results and raises a notification.
export function useJobWatcher() {
  const job = useJob().data;
  const prev = useRef<string | undefined>();
  const qc = useQueryClient();
  const notify = useStore((s) => s.notify);
  const log = useStore((s) => s.log);
  const lastStage = useRef<string | undefined>();
  useEffect(() => {
    if (!job) return;
    if (job.state === "running" && job.stage !== lastStage.current) {
      log({ tag: (job.stage ?? "run").split(":")[0].toUpperCase(), stage: job.stage, text: `Stage "${job.stage}" started at ${Math.round((job.progress ?? 0) * 100)}% of workspace "${job.workspace}"` });
      lastStage.current = job.stage;
    }
    if (prev.current === "running" && job.state !== "running") {
      lastStage.current = undefined;
      if (job.state === "done" && job.stats) log({ tag: "DONE", tone: "ok", stage: "done", text: `${job.stats.ingest.events.toLocaleString("en-US")} events, ${job.stats.ingest.errors} parse errors, ${job.stats.detections} detections, ${job.stats.alert_groups} alert groups, ${job.stats.incidents} incidents in ${job.stats.wall_time_s} s` });
      if (job.state === "failed") log({ tag: "FAILED", tone: "crit", stage: "done", text: job.error ?? "run failed" });
    }
    if (prev.current === "running" && job.state !== "running") {
      qc.invalidateQueries();
      if (job.state === "done") notify({ level: "ok", text: `Analysis of "${job.workspace}" finished: ${job.stats?.detections ?? 0} detections, ${job.stats?.incidents ?? 0} incidents`, route: "incidents" });
      if (job.state === "failed") notify({ level: "crit", text: `Analysis of "${job.workspace}" failed: ${job.error}`, route: "ingest" });
    }
    prev.current = job.state;
  }, [job, qc, notify, log]);
}
