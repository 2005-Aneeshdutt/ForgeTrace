// Typed client for the FastAPI backend. Every call records its latency and failures so the
// System Health page can report what this browser actually measured.
import { create } from "zustand";

export type Sev = "critical" | "high" | "medium" | "low" | string;

export interface Workspace {
  name: string; analysed: boolean; live: boolean; runnable: boolean; source: string | null; finished_at: string | null;
  incidents: number | null; events: number | null; files: string[]; has_metrics: boolean; alerts?: number; batches?: number;
}
export interface IncidentSummary {
  incident_id: number; risk_score: number; severity: Sev; status: string; ts_first: string; ts_last: string;
  tactics: string[]; tactic_count: number; techniques: string[]; raw_alert_count_total: number;
  member_event_count: number; top_entities: string[];
}
export type Entities = Record<string, string[]>;
export interface GroupNode {
  group_id: string; rule_id: string; rule_title: string; technique_id: string; technique_name: string; tactic: string;
  tactic_ordinal: number; kill_chain_phase: string | null; severity: number; confidence: number; p_malicious?: number;
  criticality?: number; contributions?: Record<string, number>; entities: Entities; evidence: string[]; detection_ids: string[];
  also_matched: { detection_id?: string; rule_id: string; technique_id: string }[];
  member_count: number; member_event_ids: number[]; raw_alert_count: number; ts_first: string; ts_last: string;
}
export interface ObservedEvent {
  event_id: number; display_id: string; ts: string; event_type: string | null; user: string | null; target_user: string | null;
  host: string | null; src_ip: string | null; dst_ip: string | null; process: string | null; command_line: string | null;
  bytes_out: number | null; line_no: number; raw_format: string; group_ids: string[]; primary_rule: string | null;
  primary_technique: string | null; also_matched: { rule_id: string; technique_id: string }[];
}
export interface InferredEdge {
  edge_id: string; src_group_id: string; dst_group_id: string; score: number; delta_t_s: number; kind: string;
  evidence_event_ids: number[]; reasons: { type: string; entity_key?: string; weight: number }[];
  score_terms: Record<string, number>; weighted_terms: Record<string, number>; strongest_entity?: string | null;
}
export interface Path { group_ids: string[]; edge_ids: string[]; stages: string[]; method: string; rank: number; hops: { edge_id: string; from: string; to: string; score: number; note: string | null }[] }
export interface ReachEdge { src: string; dst: string; relation: string; kind: string; weight: number; evidence: { event_ids?: number[]; text?: string; fixture?: string } }
export interface ReachRow {
  asset: string; criticality: number; critical: boolean; reach: number; rank_score: number; hops: number; start: string;
  start_evidence_event_ids: number[]; path: string[]; path_edges: ReachEdge[]; supporting_event_ids: number[]; explanation: string;
}
export interface Candidate { action: { type: string; target: string }; before: number; after: number; reduction: number }
export interface Reach {
  compromised: { node: string; weight: number; reason: string; evidence_event_ids: number[] }[];
  reachable: ReachRow[]; critical_reachable: number; total_critical_assets: number; mode: string; hop_limit: number;
  min_reach: number; removed_relationships: ReachEdge[]; graph: { nodes: number; edges: number }; disclaimer?: string;
  containment_candidates?: Candidate[];
}
export interface Incident {
  incident_id: number; risk_score: number; risk_terms: Record<string, number>; severity: Sev; status: string; ts_first: string; ts_last: string;
  tactics: string[]; techniques: string[]; raw_alert_count_total: number; member_event_count: number; entity_keys: string[];
  group_ids: string[]; uncertainty: string[]; abstention_reason: string | null; config_hash: string; code_version: string;
  observed: { nodes: GroupNode[]; events: ObservedEvent[]; note: string };
  inferred: { edges: InferredEdge[]; primary_path: Path; strongest_chain: Path; containment_candidates: Candidate[]; reachability: Reach; note: string };
}
export interface Detection {
  detection_id: string; rule_id: string; rule_title: string; technique_id: string; technique_name: string; tactic: string;
  severity: number; confidence: number; ts_first: string; ts_last: string; member_count: number; member_event_ids: number[];
  evidence: string; duplicate_of: string | null; users: string[]; hosts: string[]; src_ips: string[]; dst_ips: string[]; incident_id: number | null;
}
export interface Rule { id: string; title: string; technique: string; tactic: string; author: string; type: string; severity: number; confidence: number; label_priority: number; source_file: string; sql: Record<string, string> }
export interface Overview {
  workspace: string; run: RunStats; files: { file_id: number; name: string; path: string; size: number; sha256: string }[];
  time_span: [string | null, string | null]; events_by_type: { key: string; count: number }[]; events_by_format: { key: string; count: number }[];
  detections_by_tactic: { key: string; ordinal: number; count: number }[];
  detections_by_rule: { key: string; technique: string; title: string; count: number; events: number }[];
  parse_errors: { line_no: number; file_id: number; error: string; preview: string }[];
  funnel: { events: number | null; detections: number | null; alert_groups: number | null; incidents: number | null; unlinked: number | null };
}
export interface RunStats {
  stages?: Record<string, number>; wall_time_s?: number; analysis_wall_time_s?: number; ingest_reused?: unknown; peak_rss_bytes?: number; peak_rss_note?: string; config_hash?: string; code_version?: string;
  ingest?: { lines: number; events: number; errors: number; empty: number }; ingest_parallel?: { workers: number; ranges: number };
  detections?: number; rule_seconds?: Record<string, number>; alert_groups?: number; candidate_edges?: number; kept_edges?: number;
  incidents?: number; abstained_components?: number; graph?: unknown; finished_at?: string;
  dataset?: { files: { size: number; path: string }[]; manifest_digest: string };
}
export interface Job { state?: "idle" | "running" | "done" | "failed"; workspace?: string; stage?: string; progress?: number; elapsed_s?: number; error?: string; stats?: { wall_time_s: number; incidents: number; detections: number; alert_groups: number; abstained_components: number; ingest: { events: number; errors: number } } }
export interface Inputs { folder: string; files: { name: string; size: number; modified: string }[]; allowed_suffixes: string[]; max_upload_bytes: number }
export interface RawEvidence { event_id: number; display_id: string; file: string | null; line_no: number | null; byte_offset: number; source_event_id: string | null; raw: string | null; stored_digest: string | null; digest: string | null; verified: boolean; reason: string | null }
export interface SimResult {
  actions: { type: string; target: string }[]; simulation_only: boolean; before_critical_reachable: number; after_critical_reachable: number;
  no_longer_reachable_critical: string[]; still_reachable_critical: { asset: string; explanation: string; supporting_event_ids: number[] }[];
  removed_relationships: ReachEdge[]; removed_from_compromised_set: string[]; caveat: string; disclaimer?: string;
}
export interface LiveStatus {
  batches: number; updated_at: string; watermark: string | null; totals?: { events?: number; errors?: number }; last_batch?: { events?: number };
  knowledge_base?: { alerts?: number; tactics?: number; edges?: number }; batch_tiers?: Record<string, number>;
  history?: { batch: number; events: number; ingest_s: number; analyse_s: number; detections_in_batch: number; alerts_updated: number; edges_added: number; batch_min_ts: string; batch_max_ts: string }[];
}
export interface LiveAlert { uid: string; rule_id: string; rule_title: string; technique_id: string; tactic: string; severity: number; ts_first: string; ts_last: string; member_count: number; first_batch: number; last_batch: number; p_malicious: number | null }
export interface EvidenceLine { event_id: number; display_id: string; file: string; line_no: number; raw: string; verified: boolean; note: string | null }
export interface Explanation {
  kind: string; id: string; error?: string; headline: string; summary: string; data_quality?: string[]; how_to_verify?: string[];
  benign_explanations?: string[]; uncertainties?: string[]; verification_status?: string; facts_hash?: string;
  narrative?: { status: string; reason?: string; label?: string; model?: string; narrative?: { summary: string; steps?: { text: string; event_ids?: number[] }[] } };
  evidence?: EvidenceLine[];
  why_flagged?: { rule: string; title?: string; type?: string; condition: string; threshold?: string; followed_by?: string; first_seen?: string; observed?: string[]; model_reasons?: string[]; technique: { id: string; name?: string; tactic: string }; technique_basis?: string; fused_probability?: number; detector_priors?: Record<string, number> };
  steps?: { order: number; alert_id: string; rule_id: string; what: string; technique: string; tactic: string; when: string; events: number; linked_from_previous: string; evidence: EvidenceLine[]; entities: Entities }[];
  risk?: { score: number; severity: string; terms: Record<string, number> };
}
export interface Metrics {
  metrics: Record<string, { value: number | null; text: string } | unknown>;
  attacks: { attack_id: string; decoy?: boolean; rejected?: boolean; steps?: { order: number; gt_technique: string; found: boolean; predicted: string | null; parent_ok: boolean; sub_ok: boolean; rules: string[] }[]; path?: { incident_id: number | null; in_order: boolean } }[]; // decoys have no steps
  eventid_mismatches: number; run_stats: RunStats;
}
export interface KgNode { id: string; label: string; props: Record<string, unknown> }
export interface KgEdge { type: string; from: string; to: string; props: Record<string, unknown> }
export interface KgGraph { found?: boolean; nodes: KgNode[]; edges: KgEdge[] }
export interface GraphStatus { available: boolean; reason?: string; uri?: string; workspaces?: unknown[] }

export class ApiError extends Error { constructor(msg: string, public status: number) { super(msg); } }

export interface CallSample { path: string; ms: number; status: number; at: number }
interface Telemetry { calls: CallSample[]; errors: CallSample[]; record: (s: CallSample) => void }
export const useTelemetry = create<Telemetry>((set) => ({
  calls: [], errors: [],
  record: (s) => set((t) => ({
    calls: [...t.calls.slice(-199), s],
    errors: s.status >= 500 || s.status === 0 ? [...t.errors.slice(-49), s] : t.errors,
  })),
}));

export async function api<T>(path: string, opts?: RequestInit): Promise<T> {
  const t0 = performance.now();
  const label = path.split("?")[0].replace(/\d{4,}/g, ":id").replace(/\/\d+(\/|$)/g, "/:id$1");
  let r: Response;
  try {
    r = await fetch(path, opts);
  } catch (e) {
    useTelemetry.getState().record({ path: label, ms: performance.now() - t0, status: 0, at: Date.now() });
    throw new ApiError("API unreachable", 0);
  }
  const text = await r.text();
  useTelemetry.getState().record({ path: label, ms: performance.now() - t0, status: r.status, at: Date.now() });
  let body: unknown;
  try { body = text ? JSON.parse(text) : null; } catch { body = text; }
  if (!r.ok) {
    const d = (body as { detail?: unknown } | null)?.detail;
    throw new ApiError(typeof d === "string" ? d : d ? JSON.stringify(d) : `HTTP ${r.status}`, r.status);
  }
  return body as T;
}

export const withWs = (path: string, ws: string) => `${path}${path.includes("?") ? "&" : "?"}ws=${encodeURIComponent(ws)}`;
