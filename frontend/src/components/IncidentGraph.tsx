import { forwardRef, useMemo } from "react";
import type { ElementDefinition } from "cytoscape";
import type { Incident, Reach, ReachRow } from "../lib/api";
import { entName, fmtTime, short } from "../lib/format";
import { useIncident, useReach } from "../lib/hooks";
import { canon, orderedSteps } from "../lib/derive";
import type { EntityGraph, GEntity } from "../lib/derive";
import { CyGraph, cardImage } from "./CyGraph";
import type { CyHandle } from "./CyGraph";
import { Empty, ErrorBox, Loading } from "./ui";

export const C = { red: "#EF4444", amber: "#F59E0B", cyan: "#26D9D0", green: "#22C55E", grey: "#64748B" };
export const TYPE_LABEL: Record<string, string> = { user: "User", host: "Host", ip: "Internal IP", external_ip: "External IP", process: "Process", group: "Group", other: "Entity" };

// Longest-path layers with one barycentre pass: a readable left-to-right flow, stable across filters and replay.
export function layered(ids: string[], edges: [string, string][], dx: number, dy: number) {
  const depth = new Map(ids.map((i) => [i, 0]));
  for (let n = 0; n < Math.min(ids.length, 12); n++) for (const [s, d] of edges) { if (s !== d && depth.has(s) && depth.has(d) && depth.get(d)! <= depth.get(s)! && depth.get(s)! < 7) depth.set(d, depth.get(s)! + 1); }
  const cols = new Map<number, string[]>();
  ids.forEach((i) => cols.set(depth.get(i)!, [...(cols.get(depth.get(i)!) ?? []), i]));
  const row = new Map<string, number>();
  const pos = new Map<string, { x: number; y: number }>();
  for (const c of [...cols.keys()].sort((a, b) => a - b)) {
    const list = cols.get(c)!;
    const bary = (i: string) => { const p = edges.filter(([, d]) => d === i).map(([s]) => row.get(s)).filter((v): v is number => v != null); return p.length ? p.reduce((a, b) => a + b, 0) / p.length : 0; };
    list.sort((a, b) => bary(a) - bary(b) || a.localeCompare(b));
    list.forEach((id, i) => { const y = i - (list.length - 1) / 2; row.set(id, y); pos.set(id, { x: c * dx, y: y * dy }); });
  }
  return pos;
}

export const entityColor = (e: GEntity) => (e.compromised ? C.red : e.incident ? C.amber : C.cyan);
const relColor = (basis: string) => (basis === "observed" ? "#94A3B8" : basis === "configured" ? C.cyan : C.amber);

// Entity view: who touched what. Solid edges are read from logs; dashed edges are configured or inferred.
export function entityElements(g: EntityGraph, keep: (e: GEntity) => boolean = () => true, keepRel: (id: string) => boolean = () => true): ElementDefinition[] {
  const out: ElementDefinition[] = [];
  const shown = new Set<string>();
  const pos = layered([...g.entities.keys()], [...g.relations.values()].map((r) => [r.src, r.dst]), 208, 66);
  for (const e of g.entities.values()) {
    if (!keep(e)) continue;
    shown.add(e.id);
    const color = entityColor(e);
    out.push({ group: "nodes", position: pos.get(e.id), data: { id: e.id, w: 164, h: 56, color, img: cardImage({ kind: TYPE_LABEL[e.type], title: e.name, color, w: 164, h: 56, sub: e.compromised ? "implicated" : e.reach ? `reachable · ${e.reach.hops} hop(s)` : e.incident ? `${e.events.length} incident events` : "context" }) } });
  }
  for (const r of g.relations.values()) {
    if (!shown.has(r.src) || !shown.has(r.dst) || !keepRel(r.id)) continue;
    out.push({ group: "edges", data: { id: r.id, source: r.src, target: r.dst, color: relColor(r.basis), label: r.count > 1 ? `${r.relation} ×${r.count}` : r.relation, style: r.basis === "observed" ? "solid" : "dashed" } });
  }
  return out;
}

// Step view: the alert groups in attack order, joined by the scored inferred edges.
export function stepElements(inc: Incident, cutoff?: string): ElementDefinition[] {
  const steps = orderedSteps(inc);
  const out: ElementDefinition[] = [];
  const path = new Set(inc.inferred.primary_path.edge_ids);
  const visible = new Set<string>();
  const cols = Math.max(2, Math.ceil(Math.sqrt(steps.length * 0.9)));
  steps.forEach((n, i) => {
    if (cutoff && n.ts_first > cutoff) return;
    visible.add(n.group_id);
    const color = n.severity >= 3 ? C.red : C.amber;
    out.push({ group: "nodes", position: { x: (Math.floor(i / cols) % 2 ? cols - 1 - (i % cols) : i % cols) * 238, y: Math.floor(i / cols) * 112 }, data: { id: n.group_id, w: 204, h: 74, color, img: cardImage({ kind: `${i + 1} · ${n.tactic}`, title: `${n.technique_id} ${n.technique_name}`, color, w: 204, h: 74, pct: n.p_malicious, sub: `${fmtTime(n.ts_first)} · ${short(n.rule_title, 34)}` }) } });
  });
  for (const e of inc.inferred.edges) {
    if (!visible.has(e.src_group_id) || !visible.has(e.dst_group_id)) continue;
    const hot = path.has(e.edge_id);
    out.push({ group: "edges", data: { id: e.edge_id, source: e.src_group_id, target: e.dst_group_id, color: hot ? C.cyan : "#475569", label: hot ? e.score.toFixed(2) : "", style: "dashed", hot } });
  }
  return out;
}

// Layered exposure graph: columns are hops from the compromised start.
export function reachElements(rows: ReachRow[], reach: Reach, status?: (id: string) => { color: string; sub: string } | null, edgeDim?: (src: string, dst: string) => boolean): ElementDefinition[] {
  const depth = new Map<string, number>(); const edges = new Map<string, { s: string; d: string; rel: string; kind: string }>();
  for (const r of rows) r.path.forEach((p, i) => { const k = canon(p); depth.set(k, Math.min(depth.get(k) ?? 99, i)); });
  for (const r of rows) for (const e of r.path_edges) { const s = canon(e.src), d = canon(e.dst); edges.set(`${s}|${e.relation}|${d}`, { s, d, rel: e.relation, kind: e.kind }); }
  const assets = new Map(rows.map((r) => [canon(`host:${r.asset}`), r]));
  const comp = new Set(reach.compromised.map((c) => canon(c.node)));
  const pos = layered([...depth.keys()], [...edges.values()].map((e) => [e.s, e.d]), 240, 72);
  const out: ElementDefinition[] = [];
  for (const id of depth.keys()) {
    const a = assets.get(id); const st = status?.(id);
    const color = st?.color ?? (comp.has(id) ? C.red : a?.critical ? C.amber : C.cyan);
    const kind = id.startsWith("user:") ? "Account" : id.startsWith("group:") ? "Group" : a?.critical ? "Critical asset" : "Host";
    out.push({ group: "nodes", position: pos.get(id), data: { id, w: 182, h: 62, color, img: cardImage({ kind, title: entName(id), color, w: 182, h: 62, sub: st?.sub ?? (comp.has(id) ? "implicated in incident" : a ? `reach ${a.reach.toFixed(2)} · ${a.hops} hop(s)` : "on path") }) } });
  }
  for (const [id, e] of edges) {
    const dim = edgeDim?.(e.s, e.d);
    out.push({ group: "edges", data: { id, source: e.s, target: e.d, color: dim ? "#334155" : relColor(e.kind), label: e.rel, style: dim ? "dotted" : e.kind === "observed" ? "solid" : "dashed" } });
  }
  return out;
}

// Compact step graph used inside the incident workspace and reports.
export const IncidentGraph = forwardRef<CyHandle, { id: number }>(function IncidentGraph({ id }, ref) {
  const q = useIncident(id); const r = useReach(id);
  const els = useMemo(() => (q.data ? stepElements(q.data) : []), [q.data]);
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  if (!els.length) return <Empty title="No graph for this incident" />;
  void r;
  return <CyGraph ref={ref} elements={els} layout="preset" hideControls />;
});
