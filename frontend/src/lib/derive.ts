// Turns backend incident records into graph and framework views. Everything here is a projection of API
// fields: nothing is added that the record does not contain, and each edge keeps the event ids it came from.
import type { Incident, Reach, ReachRow, GroupNode } from "./api";

// Lockheed Martin stages (framework definition). Which stage a detection sits in always comes from the
// backend's kill_chain_phase (config/attack.yml), never from here.
export const KILL_CHAIN = ["Reconnaissance", "Weaponization", "Delivery", "Exploitation", "Installation", "Command and Control", "Actions on Objectives"];

// ATT&CK Enterprise tactic columns (framework definition).
export const TACTICS = ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"];

export type EntityType = "user" | "host" | "ip" | "external_ip" | "process" | "group" | "other";
export type Basis = "observed" | "configured" | "inferred";

export interface GEntity { id: string; name: string; type: EntityType; events: number[]; first?: string; last?: string; techniques: Set<string>; rules: Set<string>; compromised?: { weight: number; reason: string }; reach?: ReachRow; incident: boolean }
export interface GRelation { id: string; src: string; dst: string; relation: string; basis: Basis; events: number[]; first?: string; last?: string; eventTypes: Set<string>; techniques: Set<string>; weight?: number; text: string; count: number }
export interface EntityGraph { entities: Map<string, GEntity>; relations: Map<string, GRelation>; sampled: boolean }

const isPrivate = (ip: string) => /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|fc|fd|fe80)/i.test(ip);
const ipKind = (ip: string): EntityType => (isPrivate(ip) ? "ip" : "external_ip");
export const canon = (key: string) => { // reachability ids use account:x (lower case); events use the raw user name
  const i = key.indexOf(":");
  const kind = key.slice(0, i);
  return kind === "account" || kind === "user" ? `user:${key.slice(i + 1).toLowerCase()}` : key;
};

function relFor(eventType: string, tactic: string | undefined) {
  if (tactic === "Exfiltration") return "TRANSFERRED_DATA_TO";
  if (eventType.startsWith("auth") || eventType.includes("logon")) return "AUTHENTICATED_TO";
  if (eventType.startsWith("proc")) return "EXECUTED_ON";
  if (eventType.startsWith("net") || eventType.startsWith("dns") || eventType.startsWith("fw")) return "CONNECTED_TO";
  if (eventType.startsWith("file") || eventType.startsWith("registry")) return "ACCESSED";
  if (eventType === "group_add") return "MEMBER_OF";
  return eventType.toUpperCase();
}

export function buildEntityGraph(inc: Incident, reach: Reach | null | undefined, opts: { potential: boolean } = { potential: true }): EntityGraph {
  const entities = new Map<string, GEntity>();
  const relations = new Map<string, GRelation>();
  const nodes = new Map(inc.observed.nodes.map((n) => [n.group_id, n]));
  const ent = (id: string, name: string, type: EntityType, incident = true) => {
    let e = entities.get(id);
    if (!e) { e = { id, name, type, events: [], techniques: new Set(), rules: new Set(), incident }; entities.set(id, e); }
    if (incident) e.incident = true;
    return e;
  };
  const touch = (e: GEntity, id: number, ts: string, tech?: string | null, rule?: string | null) => {
    e.events.push(id);
    if (!e.first || ts < e.first) e.first = ts;
    if (!e.last || ts > e.last) e.last = ts;
    if (tech) e.techniques.add(tech);
    if (rule) e.rules.add(rule);
  };
  for (const ev of inc.observed.events) {
    const type = ev.event_type ?? "event";
    const group = ev.group_ids?.map((g) => nodes.get(g)).find((n): n is GroupNode => !!n && n.technique_id === ev.primary_technique) ?? nodes.get(ev.group_ids?.[0]);
    const tactic = group?.tactic;
    const link = (src: GEntity, dst: GEntity, relation: string) => {
      const id = `${src.id}|${relation}|${dst.id}`;
      let r = relations.get(id);
      if (!r) { r = { id, src: src.id, dst: dst.id, relation, basis: "observed", events: [], eventTypes: new Set(), techniques: new Set(), text: "", count: 0 }; relations.set(id, r); }
      r.events.push(ev.event_id); r.count++; r.eventTypes.add(type);
      if (ev.primary_technique) r.techniques.add(ev.primary_technique);
      if (!r.first || ev.ts < r.first) r.first = ev.ts;
      if (!r.last || ev.ts > r.last) r.last = ev.ts;
    };
    const list: GEntity[] = [];
    const add = (e: GEntity | null) => { if (e) { list.push(e); touch(e, ev.event_id, ev.ts, ev.primary_technique, ev.primary_rule); } return e; };
    const host = add(ev.host ? ent(`host:${ev.host}`, ev.host, "host") : null);
    const user = add(ev.user ? ent(`user:${ev.user.toLowerCase()}`, ev.user, "user") : null);
    const target = add(ev.target_user ? ent(`user:${ev.target_user.toLowerCase()}`, ev.target_user, "user") : null);
    const src = add(ev.src_ip ? ent(`ip:${ev.src_ip}`, ev.src_ip, ipKind(ev.src_ip)) : null);
    const dst = add(ev.dst_ip ? ent(`ip:${ev.dst_ip}`, ev.dst_ip, ipKind(ev.dst_ip)) : null);
    const proc = add(ev.process ? ent(`process:${ev.process}`, ev.process, "process") : null);
    const rel = relFor(type, tactic);
    if (src && host) link(src, host, rel === "AUTHENTICATED_TO" ? "AUTHENTICATED_TO" : "CONNECTED_TO");
    if (user && host) link(user, host, rel === "CONNECTED_TO" ? "ACCESSED" : rel);
    if (host && dst) link(host, dst, rel === "TRANSFERRED_DATA_TO" ? rel : "CONNECTED_TO");
    if (proc && host) link(proc, host, "EXECUTED_ON");
    if (user && target && user !== target) link(user, target, rel);
    if (target && host && type !== "group_add") link(target, host, rel);
  }
  for (const r of relations.values()) {
    const a = entities.get(r.src)!, b = entities.get(r.dst)!;
    r.text = `${r.count} logged event(s) of type ${[...r.eventTypes].join(", ")} name both ${a.name} and ${b.name}. The relationship is read directly from those log lines.`;
  }
  if (reach) {
    for (const c of reach.compromised) {
      const id = canon(c.node);
      const e = entities.get(id) ?? ent(id, c.node.slice(c.node.indexOf(":") + 1), id.startsWith("user:") ? "user" : "host");
      e.compromised = { weight: c.weight, reason: c.reason };
    }
    if (opts.potential) {
      for (const row of reach.reachable) {
        for (const pe of row.path_edges) {
          const sid = canon(pe.src), did = canon(pe.dst);
          for (const k of [sid, did]) {
            if (!entities.has(k)) {
              const kind = k.slice(0, k.indexOf(":"));
              ent(k, k.slice(k.indexOf(":") + 1), kind === "user" ? "user" : kind === "group" ? "group" : "host", false);
            }
          }
          const id = `${sid}|${pe.relation}|${did}`;
          if (!relations.has(id)) relations.set(id, {
            id, src: sid, dst: did, relation: pe.relation, basis: pe.kind as Basis, events: pe.evidence.event_ids ?? [], eventTypes: new Set(),
            techniques: new Set(), weight: pe.weight, text: pe.evidence.text ?? "", count: pe.evidence.event_ids?.length ?? 0,
          });
        }
        const e = entities.get(canon(`host:${row.asset}`));
        if (e) e.reach = row;
      }
    }
  }
  return { entities, relations, sampled: inc.observed.events.length < inc.member_event_count };
}

// One row per step of an incident, in attack order: the primary path first, then any linked group off the path.
export function orderedSteps(inc: Incident): GroupNode[] {
  const by = new Map(inc.observed.nodes.map((n) => [n.group_id, n]));
  const out = inc.inferred.primary_path.group_ids.map((g) => by.get(g)).filter((n): n is GroupNode => !!n);
  const seen = new Set(out.map((n) => n.group_id));
  return [...out, ...inc.observed.nodes.filter((n) => !seen.has(n.group_id)).sort((a, b) => a.ts_first.localeCompare(b.ts_first))];
}

// A technique is ambiguous when this incident places it in more than one kill chain stage.
export function ambiguousTechniques(nodes: GroupNode[]) {
  const m = new Map<string, Set<string>>();
  for (const n of nodes) { if (!m.has(n.technique_id)) m.set(n.technique_id, new Set()); m.get(n.technique_id)!.add(n.kill_chain_phase ?? "Unknown"); }
  return new Set([...m].filter(([, s]) => s.size > 1).map(([k]) => k));
}

export function incidentName(i: { tactics: string[]; techniques: string[] }) {
  if (!i.tactics.length) return "Correlated activity";
  const last = i.tactics[i.tactics.length - 1];
  return i.tactics.length === 1 ? `${last} activity` : `${i.tactics[0]} → ${last}`;
}
