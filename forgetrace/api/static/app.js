// ForgeTrace dashboard. Every log-derived string is written with textContent (never innerHTML).
"use strict";

const $ = (id) => document.getElementById(id);
const api = async (path, opts) => {
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error(`${path}: ${r.status} ${await r.text()}`);
  return r.json();
};
function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined && text !== null) e.textContent = String(text);
  if (cls) e.className = cls;
  return e;
}
function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
function evLink(eid, label) {
  const a = el("a", label || String(eid), "ev");
  a.addEventListener("click", (e) => { e.stopPropagation(); showEvidence(eid); });
  return a;
}

let cy = null;
let current = null;

async function init() {
  try {
    const h = await api("/health");
    $("health").textContent = `${h.incidents} incident(s) · config ${h.config_hash.slice(0, 10)} · ${h.code_version}`;
  } catch (e) { $("health").textContent = String(e); return; }
  const list = await api("/incidents?sort=risk");
  const box = $("incident-list");
  for (const s of list) {
    const d = el("div", null, "inc");
    d.dataset.id = s.incident_id;
    const top = el("div");
    top.append(el("strong", `INC-${String(s.incident_id).padStart(4, "0")}`), " ",
      el("span", s.severity, `badge sev-${s.severity}`), el("span", `risk ${s.risk_score}`, "badge"));
    d.append(top,
      el("div", `${s.tactic_count} tactics · ${s.raw_alert_count_total} raw alerts → 1 incident · ${s.member_event_count} events`, "small"),
      el("div", s.tactics.join(" → "), "small muted"),
      el("div", s.top_entities.join(", "), "small muted"));
    d.addEventListener("click", () => openIncident(s.incident_id));
    box.append(d);
  }
  const un = await api("/alerts?unlinked=true");
  for (const a of un) $("unlinked").append(el("div", `${a.group_ids.join(", ")} [${a.tactics.join(", ")}] — ${a.reason}`));
  $("ev-close").addEventListener("click", () => { $("drawer").hidden = true; });
  $("sim-btn").addEventListener("click", runSim);
  if (list.length) openIncident(list[0].incident_id);
}

async function openIncident(id) {
  document.querySelectorAll(".inc").forEach((n) => n.classList.toggle("active", n.dataset.id === String(id)));
  const p = await api(`/incidents/${id}`);
  current = p;
  $("empty").hidden = true; $("detail").hidden = false;
  $("inc-title").textContent = `INC-${String(p.incident_id).padStart(4, "0")} · risk ${p.risk_score} (${p.severity}) · ${p.status}`;
  const meta = $("inc-meta"); clear(meta);
  meta.append(el("div", `${p.ts_first} → ${p.ts_last} · ${p.raw_alert_count_total} raw alerts · ${p.member_event_count} raw events`));
  const chips = el("div");
  for (const t of p.tactics) chips.append(el("span", t, "chip"));
  for (const t of p.techniques) chips.append(el("span", t, "chip"));
  meta.append(chips);
  $("risk-terms").textContent = "risk terms: " + Object.entries(p.risk_terms).map(([k, v]) => `${k}=${v}`).join(", ");
  const nodes = Object.fromEntries(p.observed.nodes.map((n) => [n.group_id, n]));
  const edges = Object.fromEntries(p.inferred.edges.map((e) => [e.edge_id, e]));

  const ol = $("path"); clear(ol);
  const pp = p.inferred.primary_path;
  pp.group_ids.forEach((g, i) => {
    const n = nodes[g];
    const li = el("li");
    li.append(el("strong", `${n.tactic}`), ` — ${n.technique_id} ${n.technique_name} (${n.rule_id}) · ${n.ts_first} · `,
      el("span", `${n.member_count} event(s) `, "muted"));
    n.member_event_ids.slice(0, 3).forEach((e) => li.append(evLink(e, "evidence")));
    if (i > 0) {
      const h = pp.hops[i - 1];
      li.append(el("div", h.edge_id ? `linked by ${h.edge_id} (score ${h.score})${h.note ? " — " + h.note : ""}` : h.note, "small muted"));
    }
    ol.append(li);
  });
  const sc = p.inferred.strongest_chain;
  $("chain").textContent = `Dossier DP strongest chain (J=${sc.objective_J}): ${sc.group_ids.join(" → ")}`;

  drawGraph(p, nodes, edges);
  drawTimeline(p);
  drawReach(p);
  const ul = $("uncertainty"); clear(ul);
  p.uncertainty.forEach((u) => ul.append(el("li", u)));
}

function drawGraph(p, nodes, edges) {
  const els = [];
  for (const n of p.observed.nodes) {
    els.push({ data: { id: n.group_id, label: `${n.group_id}\n${n.tactic}\n${n.technique_id} ×${n.raw_alert_count}` } });
  }
  for (const e of p.inferred.edges) {
    els.push({ data: { id: e.edge_id, source: e.src_group_id, target: e.dst_group_id, label: e.score.toFixed(2) } });
  }
  if (cy) cy.destroy();
  cy = cytoscape({
    container: $("graph"), elements: els,
    layout: { name: "breadthfirst", directed: true, spacingFactor: 1.1 },
    style: [
      { selector: "node", style: { label: "data(label)", "text-wrap": "wrap", "font-size": 9, "text-valign": "center",
        width: 110, height: 52, shape: "round-rectangle", "background-color": "#dbe4ff", "border-width": 1, "border-color": "#2457c5" } },
      { selector: "edge", style: { label: "data(label)", "font-size": 9, "line-style": "dashed", width: 2,
        "curve-style": "bezier", "target-arrow-shape": "triangle", "line-color": "#888", "target-arrow-color": "#888",
        "text-background-color": "#fff", "text-background-opacity": 1 } },
      { selector: ":selected", style: { "border-width": 3, "line-color": "#c77700", "target-arrow-color": "#c77700" } },
    ],
  });
  const sel = $("sel");
  clear(sel); sel.append(el("span", "Click a node or a dashed (inferred) edge for its evidence.", "muted"));
  cy.on("tap", "edge", (ev) => {
    const e = edges[ev.target.id()];
    clear(sel);
    sel.append(el("strong", `Inferred edge ${e.edge_id} · score ${e.score} (keep ≥ 0.45)`));
    const t = e.score_terms, w = e.weighted_terms;
    sel.append(el("div", `s = clip(0.45·L + 0.20·T + 0.20·P + 0.10·R − 0.25·F) = ${w.L} + ${w.T} + ${w.P} + ${w.R} ${w.F}`));
    sel.append(el("div", `L=${t.L} T=${t.T} (Δt ${e.delta_t_s}s, τ ${e.tau_s}s) P=${t.P} R=${t.R} (target criticality ${e.target_criticality}) F=${t.F} (strongest entity ${e.strongest_entity}, degree ${e.strongest_entity_degree})`));
    const rs = el("div", "reasons: ");
    e.reasons.forEach((r) => rs.append(el("span", `${r.type} ${r.entity_key} (w ${r.weight})`, "chip")));
    sel.append(rs);
    const evs = el("div", "evidence events: ");
    e.evidence_event_ids.slice(0, 30).forEach((x) => evs.append(evLink(x)));
    sel.append(evs);
  });
  cy.on("tap", "node", (ev) => {
    const n = nodes[ev.target.id()];
    clear(sel);
    sel.append(el("strong", `${n.group_id} · ${n.rule_id} ${n.rule_title}`));
    sel.append(el("div", `${n.technique_id} ${n.technique_name} · ${n.tactic} · severity ${n.severity} · confidence ${n.confidence} · raw alerts ${n.raw_alert_count} · events ${n.member_count}`));
    n.evidence.forEach((x) => sel.append(el("div", x, "muted")));
    if (n.also_matched.length) sel.append(el("div", "also matched: " + n.also_matched.map((a) => `${a.rule_id} ${a.technique_id}`).join(", ")));
    sel.append(el("div", "entities: " + Object.entries(n.entities).filter(([, v]) => v.length).map(([k, v]) => `${k}=${v.join("|")}`).join("; ")));
    const evs = el("div", "member events: ");
    n.member_event_ids.slice(0, 60).forEach((x) => evs.append(evLink(x)));
    sel.append(evs);
  });
}

function drawTimeline(p) {
  const tb = $("timeline").querySelector("tbody"); clear(tb);
  for (const e of p.observed.events) {
    const tr = el("tr");
    const also = (e.also_matched || []).map((a) => a.technique_id).join(", ");
    const detail = e.command_line || (e.bytes_out ? `${e.bytes_out} bytes out` : "") || e.target_user || e.process || "";
    [e.ts, e.display_id, e.line_no, e.event_type, `${e.primary_technique || ""}${also ? " / " + also : ""}`,
      e.user, e.host, `${e.src_ip || ""} → ${e.dst_ip || ""}`, detail].forEach((v) => tr.append(el("td", v ?? "")));
    tr.addEventListener("click", () => showEvidence(e.event_id));
    tb.append(tr);
  }
}

function drawReach(p) {
  const r = p.inferred.reachability;
  const box = $("reach"); clear(box);
  box.append(el("div", `mode: ${r.mode} · hop limit ${r.hop_limit} · min reach ${r.min_reach} · critical reachable ${r.critical_reachable} / ${r.total_critical_assets}`));
  const c = el("div", "compromised set: ");
  r.compromised.forEach((m) => c.append(el("span", `${m.node} (${m.weight})`, "chip")));
  box.append(c);
  const t = el("table");
  const hr = el("tr");
  ["asset", "criticality", "critical", "reach", "hops", "from", "explanation", "evidence"].forEach((h) => hr.append(el("th", h)));
  t.append(hr);
  for (const a of r.reachable) {
    const tr = el("tr");
    [a.asset, a.criticality, a.critical ? "yes" : "no", a.reach, a.hops, a.start].forEach((v) => tr.append(el("td", v)));
    const ex = el("td");
    ex.append(el("div", a.explanation));
    a.path_edges.forEach((pe) => ex.append(el("div", `${pe.src} -${pe.relation}/${pe.kind} ${pe.weight}→ ${pe.dst}: ${pe.evidence.text}${pe.evidence.fixture ? " [" + pe.evidence.fixture + "]" : ""}`, "muted")));
    tr.append(ex);
    const evd = el("td");
    a.supporting_event_ids.slice(0, 6).forEach((x) => evd.append(evLink(x)));
    tr.append(evd);
    t.append(tr);
  }
  box.append(t);
  const cands = p.inferred.containment_candidates;
  box.append(el("div", "Ranked disable_account candidates: " + cands.map((c) => `${c.action.target} (${c.before}→${c.after})`).join(", "), "muted"));
  const s = $("sim-target"); clear(s);
  cands.forEach((c) => { const o = el("option", c.action.target); o.value = c.action.target; s.append(o); });
  clear($("sim-out"));
}

async function runSim() {
  const target = $("sim-target").value;
  const out = $("sim-out"); clear(out);
  if (!current || !target) return;
  try {
    const r = await api(`/incidents/${current.incident_id}/simulate`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ actions: [{ type: "disable_account", target }] }),
    });
    out.append(el("strong", `SIMULATION ONLY — disable_account(${target}): critical reachable ${r.before_critical_reachable} → ${r.after_critical_reachable}`));
    out.append(el("div", "no longer reachable: " + (r.no_longer_reachable_critical.join(", ") || "none")));
    out.append(el("div", "still reachable: " + (r.still_reachable_critical.map((x) => x.explanation).join("; ") || "none")));
    const rm = el("div", `removed relationships (${r.removed_relationships.length}): `);
    r.removed_relationships.forEach((x) => rm.append(el("span", `${x.src} -${x.relation}/${x.kind}→ ${x.dst}`, "chip")));
    out.append(rm);
    out.append(el("div", r.caveat, "muted"));
    out.append(el("div", r.disclaimer, "disclaimer"));
  } catch (e) { out.append(el("div", String(e), "bad")); }
}

async function showEvidence(eid) {
  $("drawer").hidden = false;
  const meta = $("ev-meta"), raw = $("ev-raw"), badge = $("ev-badge");
  clear(meta); raw.textContent = "loading…"; badge.textContent = ""; badge.className = "";
  try {
    const r = await api(`/events/${eid}/raw`);
    badge.textContent = r.verified ? "verified: true (SHA-256 match)" : `verified: false — ${r.reason}`;
    badge.className = r.verified ? "ok" : "bad";
    meta.append(el("div", `event_id ${r.event_id} (${r.display_id}) · source_event_id ${r.source_event_id ?? "—"} · file ${r.file} · line ${r.line_no} · byte offset ${r.byte_offset}`));
    meta.append(el("div", `sha256 ${r.digest}`, "muted"));
    raw.textContent = r.raw ?? "";
  } catch (e) { raw.textContent = String(e); badge.textContent = "error"; badge.className = "bad"; }
}

init();
