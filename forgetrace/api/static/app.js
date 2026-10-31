// ForgeTrace console.
// Security: every log-derived string reaches the DOM through textContent / text nodes (never innerHTML).
// Cytoscape labels are drawn on canvas. No network access other than this server.
"use strict";

// ------------------------------------------------------------------ utilities
const $ = (id) => document.getElementById(id);

function h(tag, props, ...kids) {
  const e = document.createElement(tag);
  if (props) {
    for (const [k, v] of Object.entries(props)) {
      if (v === undefined || v === null || v === false) continue;
      if (k === "class") e.className = v;
      else if (k === "text") e.textContent = String(v);
      else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
      else if (k === "dataset") Object.assign(e.dataset, v);
      else e.setAttribute(k, v === true ? "" : String(v));
    }
  }
  for (const c of kids.flat(Infinity)) {
    if (c === undefined || c === null || c === false) continue;
    e.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return e;
}
const clear = (n) => { while (n.firstChild) n.removeChild(n.firstChild); return n; };
const fmtN = (n) => (n === null || n === undefined ? "—" : Number(n).toLocaleString());
const fmtBytes = (b) => { if (b == null) return "—"; const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0; while (b >= 1024 && i < 4) { b /= 1024; i++; } return `${b.toFixed(i ? 1 : 0)} ${u[i]}`; };
const fmtTs = (s) => (s ? String(s).replace("T", " ").replace(/\.\d+Z?$/, "").replace(/Z$/, "") + " UTC" : "—");
const pad = (n) => `INC-${String(n).padStart(4, "0")}`;
const store = { get(k) { try { return localStorage.getItem(k); } catch { return null; } },
                set(k, v) { try { localStorage.setItem(k, v); } catch { /* storage unavailable */ } } };

function svgIcon(d) {
  const ns = "http://www.w3.org/2000/svg";
  const s = document.createElementNS(ns, "svg");
  s.setAttribute("viewBox", "0 0 24 24"); s.setAttribute("fill", "none"); s.setAttribute("stroke", "currentColor");
  s.setAttribute("stroke-width", "2"); s.setAttribute("stroke-linecap", "round"); s.setAttribute("stroke-linejoin", "round");
  for (const p of d) { const path = document.createElementNS(ns, "path"); path.setAttribute("d", p); s.append(path); }
  return s;
}
const ICONS = {
  overview: ["M3 13h8V3H3z", "M13 21h8V11h-8z", "M3 21h8v-6H3z", "M13 3v6h8V3z"],
  incidents: ["M12 2 3 6v6c0 5 3.8 9.3 9 10 5.2-.7 9-5 9-10V6z", "M12 8v4", "M12 16h.01"],
  detections: ["M3 12h4l3 8 4-16 3 8h4"],
  sources: ["M4 4h16v6H4z", "M4 14h16v6H4z", "M8 7h.01", "M8 17h.01"],
  rules: ["M8 6h13", "M8 12h13", "M8 18h13", "M3 6h.01", "M3 12h.01", "M3 18h.01"],
  evaluation: ["M9 11l3 3 8-8", "M20 12v7a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h9"],
  brand: ["M12 3v18", "M5 8l7-5 7 5", "M5 16l7 5 7-5"],
  demo: ["M6 4l14 8-14 8z"],
  live: ["M2 12h4l3-8 4 16 3-8h6"],
  graph: ["M6 6m-2 0a2 2 0 1 0 4 0a2 2 0 1 0 -4 0", "M18 6m-2 0a2 2 0 1 0 4 0a2 2 0 1 0 -4 0", "M12 18m-2 0a2 2 0 1 0 4 0a2 2 0 1 0 -4 0", "M8 6h8", "M7 8l4 8", "M17 8l-4 8"],
};

async function api(path, opts = {}) {
  const r = await fetch(path, opts);
  const text = await r.text();
  let body; try { body = text ? JSON.parse(text) : null; } catch { body = text; }
  if (!r.ok) {
    const msg = body && body.detail ? (typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail)) : `${r.status}`;
    const err = new Error(msg); err.status = r.status; throw err;
  }
  return body;
}
const wsq = (path) => `${path}${path.includes("?") ? "&" : "?"}ws=${encodeURIComponent(state.ws || "")}`;

function toast(msg) {
  const t = $("toast"); t.textContent = msg; t.classList.add("show");
  clearTimeout(toast._t); toast._t = setTimeout(() => t.classList.remove("show"), 2600);
}
function sevPill(sev) {
  const label = { high: "High", medium: "Medium", low: "Low" }[sev] || sev;
  return h("span", { class: `pill sev-${sev}`, title: `Severity: ${label}` }, h("span", { class: "dot" }), label);
}
function riskBar(score) { const b = h("span", { class: "riskbar" }, h("i")); b.firstChild.style.width = `${Math.min(100, score)}%`; return b; }
function evLink(eid, label, ws) {
  return h("a", { class: "ev", title: `Open raw evidence for event ${eid}`, onclick: (e) => { e.stopPropagation(); openEvidence(eid, ws); } }, label || String(eid));
}
function card(title, sub, actions, ...body) {
  return h("section", { class: "card" },
    h("div", { class: "card-h" }, h("h2", { text: title }), sub ? h("span", { class: "sub", text: sub }) : null,
      actions ? h("div", { class: "actions" }, actions) : null),
    ...body);
}
function emptyState(title, text, action) {
  return h("div", { class: "empty" }, h("h3", { text: title }), h("p", { text }), action || null);
}

// tooltip
const tip = { show(e, lines) { const t = $("tip"); clear(t); lines.forEach((l, i) => t.append(i ? h("div", { class: "muted", text: l }) : h("strong", { text: l }))); t.classList.remove("hidden"); tip.move(e); },
  move(e) { const t = $("tip"); t.style.left = `${Math.min(e.clientX + 12, innerWidth - 340)}px`; t.style.top = `${e.clientY + 12}px`; },
  hide() { $("tip").classList.add("hidden"); } };

// Single-series horizontal bar chart: one hue, value labels, hover tooltip, accessible table via title text.
function barChart(rows, { label = (r) => r.key, value = (r) => r.count, detail = () => [] } = {}) {
  const max = Math.max(1, ...rows.map(value));
  const g = h("div", { class: "bars", role: "table" });
  for (const r of rows) {
    const bar = h("div", { class: "bar" });
    bar.style.width = `${(100 * value(r)) / max}%`;
    const track = h("div", { class: "track", role: "cell" }, bar);
    track.addEventListener("mousemove", (e) => tip.show(e, [`${label(r)}: ${fmtN(value(r))}`, ...detail(r)]));
    track.addEventListener("mouseleave", tip.hide);
    g.append(h("div", { class: "bl", role: "rowheader", text: label(r) }), track, h("div", { class: "bv", text: fmtN(value(r)) }));
  }
  return g;
}

// ------------------------------------------------------------------ state + routing
const state = { ws: null, workspaces: [], route: "overview", param: null, job: null, cache: {} };
const TITLES = { demo: "Pipeline demo", live: "Live", graph: "Knowledge graph", overview: "Overview", incidents: "Incidents", detections: "Detections", sources: "Data sources", rules: "Detection rules", evaluation: "Evaluation" };

function navigate(route, param) { location.hash = `#/${route}${param ? "/" + param : ""}`; }
function parseHash() {
  const [, route, param, tab] = (location.hash || "#/overview").split("/");
  state.route = TITLES[route] ? route : "overview";
  state.param = param || null;
  state.tab = tab || null;
}

async function render() {
  parseHash();
  document.querySelectorAll(".nav a").forEach((a) => a.classList.toggle("active", a.dataset.route === state.route));
  const title = $("page-title"); clear(title);
  title.append(TITLES[state.route]);
  if (state.route === "incidents" && state.param) title.append(h("span", { class: "crumb", text: ` / ${pad(state.param)}` }));
  const view = clear($("view"));
  const ready = state.workspaces.find((w) => w.name === state.ws && w.analysed);
  if (!ready && !["sources", "rules", "demo"].includes(state.route)) {
    view.append(card("No analysed workspace", null, null, emptyState("Nothing analysed yet",
      "Add log files to the input folder (or generate the sample with `make sample`), then run an analysis.",
      h("button", { class: "btn primary", onclick: () => navigate("sources"), text: "Go to Data sources" }))));
    return;
  }
  const wsInfo = state.workspaces.find((w) => w.name === state.ws) || {};
  if (wsInfo.live && ["overview", "incidents", "detections"].includes(state.route)) {
    view.append(card("Live workspace", null, null, h("div", { class: "card-b" },
      h("div", { class: "callout", text: "This workspace is analysed continuously. Its alerts, incidents and campaigns live in the knowledge base and graph." }),
      h("div", { class: "row-gap" }, h("button", { class: "btn primary", text: "Open Live", onclick: () => navigate("live") }),
        h("button", { class: "btn", text: "Open Knowledge graph", onclick: () => navigate("graph") })))));
    return;
  }
  try {
    await VIEWS[state.route](view);
  } catch (e) {
    clear(view).append(card("Could not load this view", null, null, h("div", { class: "card-b" }, h("div", { class: "callout warn", text: String(e.message || e) }))));
  }
}

async function loadWorkspaces() {
  state.workspaces = await api("/workspaces");
  const saved = store.get("ft.ws");
  const analysed = state.workspaces.filter((w) => w.analysed).sort((a, b) => String(b.finished_at).localeCompare(String(a.finished_at)));
  const urlWs = new URLSearchParams(location.search).get("ws");
  if (!state.ws && urlWs && analysed.some((w) => w.name === urlWs)) state.ws = urlWs;
  if (!state.ws || !state.workspaces.some((w) => w.name === state.ws)) {
    state.ws = (analysed.find((w) => w.name === saved) || analysed[0] || state.workspaces[0] || {}).name || null;
  }
  const sel = clear($("ws-select"));
  for (const w of state.workspaces) {
    const label = w.live ? `${w.name} · live · ${fmtN(w.alerts)} alerts` :
      `${w.name}${w.analysed ? ` · ${fmtN(w.incidents)} incident${w.incidents === 1 ? "" : "s"}` : " · not analysed"}`;
    const o = h("option", { value: w.name, text: label });
    if (w.name === state.ws) o.selected = true;
    sel.append(o);
  }
  const w = state.workspaces.find((x) => x.name === state.ws);
  const cnt = $("nav-incidents").querySelector(".count");
  if (cnt) cnt.textContent = w && w.analysed ? fmtN(w.incidents) : "–";
}

// ------------------------------------------------------------------ views
const VIEWS = {};

VIEWS.overview = async (view) => {
  const o = await api(wsq("/overview"));
  const run = o.run || {};
  const f = o.funnel;
  const funnel = h("div", { class: "funnel" },
    [["Raw events ingested", f.events, `${fmtN(run.ingest?.errors)} parse errors`],
     ["Detections", f.detections, "rule hits (YAML rules)"],
     ["Alert groups", f.alert_groups, "repeats merged (15 min)"],
     ["Incidents", f.incidents, "≥ 2 linked tactics"],
     ["Unlinked alerts", f.unlinked, "below incident gate"]].map(([l, v, hint], i, a) =>
      h("div", { class: "step" }, h("div", { class: "label", text: l }), h("div", { class: "value", text: fmtN(v) }),
        h("div", { class: "muted small", text: hint }), i < a.length - 1 ? h("span", { class: "arrow", text: "›" }) : null)));
  const kpis = h("div", { class: "kpis" },
    [["Source files", o.files.length, o.files.map((x) => x.name).join(", ")],
     ["Data span", o.time_span[0] ? fmtTs(o.time_span[0]).slice(0, 16) : "—", o.time_span[1] ? `to ${fmtTs(o.time_span[1]).slice(0, 16)}` : ""],
     ["Run time", run.wall_time_s != null ? `${run.wall_time_s}s` : "—", run.finished_at ? `finished ${run.finished_at.replace("T", " ")}` : ""],
     ["Peak memory", run.peak_rss_bytes ? fmtBytes(run.peak_rss_bytes) : "—", "process RSS during run"]].map(([l, v, hint]) =>
      h("div", { class: "kpi" }, h("div", { class: "label", text: l }), h("div", { class: "value", text: v }), h("div", { class: "hint truncate", text: hint, title: hint }))));
  const incs = await api(wsq("/incidents?sort=risk&limit=5"));
  const topInc = h("table", { class: "t" }, h("thead", null, h("tr", null, ["Incident", "Severity", "Risk", "Tactics", "Alerts", "First seen"].map((c) => h("th", { text: c })))),
    h("tbody", null, incs.map((i) => h("tr", { class: "click", onclick: () => navigate("incidents", i.incident_id) },
      h("td", { class: "mono", text: pad(i.incident_id) }), h("td", null, sevPill(i.severity)),
      h("td", { class: "nowrap" }, `${i.risk_score}`, riskBar(i.risk_score)), h("td", { text: i.tactics.join(" → ") }),
      h("td", { class: "num", text: fmtN(i.raw_alert_count_total) }), h("td", { class: "nowrap", text: fmtTs(i.ts_first) })))));
  view.append(h("div", { class: "stack" },
    funnel, kpis,
    h("div", { class: "grid g2" },
      card("Detections by tactic", "kill-chain order", null, h("div", { class: "card-b" },
        o.detections_by_tactic.length ? barChart(o.detections_by_tactic, { detail: (r) => [`ATT&CK tactic ordinal ${r.ordinal}`] }) : h("div", { class: "muted", text: "No detections." }))),
      card("Events by type", "normalised event_type", null, h("div", { class: "card-b" },
        barChart(o.events_by_type.slice(0, 12)), o.events_by_format.length ? h("div", { class: "muted small", text: `Formats: ${o.events_by_format.map((x) => `${x.key} ${fmtN(x.count)}`).join(" · ")}` }) : null))),
    card("Highest-risk incidents", null, h("button", { class: "btn sm", onclick: () => navigate("incidents"), text: "All incidents" }),
      h("div", { class: "card-b flush" }, incs.length ? topInc : emptyState("No incidents", "No component reached the two-tactic incident gate."))),
    card("Detections by rule", null, h("button", { class: "btn sm", onclick: () => navigate("detections"), text: "Explore detections" }),
      h("div", { class: "card-b flush" }, h("table", { class: "t" },
        h("thead", null, h("tr", null, ["Rule", "Technique", "Title", "Detections", "Raw events"].map((c, i) => h("th", { class: i > 2 ? "num" : null, text: c })))),
        h("tbody", null, o.detections_by_rule.map((r) => h("tr", null, h("td", { class: "mono", text: r.key }), h("td", { class: "mono", text: r.technique }),
          h("td", { text: r.title }), h("td", { class: "num", text: fmtN(r.count) }), h("td", { class: "num", text: fmtN(r.events) }))))))),
    o.parse_errors.length ? card("Parse errors", `${fmtN(run.ingest?.errors)} lines could not be parsed (kept with byte offset, never dropped)`, null,
      h("div", { class: "card-b flush scroll" }, h("table", { class: "t" }, h("thead", null, h("tr", null, ["File", "Line", "Error", "Preview"].map((c) => h("th", { text: c })))),
        h("tbody", null, o.parse_errors.map((e) => h("tr", null, h("td", { class: "num", text: e.file_id }), h("td", { class: "num", text: e.line_no }),
          h("td", { text: e.error }), h("td", { class: "mono truncate", text: e.preview, title: e.preview }))))))) : null));
};

VIEWS.incidents = async (view) => {
  const [list, unlinked] = await Promise.all([api(wsq("/incidents?sort=risk")), api(wsq("/alerts?unlinked=true"))]);
  const listCard = card("Incidents", `${list.length} · sorted by risk`, null, h("div", { class: "inc-list" },
    list.length ? list.map((i) => h("div", { class: `inc${String(i.incident_id) === state.param ? " active" : ""}`, onclick: () => navigate("incidents", i.incident_id) },
      h("div", null, h("span", { class: "id mono", text: pad(i.incident_id) }), " ", sevPill(i.severity)),
      h("div", { class: "nowrap" }, h("strong", { text: i.risk_score }), riskBar(i.risk_score)),
      h("div", { class: "meta" }, `${i.tactic_count} tactics · ${fmtN(i.raw_alert_count_total)} alerts → 1 incident · ${fmtN(i.member_event_count)} events`),
      h("div", { class: "meta" }, i.top_entities.slice(0, 4).map((e) => h("span", { class: "chip mono", text: e }))))) :
      emptyState("No incidents", "No connected group of alerts spans two or more tactics.")));
  const unl = card("Unlinked alerts", `${unlinked.length} · did not meet the incident gate`, null, h("div", { class: "card-b flush scroll" },
    unlinked.length ? h("table", { class: "t" }, h("tbody", null, unlinked.flatMap((u) => u.groups.map((g) => h("tr", null,
      h("td", null, h("div", { class: "mono", text: `${g.rule_id} · ${g.technique_id}` }), h("div", { class: "muted", text: g.tactic })),
      h("td", null, h("div", { text: [...g.users, ...g.hosts].join(", ") || "—" }), h("div", { class: "muted small", text: u.reason }))))))) :
      h("div", { class: "card-b muted", text: "None." })));
  const side = h("div", { class: "stack" }, listCard, unl);
  const main = h("div", { id: "inc-main" });
  view.append(h("div", { class: "grid g-main-side" }, main, side));
  // The detail goes left (wide), the list right on wide screens; select the top incident by default.
  const id = state.param || (list[0] && list[0].incident_id);
  if (!id) { main.append(card("Incident", null, null, emptyState("Nothing to investigate", "There are no incidents in this workspace."))); return; }
  await renderIncident(main, id);
};

async function renderIncident(root, id) {
  const p = await api(wsq(`/incidents/${id}`));
  state.cache.incident = p;
  const nodes = Object.fromEntries(p.observed.nodes.map((n) => [n.group_id, n]));
  const pp = p.inferred.primary_path;
  const reach = p.inferred.reachability;
  const users = [...new Set(p.observed.nodes.flatMap((n) => n.entities.user))];
  const hosts = [...new Set(p.observed.nodes.flatMap((n) => n.entities.host))];
  const ext = [...new Set(p.observed.nodes.flatMap((n) => [...n.entities.src_ip, ...n.entities.dst_ip]))];
  const topReach = reach.reachable.find((r) => r.critical);
  const narrative = `${p.observed.nodes.length} alert groups (${fmtN(p.raw_alert_count_total)} detections over ${fmtN(p.member_event_count)} raw events) linked across ${p.tactics.length} tactics between ${fmtTs(p.ts_first)} and ${fmtTs(p.ts_last)}. ` +
    `Sequence: ${pp.stages.filter((t, i, a) => t !== a[i - 1]).join(" → ")}. Accounts involved: ${users.join(", ") || "none"}; hosts: ${hosts.join(", ") || "none"}. ` +
    (topReach ? `Most exposed critical asset: ${topReach.asset} (reach ${topReach.reach}, ${topReach.hops} hop${topReach.hops > 1 ? "s" : ""}). ` : "No critical asset is modelled as reachable. ") +
    `${reach.critical_reachable} of ${reach.total_critical_assets} critical assets are modelled as reachable.`;
  const header = card(pad(p.incident_id), null, h("button", { class: "btn sm", text: "Copy summary", onclick: () => { navigator.clipboard?.writeText(narrative); toast("Summary copied"); } }),
    h("div", { class: "card-b" },
      h("div", { class: "inc-head" }, sevPill(p.severity),
        h("span", { class: "risk", text: p.risk_score }), h("span", { class: "muted", text: "risk / 100" }), riskBar(p.risk_score),
        h("span", { class: "chip", text: p.status })),
      h("div", { class: "facts" },
        [["First seen", fmtTs(p.ts_first)], ["Last seen", fmtTs(p.ts_last)], ["Tactics", p.tactics.length], ["Detections → incident", `${fmtN(p.raw_alert_count_total)} → 1`],
         ["Raw events", fmtN(p.member_event_count)], ["Critical assets reachable", `${reach.critical_reachable} / ${reach.total_critical_assets}`]].map(([k, v]) =>
          h("div", null, h("div", { class: "k", text: k }), h("div", { class: "v", text: v })))),
      h("div", { class: "narrative" }, h("span", { class: "tag", text: "Summary · generated from incident data by template (no AI)" }), narrative),
      h("div", { class: "small muted" }, "Risk terms: ", Object.entries(p.risk_terms).map(([k, v]) => h("span", { class: "chip mono", text: `${k} ${v}` }))),
      h("div", null, p.tactics.map((t) => h("span", { class: "chip", text: t })), p.techniques.map((t) => h("span", { class: "chip mono", text: t }))),
      ext.length ? h("div", { class: "small muted" }, "IPs: ", ext.map((x) => h("span", { class: "chip mono", text: x }))) : null));

  const tabs = [
    ["path", "Attack path", pp.group_ids.length], ["graph", "Graph", p.inferred.edges.length],
    ["timeline", "Timeline", p.observed.events.length], ["reach", "Reachability & containment", reach.reachable.length],
    ["edges", "Correlation evidence", p.inferred.edges.length], ["notes", "Uncertainty", p.uncertainty.length]];
  const want = state.tab || store.get("ft.tab");
  const active = want && tabs.some((t) => t[0] === want) ? want : "path";
  const body = h("div");
  const tabBar = h("div", { class: "tabs", role: "tablist" });
  const show = (key) => {
    store.set("ft.tab", key);
    tabBar.querySelectorAll("button").forEach((b) => b.classList.toggle("active", b.dataset.key === key));
    clear(body);
    ({ path: tabPath, graph: tabGraph, timeline: tabTimeline, reach: tabReach, edges: tabEdges, notes: tabNotes })[key](body, p, nodes);
  };
  tabs.forEach(([key, label, n]) => tabBar.append(h("button", { type: "button", role: "tab", dataset: { key }, onclick: () => show(key) }, label, h("span", { class: "n", text: n }))));
  clear(root).append(h("div", { class: "stack" }, header, h("section", { class: "card" }, tabBar, body)));
  show(active);
}

function tabPath(body, p, nodes) {
  const pp = p.inferred.primary_path;
  const ol = h("ol", { class: "stepper" });
  pp.group_ids.forEach((g, i) => {
    const n = nodes[g];
    const hop = i > 0 ? pp.hops[i - 1] : null;
    const ents = [...n.entities.user.map((u) => `user:${u}`), ...n.entities.host.map((x) => `host:${x}`), ...n.entities.target_user.map((u) => `target:${u}`)];
    ol.append(h("li", null, h("span", { class: "num", text: i + 1 }),
      h("div", null, h("span", { class: "tactic", text: n.tactic }), "  ", h("span", { class: "tech mono", text: `${n.technique_id}` }), " ", h("span", { class: "tech", text: n.technique_name })),
      h("div", { class: "when" }, `${fmtTs(n.ts_first)} · rule ${n.rule_id} — ${n.rule_title} · ${fmtN(n.member_count)} event${n.member_count === 1 ? "" : "s"} · severity ${n.severity}/4 · confidence ${n.confidence}`),
      n.also_matched.length ? h("div", { class: "small muted", text: `Also matched: ${n.also_matched.map((a) => `${a.rule_id} ${a.technique_id}`).join(", ")}` }) : null,
      h("div", { class: "ent" }, ents.map((e) => h("span", { class: "chip mono", text: e }))),
      h("div", { class: "evlinks small" }, "Evidence: ", n.member_event_ids.slice(0, 6).map((e) => evLink(e)), n.member_event_ids.length > 6 ? h("span", { class: "muted", text: `+${n.member_event_ids.length - 6} more in Timeline` }) : null),
      hop ? h("div", { class: "link" }, hop.edge_id ? `Linked from previous step by inferred edge ${hop.edge_id}, score ${hop.score}` : hop.note,
        hop.note && hop.edge_id ? ` (${hop.note})` : "") : null));
  });
  const sc = p.inferred.strongest_chain;
  body.append(h("div", { class: "card-b" }, ol,
    h("div", { class: "callout small" }, h("strong", { text: "How this path was built. " }),
      "Steps are the incident's alert groups ordered by time, then ATT&CK tactic order. Each link is an inferred edge scored from shared entities, time gap and tactic progression (open the Correlation evidence tab for the score terms). ",
      `For comparison, the dossier's score-maximising chain (J = ${sc.objective_J}) covers ${sc.group_ids.length} of ${pp.group_ids.length} steps: ${sc.group_ids.join(" → ")}.`)));
}

function cssVar(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }
let cy = null;
function tabGraph(body, p, nodes) {
  const box = h("div", { id: "graph" });
  const detail = h("div", { class: "card-b small" }, h("span", { class: "muted", text: "Select a node (alert group) or an edge (inferred relationship) to see its evidence." }));
  body.append(box, h("div", { class: "graph-legend" },
    h("span", null, h("span", { class: "sw node" }), "Alert group (tactic · technique · alerts)"),
    h("span", null, h("span", { class: "sw" }), "Inferred relationship (score)"),
    h("span", null, h("span", { class: "sw path" }), "Primary-path hop")), detail);
  const pathEdges = new Set(p.inferred.primary_path.edge_ids);
  const order = p.inferred.primary_path.group_ids;
  const els = order.map((g, i) => {
    const n = nodes[g];
    // Snake layout, 3 per row, in primary-path order: reads left-to-right, then wraps.
    const row = Math.floor(i / 3), col = row % 2 ? 2 - (i % 3) : i % 3;
    return { data: { id: g, label: `${i + 1}. ${n.tactic}\n${n.technique_id} · ${n.rule_id}\n${n.raw_alert_count} alert(s) · ${n.member_count} event(s)` },
             position: { x: col * 280, y: row * 150 } };
  });
  for (const e of p.inferred.edges) els.push({ data: { id: e.edge_id, source: e.src_group_id, target: e.dst_group_id, label: e.score.toFixed(2), w: 1 + 4 * e.score, path: pathEdges.has(e.edge_id) ? 1 : 0 } });
  if (cy) cy.destroy();
  const ink = cssVar("--text-primary"), muted = cssVar("--text-muted"), accent = cssVar("--accent"), surface = cssVar("--surface-2"), surface1 = cssVar("--surface-1");
  cy = cytoscape({
    container: box, elements: els, layout: { name: "preset", fit: true, padding: 50 }, wheelSensitivity: 0.3, maxZoom: 1.6, minZoom: 0.3,
    style: [
      { selector: "node", style: { shape: "round-rectangle", width: 190, height: 64, "background-color": surface, "border-width": 2, "border-color": accent,
        label: "data(label)", "text-wrap": "wrap", "font-size": 12, color: ink, "text-valign": "center", "text-halign": "center" } },
      { selector: "edge", style: { width: "data(w)", "line-style": "dashed", "line-color": muted, "target-arrow-color": muted, "target-arrow-shape": "triangle",
        "curve-style": "bezier", label: "data(label)", "font-size": 11, color: ink, "text-background-color": surface1, "text-background-opacity": 1, "text-background-padding": 2 } },
      { selector: "edge[path = 1]", style: { "line-color": accent, "target-arrow-color": accent } },
      { selector: ":selected", style: { "border-width": 4, "line-color": cssVar("--serious"), "target-arrow-color": cssVar("--serious") } },
    ],
  });
  cy.on("tap", "edge", (ev) => { clear(detail).append(edgeDetail(p.inferred.edges.find((x) => x.edge_id === ev.target.id()), nodes)); });
  cy.on("tap", "node", (ev) => { clear(detail).append(nodeDetail(nodes[ev.target.id()])); });
}

function termRows(e) {
  const W = { L: 0.45, T: 0.2, P: 0.2, R: 0.1, F: -0.25 };
  const names = { L: "Link strength (shared entities)", T: "Temporal proximity", P: "Tactic progression", R: "Impact (severity, criticality)", F: "Benign-frequency penalty" };
  const g = h("div", { class: "terms" });
  for (const k of ["L", "T", "P", "R", "F"]) {
    const bar = h("div", { class: `tb${k === "F" ? " neg" : ""}` }, h("i"));
    bar.firstChild.style.width = `${Math.min(100, 100 * e.score_terms[k])}%`;
    g.append(h("div", { text: `${k} · ${names[k]}` }), bar, h("div", { class: "mono", text: `${e.score_terms[k]} × ${W[k]} = ${e.weighted_terms[k]}` }));
  }
  return g;
}
function edgeDetail(e, nodes) {
  const a = nodes[e.src_group_id], b = nodes[e.dst_group_id];
  return h("div", { class: "stack" },
    h("div", null, h("strong", { text: `Inferred: ${a.tactic} (${e.src_group_id}) → ${b.tactic} (${e.dst_group_id})` }), "  ",
      h("span", { class: "chip mono", text: `score ${e.score}` }), h("span", { class: "muted", text: " kept because score ≥ 0.45 and at least one shared entity" })),
    termRows(e),
    h("div", { class: "kv" },
      h("div", { class: "k", text: "Shared entities" }), h("div", null, e.reasons.map((r) => h("span", { class: "chip mono", text: `${r.type}: ${r.entity_key} (w ${r.weight})` }))),
      h("div", { class: "k", text: "Time gap" }), h("div", { text: `${e.delta_t_s}s (τ = ${e.tau_s}s)` }),
      h("div", { class: "k", text: "Strongest entity" }), h("div", { class: "mono", text: `${e.strongest_entity} (seen with ${e.strongest_entity_degree} peers)` }),
      h("div", { class: "k", text: "Target criticality" }), h("div", { text: e.target_criticality }),
      h("div", { class: "k", text: "Evidence events" }), h("div", { class: "evlinks" }, e.evidence_event_ids.slice(0, 24).map((x) => evLink(x)))));
}
function nodeDetail(n) {
  return h("div", { class: "stack" },
    h("div", null, h("strong", { text: `${n.group_id} · ${n.rule_id} ${n.rule_title}` })),
    h("div", { class: "kv" },
      h("div", { class: "k", text: "Technique" }), h("div", { text: `${n.technique_id} ${n.technique_name} (${n.tactic})` }),
      h("div", { class: "k", text: "Severity / confidence" }), h("div", { text: `${n.severity}/4 · prior ${n.confidence}` }),
      h("div", { class: "k", text: "Alerts / events" }), h("div", { text: `${n.raw_alert_count} detection(s), ${n.member_count} raw event(s)` }),
      h("div", { class: "k", text: "Why it fired" }), h("div", null, n.evidence.map((x) => h("div", { text: x }))),
      h("div", { class: "k", text: "Also matched" }), h("div", { text: n.also_matched.map((a) => `${a.rule_id} ${a.technique_id}`).join(", ") || "—" }),
      h("div", { class: "k", text: "Entities" }), h("div", null, Object.entries(n.entities).filter(([, v]) => v.length).map(([k, v]) => h("span", { class: "chip mono", text: `${k}=${v.join("|")}` }))),
      h("div", { class: "k", text: "Member events" }), h("div", { class: "evlinks" }, n.member_event_ids.slice(0, 40).map((x) => evLink(x)))));
}

function tabTimeline(body, p) {
  const q = h("input", { type: "search", placeholder: "Filter events (user, host, IP, technique…)" });
  const tbody = h("tbody");
  const draw = () => {
    const f = q.value.toLowerCase();
    clear(tbody);
    for (const e of p.observed.events) {
      const also = (e.also_matched || []).map((a) => a.technique_id);
      const cells = [fmtTs(e.ts), e.event_type, e.primary_technique || "", e.user || "", e.host || "", `${e.src_ip || ""}${e.dst_ip ? " → " + e.dst_ip : ""}`,
        e.command_line || (e.bytes_out ? `${fmtBytes(e.bytes_out)} out` : "") || (e.target_user ? `target ${e.target_user}` : "") || e.process || ""];
      if (f && !cells.concat([e.display_id, String(e.line_no)]).join(" ").toLowerCase().includes(f)) continue;
      tbody.append(h("tr", { class: "click", onclick: () => openEvidence(e.event_id) },
        h("td", { class: "nowrap", text: cells[0] }), h("td", { class: "mono", text: e.display_id }), h("td", { class: "num", text: e.line_no }),
        h("td", { text: cells[1] }), h("td", null, h("span", { class: "mono", text: cells[2] }), also.length ? h("div", { class: "muted small", text: `also ${also.join(", ")}` }) : null),
        h("td", { text: cells[3] }), h("td", { text: cells[4] }), h("td", { class: "mono", text: cells[5] }), h("td", { class: "mono truncate", text: cells[6], title: cells[6] })));
    }
  };
  q.addEventListener("input", draw);
  body.append(h("div", { class: "toolbar" }, q, h("span", { class: "muted small", text: "Click a row to open the verified raw line." })),
    h("div", { class: "scroll" }, h("table", { class: "t" }, h("thead", null, h("tr", null, ["Time", "Event ID", "Line", "Type", "Technique", "User", "Host", "Source → destination", "Detail"].map((c) => h("th", { text: c })))), tbody)));
  draw();
}

function tabReach(body, p) {
  const r = p.inferred.reachability;
  const cands = p.inferred.containment_candidates;
  const comp = h("div", null, r.compromised.map((c) => h("span", { class: "chip mono", title: c.reason, text: `${c.node} · ${c.weight}` })));
  const table = h("table", { class: "t" }, h("thead", null, h("tr", null, ["Asset", "Criticality", "Reach", "Hops", "From", "Path (kind: observed / configured / inferred)", "Evidence"].map((c) => h("th", { text: c })))),
    h("tbody", null, r.reachable.map((a) => h("tr", null,
      h("td", { class: "nowrap" }, h("strong", { class: "mono", text: a.asset }), a.critical ? h("div", null, h("span", { class: "pill sev-high" }, h("span", { class: "dot" }), "Critical")) : null),
      h("td", { class: "num", text: a.criticality }), h("td", { class: "num", text: a.reach }), h("td", { class: "num", text: a.hops }),
      h("td", { class: "mono nowrap", text: a.start }),
      h("td", null, a.path_edges.map((e) => h("div", { class: "small" }, h("span", { class: "chip", text: `${e.relation} · ${e.kind} · ${e.weight}` }), e.evidence.text, e.evidence.fixture ? h("span", { class: "muted", text: ` [${e.evidence.fixture}]` }) : null))),
      h("td", { class: "evlinks nowrap" }, a.supporting_event_ids.slice(0, 4).map((x, i) => evLink(x, `event ${i + 1}`)))))));
  const sel = h("select", null, cands.map((c) => h("option", { value: c.action.target, text: `${c.action.target}  (${c.before} → ${c.after} critical)` })));
  const out = h("div");
  const runSim = async () => {
    clear(out).append(h("div", { class: "muted", text: "Simulating…" }));
    try {
      const s = await api(wsq(`/incidents/${p.incident_id}/simulate`), { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ actions: [{ type: "disable_account", target: sel.value }] }) });
      const delta = s.before_critical_reachable - s.after_critical_reachable;
      clear(out).append(h("div", { class: "stack" },
        h("div", { class: "kpis" },
          h("div", { class: "kpi" }, h("div", { class: "label", text: "Critical reachable before" }), h("div", { class: "value", text: s.before_critical_reachable })),
          h("div", { class: "kpi" }, h("div", { class: "label", text: "After disable_account" }), h("div", { class: "value", text: s.after_critical_reachable })),
          h("div", { class: "kpi" }, h("div", { class: "label", text: "Reduction" }), h("div", { class: "value", text: delta }))),
        h("div", { class: "callout" }, h("strong", { text: "Simulation only — nothing was changed. " }), s.disclaimer),
        h("div", { class: "kv" },
          h("div", { class: "k", text: "No longer reachable" }), h("div", { class: "mono", text: s.no_longer_reachable_critical.join(", ") || "none" }),
          h("div", { class: "k", text: "Still reachable" }), h("div", null, s.still_reachable_critical.map((x) => h("div", { class: "small", text: x.explanation })), s.still_reachable_critical.length ? null : "none"),
          h("div", { class: "k", text: "Relationships removed" }), h("div", null, s.removed_relationships.map((x) => h("span", { class: "chip mono", text: `${x.src} -${x.relation}/${x.kind}→ ${x.dst}` })), s.removed_relationships.length ? null : "none"),
          h("div", { class: "k", text: "Caveat" }), h("div", { class: "muted", text: s.caveat }))));
    } catch (e) { clear(out).append(h("div", { class: "callout warn", text: String(e.message) })); }
  };
  body.append(h("div", { class: "card-b stack" },
    h("div", { class: "callout small" }, `Mode: ${r.mode}. Starting from what this incident shows as compromised, assets are reachable through observed logons, configured admin relationships (config/assets.yaml) and inferred credential exposure; reach = product of edge weights × start weight, hop limit ${r.hop_limit}, shown if ≥ ${r.min_reach}.`),
    h("div", null, h("div", { class: "muted small", text: "Compromised set (hover for evidence reason)" }), comp),
    r.reachable.length ? h("div", { class: "scroll" }, table) : h("div", { class: "muted", text: "No asset reaches the reporting threshold." }),
    card("Containment simulation", "disable_account (Phase 1)", null, h("div", { class: "card-b stack" },
      cands.length ? h("div", { class: "toolbar" }, h("label", null, "Disable account ", sel), h("button", { class: "btn primary", type: "button", onclick: runSim, text: "Run simulation" }),
        h("span", { class: "muted small", text: "Candidates ranked by modelled reduction in reachable critical assets." })) : h("div", { class: "muted", text: "No account candidates." }),
      out))));
}

function tabEdges(body, p, nodes) {
  const list = h("div", { class: "card-b stack" });
  if (!p.inferred.edges.length) list.append(h("div", { class: "muted", text: "No inferred edges." }));
  for (const e of [...p.inferred.edges].sort((a, b) => b.score - a.score)) list.append(h("div", { class: "callout" }, edgeDetail(e, nodes)));
  body.append(h("div", { class: "card-b small muted", text: "s = clip(0.45·L + 0.20·T + 0.20·P + 0.10·R − 0.25·F); an edge is kept when s ≥ 0.45 and at least one entity is shared (time alone never links). All edges are inferences, not facts." }), list);
}
function tabNotes(body, p) {
  body.append(h("div", { class: "card-b" }, h("ul", null, p.uncertainty.map((u) => h("li", { text: u })))));
}

VIEWS.detections = async (view) => {
  const rows = await api(wsq("/detections"));
  const tactics = [...new Set(rows.map((r) => r.tactic))];
  const rules = [...new Set(rows.map((r) => r.rule_id))].sort();
  const q = h("input", { type: "search", placeholder: "Search user, host, IP, technique, evidence…" });
  const ft = h("select", null, h("option", { value: "", text: "All tactics" }), tactics.map((t) => h("option", { value: t, text: t })));
  const fr = h("select", null, h("option", { value: "", text: "All rules" }), rules.map((t) => h("option", { value: t, text: t })));
  const fi = h("select", null, [["", "Any status"], ["in", "In an incident"], ["out", "Not in an incident"]].map(([v, t]) => h("option", { value: v, text: t })));
  const count = h("span", { class: "muted small" });
  const tbody = h("tbody");
  const draw = () => {
    clear(tbody);
    const f = q.value.toLowerCase();
    let n = 0;
    for (const d of rows) {
      if (ft.value && d.tactic !== ft.value) continue;
      if (fr.value && d.rule_id !== fr.value) continue;
      if (fi.value === "in" && !d.incident_id) continue;
      if (fi.value === "out" && d.incident_id) continue;
      const hay = [d.rule_id, d.technique_id, d.technique_name, d.evidence, ...d.users, ...d.hosts, ...d.src_ips, ...d.dst_ips].join(" ").toLowerCase();
      if (f && !hay.includes(f)) continue;
      n++;
      tbody.append(h("tr", { class: "click", onclick: () => openEvidence(d.member_event_ids[0]) },
        h("td", { class: "nowrap", text: fmtTs(d.ts_first) }),
        h("td", null, h("span", { class: "mono", text: d.rule_id }), h("div", { class: "muted small", text: d.rule_title })),
        h("td", null, h("span", { class: "mono", text: d.technique_id }), h("div", { class: "muted small", text: d.tactic })),
        h("td", { text: [...d.users].join(", ") || "—" }), h("td", { text: [...d.hosts].join(", ") || "—" }),
        h("td", { class: "num", text: fmtN(d.member_count) }),
        h("td", { class: "truncate", text: d.evidence, title: d.evidence }),
        h("td", null, d.incident_id ? h("a", { class: "ev", text: pad(d.incident_id), onclick: (e) => { e.stopPropagation(); navigate("incidents", d.incident_id); } }) :
          h("span", { class: "muted", text: d.duplicate_of ? "duplicate" : "unlinked" }))));
    }
    count.textContent = `${n} of ${rows.length}`;
  };
  [q, ft, fr, fi].forEach((x) => x.addEventListener("input", draw));
  view.append(card("Detections", "every rule hit, with member raw events", null,
    h("div", { class: "toolbar" }, q, ft, fr, fi, count),
    h("div", { class: "scroll" }, h("table", { class: "t" }, h("thead", null, h("tr", null, ["First seen", "Rule", "Technique", "User", "Host", "Events", "Why it fired", "Incident"].map((c) => h("th", { text: c })))), tbody))));
  draw();
};

VIEWS.sources = async (view) => {
  const [inputs, overview] = await Promise.all([api("/inputs"), state.workspaces.some((w) => w.name === state.ws && w.analysed) ? api(wsq("/overview")).catch(() => null) : null]);
  const fileInput = h("input", { type: "file", multiple: true, class: "hidden", accept: inputs.allowed_suffixes.join(",") });
  const uploads = h("div", { class: "uploads" });
  const drop = h("div", { class: "drop" },
    h("div", null, h("strong", { text: "Drop log files here" }), " or ", h("button", { class: "btn sm", type: "button", text: "Choose files", onclick: () => fileInput.click() })),
    h("div", { class: "small", text: `Saved to ${inputs.folder}/ · ${inputs.allowed_suffixes.join(" ")} · up to ${fmtBytes(inputs.max_upload_bytes)} each` }), fileInput);
  ["dragenter", "dragover"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.add("over"); }));
  ["dragleave", "drop"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
  drop.addEventListener("drop", (e) => uploadFiles(e.dataTransfer.files, uploads));
  fileInput.addEventListener("change", () => uploadFiles(fileInput.files, uploads));

  const fileRows = inputs.files.map((f) => h("tr", null, h("td", { class: "mono", text: f.name }), h("td", { class: "num", text: fmtBytes(f.size) }), h("td", { class: "nowrap", text: f.modified.replace("T", " ") }),
    h("td", { class: "right" }, h("button", { class: "btn sm danger", type: "button", text: "Remove", onclick: async () => {
      if (!confirm(`Remove ${f.name} from ${inputs.folder}/? The file is deleted from disk.`)) return;
      try { await api(`/inputs/${encodeURIComponent(f.name)}`, { method: "DELETE" }); toast(`Removed ${f.name}`); render(); } catch (e) { toast(e.message); }
    } }))));
  const job = state.job && state.job.state === "running";
  const analyzeBtn = h("button", { class: "btn primary", type: "button", disabled: !inputs.files.length || job, text: "Analyze input folder", onclick: () => startRun("input") });
  const inputCard = card("Input folder", `${inputs.folder}/ · ${inputs.files.length} file${inputs.files.length === 1 ? "" : "s"}`, analyzeBtn,
    h("div", { class: "card-b stack" }, drop, uploads,
      inputs.files.length ? h("table", { class: "t" }, h("thead", null, h("tr", null, ["File", "Size", "Modified", ""].map((c) => h("th", { text: c })))), h("tbody", null, fileRows)) :
        h("div", { class: "muted", text: "The folder is empty. Upload files above, or copy them into the folder and refresh." }),
      h("div", { class: "muted small", text: "Command line equivalent: copy files into data/input/ and run `make analyze`. Results go to the `input` workspace." })));

  const runCard = card("Analysis runs", null, null, h("div", { class: "card-b", id: "run-panel" }));
  const wsTable = h("table", { class: "t" }, h("thead", null, h("tr", null, ["Workspace", "Source", "Files analysed", "Events", "Incidents", "Last run", ""].map((c) => h("th", { text: c })))),
    h("tbody", null, state.workspaces.map((w) => h("tr", null,
      h("td", null, h("strong", { text: w.name }), w.name === state.ws ? h("span", { class: "chip", text: "active" }) : null),
      h("td", { class: "mono", text: w.source || "—" }), h("td", { class: "mono small", text: w.files.join(", ") || "—" }),
      h("td", { class: "num", text: fmtN(w.events) }), h("td", { class: "num", text: fmtN(w.incidents) }), h("td", { class: "nowrap", text: w.finished_at ? w.finished_at.replace("T", " ") : "never" }),
      h("td", { class: "right nowrap" },
        w.analysed && w.name !== state.ws ? h("button", { class: "btn sm", type: "button", text: "Open", onclick: () => switchWs(w.name) }) : null, " ",
        w.runnable ? h("button", { class: "btn sm", type: "button", disabled: job, text: w.analysed ? "Re-run" : "Run", onclick: () => startRun(w.name) }) : null)))));
  const filesCard = overview ? card("Files behind the active workspace", `${state.ws} · fingerprints recorded at ingest`, null, h("div", { class: "card-b flush" },
    h("table", { class: "t" }, h("thead", null, h("tr", null, ["file_id", "File", "Size", "SHA-256"].map((c) => h("th", { text: c })))),
      h("tbody", null, overview.files.map((f) => h("tr", null, h("td", { class: "num", text: f.file_id }), h("td", { class: "mono", text: f.name, title: f.path }), h("td", { class: "num", text: fmtBytes(f.size) }), h("td", { class: "mono small", text: f.sha256 }))))))) : null;
  const formats = card("Supported log formats", "auto-detected per line", null, h("div", { class: "card-b" }, h("table", { class: "t" }, h("tbody", null,
    [["JSON (ECS / SimEDR EDR)", "line starts with {", "edr_events.json, data/sample/events.log"],
     ["ArcSight CEF", "line starts with CEF:", "10% of the sample"],
     ["FortiGate key=value", "line starts with date=", "firex-*.log firewall logs"]].map((r) => h("tr", null, r.map((c, i) => h("td", { class: i === 1 ? "mono" : null, text: c })))))),
    h("p", { class: "muted small", text: "Field mapping lives in config/field_map.yaml. Lines in other formats are kept in parse_errors with their byte offset and shown on the Overview page." })));
  view.append(h("div", { class: "stack" }, h("div", { class: "grid g2" }, inputCard, h("div", { class: "stack" }, runCard, formats)),
    card("Workspaces", "each analysis writes to its own workspace under out/", null, h("div", { class: "card-b flush" }, wsTable)), filesCard));
  drawRunPanel();
};

function uploadFiles(files, box) {
  for (const file of files) {
    const bar = h("div", { class: "progress" }, h("i"));
    const status = h("span", { class: "small muted", text: "0%" });
    box.append(h("div", { class: "row" }, h("span", { class: "mono truncate", text: file.name }), bar, status));
    const send = (overwrite) => {
      const xhr = new XMLHttpRequest();
      xhr.open("POST", `/inputs?filename=${encodeURIComponent(file.name)}${overwrite ? "&overwrite=true" : ""}`);
      xhr.setRequestHeader("Content-Type", "application/octet-stream");
      xhr.upload.onprogress = (e) => { if (e.lengthComputable) { const pc = Math.round((100 * e.loaded) / e.total); bar.firstChild.style.width = `${pc}%`; status.textContent = `${pc}%`; } };
      xhr.onload = () => {
        if (xhr.status === 409 && !overwrite && confirm(`${file.name} already exists in the input folder. Replace it?`)) return send(true);
        if (xhr.status >= 200 && xhr.status < 300) { bar.firstChild.style.width = "100%"; status.textContent = "uploaded"; toast(`Uploaded ${file.name}`); setTimeout(render, 400); }
        else { let m = xhr.statusText; try { m = JSON.parse(xhr.responseText).detail; } catch { /* keep status text */ } status.textContent = "failed"; toast(`${file.name}: ${m}`); }
      };
      xhr.onerror = () => { status.textContent = "failed"; };
      xhr.send(file);
    };
    send(false);
  }
}

async function startRun(name) {
  try { state.job = await api("/runs", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ workspace: name }) }); toast(`Analysing ${name}…`); pollRun(); render(); }
  catch (e) { toast(e.message); }
}
async function pollRun() {
  try { state.job = await api("/runs/current"); } catch { return; }
  drawRunChip(); drawRunPanel();
  if (state.job.state === "running") { setTimeout(pollRun, 600); return; }
  if (state.job.state === "done") { toast(`Analysis of ${state.job.workspace} finished: ${state.job.stats.incidents} incident(s)`); await switchWs(state.job.workspace); }
  if (state.job.state === "failed") { toast(`Analysis failed: ${state.job.error}`); render(); }
}
function drawRunChip() {
  const c = clear($("run-chip")); const j = state.job;
  if (!j || j.state === "idle") return;
  if (j.state === "running") c.append(h("span", { class: "pill" }, h("span", { class: "dot" }), `Analysing ${j.workspace} · ${j.stage} ${Math.round(100 * j.progress)}%`));
  else if (j.state === "failed") c.append(h("span", { class: "pill bad-pill" }, h("span", { class: "dot" }), "Last run failed"));
}
function drawRunPanel() {
  const p = $("run-panel"); if (!p) return; clear(p); const j = state.job;
  if (!j || j.state === "idle") { p.append(h("div", { class: "muted", text: "No analysis has run in this server session. Use “Analyze input folder”, or Re-run a workspace below." })); return; }
  const bar = h("div", { class: "progress" }, h("i")); bar.firstChild.style.width = `${Math.round(100 * (j.progress || 0))}%`;
  p.append(h("div", { class: "kv" },
    h("div", { class: "k", text: "Workspace" }), h("div", { text: j.workspace }),
    h("div", { class: "k", text: "Status" }), h("div", null, j.state === "done" ? h("span", { class: "pill ok-pill" }, h("span", { class: "dot" }), "Completed") :
      j.state === "failed" ? h("span", { class: "pill bad-pill" }, h("span", { class: "dot" }), "Failed") : `Running · ${j.stage}`),
    h("div", { class: "k", text: "Elapsed" }), h("div", { text: `${j.elapsed_s ?? 0}s` })), bar);
  if (j.state === "done") p.append(h("div", { class: "small secondary", text: `${fmtN(j.stats.ingest.events)} events (${fmtN(j.stats.ingest.errors)} parse errors) → ${fmtN(j.stats.detections)} detections → ${fmtN(j.stats.alert_groups)} groups → ${fmtN(j.stats.incidents)} incidents in ${j.stats.wall_time_s}s` }));
  if (j.state === "failed") p.append(h("div", { class: "callout warn mono small", text: j.error }));
}

VIEWS.rules = async (view) => {
  const rules = await api("/rules");
  view.append(card("Detection rules", `${rules.length} rules loaded from config/rules/*.yml · edit the YAML and re-run an analysis to apply`, null,
    h("div", { class: "card-b flush" }, h("table", { class: "t" },
      h("thead", null, h("tr", null, ["Rule", "Title", "Technique", "Tactic", "Type", "Severity", "Confidence", "Label priority", "File"].map((c) => h("th", { text: c })))),
      h("tbody", null, rules.flatMap((r) => [h("tr", null,
        h("td", { class: "mono", text: r.id }),
        h("td", null, r.title, h("details", null, h("summary", { class: "small", text: "compiled DuckDB SQL" }), Object.entries(r.sql).map(([k, v]) => h("div", null, h("div", { class: "muted small", text: k }), h("pre", { class: "sql", text: v }))))),
        h("td", { class: "mono", text: r.technique }), h("td", { text: r.tactic }), h("td", { text: r.type }),
        h("td", { class: "num", text: `${r.severity}/4` }), h("td", { class: "num", text: r.confidence }), h("td", { class: "num", text: r.label_priority }), h("td", { class: "mono small", text: r.source_file }))])))),
    h("div", { class: "card-b small muted", text: "Rules may only reference normalised envelope fields; vendor verdict fields (threat.*, rule.*, labels.*, event.kind, event.severity) are rejected at load time." })));
};

VIEWS.evaluation = async (view) => {
  let m;
  try { m = await api(wsq("/metrics")); }
  catch (e) { view.append(card("Evaluation", null, null, emptyState("No evaluation for this workspace", "Only workspaces with ground truth can be scored. For the sample: `make run && make score`, then select the `sample` workspace."))); return; }
  const mm = m.metrics;
  const tile = (label, x, target) => h("div", { class: "kpi" }, h("div", { class: "label", text: label }), h("div", { class: "value", text: x.value == null ? "N/A" : `${(100 * x.value).toFixed(1)}%` }), h("div", { class: "hint", text: `${x.text} · target ${target}` }));
  const steps = m.attacks.filter((a) => !a.decoy).flatMap((a) => a.steps.map((s) => ({ ...s, attack: a.attack_id })));
  view.append(h("div", { class: "stack" },
    h("div", { class: "callout warn" }, h("strong", { text: "Read with care. " }), "Ground truth comes from the synthetic generator (tools/gen_scenarios.py), written alongside the rules, so these numbers show the pipeline works end to end rather than how it generalises."),
    h("div", { class: "kpis" }, tile("Step recall", mm.step_recall, "> 90%"), tile("Label accuracy (parent)", mm.label_accuracy_parent, "> 85%"),
      tile("Label accuracy (sub-technique)", mm.label_accuracy_subtechnique, "> 85%"), tile("Attacks in correct order", mm.attacks_in_correct_order, "all"),
      tile("False-alarm share", mm.false_alarm_share, "< 10%"),
      h("div", { class: "kpi" }, h("div", { class: "label", text: "Run time / peak RSS" }), h("div", { class: "value", text: `${m.run_stats.wall_time_s}s` }), h("div", { class: "hint", text: fmtBytes(m.run_stats.peak_rss_bytes) }))),
    card("Planted steps", null, null, h("div", { class: "card-b flush" }, h("table", { class: "t" },
      h("thead", null, h("tr", null, ["Attack", "Step", "Ground truth", "Predicted", "Found", "Parent", "Sub-technique", "Rules"].map((c) => h("th", { text: c })))),
      h("tbody", null, steps.map((s) => h("tr", null, h("td", { text: s.attack }), h("td", { class: "num", text: s.order }), h("td", { class: "mono", text: s.gt_technique }), h("td", { class: "mono", text: s.predicted || "—" }),
        ...[s.found, s.parent_ok, s.sub_ok].map((ok) => h("td", null, h("span", { class: `pill ${ok ? "ok-pill" : "bad-pill"}` }, h("span", { class: "dot" }), ok ? "Yes" : "No"))),
        h("td", { class: "mono small", text: s.rules.join(", ") }))))))),
    card("Path order and decoys", null, null, h("div", { class: "card-b" }, m.attacks.map((a) => h("div", { class: "small" }, h("strong", { text: `${a.attack_id}: ` }),
      a.decoy ? (a.rejected ? "decoy correctly rejected (not in any incident)" : `decoy promoted into incident(s) ${a.in_incidents.join(", ")}`) :
        `${a.path.in_order ? "reconstructed in order" : "not in order"} in ${pad(a.path.incident_id)} · dossier DP chain ${a.strongest_chain.in_order ? "complete" : `misses steps ${(a.strongest_chain.missing_found_steps || []).join(", ")}`}`))))));
};

// ------------------------------------------------------------------ pipeline demo (walkthrough)
// Shows the stored output of every stage for data/demo/demo_events.log (5 events), one step at a time.
const DEMO_STEPS = [
  ["ingest", "Ingest"], ["normalise", "Normalise & store"], ["detect", "Detect & flag"], ["aggregate", "Aggregate alerts"],
  ["correlate", "Correlate"], ["graph", "Attack graph"], ["path", "Reconstruct path"], ["rest", "Risk, reach & evidence"]];
let demoCy = null;

function flow(items) {
  const f = h("div", { class: "flow" });
  items.forEach((it, i) => {
    if (i) f.append(h("div", { class: "flow-arrow", text: "→" }));
    f.append(h("div", { class: "flow-box" }, h("div", { class: "flow-k", text: it[0] }), h("div", { class: "flow-v", text: it[1] })));
  });
  return f;
}
function stage(n, title, flowItems, ...body) {
  return h("section", { class: "card" },
    h("div", { class: "card-h" }, h("span", { class: "stage-num", text: n }), h("h2", { text: title })),
    h("div", { class: "card-b stack" }, flowItems ? flow(flowItems) : null, ...body));
}
const evName = (w, eid) => { const i = w.lines.findIndex((l) => l.event_id === eid); return i >= 0 ? `E${i + 1}` : String(eid); };
const okPill = (t) => h("span", { class: "pill ok-pill" }, h("span", { class: "dot" }), t);
const noPill = (t) => h("span", { class: "pill" }, h("span", { class: "dot muted-dot" }), t);
const badPill = (t) => h("span", { class: "pill bad-pill" }, h("span", { class: "dot" }), t);
function eventGist(l) {
  const e = l.envelope;
  const detail = e.command_line || (e.bytes_out ? `${fmtBytes(e.bytes_out)} sent to ${e.dst_ip}` : "") ||
    (e.target_user ? `created account ${e.target_user}` : "") || (e.src_ip ? `from ${e.src_ip}` : "") || e.process || "";
  return `${e.event_type} · ${e.user || "?"} @ ${e.host || "?"}${detail ? " · " + detail : ""}`;
}

VIEWS.demo = async (view) => {
  const step = Math.min(DEMO_STEPS.length, Math.max(1, parseInt(state.param || "1", 10) || 1));
  const demoWs = state.workspaces.find((w) => w.name === "demo");
  const running = state.job && state.job.state === "running";
  const runBtn = h("button", { class: "btn primary", type: "button", disabled: running, text: demoWs && demoWs.analysed ? "Re-run demo pipeline" : "Run demo pipeline", onclick: () => startRun("demo") });
  if (!demoWs || !demoWs.analysed) {
    view.append(card("Pipeline demo", "data/demo/demo_events.log · 5 events", runBtn, emptyState("Run the demo first",
      "Click “Run demo pipeline” (or run `make demo`). ForgeTrace ingests the 5-event demo file and this page then walks through every stage’s real output.")));
    return;
  }
  const w = await api("/walkthrough?ws=demo");
  const strip = h("div", { class: "stages" }, DEMO_STEPS.map(([, label], i) =>
    h("button", { type: "button", class: `stage-pill${i + 1 === step ? " active" : ""}${i + 1 < step ? " done" : ""}`, onclick: () => navigate("demo", i + 1) },
      h("span", { class: "n", text: i + 1 }), label)));
  const nav = h("div", { class: "demo-nav" },
    h("button", { class: "btn", type: "button", disabled: step === 1, text: "← Previous", onclick: () => navigate("demo", step - 1) }),
    h("span", { class: "muted small", text: `Step ${step} of ${DEMO_STEPS.length}` }),
    h("button", { class: "btn primary", type: "button", disabled: step === DEMO_STEPS.length, text: "Next →", onclick: () => navigate("demo", step + 1) }));
  const head = card("Pipeline demo", `${w.files.map((f) => f.file).join(", ")} · ${w.lines.length} raw events · one stage per step`, runBtn,
    h("div", { class: "card-b stack" }, strip,
      h("div", { class: "demo-events" }, w.lines.map((l, i) => h("div", { class: `demo-ev${l.label ? " flagged" : ""}` },
        h("span", { class: "ev-tag", text: `E${i + 1}` }), h("span", { class: "small", text: eventGist(l) }))))));
  const body = h("div");
  view.append(h("div", { class: "stack" }, head, body, nav));
  ({ 1: demoIngest, 2: demoNormalise, 3: demoDetect, 4: demoAggregate, 5: demoCorrelate, 6: demoGraph, 7: demoPath, 8: demoRest })[step](body, w);
};

function demoIngest(body, w) {
  const pre = h("pre", { class: "raw", text: w.lines[0].raw });
  const sel = h("div", { class: "muted small", text: "Raw line E1 (click a row to show another):" });
  const tb = h("tbody", null, w.lines.map((l, i) => {
    const tr = h("tr", { class: `click${i === 0 ? " selected" : ""}` },
      h("td", { class: "mono", text: `E${i + 1}` }), h("td", { class: "num", text: l.line_no }), h("td", { class: "num", text: l.byte_offset }),
      h("td", { class: "num", text: l.length }), h("td", null, h("span", { class: "chip mono", text: l.format })),
      h("td", { class: "mono small", text: `(${l.file_id} << 48) | ${l.byte_offset} = ${l.event_id}` }), h("td", { class: "mono", text: l.display_id }),
      h("td", { class: "mono small", text: `${l.sha256.slice(0, 16)}…`, title: l.sha256 }));
    tr.addEventListener("click", () => { tb.querySelectorAll("tr").forEach((x) => x.classList.remove("selected")); tr.classList.add("selected"); pre.textContent = l.raw; sel.textContent = `Raw line E${i + 1} (click a row to show another):`; });
    return tr;
  }));
  body.append(stage(1, "Ingest — stream the file line by line",
    [["Input", `${w.files[0].file} (${fmtBytes(w.files[0].size)})`], ["Read", `${w.lines.length} lines, streamed`], ["Output", `${w.lines.length} raw events, each with an event_id`]],
    h("div", { class: "scroll" }, h("table", { class: "t" }, h("thead", null, h("tr", null, ["Event", "Line", "Byte offset", "Bytes", "Format", "event_id = (file_id << 48) | offset", "Display ID", "SHA-256"].map((c) => h("th", { text: c })))), tb)),
    sel, pre));
}

function demoNormalise(body, w) {
  let cur = 0;
  const tabs = h("div", { class: "seg" });
  const pane = h("div");
  const draw = () => {
    tabs.querySelectorAll("button").forEach((b, i) => b.classList.toggle("active", i === cur));
    const l = w.lines[cur], t = l.trace;
    clear(pane);
    if (t.error) { pane.append(h("div", { class: "callout warn", text: t.error })); return; }
    pane.append(h("div", { class: "split" },
      h("div", null, h("div", { class: "lbl", text: `1 · Raw ${t.format} line (${t.raw_field_count} vendor fields)` }), h("pre", { class: "raw", text: l.raw }),
        t.ignored_vendor_fields.length ? h("div", { class: "small muted" }, "Present but deliberately not mapped (vendor verdicts are never used for detection): ",
          t.ignored_vendor_fields.map((x) => h("span", { class: "chip mono", text: x }))) : null),
      h("div", { class: "split-arrow", text: "↓  config/field_map.yaml" }),
      h("div", null, h("div", { class: "lbl", text: "2 · Normalised envelope (one row in Parquet)" }),
        h("table", { class: "t" }, h("thead", null, h("tr", null, ["Envelope field", "From vendor field", "Raw value", "Stored value", "How"].map((c) => h("th", { text: c })))),
          h("tbody", null, t.mapping.map((m) => h("tr", null, h("td", { class: "mono", text: m.field }), h("td", { class: "mono small", text: m.source }),
            h("td", { class: "mono small truncate", text: m.raw ?? "—", title: m.raw ?? "" }), h("td", { class: "mono small truncate", text: String(m.value ?? "—"), title: String(m.value ?? "") }),
            h("td", { class: "small", text: m.how }))))))));
  };
  w.lines.forEach((l, i) => tabs.append(h("button", { type: "button", onclick: () => { cur = i; draw(); } }, `E${i + 1}`, h("span", { class: "muted", text: ` ${l.format}` }))));
  const st = w.storage;
  body.append(stage(2, "Normalise & store — one schema for every log format",
    [["Raw line", "JSON or CEF text"], ["field_map.yaml", "vendor field → envelope field"], ["Envelope row", "~40 typed columns"], ["Storage", `${st.parquet_files.map((p) => p.name).join(", ")}`]],
    tabs, pane,
    h("div", { class: "kpis" },
      [["Rows stored", st.rows], ["Columns", st.columns], ["Parse errors", st.parse_errors], ["Parquet size", fmtBytes(st.parquet_files.reduce((a, p) => a + p.bytes, 0))]].map(([k, v]) =>
        h("div", { class: "kpi" }, h("div", { class: "label", text: k }), h("div", { class: "value", text: v })))),
    h("div", { class: "small muted", text: `Query layer: ${st.duckdb}. Source fingerprint (SHA-256) recorded at ingest: ${st.manifest[0].sha256}` })));
  draw();
}

function demoDetect(body, w) {
  const fired = w.rules.filter((r) => r.matched.length);
  const rows = w.lines.map((l, i) => h("div", { class: `det-row${l.label ? " hit" : ""}` },
    h("span", { class: "ev-tag", text: `E${i + 1}` }),
    h("div", { class: "small grow" }, eventGist(l)),
    l.label ? h("div", { class: "det-out" },
      h("div", null, badPill("Flagged"), " ", h("strong", { class: "mono", text: `${l.label.primary_rule} · ${l.label.primary_technique}` }), " ", h("span", { text: l.label.primary_tactic })),
      l.label.also_matched.length ? h("div", { class: "small muted", text: `also matched ${l.label.also_matched.map((a) => `${a.rule_id} ${a.technique_id}`).join(", ")} → kept as secondary label` }) : null)
      : h("div", { class: "det-out" }, noPill("Not flagged"), h("span", { class: "small muted", text: " no rule condition matched — normal activity" }))));
  body.append(stage(3, "Detect & flag — YAML rules compiled to SQL",
    [["Envelope rows", `${w.lines.length} events`], ["Rules evaluated", `${w.rules.length} rules`], ["Rules that fired", `${fired.length}`], ["Detections", `${w.detections.length}`]],
    h("div", { class: "stack-sm" }, rows),
    h("table", { class: "t" }, h("thead", null, h("tr", null, ["Detection", "Rule", "Technique", "Tactic", "Events", "Why it fired"].map((c) => h("th", { text: c })))),
      h("tbody", null, w.detections.map((d) => h("tr", null, h("td", { class: "mono small", text: d.detection_id }), h("td", null, h("span", { class: "mono", text: d.rule_id }), h("div", { class: "muted small", text: d.rule_title })),
        h("td", { class: "mono", text: `${d.technique_id}` }), h("td", { text: d.tactic }), h("td", { class: "mono", text: d.member_event_ids.map((x) => evName(w, x)).join(", ") }), h("td", { class: "small", text: d.evidence })))))));
}

function demoAggregate(body, w) {
  const folded = w.groups.flatMap((g) => g.also_matched.map((a) => ({ ...a, into: g.group_id })));
  body.append(stage(4, "Aggregate alerts — merge repeats, fold secondary labels",
    [["Detections", `${w.detections.length}`], ["Merge rule", "same rule + entities, gap ≤ 15 min"], ["Alert groups", `${w.groups.length}`], ["Folded", `${folded.length} secondary label(s)`]],
    h("table", { class: "t" }, h("thead", null, h("tr", null, ["Alert group", "Rule", "Technique · tactic", "Detections merged", "raw_alert_count", "Events", "Entities", "Also matched (folded)"].map((c) => h("th", { text: c })))),
      h("tbody", null, w.groups.map((g) => h("tr", null, h("td", { class: "mono", text: g.group_id }), h("td", { class: "mono", text: g.rule_id }),
        h("td", null, h("span", { class: "mono", text: g.technique_id }), h("div", { class: "muted small", text: g.tactic })),
        h("td", { class: "mono small", text: g.detection_ids.join(", ") }), h("td", { class: "num", text: g.raw_alert_count }),
        h("td", { class: "mono", text: g.member_event_ids.map((x) => evName(w, x)).join(", ") }),
        h("td", null, Object.entries(g.entities).filter(([k]) => ["user", "target_user", "host", "src_ip", "dst_ip", "logon_id"].includes(k)).map(([k, v]) => h("span", { class: "chip mono", text: `${k}=${v.join("|")}` }))),
        h("td", { class: "small", text: g.also_matched.map((a) => `${a.rule_id} ${a.technique_id} (${a.tactic})`).join(", ") || "—" }))))),
    folded.length ? h("div", { class: "callout small", text: folded.map((f) => `${f.rule_id} (${f.technique_id}) fired on the same event as ${f.into}; label priority made it a secondary label, so it is folded into ${f.into} instead of becoming its own node.`).join(" ") } ) : null));
}

function demoCorrelate(body, w) {
  const kept = w.candidate_edges.filter((e) => e.kept).length;
  const W = w.weights;
  body.append(stage(5, "Correlate — link alert groups that share an entity",
    [["Alert groups", `${w.groups.length}`], ["Shared entities", `${Object.keys(w.shared_entities).length}`], ["Candidate pairs", `${w.candidate_edges.length}`], ["Kept edges", `${kept} (θ ≥ ${w.theta_edge})`]],
    h("div", null, h("div", { class: "lbl", text: "Entity index: entities seen in more than one group" }),
      h("div", { class: "kv" }, Object.entries(w.shared_entities).flatMap(([k, v]) => [h("div", { class: "mono", text: k }), h("div", { class: "mono", text: v.join(", ") })]))),
    h("div", { class: "formula mono", text: `s = clip( ${W.L}·L + ${W.T}·T + ${W.P}·P + ${W.R}·R − ${W.F}·F )    L = links via shared entities · T = e^(−Δt/τ) · P = tactic progression · R = impact · F = common-entity penalty` }),
    h("div", { class: "scroll" }, h("table", { class: "t" }, h("thead", null, h("tr", null, ["Pair (earlier → later)", "Why linked (shared entities)", "Δt", "L", "T", "P", "R", "F", "Score", "Decision"].map((c, i) => h("th", { class: i >= 2 && i <= 8 ? "num" : null, text: c })))),
      h("tbody", null, w.candidate_edges.map((e) => h("tr", { class: e.kept ? null : "dropped" },
        h("td", { class: "mono", text: `${e.src_group_id} → ${e.dst_group_id}` }),
        h("td", null, e.reasons.map((r) => h("span", { class: "chip mono", text: `${r.type} ${r.entity_key.split(":").slice(1).join(":")}` }))),
        h("td", { class: "num", text: `${Math.round(e.delta_t_s)}s` }),
        ...["L", "T", "P", "R", "F"].map((k) => h("td", { class: "num mono", text: e.score_terms[k] })),
        h("td", { class: "num mono" }, h("strong", { text: e.score })),
        h("td", null, e.kept ? okPill("kept") : badPill(e.decision.replace(/^dropped: /, "dropped: "))))))))));
}

function demoGraph(body, w) {
  const inc = w.incidents[0];
  const box = h("div", { id: "demo-graph" });
  body.append(stage(6, "Attack graph — connected components become incidents",
    [["Kept edges", `${w.candidate_edges.filter((e) => e.kept).length}`], ["Components", `${w.incidents.length + w.abstained.length}`], ["Gate", "≥ 2 distinct tactics"], ["Incidents", `${w.incidents.length}`]],
    box,
    inc ? h("div", { class: "callout small" }, `Component {${inc.group_ids.join(", ")}} spans ${inc.tactics.length} tactics (${inc.tactics.join(", ")}) → promoted to `, h("strong", { text: pad(inc.incident_id) }), ".",
      w.abstained.length ? ` ${w.abstained.length} other component(s) stayed unlinked.` : " No other components.") : h("div", { class: "callout warn", text: "No component passed the gate." })));
  if (!inc) return;
  const nodes = Object.fromEntries(inc.observed.nodes.map((n) => [n.group_id, n]));
  const order = inc.inferred.primary_path.group_ids;
  const els = order.map((g, i) => ({ data: { id: g, label: `${g}\n${nodes[g].tactic}\n${nodes[g].technique_id} · ${nodes[g].rule_id}` }, position: { x: i * 230, y: i % 2 ? 120 : 0 } }));
  inc.inferred.edges.forEach((e) => els.push({ data: { id: e.edge_id, source: e.src_group_id, target: e.dst_group_id, label: e.score.toFixed(2) } }));
  if (demoCy) demoCy.destroy();
  const ink = cssVar("--text-primary"), muted = cssVar("--text-muted"), accent = cssVar("--accent");
  demoCy = cytoscape({ container: box, elements: els, layout: { name: "preset", fit: true, padding: 40 }, userZoomingEnabled: false, maxZoom: 1.4,
    style: [
      { selector: "node", style: { shape: "round-rectangle", width: 170, height: 62, "background-color": cssVar("--surface-2"), "border-width": 2, "border-color": accent,
        label: "data(label)", "text-wrap": "wrap", "font-size": 12, color: ink, "text-valign": "center" } },
      { selector: "edge", style: { width: 2, "line-style": "dashed", "line-color": muted, "target-arrow-color": muted, "target-arrow-shape": "triangle", "curve-style": "bezier",
        label: "data(label)", "font-size": 11, color: ink, "text-background-color": cssVar("--surface-1"), "text-background-opacity": 1, "text-background-padding": 2 } }] });
}

function demoPath(body, w) {
  const inc = w.incidents[0];
  if (!inc) { body.append(stage(7, "Reconstruct path", null, h("div", { class: "muted", text: "No incident to reconstruct." }))); return; }
  const nodes = Object.fromEntries(inc.observed.nodes.map((n) => [n.group_id, n]));
  const pp = inc.inferred.primary_path, sc = inc.inferred.strongest_chain;
  const chain = h("div", { class: "chain" });
  pp.group_ids.forEach((g, i) => {
    if (i) {
      const hop = pp.hops[i - 1];
      chain.append(h("div", { class: "chain-link" }, h("div", { class: "mono small", text: hop.edge_id ? `${hop.score}` : "—" }), h("div", { class: "arrow", text: "→" }),
        h("div", { class: "muted small", text: hop.edge_id ? (hop.note ? `via ${hop.edge_id}` : "direct edge") : "no edge" })));
    }
    const n = nodes[g];
    chain.append(h("div", { class: "chain-node" }, h("div", { class: "muted small", text: `${i + 1} · ${fmtTs(n.ts_first).slice(11, 19)}` }), h("strong", { text: n.tactic }),
      h("div", { class: "mono small", text: `${n.technique_id} ${n.technique_name}` }), h("div", { class: "evlinks small" }, n.member_event_ids.map((x) => evLink(x, evName(w, x), "demo")))));
  });
  const notes = pp.hops.filter((hp) => hp.note).map((hp) => {
    const direct = w.candidate_edges.find((e) => e.src_group_id === hp.from && e.dst_group_id === hp.to);
    const why = direct ? `the pair ${hp.from} → ${hp.to} scored ${direct.score} and was dropped in step 5 (below θ ${w.theta_edge})` : `${hp.from} and ${hp.to} share no entity`;
    return hp.edge_id ? `Hop ${hp.from} → ${hp.to} has no direct edge: ${why}. ${hp.to} is still part of the story because it links from an earlier step via ${hp.edge_id} (score ${hp.score}).`
      : `Hop ${hp.from} → ${hp.to}: ${why}; it is in the same connected component.`;
  });
  body.append(stage(7, "Reconstruct the attack path — order the story",
    [["Incident", pad(inc.incident_id)], ["Ordering", "time → tactic order"], ["Steps", `${pp.group_ids.length}`], ["Stages", pp.stages.join(" → ")]],
    chain,
    notes.length ? h("div", { class: "callout small", text: notes.join(" ") }) : null,
    h("div", { class: "small muted", text: `For comparison, the dossier’s score-maximising chain (J = ${sc.objective_J}) is ${sc.group_ids.join(" → ")}.` })));
}

function demoRest(body, w) {
  const inc = w.incidents[0];
  const v = w.verify;
  const parts = [];
  if (inc) {
    const r = inc.inferred.reachability, best = inc.inferred.containment_candidates[0];
    parts.push(h("div", { class: "grid g3" },
      h("div", { class: "mini" }, h("div", { class: "lbl", text: "Risk score" }), h("div", { class: "big" }, `${inc.risk_score}`, " ", sevPill(inc.severity)),
        h("div", { class: "small muted", text: Object.entries(inc.risk_terms).map(([k, x]) => `${k} ${x}`).join(" + ") + " (× 100)" })),
      h("div", { class: "mini" }, h("div", { class: "lbl", text: "Reachable critical assets" }), h("div", { class: "big", text: `${r.critical_reachable} / ${r.total_critical_assets}` }),
        h("div", { class: "small muted", text: r.reachable.map((a) => `${a.asset} (reach ${a.reach}: ${a.path_edges.map((e) => `${e.relation}/${e.kind}`).join(" → ")})`).join("; ") || "none" })),
      h("div", { class: "mini" }, h("div", { class: "lbl", text: "Best containment (simulated)" }),
        h("div", { class: "big", text: best ? `${best.before} → ${best.after}` : "—" }), h("div", { class: "small muted", text: best ? `disable_account(${best.action.target}); nothing is actually changed` : "no candidate" }))));
    parts.push(h("div", { class: "small" }, h("strong", { text: "Compromised set (from the incident): " }), r.compromised.map((c) => h("span", { class: "chip mono", title: c.reason, text: `${c.node} · ${c.weight}` }))));
  }
  if (v) parts.push(h("div", { class: "callout small" }, h("strong", { text: "Evidence check: " }), `event ${v.display_id} (line ${v.line_no}) was re-read from ${v.file} at byte ${v.byte_offset} and re-hashed → `,
    v.verified ? okPill("verified: SHA-256 matches") : badPill("not verified"), " ", evLink(v.event_id, "open raw line", "demo")));
  parts.push(h("div", null, h("button", { class: "btn primary", type: "button", text: `Open ${inc ? pad(inc.incident_id) : "incidents"} in the investigation view`,
    onclick: async () => { await switchWs("demo"); navigate("incidents", inc ? inc.incident_id : null); } })));
  body.append(stage(8, "Risk, reachability, containment & evidence — in brief",
    [["Incident", inc ? pad(inc.incident_id) : "—"], ["Risk", inc ? `${inc.risk_score} (${inc.severity})` : "—"], ["Reach", inc ? `${inc.inferred.reachability.critical_reachable} critical` : "—"], ["Evidence", v && v.verified ? "verified" : "—"]],
    ...parts));
}

// ------------------------------------------------------------------ evidence drawer
let evRaw = "";
async function openEvidence(eid, ws) {
  const d = $("drawer"); d.classList.add("open");
  const meta = clear($("ev-meta")), raw = $("ev-raw"), badge = clear($("ev-badge"));
  raw.textContent = "Loading…";
  try {
    const r = await api(`/events/${eid}/raw?ws=${encodeURIComponent(ws || state.ws || "")}`);
    evRaw = r.raw || "";
    badge.append(r.verified ? h("span", { class: "pill ok-pill" }, h("span", { class: "dot" }), "Verified · SHA-256 match")
      : h("span", { class: "pill bad-pill" }, h("span", { class: "dot" }), `Not verified · ${r.reason}`));
    [["Event ID", `${r.event_id} (${r.display_id})`], ["Source event ID", r.source_event_id || "—"], ["File", r.file], ["Line / byte offset", `${r.line_no} / ${r.byte_offset}`],
     ["SHA-256 (now)", r.digest], ["SHA-256 (ingest)", r.stored_digest]].forEach(([k, v]) => meta.append(h("div", { class: "k", text: k }), h("div", { class: "mono", text: v })));
    raw.textContent = evRaw;
  } catch (e) { raw.textContent = String(e.message); badge.append(h("span", { class: "pill bad-pill" }, h("span", { class: "dot" }), "Error")); }
}


// ------------------------------------------------------------------ explanations (human verification)
function listSection(title, items, mono) {
  if (!items || !items.length) return null;
  return h("div", { class: "xsec" }, h("h4", { text: title }),
    h("ul", { class: "xlist" }, items.map((t) => h("li", { class: mono && /^(Print|Every line)/.test(t) ? "mono small" : "" , text: t }))));
}

function renderExplanation(box, x) {
  clear(box);
  if (x.error) { box.append(h("div", { class: "callout warn", text: x.error })); return; }
  box.append(h("div", { class: "xhead", text: x.headline }), h("p", { class: "xsum", text: x.summary }));
  if (x.data_quality && x.data_quality.length) box.append(h("div", { class: "callout warn" }, x.data_quality.map((d) => h("div", { text: d }))));
  const nar = x.narrative;
  if (nar) {
    if (nar.narrative) {
      box.append(h("div", { class: "xsec ai" }, h("h4", null, h("span", { class: "pill" }, h("span", { class: "dot" }), nar.label || "AI-written summary of verified evidence"),
        h("span", { class: "muted small", text: ` ${nar.model || ""} · ${nar.status}` })),
        h("p", { text: nar.narrative.summary }),
        h("ol", { class: "xlist" }, (nar.narrative.steps || []).map((st) => h("li", { text: `${st.text} (events ${(st.event_ids || []).join(", ")})` })))));
    } else {
      box.append(h("div", { class: "callout", text: `AI summary not shown: ${nar.reason || nar.status}. The explanation below is complete without it.` }));
    }
  }
  if (x.why_flagged) {
    const w = x.why_flagged;
    box.append(h("div", { class: "xsec" }, h("h4", { text: "Why it was flagged" }),
      h("div", { class: "kv" },
        h("div", { class: "k", text: "Rule" }), h("div", { text: `${w.rule} · ${w.title || ""}` }),
        h("div", { class: "k", text: "Technique" }), h("div", { text: `${w.technique.id} ${w.technique.name || ""} (${w.technique.tactic})` }),
        h("div", { class: "k", text: "Condition" }), h("div", { class: "mono small", text: w.condition }),
        w.threshold ? [h("div", { class: "k", text: "Threshold" }), h("div", { text: w.threshold })] : null,
        w.followed_by ? [h("div", { class: "k", text: "Then" }), h("div", { text: w.followed_by })] : null,
        w.first_seen ? [h("div", { class: "k", text: "First seen" }), h("div", { text: w.first_seen })] : null,
        (w.observed || []).length ? [h("div", { class: "k", text: "Observed" }), h("div", null, w.observed.map((o) => h("div", { class: "small", text: o })))] : null)));
  }
  if (x.steps) {
    box.append(h("div", { class: "xsec" }, h("h4", { text: "Steps, in order" }),
      h("ol", { class: "xsteps" }, x.steps.map((st) => h("li", null,
        h("div", null, h("strong", { text: st.what }), h("span", { class: "muted small", text: ` · ${st.technique} · ${st.tactic} · ${fmtTs(st.when)} · ${fmtN(st.events)} event(s)` })),
        h("div", { class: "small", text: st.linked_from_previous }),
        evidenceList(st.evidence))))));
  }
  if (x.evidence) box.append(h("div", { class: "xsec" }, h("h4", { text: "Evidence (raw log lines, re-read and hash-checked)" }), evidenceList(x.evidence)));
  box.append(listSection("How to verify by hand", x.how_to_verify, true), listSection("What else it could be (rule these out)", x.benign_explanations),
             listSection("Uncertainties", x.uncertainties));
}

function evidenceList(ev) {
  if (!ev || !ev.length) return h("div", { class: "muted small", text: "No raw lines available for this step." });
  return h("div", { class: "xev" }, ev.map((e) => h("div", { class: "xline" },
    h("div", { class: "small" }, e.verified ? okPill("verified") : badPill(e.note || "not verified"),
      h("span", { class: "muted", text: ` ${e.file || "?"} line ${e.line_no ?? "?"} · ` }), evLink(e.event_id, e.display_id || String(e.event_id))),
    h("pre", { class: "raw small", text: e.raw || "" }))));
}

async function showExplanation(target, kind, id, withLlm) {
  clear(target).append(h("div", { class: "muted", text: withLlm ? "Asking for an AI summary of the verified facts…" : "Building explanation…" }));
  try {
    const x = await api(wsq(`/explain/${kind}/${encodeURIComponent(id)}${withLlm ? "?llm=true" : ""}`));
    clear(target).append(h("div", { class: "row-gap" },
      h("button", { class: "btn sm", text: "AI summary", title: "Optional: restates these facts via OpenRouter (validated, cached)", onclick: () => showExplanation(target, kind, id, true) }),
      h("button", { class: "btn sm", text: "Copy as text", onclick: () => { navigator.clipboard?.writeText(JSON.stringify(x, null, 2)); toast("Explanation copied"); } })));
    const body = h("div", { class: "xbox" }); target.append(body); renderExplanation(body, x);
  } catch (e) { clear(target).append(h("div", { class: "callout warn", text: String(e.message || e) })); }
}

// ------------------------------------------------------------------ live view
let liveTimer = null;
VIEWS.live = async (view) => {
  const draw = async () => {
    if (state.route !== "live") { clearInterval(liveTimer); liveTimer = null; return; }
    let st;
    try { st = await api(wsq("/live/status")); } catch (e) {
      clear(view).append(card("Not a live workspace", null, null, emptyState("No live analysis here",
        "Start one with: forgetrace live --watch <files or folder> --out out/<name> --graph", null)));
      return;
    }
    const kb = st.knowledge_base || {}, t = st.totals || {}, lb = st.last_batch || {};
    const tiles = h("div", { class: "kpis" }, [
      ["Batches processed", st.batches, `last: ${fmtN(lb.events)} events`],
      ["Events ingested", t.events, `${fmtN(t.errors)} parse errors`],
      ["Knowledge-base alerts", kb.alerts, `${fmtN(kb.tactics)} tactics`],
      ["Correlation edges", kb.edges, "stored, any batch"],
      ["Watermark (latest event)", null, fmtTs(st.watermark)],
      ["Storage tiers", null, Object.entries(st.batch_tiers || {}).map(([k, v]) => `${k}: ${v}`).join(" · ")],
    ].map(([l, v, sub]) => h("div", { class: "kpi" }, h("div", { class: "label", text: l }), v === null ? null : h("div", { class: "value", text: fmtN(v) }), h("div", { class: "muted small", text: sub }))));
    const hist = (st.history || []).slice(-15).reverse();
    const histT = h("table", { class: "t" }, h("thead", null, h("tr", null, ["Batch", "Events", "Ingest s", "Analyse s", "Detections", "Alerts updated", "Edges added", "Event time span"].map((c) => h("th", { text: c })))),
      h("tbody", null, hist.map((b) => h("tr", null, [b.batch, fmtN(b.events), b.ingest_s, b.analyse_s, fmtN(b.detections_in_batch), fmtN(b.alerts_updated), fmtN(b.edges_added),
        `${fmtTs(b.batch_min_ts)} → ${fmtTs(b.batch_max_ts)}`].map((c) => h("td", { text: c }))))));
    let alerts = [];
    try { alerts = await api(wsq("/live/alerts?limit=50")); } catch { /* none yet */ }
    const detail = h("div", { class: "card-b" }, h("span", { class: "muted", text: "Select an alert to see why it was flagged and how to verify it." }));
    const alertT = h("table", { class: "t" }, h("thead", null, h("tr", null, ["Last seen", "Rule", "Technique", "Tactic", "Events", "Batches"].map((c) => h("th", { text: c })))),
      h("tbody", null, alerts.map((a) => h("tr", { class: "click", onclick: () => showExplanation(detail, "alert", a.uid) },
        [fmtTs(a.ts_last), `${a.rule_id} · ${a.rule_title}`, a.technique_id, a.tactic, fmtN(a.member_count), `${a.first_batch}–${a.last_batch}`].map((c) => h("td", { text: c }))))));
    clear(view).append(h("div", { class: "stack" }, tiles,
      card("Recent batches", `updated ${String(st.updated_at || "").replace("T", " ")} · refreshes every 5 s`, h("button", { class: "btn sm", text: "Knowledge graph", onclick: () => navigate("graph") }), h("div", { class: "card-b flush scroll-x" }, histT)),
      card("Knowledge-base alerts (latest first)", null, null, h("div", { class: "card-b flush scroll-x" }, alertT)),
      card("Explanation", null, null, detail)));
  };
  await draw();
  if (!liveTimer) liveTimer = setInterval(draw, 5000);
};

// ------------------------------------------------------------------ knowledge graph view
let kg = null;
const KG_COLORS = { Alert: "--accent", User: "--series-2", Host: "--series-3", IP: "--series-4", Domain: "--series-5", Group: "--series-6" };
function kgLabel(n) {
  const p = n.props || {};
  if (n.label === "Alert") return `${p.step ? p.step + ". " : ""}${p.tactic || ""}\n${p.technique_id || ""} · ${p.rule_id || ""}`;
  return `${n.label}\n${p.name || p.addr || ""}`;
}
function kgPositions(data) {
  // Chains: alerts left to right in attack order (a timeline); each entity under the first step using it.
  const alerts = data.nodes.filter((n) => n.label === "Alert").sort((a, b) => (a.props.step || 0) - (b.props.step || 0));
  if (!alerts.length || !alerts.some((a) => a.props.step)) return null;
  const pos = {}, col = {}, depth = {};
  alerts.forEach((a, i) => { pos[a.id] = { x: i * 170, y: (i % 2) * 46 }; col[a.id] = i; });  // slight zig-zag keeps arrows visible
  for (const e of data.edges.filter((x) => x.type === "INVOLVES").sort((a, b) => col[a.from] - col[b.from])) {
    if (pos[e.to] || col[e.from] === undefined) continue;
    const c = col[e.from]; depth[c] = (depth[c] || 0) + 1;
    pos[e.to] = { x: c * 170 + (depth[c] % 2 ? -38 : 38), y: 110 + depth[c] * 56 };
  }
  return pos;
}
function kgDraw(box, data, onSelect) {
  const els = [];
  const pos = kgPositions(data);
  for (const n of data.nodes) els.push({ data: { id: n.id, label: kgLabel(n), kind: n.label, raw: n }, ...(pos && pos[n.id] ? { position: pos[n.id] } : {}) });
  const ids = new Set(data.nodes.map((n) => n.id));
  // One long-range edge per alert pair (labelled with how many shared entities it stands for), and none
  // where a windowed LEADS_TO already links the pair: keeps the picture readable without hiding a link.
  const pair = (e) => [e.from, e.to].sort().join("|");
  const led = new Set(data.edges.filter((e) => e.type === "LEADS_TO").map(pair));
  const rel = {};
  for (const e of data.edges.filter((x) => x.type === "RELATED")) { if (!led.has(pair(e))) (rel[pair(e)] = rel[pair(e)] || []).push(e); }
  const shown = data.edges.filter((e) => e.type !== "RELATED").concat(Object.values(rel).map((g) => ({ ...g[0], _n: g.length, _all: g })));
  shown.forEach((e, i) => { if (ids.has(e.from) && ids.has(e.to)) els.push({ data: { id: `e${i}`, source: e.from, target: e.to, type: e.type,
    label: e.type === "INVOLVES" ? "" : e.type === "LEADS_TO" ? `${Number(e.props.score || 0).toFixed(2)}` : e.type === "RELATED" ? `related${e._n > 1 ? ` ×${e._n}` : ""}` : e.type.toLowerCase(), raw: e } }); });
  if (kg) kg.destroy();
  const col = (k) => cssVar(KG_COLORS[k] || "--text-muted") || cssVar("--accent");
  kg = cytoscape({ container: box, elements: els, wheelSensitivity: 0.3, minZoom: 0.2, maxZoom: 2,
    layout: pos ? { name: "preset", fit: true, padding: 40 } : { name: "cose", animate: false, nodeRepulsion: 40000, idealEdgeLength: 160, nodeOverlap: 20, padding: 40 },
    style: [
      { selector: "node", style: { label: "data(label)", "text-wrap": "wrap", "text-max-width": 140, "font-size": 11, color: cssVar("--text-primary"), "text-valign": "bottom", "text-margin-y": 4,
        width: 22, height: 22, "background-color": (n) => col(n.data("kind")), "border-width": 1, "border-color": cssVar("--surface-1") } },
      { selector: "node[kind = 'Alert']", style: { shape: "round-rectangle", width: 30, height: 22, "text-valign": "top", "text-margin-y": -4, "font-weight": 600 } },
      { selector: "edge", style: { width: 1.5, "line-color": cssVar("--text-muted"), "target-arrow-shape": "triangle", "target-arrow-color": cssVar("--text-muted"),
        "curve-style": "bezier", label: "data(label)", "font-size": 10, color: cssVar("--text-muted"), opacity: 0.85 } },
      { selector: "edge[type = 'INVOLVES']", style: { width: 1, "target-arrow-shape": "none", label: "", opacity: 0.45 } },
      { selector: "edge[type = 'LEADS_TO']", style: { width: 3, "line-color": cssVar("--accent"), "target-arrow-color": cssVar("--accent") } },
      { selector: "edge[type = 'RELATED']", style: { "line-style": "dashed", width: 2, "line-color": cssVar("--serious"), "target-arrow-color": cssVar("--serious") } },
      { selector: ":selected", style: { "border-width": 4, "border-color": cssVar("--serious") } },
    ] });
  kg.on("tap", "node", (ev) => onSelect("node", ev.target.data("raw")));
  kg.on("tap", "edge", (ev) => onSelect("edge", ev.target.data("raw")));
}

function kgDetail(detail, kind, item, wsName) {
  clear(detail);
  const props = Object.entries(item.props || {}).filter(([k]) => !["sample_event_ids", "evidence_event_ids", "reasons_json", "score_terms"].includes(k));
  if (item._all) props.push(["shared entities", item._all.map((x) => String(x.props.via || "").split("|").pop()).join(", ")]);
  detail.append(h("div", { class: "xhead", text: kind === "node" ? `${item.label} ${item.props.name || item.props.addr || item.props.rule_id || ""}` : `${item.type} relationship` }),
    h("div", { class: "kv" }, props.map(([k, v]) => [h("div", { class: "k", text: k }), h("div", { class: "small", text: Array.isArray(v) ? v.join(", ") : String(v) })])));
  const ev = item.props.sample_event_ids || item.props.evidence_event_ids || [];
  if (ev.length) detail.append(h("div", { class: "small" }, "Evidence: ", ev.slice(0, 8).map((e) => [evLink(e, String(e), wsName), " "])));
  if (kind === "node" && item.label === "Alert") {
    const box = h("div");
    detail.append(h("button", { class: "btn sm primary", text: "Explain this alert", onclick: () => showExplanation(box, "alert", item.props.group_id) }), box);
  }
  if (kind === "node" && item.label !== "Alert") {
    const key = `${item.label.toLowerCase()}:${item.props.name || item.props.addr}`;
    detail.append(h("button", { class: "btn sm", text: "Explore neighbours", onclick: () => navigate("graph", `explore:${encodeURIComponent(key)}`) }));
  }
}

let kgTimer = null;
VIEWS.graph = async (view) => {
  let status;
  try { status = await api("/graph/status"); } catch (e) { status = { available: false, reason: e.message }; }
  if (!status.available) {
    view.append(card("Graph store unavailable", null, null, emptyState("Neo4j is not reachable", `${status.reason || ""} — start it with: make graph-up`, null)));
    return;
  }
  const param = state.param ? decodeURIComponent(state.param) : "";
  const list = h("div", { class: "kg-list" });
  const gbox = h("div", { id: "kg-graph" });
  const detail = h("div", { class: "card-b small" }, h("span", { class: "muted", text: "Choose an incident or campaign, or explore an entity. Click any node or edge for details and evidence." }));
  const search = h("input", { class: "input", placeholder: "Explore: user:alice · ip:10.0.0.5 · host:SRV-01", value: param.startsWith("explore:") ? param.slice(8) : "" });
  search.addEventListener("keydown", (e) => { if (e.key === "Enter" && search.value.trim()) navigate("graph", `explore:${encodeURIComponent(search.value.trim())}`); });
  const legend = h("div", { class: "graph-legend" },
    h("span", null, h("span", { class: "sw node" }), "Alert"), h("span", null, h("span", { class: "sw path" }), "LEADS_TO: windowed correlation (score)"),
    h("span", null, h("span", { class: "sw related" }), "RELATED: long-range shared entity"), h("span", { class: "muted", text: "Circles: users, hosts, IPs" }));
  view.append(h("div", { class: "kg-layout" },
    card("Incidents & campaigns", null, null, h("div", { class: "card-b" }, search), list),
    h("div", { class: "stack" }, card("Graph", param || "nothing selected", null, gbox, legend), card("Details & explanation", null, null, detail))));
  const select = (kind, item) => kgDetail(detail, kind, item, state.ws);
  const fill = async () => {
    const [inc, camp] = await Promise.all([api(wsq("/graph/incidents")).catch(() => ({ incidents: [] })), api(wsq("/graph/campaigns")).catch(() => ({ campaigns: [] }))]);
    clear(list).append(...[h("div", { class: "nav-section", text: `Incidents (${inc.incidents.length})` }),
      inc.incidents.map((i) => h("div", { class: `inc${param === `incident:${i.id}` ? " active" : ""}`, onclick: () => navigate("graph", `incident:${encodeURIComponent(i.id)}`) },
        h("div", { class: "small", text: (i.tactics || []).join(" → ") }), h("div", { class: "muted small", text: `${i.alerts} alerts · ${fmtTs(i.ts_first)}` }))),
      h("div", { class: "nav-section", text: `Campaigns (${camp.campaigns.length})` }),
      camp.campaigns.map((c) => h("div", { class: `inc${param === `campaign:${c.campaign_id}` ? " active" : ""}`, onclick: () => navigate("graph", `campaign:${c.campaign_id}`) },
        h("div", { class: "small", text: (c.tactics || []).join(" → ") }),
        h("div", { class: "muted small", text: `${c.alerts.length} alerts${c.long_range ? ` · long-range (gap ${(c.max_related_gap_s / 3600).toFixed(1)} h)` : ""}` })))].flat());
  };
  await fill();
  try {
    if (param.startsWith("incident:") || param.startsWith("campaign:")) {
      const [kind, ...rest] = param.split(":"); const id = rest.join(":");
      const g = await api(wsq(`/graph/chain?kind=${kind}&id=${encodeURIComponent(id)}`));
      kgDraw(gbox, g, select);
      const box = h("div"); clear(detail).append(h("button", { class: "btn sm primary", text: `Explain this ${kind}`, onclick: () => showExplanation(box, kind, id) }), box);
    } else if (param.startsWith("explain:")) {  // deep link: #/graph/explain:<alert|incident|campaign>:<id>
      const [, kind, ...rest] = param.split(":");
      await showExplanation(detail, kind, rest.join(":"));
    } else if (param.startsWith("explore:")) {
      const g = await api(wsq(`/graph/neighbors?key=${encodeURIComponent(param.slice(8))}&limit=150`));
      if (!g.found) clear(detail).append(h("div", { class: "callout warn", text: `No entity ${param.slice(8)} in this workspace's graph.` }));
      else kgDraw(gbox, g, select);
    }
  } catch (e) { clear(detail).append(h("div", { class: "callout warn", text: `${String(e.message || e)} — it may have been merged or renumbered by a newer batch; pick it again from the list.` })); }
  clearInterval(kgTimer);
  if ((state.workspaces.find((w) => w.name === state.ws) || {}).live) kgTimer = setInterval(() => { if (state.route === "graph") fill(); else clearInterval(kgTimer); }, 10000);
};

// ------------------------------------------------------------------ boot
async function switchWs(name) { state.ws = name; store.set("ft.ws", name); await loadWorkspaces(); render(); }

async function init() {
  $("brand-mark").append(svgIcon(ICONS.brand));
  for (const r of Object.keys(TITLES)) {
    const a = $(`nav-${r}`);
    a.append(svgIcon(ICONS[r]), TITLES[r]);
    if (r === "incidents") a.append(h("span", { class: "count", text: "–" }));
    a.addEventListener("click", () => navigate(r));
  }
  const theme = store.get("ft.theme");
  if (theme) document.documentElement.dataset.theme = theme;
  $("theme-btn").addEventListener("click", () => {
    const dark = document.documentElement.dataset.theme ? document.documentElement.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
    document.documentElement.dataset.theme = dark ? "light" : "dark"; store.set("ft.theme", document.documentElement.dataset.theme); render();
  });
  $("ws-select").addEventListener("change", (e) => switchWs(e.target.value));
  $("ev-close").addEventListener("click", () => $("drawer").classList.remove("open"));
  $("ev-copy").addEventListener("click", () => { navigator.clipboard?.writeText(evRaw); toast("Raw line copied"); });
  $("ev-pretty").addEventListener("click", () => { try { $("ev-raw").textContent = JSON.stringify(JSON.parse(evRaw), null, 2); } catch { toast("This line is not JSON"); } });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") $("drawer").classList.remove("open"); });
  window.addEventListener("hashchange", render);
  try { const hlt = await api("/rules"); $("nav-version").textContent = `${hlt.length} rules loaded`; } catch { /* non-fatal */ }
  await loadWorkspaces();
  try { state.job = await api("/runs/current"); if (state.job.state === "running") pollRun(); drawRunChip(); } catch { /* ignore */ }
  render();
}
init();
