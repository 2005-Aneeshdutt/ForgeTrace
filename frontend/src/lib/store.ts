// Shared investigation context: survives navigation, so every page works on the same workspace and incident.
import { create } from "zustand";

export type Route = "command" | "live" | "ingest" | "detections" | "incidents" | "graph" | "attack" | "killchain" | "reach"
  | "decision" | "simulate" | "reports" | "rules" | "health" | "walkthrough";

export interface DetFilter { model?: string; severity?: string; technique?: string; entity?: string; day?: string; text?: string; tactic?: string }
export interface RunLine { at: number; tag: string; text: string; stage?: string; tone?: "ok" | "crit" }
export interface Notice { id: number; at: number; text: string; level: "info" | "ok" | "crit"; route?: Route; param?: string }

const read = (k: string) => { try { return localStorage.getItem(k); } catch { return null; } };
const write = (k: string, v: string) => { try { localStorage.setItem(k, v); } catch { /* storage unavailable */ } };

interface Store {
  ws: string | null; incident: number | null; route: Route; param: string | null;
  detFilter: DetFilter; evidence: number | null; evidenceWs: string | null; notices: Notice[]; unread: number; simTargets: string[]; runLog: RunLine[];
  log: (l: Omit<RunLine, "at">) => void;
  setWs: (w: string) => void; setIncident: (i: number | null) => void; setRoute: (r: Route, p: string | null) => void;
  go: (r: Route, p?: string | number | null) => void; openEvidence: (id: number | null, ws?: string) => void;
  setDetFilter: (f: DetFilter) => void; notify: (n: Omit<Notice, "id" | "at">) => void; markRead: () => void; setSimTargets: (t: string[]) => void;
}

export const useStore = create<Store>((set) => ({
  ws: read("ft.ws"), incident: null, route: "command", param: null, detFilter: {}, evidence: null, evidenceWs: null, notices: [], unread: 0, simTargets: [], runLog: [],
  log: (l) => set((s) => ({ runLog: [...s.runLog.slice(-299), { ...l, at: Date.now() }] })),
  setWs: (ws) => { write("ft.ws", ws); set({ ws, incident: null, detFilter: {}, simTargets: [] }); },
  setIncident: (incident) => set({ incident }),
  setRoute: (route, param) => set({ route, param }),
  go: (r, p) => { location.hash = `#/${r}${p != null ? `/${p}` : ""}`; },
  openEvidence: (evidence, ws) => set({ evidence, evidenceWs: ws ?? null }),
  setDetFilter: (detFilter) => set({ detFilter }),
  notify: (n) => set((s) => ({ notices: [{ ...n, id: Date.now() + Math.random(), at: Date.now() }, ...s.notices].slice(0, 40), unread: s.unread + 1 })),
  markRead: () => set({ unread: 0 }),
  setSimTargets: (simTargets) => set({ simTargets }),
}));

export function syncRoute() {
  const [, r, p] = (location.hash || "#/command").split("/");
  const routes: Route[] = ["command", "live", "ingest", "detections", "incidents", "graph", "attack", "killchain", "reach", "decision", "simulate", "reports", "rules", "health", "walkthrough"];
  useStore.getState().setRoute(routes.includes(r as Route) ? (r as Route) : "command", p ? decodeURIComponent(p) : null);
}
