export const fmtN = (n: number | null | undefined) => (n == null ? "—" : Number(n).toLocaleString("en-US"));
export const fmtP = (p: number | null | undefined) => (p == null ? "—" : p > 0.999 ? ">0.999" : Number(p).toFixed(3));
export const fmtPct = (p: number | null | undefined) => (p == null ? "—" : `${(p * 100).toFixed(1)}%`);

export function fmtBytes(b: number | null | undefined) {
  if (b == null) return "—";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0, v = b;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${u[i]}`;
}

// Log timestamps stay in UTC, exactly as stored.
const norm = (t: string) => t.replace("T", " ").replace("Z", "");
export const fmtTs = (t: string | null | undefined) => (t ? norm(t).slice(0, 19) : "—");
export const fmtTime = (t: string | null | undefined) => (t ? norm(t).slice(11, 19) : "—");
export const fmtDay = (t: string | null | undefined) => (t ? norm(t).slice(0, 10) : "—");
export const tsMs = (t: string) => Date.parse(`${norm(t).replace(" ", "T")}Z`);

export function fmtDur(s: number | null | undefined) {
  if (s == null) return "—";
  if (s < 1) return `${Math.round(s * 1000)} ms`;
  if (s < 60) return `${s.toFixed(1)} s`;
  const m = Math.floor(s / 60);
  return `${m}m ${Math.round(s - m * 60)}s`;
}

export const sevName = (n: number) => (({ 4: "critical", 3: "high", 2: "medium", 1: "low" } as Record<number, string>)[n] ?? `level ${n}`);
export const pad = (id: number | string) => `INC-${String(id).padStart(3, "0")}`;
export const isModel = (rule: string) => rule.startsWith("ML-");
export const short = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);
export const entName = (k: string) => k.slice(k.indexOf(":") + 1);
export const entKind = (k: string) => k.slice(0, k.indexOf(":"));

export function uniq<T>(a: T[]) { return [...new Set(a)]; }
export function countBy<T>(a: T[], f: (x: T) => string) {
  const m = new Map<string, number>();
  for (const x of a) m.set(f(x), (m.get(f(x)) ?? 0) + 1);
  return [...m.entries()].map(([key, count]) => ({ key, count }));
}

export function download(name: string, text: string, type: string) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type }));
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

// Which backend model a detector id belongs to. Rule/model ids come from the API, only the prefixes are matched.
export function detectorLabel(rule: string) {
  if (rule.startsWith("ML-UEBA")) return "Isolation Forest (behaviour)";
  if (rule.startsWith("ML-LINK")) return "Adamic-Adar (graph link)";
  if (rule.startsWith("ML-")) return "ML model";
  return "YAML rule";
}
