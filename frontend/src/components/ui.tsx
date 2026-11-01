import { Component } from "react";
import type { ReactNode } from "react";
import { AlertTriangle, CircleSlash, Inbox, Loader2, X } from "lucide-react";
import { useStore } from "../lib/store";
import type { Route } from "../lib/store";
import { isModel, pad, sevName } from "../lib/format";

export function Panel({ title, actions, children, className = "", body = "" }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; body?: string }) {
  return (
    <section className={`panel flex flex-col min-h-0 min-w-0 ${className}`}>
      {title != null && <header className="panel-h"><span className="truncate">{title}</span><span className="flex-1" />{actions}</header>}
      <div className={`flex-1 min-h-0 ${body}`}>{children}</div>
    </section>
  );
}

export function Kpi({ label, value, sub, tone, onClick }: { label: string; value: ReactNode; sub?: ReactNode; tone?: "crit" | "warn" | "ok" | "cyan"; onClick?: () => void }) {
  const c = tone === "crit" ? "text-crit" : tone === "warn" ? "text-warn" : tone === "ok" ? "text-ok" : tone === "cyan" ? "text-cyan" : "text-ink";
  return (
    <div onClick={onClick} className={`panel px-3 py-2.5 min-w-0 ${onClick ? "cursor-pointer hover:border-cyan/40 transition-colors" : ""}`}>
      <div className="label truncate" title={label}>{label}</div>
      <div className={`mono text-[21px] leading-7 font-semibold tracking-tight truncate ${c}`}>{value}</div>
      {sub != null && <div className="text-2xs text-mute truncate" title={typeof sub === "string" ? sub : undefined}>{sub}</div>}
    </div>
  );
}

const SEV: Record<string, string> = { critical: "text-crit border-crit/50 bg-crit/10", high: "text-[#F87171] border-crit/35 bg-crit/[.07]", medium: "text-warn border-warn/40 bg-warn/10", low: "text-sub border-line bg-raised" };
export function Sev({ s }: { s: string | number }) {
  const name = typeof s === "number" ? sevName(s) : s;
  return <span className={`inline-flex items-center gap-1 h-[18px] px-1.5 rounded-sm border text-2xs font-semibold capitalize whitespace-nowrap ${SEV[name] ?? SEV.low}`}><i className="w-1.5 h-1.5 rounded-full bg-current" />{name}</span>;
}

export function Pill({ children, tone = "mute", title }: { children: ReactNode; tone?: "mute" | "cyan" | "crit" | "warn" | "ok"; title?: string }) {
  const c = { mute: "text-sub border-line bg-raised", cyan: "text-cyan border-cyan/40 bg-cyan/10", crit: "text-crit border-crit/40 bg-crit/10", warn: "text-warn border-warn/40 bg-warn/10", ok: "text-ok border-ok/40 bg-ok/10" }[tone];
  return <span title={title} className={`inline-flex items-center gap-1 h-[18px] px-1.5 rounded-sm border text-2xs font-medium whitespace-nowrap ${c}`}>{children}</span>;
}

export const Detector = ({ rule }: { rule: string }) => <Pill tone={isModel(rule) ? "cyan" : "mute"} title={rule}>{isModel(rule) ? "ML" : "Rule"}</Pill>;
export const Basis = ({ kind }: { kind: string }) => <Pill tone={kind === "observed" ? "ok" : kind === "configured" ? "cyan" : "warn"}>{kind}</Pill>;

export function Tech({ id }: { id: string }) {
  const go = useStore((s) => s.go);
  return <span className="link text-2xs" onClick={(e) => { e.stopPropagation(); go("attack", id); }}>{id}</span>;
}
export function IncLink({ id }: { id: number }) {
  const go = useStore((s) => s.go);
  return <span className="link text-xs" onClick={(e) => { e.stopPropagation(); go("incidents", id); }}>{pad(id)}</span>;
}
export function EvLink({ id, label, ws }: { id: number; label?: string; ws?: string }) {
  const open = useStore((s) => s.openEvidence);
  return <button className="link text-2xs" onClick={(e) => { e.stopPropagation(); open(id, ws); }} title="Open raw evidence">{label ?? id}</button>;
}

export function Bar({ value, tone = "#26D9D0" }: { value: number; tone?: string }) {
  return <div className="bar"><i style={{ width: `${Math.max(0, Math.min(100, value * 100))}%`, background: tone }} /></div>;
}
export const riskTone = (r: number) => (r >= 80 ? "#EF4444" : r >= 50 ? "#F59E0B" : "#26D9D0");

export function Loading({ label = "Loading" }: { label?: string }) {
  return <div className="flex items-center justify-center gap-2 h-full min-h-24 text-mute text-xs"><Loader2 size={14} className="animate-spin text-cyan" />{label}…</div>;
}
export function ErrorBox({ error }: { error: unknown }) {
  return <div className="m-3 flex items-start gap-2 rounded border border-crit/40 bg-crit/10 px-3 py-2 text-xs text-[#FCA5A5]"><AlertTriangle size={14} className="shrink-0 mt-0.5" /><span className="break-words min-w-0">{String((error as Error)?.message ?? error)}</span></div>;
}
export function Empty({ title, text, action }: { title: string; text?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center text-center gap-1.5 px-6 py-8 h-full min-h-28">
      <Inbox size={20} className="text-mute" /><div className="text-sm font-medium text-ink">{title}</div>
      {text && <div className="text-xs text-mute max-w-md">{text}</div>}{action && <div className="mt-2">{action}</div>}
    </div>
  );
}
// Honest marker for anything the backend does not implement.
export function NotAvailable({ title, why, cmd }: { title: string; why: string; cmd?: string }) {
  return (
    <div className="rounded border border-dashed border-line bg-bg2/60 px-3 py-2.5">
      <div className="flex items-center gap-1.5 text-xs font-medium text-sub"><CircleSlash size={12} className="text-mute shrink-0" />{title}<Pill>Not implemented</Pill></div>
      <div className="text-2xs text-mute mt-1">{why}</div>{cmd && <code className="mono text-2xs text-cyan block mt-1">{cmd}</code>}
    </div>
  );
}
export function Callout({ tone = "warn", children }: { tone?: "warn" | "cyan" | "crit"; children: ReactNode }) {
  const c = { warn: "border-warn/30 bg-warn/[.07] text-[#FCD34D]", cyan: "border-cyan/30 bg-cyan/[.06] text-[#99F6E4]", crit: "border-crit/40 bg-crit/10 text-[#FCA5A5]" }[tone];
  return <div className={`rounded border px-3 py-2 text-xs ${c}`}>{children}</div>;
}
export function KV({ rows }: { rows: [ReactNode, ReactNode][] }) {
  return <dl className="grid grid-cols-[minmax(84px,auto)_1fr] gap-x-3 gap-y-1 text-xs">{rows.map(([k, v], i) => [<dt key={`k${i}`} className="text-mute">{k}</dt>, <dd key={`v${i}`} className="text-ink min-w-0 break-words">{v ?? "—"}</dd>])}</dl>;
}

export function Page({ title, sub, actions, children }: { title: string; sub?: ReactNode; actions?: ReactNode; children: ReactNode }) {
  return (
    <div className="fade-in flex flex-col gap-3 p-4 min-h-full">
      <div className="flex items-end gap-3 flex-wrap">
        <div className="min-w-0"><h1 className="text-[17px] leading-6 font-semibold tracking-tight">{title}</h1>{sub && <div className="text-xs text-mute truncate">{sub}</div>}</div>
        <span className="flex-1" />{actions}
      </div>
      {children}
    </div>
  );
}

export function Drawer({ title, onClose, children, width = 560, badge }: { title: ReactNode; onClose: () => void; children: ReactNode; width?: number; badge?: ReactNode }) {
  return (
    <aside style={{ width, maxWidth: "100vw" }} className="slide-in no-print fixed right-0 top-0 bottom-0 z-40 bg-bg2 border-l border-line flex flex-col shadow-[-20px_0_50px_rgba(0,0,0,.55)]">
      <header className="flex items-center gap-2 h-11 px-3 border-b border-line shrink-0">
        <h3 className="text-sm font-semibold truncate">{title}</h3>{badge}<span className="flex-1" />
        <button className="btn btn-ghost !px-1.5" onClick={onClose} aria-label="Close"><X size={14} /></button>
      </header>
      <div className="flex-1 overflow-auto p-3 space-y-3">{children}</div>
    </aside>
  );
}

export function Select({ value, onChange, options, label }: { value: string; onChange: (v: string) => void; options: (string | [string, string])[]; label: string }) {
  return (
    <select aria-label={label} className="field max-w-44" value={value} onChange={(e) => onChange(e.target.value)}>
      <option value="">{label}</option>
      {options.map((o) => { const [v, t] = Array.isArray(o) ? o : [o, o]; return <option key={v} value={v}>{t}</option>; })}
    </select>
  );
}

export function GoBtn({ to, param, children, primary }: { to: Route; param?: string | number | null; children: ReactNode; primary?: boolean }) {
  const go = useStore((s) => s.go);
  return <button className={`btn ${primary ? "btn-primary" : ""}`} onClick={() => go(to, param)}>{children}</button>;
}
export function Section({ title, children }: { title: ReactNode; children: ReactNode }) {
  return <div><div className="label mb-1.5">{title}</div>{children}</div>;
}

// One malformed record must cost one page, never the whole console.
export class PageBoundary extends Component<{ children: ReactNode; name: string }, { error: unknown }> {
  state = { error: null as unknown };
  static getDerivedStateFromError(error: unknown) { return { error }; }
  componentDidUpdate(prev: { name: string }) { if (prev.name !== this.props.name && this.state.error) this.setState({ error: null }); }
  render() {
    if (!this.state.error) return this.props.children;
    return <div className="p-4 space-y-2"><div className="text-sm font-medium">This page could not render this data</div><ErrorBox error={this.state.error} /><button className="btn" onClick={() => this.setState({ error: null })}>Try again</button></div>;
  }
}
