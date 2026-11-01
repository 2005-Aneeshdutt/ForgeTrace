import type { ReactNode } from "react";
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

const tip = { contentStyle: { background: "#151F30", border: "1px solid #253247", borderRadius: 4, fontSize: 11, padding: "4px 8px" }, labelStyle: { color: "#94A3B8" }, itemStyle: { color: "#E5E7EB" }, cursor: { fill: "rgba(38,217,208,.06)" } };
const tick = { fill: "#64748B", fontSize: 10 };

export function HBars({ data, unit, color = "#26D9D0", colors, onClick, h }: { data: { key: string; value: number }[]; unit?: string; color?: string; colors?: (k: string) => string; onClick?: (k: string) => void; h?: number }) {
  const height = h ?? Math.max(70, data.length * 24 + 8);
  return <ResponsiveContainer width="100%" height={height}>
    <BarChart data={data} layout="vertical" margin={{ left: 0, right: 34, top: 0, bottom: 0 }}>
      <XAxis type="number" hide /><YAxis type="category" dataKey="key" width={124} tick={{ ...tick, fill: "#94A3B8" }} axisLine={false} tickLine={false} interval={0} />
      <Tooltip {...tip} formatter={(v: number) => [`${v.toLocaleString("en-US")}${unit ? ` ${unit}` : ""}`, ""]} separator="" />
      <Bar dataKey="value" barSize={9} radius={[0, 2, 2, 0]} isAnimationActive={false} onClick={(d: { key?: string }) => d.key && onClick?.(d.key)} cursor={onClick ? "pointer" : undefined} label={{ position: "right", fill: "#94A3B8", fontSize: 10, formatter: (v: number) => v.toLocaleString("en-US") }}>
        {data.map((d) => <Cell key={d.key} fill={colors?.(d.key) ?? color} />)}
      </Bar>
    </BarChart>
  </ResponsiveContainer>;
}

export function Trend({ data, color = "#26D9D0", height = 130, name = "count" }: { data: { key: string; value: number }[]; color?: string; height?: number; name?: ReactNode }) {
  const id = `g${color.slice(1)}`;
  return <ResponsiveContainer width="100%" height={height}>
    <AreaChart data={data} margin={{ left: -22, right: 8, top: 6, bottom: 0 }}>
      <defs><linearGradient id={id} x1="0" x2="0" y1="0" y2="1"><stop offset="0" stopColor={color} stopOpacity={.32} /><stop offset="1" stopColor={color} stopOpacity={0} /></linearGradient></defs>
      <CartesianGrid stroke="#1A2536" vertical={false} /><XAxis dataKey="key" tick={tick} axisLine={{ stroke: "#253247" }} tickLine={false} minTickGap={36} /><YAxis tick={tick} axisLine={false} tickLine={false} allowDecimals={false} />
      <Tooltip {...tip} /><Area type="monotone" dataKey="value" name={String(name)} stroke={color} strokeWidth={1.6} fill={`url(#${id})`} isAnimationActive={false} />
    </AreaChart>
  </ResponsiveContainer>;
}
