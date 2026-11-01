// Cytoscape wrapper. Elements are diffed against the live graph, so new data updates the picture in place
// instead of rebuilding it; layout only reruns when elements were added or removed.
import { forwardRef, useEffect, useImperativeHandle, useRef, useState } from "react";
import cytoscape from "cytoscape";
import type { Core, ElementDefinition, LayoutOptions } from "cytoscape";
import fcose from "cytoscape-fcose";
import { Lock, Maximize, Minus, Plus, Unlock } from "lucide-react";

cytoscape.use(fcose as cytoscape.Ext);

export interface CardSpec { kind: string; title: string; sub?: string; pct?: number; color: string; w?: number; h?: number }
const esc = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const cut = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

// Node face as an SVG image: strings are escaped and an image context never executes anything in it.
export function cardImage({ kind, title, sub, pct, color, w = 196, h = 70 }: CardSpec) {
  const c = Math.round(w / 8.1);
  const bar = pct != null ? `<rect x="12" y="44" width="${w - 62}" height="3" rx="1.5" fill="#253247"/><rect x="12" y="44" width="${(w - 62) * Math.min(1, pct)}" height="3" rx="1.5" fill="${color}"/><text x="${w - 12}" y="48" text-anchor="end" font-size="9.5" fill="#94A3B8" font-family="Menlo,monospace">${pct >= 1 ? 100 : Math.min(99, Math.round(pct * 100))}%</text>` : "";
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${w * 2}" height="${h * 2}" viewBox="0 0 ${w} ${h}"><rect x=".75" y=".75" width="${w - 1.5}" height="${h - 1.5}" rx="5" fill="#0D1422" stroke="${color}" stroke-width="1.5"/>`
    + `<circle cx="16" cy="14.5" r="3" fill="${color}"/><text x="24" y="18" font-size="9" letter-spacing="1" fill="#94A3B8" font-family="Menlo,monospace">${esc(cut(kind.toUpperCase(), c))}</text>`
    + `<text x="12" y="35" font-size="12.5" font-weight="600" fill="#E5E7EB" font-family="Menlo,monospace">${esc(cut(title, Math.floor((w - 20) / 7.8)))}</text>${bar}`
    + (sub ? `<text x="12" y="${h - 8}" font-size="9.5" fill="#64748B" font-family="Helvetica,Arial,sans-serif">${esc(cut(sub, Math.floor((w - 20) / 4.9)))}</text>` : "") + `</svg>`;
  return `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;
}

const STYLE: cytoscape.StylesheetCSS[] | any = [
  { selector: "node", style: { width: "data(w)", height: "data(h)", shape: "round-rectangle", "background-opacity": 0, "background-image": "data(img)", "background-fit": "contain", "background-clip": "none", "border-width": 0, "underlay-color": "data(color)", "underlay-opacity": 0.1, "underlay-padding": 5, "underlay-shape": "round-rectangle", "transition-property": "opacity, underlay-opacity", "transition-duration": 0.18 } },
  { selector: "edge", style: { width: 1.5, "line-color": "data(color)", "target-arrow-color": "data(color)", "target-arrow-shape": "triangle", "arrow-scale": 0.8, "curve-style": "bezier", opacity: 0.8, label: "data(label)", "font-size": 8.5, "font-family": "Menlo, monospace", color: "#94A3B8", "text-background-color": "#070B14", "text-background-opacity": 0.85, "text-background-padding": 2, "text-rotation": "autorotate", "min-zoomed-font-size": 7 } },
  { selector: "edge[style = 'dashed']", style: { "line-style": "dashed", "line-dash-pattern": [6, 4] } },
  { selector: "edge[style = 'dotted']", style: { "line-style": "dotted" } },
  { selector: "edge[?hot]", style: { width: 2.6, opacity: 1, "z-index": 5 } },
  { selector: ":selected", style: { "underlay-color": "#26D9D0", "underlay-opacity": 0.42, "underlay-padding": 7 } },
  { selector: "edge:selected", style: { "line-color": "#26D9D0", "target-arrow-color": "#26D9D0", width: 3, opacity: 1 } },
  { selector: ".dim", style: { opacity: 0.14 } },
  { selector: ".lit", style: { "underlay-opacity": 0.35 } },
  { selector: "edge.lit", style: { "line-color": "#26D9D0", "target-arrow-color": "#26D9D0", width: 3, opacity: 1 } },
];

export interface CyHandle { cy: () => Core | null; png: () => string | null; highlight: (ids: string[] | null) => void }

export const CyGraph = forwardRef<CyHandle, { elements: ElementDefinition[]; layout?: "fcose" | "preset"; onSelect?: (id: string | null, kind: "node" | "edge" | null) => void; height?: string; selected?: string | null; hideControls?: boolean }>(
  function CyGraph({ elements, layout = "fcose", onSelect, selected, hideControls }, ref) {
    const box = useRef<HTMLDivElement>(null);
    const cyRef = useRef<Core | null>(null);
    const cb = useRef(onSelect);
    cb.current = onSelect;
    const [locked, setLocked] = useState(false);

    useEffect(() => {
      const cy = cytoscape({ container: box.current, style: STYLE, minZoom: 0.15, maxZoom: 3, wheelSensitivity: 0.25, boxSelectionEnabled: false, selectionType: "single" });
      cyRef.current = cy;
      cy.on("tap", "node", (e) => cb.current?.(e.target.id(), "node"));
      cy.on("tap", "edge", (e) => cb.current?.(e.target.id(), "edge"));
      cy.on("tap", (e) => { if (e.target === cy) cb.current?.(null, null); });
      const ro = new ResizeObserver(() => { cy.resize(); });
      ro.observe(box.current!);
      return () => { ro.disconnect(); cy.destroy(); cyRef.current = null; };
    }, []);

    useEffect(() => {
      const cy = cyRef.current;
      if (!cy) return;
      const next = new Set(elements.map((e) => e.data.id!));
      let changed = false;
      cy.batch(() => {
        cy.elements().forEach((el) => { if (!next.has(el.id())) { el.remove(); changed = true; } });
        const add: ElementDefinition[] = [];
        for (const e of elements) {
          const cur = cy.getElementById(e.data.id!);
          if (cur.nonempty()) { cur.data(e.data); if (e.position && layout === "preset") cur.position(e.position); } else { add.push(e); changed = true; }
        }
        cy.add([...add.filter((e) => e.group === "nodes" || !e.data.source), ...add.filter((e) => e.group === "edges" || e.data.source)]);
      });
      if (changed && cy.nodes().length) {
        const opts: LayoutOptions | any = layout === "preset" ? { name: "preset", fit: true, padding: 30 } : { name: "fcose", quality: "proof", randomize: true, animate: false, nodeRepulsion: 18000, idealEdgeLength: 150, edgeElasticity: 0.3, nodeSeparation: 130, nodeDimensionsIncludeLabels: true, padding: 34, tile: true };
        cy.layout(opts).run();
      }
    }, [elements, layout]);

    useEffect(() => {
      const cy = cyRef.current;
      if (!cy) return;
      cy.elements().unselect();
      if (selected) cy.getElementById(selected).select();
    }, [selected, elements]);

    useImperativeHandle(ref, () => ({
      cy: () => cyRef.current,
      png: () => cyRef.current?.png({ full: true, scale: 1.5, bg: "#070B14" }) ?? null,
      highlight: (ids) => {
        const cy = cyRef.current;
        if (!cy) return;
        cy.elements().removeClass("dim lit");
        if (ids) { const on = cy.collection(); ids.forEach((i) => on.merge(cy.getElementById(i))); cy.elements().not(on).addClass("dim"); on.addClass("lit"); }
      },
    }), []);

    const zoom = (f: number) => { const cy = cyRef.current!; cy.zoom({ level: cy.zoom() * f, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } }); };
    const toggleLock = () => { const cy = cyRef.current!; const l = !locked; setLocked(l); cy.autoungrabify(l); cy.panningEnabled(!l); cy.userZoomingEnabled(!l); };
    return (
      <div className="relative w-full h-full grid-bg bg-[#080C16] overflow-hidden">
        <div ref={box} className="absolute inset-0" />
        {!hideControls && (
          <div className="absolute left-3 bottom-3 flex flex-col rounded border border-line bg-panel/90 no-print">
            {([["Zoom in", <Plus size={13} />, () => zoom(1.25)], ["Zoom out", <Minus size={13} />, () => zoom(0.8)], ["Fit to screen", <Maximize size={12} />, () => cyRef.current?.fit(undefined, 34)], [locked ? "Unlock graph" : "Lock graph", locked ? <Lock size={12} /> : <Unlock size={12} />, toggleLock]] as const).map(([t, ic, f]) => (
              <button key={t} title={t} aria-label={t} onClick={f} className="w-7 h-7 grid place-items-center text-sub hover:text-cyan border-b last:border-b-0 border-line2">{ic}</button>))}
          </div>
        )}
      </div>
    );
  });
