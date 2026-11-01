import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { CheckCircle2, Copy, XCircle } from "lucide-react";
import { api, withWs } from "../lib/api";
import type { RawEvidence } from "../lib/api";
import { useWs } from "../lib/hooks";
import { useStore } from "../lib/store";
import { Callout, Drawer, ErrorBox, KV, Loading, Pill } from "./ui";

// Evidence is the source line itself: the backend re-reads it at its byte offset and re-hashes it.
export function EvidenceDrawer() {
  const id = useStore((s) => s.evidence);
  const close = useStore((s) => s.openEvidence);
  const current = useWs();
  const ws = useStore((s) => s.evidenceWs) ?? current;
  const q = useQuery({ queryKey: ["raw", ws, id], enabled: id != null && !!ws, queryFn: () => api<RawEvidence>(withWs(`/events/${id}/raw`, ws!)) });
  const [pretty, setPretty] = useState(true);
  const r = q.data;
  const text = useMemo(() => {
    if (!r?.raw) return "";
    if (!pretty) return r.raw;
    try { return JSON.stringify(JSON.parse(r.raw), null, 2); } catch { return r.raw; }
  }, [r, pretty]);
  if (id == null) return null;
  return (
    <Drawer title="Raw evidence" onClose={() => close(null)} badge={r && (r.verified ? <Pill tone="ok"><CheckCircle2 size={10} />SHA-256 verified</Pill> : <Pill tone="crit"><XCircle size={10} />Not verified</Pill>)}>
      {q.isLoading && <Loading />}{q.error && <ErrorBox error={q.error} />}
      {r && <>
        <KV rows={[["Display ID", <span className="mono">{r.display_id}</span>], ["Event ID", <span className="mono">{r.event_id}</span>], ["File", r.file], ["Line", r.line_no], ["Byte offset", r.byte_offset], ["Source event", <span className="mono text-2xs">{r.source_event_id}</span>], ["Stored digest", <span className="mono text-2xs break-all">{r.stored_digest}</span>], ["Recomputed", <span className="mono text-2xs break-all">{r.digest}</span>]]} />
        {r.reason && <Callout>{r.reason}</Callout>}
        <div className="flex gap-2"><button className="btn" onClick={() => setPretty(!pretty)}>{pretty ? "Raw line" : "Pretty"}</button>
          <button className="btn" onClick={() => r.raw && navigator.clipboard?.writeText(r.raw)}><Copy size={12} />Copy line</button></div>
        <pre className="raw rounded border border-line bg-bg p-2.5 text-[#A7F3D0]">{text}</pre>
        <p className="text-2xs text-mute">The line is re-read from the source file at its byte offset and its SHA-256 is compared with the digest stored at ingest. A mismatch means the source changed.</p>
      </>}
    </Drawer>
  );
}
