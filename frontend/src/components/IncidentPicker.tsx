import { pad } from "../lib/format";
import { useIncidents } from "../lib/hooks";
import { useStore } from "../lib/store";

export function IncidentPicker() {
  const list = useIncidents().data ?? []; const { incident, setIncident } = useStore();
  return <select aria-label="Incident" className="field" value={incident ?? ""} onChange={(e) => setIncident(Number(e.target.value))}>
    {list.map((i) => <option key={i.incident_id} value={i.incident_id}>{pad(i.incident_id)} · risk {i.risk_score.toFixed(1)} · {i.severity}</option>)}
  </select>;
}
