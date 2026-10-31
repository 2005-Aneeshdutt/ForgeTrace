# GR-2 — Long-range correlation in the graph (campaigns)

**Why (mentor's rationale).** Live data arrives continuously and in volume; some attacks are spread over days. The windowed correlator (dossier §12) links alert groups at most 6 h apart, which keeps every edge explainable but cannot connect a Monday scan to a Thursday exfiltration. In a graph, "alerts that share something uncommon, at any distance in time" is a traversal.

**Method.** After each graph load (`forgetrace/graph/campaigns.py`):
1. For every User / IP / Domain node involved in at least two and at most `max_entity_alerts` (25) alerts, add `(:Alert)-[:RELATED {via, entity_alerts, gap_s}]->(:Alert)` in time order. Entities shared by more alerts (the firewall's management address, a public resolver) are too common to mean anything, the same reasoning as the degree penalty F in §12.
2. Connected components over `LEADS_TO ∪ RELATED`; a component with ≥ 2 ATT&CK tactics becomes `(:Campaign {tactics, techniques, ts_first, ts_last, max_related_gap_s, long_range})-[:INCLUDES {order}]->(:Alert)`. `long_range` = some RELATED link spans more than the 6 h correlation window.
3. Incidents are unchanged: campaigns are an additional long-range view (API `/graph/campaigns`), each link carrying the shared entity and the gap.

**Acceptance.** Dev sample: both planted attacks appear as campaigns. Recomputing is idempotent. Precision of campaigns is measured on firex-30G (attack = campaign whose alerts cover its events).
