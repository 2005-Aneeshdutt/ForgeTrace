# Dossier digest (sections used by Phase 1)

- §11 Ingestion: stream lines, keep byte offset, `event_id = file_id<<48 | byte_offset`, Parquet out, `parse_errors` with offset + 200-byte preview, evidence = seek + re-hash + `verified`.
- §12 Correlation: detect → aggregate (gap ≤ 15 min, `raw_alert_count`) → entity index → candidate edges (entity reason required, never time alone) → score `s = clip(0.45L + 0.20T + 0.20P + 0.10R − 0.25F)` → keep `s ≥ 0.45 and L > 0`, top-K=3 in/out → union-find → abstain unless ≥ 2 tactics → top-k temporal path DP `J = Σ log s_e + λ Σ n(v)`, `n(v) = severity/4 × conf`.
  - L = noisy-OR of reason weights: same_session .35, same_proc_tree .30, pivot_host .30, pivot_ip .25, same_hash_or_domain .20, same_user .20, same_host .15, observed_connector .25.
  - T = exp(−Δt/τ), τ = 30 min (2 h for same_user). P: forward 1.0, same 0.7, one back 0.4, further back 0.1. R = .5·maxsev/4 + .5·target criticality. F = min(1, log10(1+deg)/log10(501)).
  - Worked example s = 0.543.
- §13 Schemas: envelope, detections, alert_groups, edges (kind = inferred), incidents, paths, API contract; payload splits `observed` vs `inferred`.
- §14 Reachability: compromised set C from incident evidence (1.0 / suspected 0.5); context graph ADMIN_TO (observed 1.0 / fixture 0.7), MEMBER_OF + GROUP_ADMIN_TO (0.7), CREDENTIAL_EXPOSURE (0.5); max-product search H = 4, report reach ≥ 0.3, critical = criticality ≥ 0.8; containment = graph edit + re-run; fixed disclaimer text.
- WP-17 risk: `100 × (0.35·maxsev/4 + 0.25·max criticality + 0.20·deepest tactic ordinal/max + 0.20·critical reachable/total critical)`.
