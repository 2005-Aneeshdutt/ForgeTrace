# EV-2 — D0 scenario suite (Must, 0.5 d, owner A)

**Responsibility.** Twenty seeded variants of the firex-style dev scenario so rules and models are tuned on seeds 1–10 and tested once on 11–20.

**Inputs.** `tools/gen_scenarios.py` event shapes (unchanged; the seed-7 dev sample stays byte-identical).

**Outputs.** `tools/gen_suite.py` → `data/d0/seed_NN/{events.log, ground_truth.json}` (gitignored, regenerable) and `data/d0/suite.json` (committed: sha256, lines, attacks per seed).

**What varies per seed.** Benign mix weights (×0.6–1.4 per event kind), 15k–40k benign events, 2–3 days, CEF ratio 0–0.3. A1 victim, target server, 25–80 failures, failure spacing, gap scale ×0.5–2, exfil 100–400 MB, lateral-before-persistence in ~30%. A2 victim, Office app, 8–20 beacons every 120–600 s, RDP target, beaconing-before-Run-key in ~30%. A3 (~50%): external login without brute force → discovery → 7-Zip archive → cloud upload (techniques with no Phase 1 rule). Decoys: D1 admin onboarding (always), D2 typo burst + success at the user's desk (~70%), D3 admin RDP + encoded PowerShell deployment (~60%).

**Failure modes.** Ground-truth order must follow time when variants reorder steps (sorted by each step's first event). Decoys D2/D3 are built to cross rule thresholds; they are expected to cost precision at E0, which is the point.

**Tests.** `tests/test_suite.py`: regenerating a seed gives byte-identical events and ground truth; every label's event_id offset matches its line; seeds 1–10 are tuning and 11–20 test; parameters actually vary.

**Acceptance criteria (from PHASE2.md / plan).** "D0 suite: 20 seeds, variants, decoys; byte-identical regeneration test." Plan: "Seeds 1–10 tuning, 11–20 test; byte-identical regeneration."
