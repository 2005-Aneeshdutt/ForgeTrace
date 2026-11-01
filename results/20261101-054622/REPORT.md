# FVS evaluation 20261101-054622

Datasets: a1, s1, t1, v110_103, v110_3, v120_103, v120_3 (from `Validation dataset/scratch_ref`).
Pipeline unchanged and untuned; it read only the .log files.

## Pooled — All steps

- Attacks detected: 24/24 (1.000); in an incident: 17/24 (0.708)
- By tier: easy: 6/6 detected, 5/6 in incident; hard: 9/9 detected, 4/9 in incident; medium: 9/9 detected, 8/9 in incident
- Step recall: 0.709 of 134 steps
- Line level (alerts): P 0.075 R 0.706 F1 0.136; (incidents): P 0.082 R 0.559 F1 0.143
- Decoys flagged by an alert: 93/298; inside an incident: 19/298
- Incidents: 32, false-alarm incidents: 9

## Pooled — Excluding steps with unverified logids

- Attacks detected: 24/24 (1.000); in an incident: 16/24 (0.667)
- By tier: easy: 6/6 detected, 4/6 in incident; hard: 9/9 detected, 4/9 in incident; medium: 9/9 detected, 8/9 in incident
- Step recall: 0.688 of 112 steps
- Line level (alerts): P 0.075 R 0.714 F1 0.135; (incidents): P 0.082 R 0.566 F1 0.143
- Decoys flagged by an alert: 93/298; inside an incident: 19/298
- Incidents: 32, false-alarm incidents: 13

## Per dataset — all_steps

| dataset | split | profile | attack_detection_rate | attack_in_incident_rate | step_recall | technique_parent_acc | technique_exact_acc | line_alert_p | line_alert_r | line_inc_p | line_inc_r | decoy_fp_alert_rate | decoy_fp_incident_rate | incidents | false_alarm_incidents | latency_min_median | runtime_s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| a1 | test | adversarial | 1.000 | 1.000 | 0.400 | 0.750 | 0.750 | 0.228 | 0.471 | 0.586 | 0.467 | 0.375 | 0.083 | 5 | 2 | 2846.900 | 10.857 |
| s1 | test | stress | 1.000 | 0.500 | 0.710 | 0.773 | 0.727 | 0.027 | 0.729 | 0.014 | 0.345 | 0.237 | 0.113 | 6 | 3 | 0.000 | 12.575 |
| t1 | tune | validation | 1.000 | 1.000 | 0.929 | 0.923 | 0.923 | 0.150 | 0.813 | 0.395 | 0.795 | 0.394 | 0.030 | 6 | 1 | 0.000 | 5.687 |
| v110_103 | test | validation | 1.000 | 0.667 | 0.714 | 0.667 | 0.533 | 0.190 | 0.756 | 0.962 | 0.595 | 0.393 | 0.000 | 4 | 0 | 0.000 | 11.947 |
| v110_3 | tune | validation | 1.000 | 0.667 | 0.867 | 0.923 | 0.923 | 0.051 | 0.686 | 0.121 | 0.372 | 0.394 | 0.030 | 3 | 1 | 0.000 | 11.392 |
| v120_103 | test | validation | 1.000 | 0.333 | 0.579 | 0.818 | 0.727 | 0.228 | 0.766 | 0.938 | 0.679 | 0.250 | 0.050 | 3 | 1 | 448.100 | 12.220 |
| v120_3 | tune | validation | 1.000 | 1.000 | 0.929 | 0.923 | 0.923 | 0.281 | 0.828 | 0.543 | 0.820 | 0.250 | 0.056 | 5 | 1 | 0.000 | 13.989 |

## Per dataset — excl_unverified

| dataset | split | profile | attack_detection_rate | attack_in_incident_rate | step_recall | technique_parent_acc | technique_exact_acc | line_alert_p | line_alert_r | line_inc_p | line_inc_r | decoy_fp_alert_rate | decoy_fp_incident_rate | incidents | false_alarm_incidents | latency_min_median | runtime_s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| a1 | test | adversarial | 1.000 | 0.667 | 0.375 | 0.667 | 0.667 | 0.227 | 0.473 | 0.583 | 0.469 | 0.375 | 0.083 | 5 | 3 | 2900.300 | 10.857 |
| s1 | test | stress | 1.000 | 0.500 | 0.741 | 0.750 | 0.700 | 0.027 | 0.762 | 0.014 | 0.362 | 0.237 | 0.113 | 6 | 3 | 0.000 | 12.575 |
| t1 | tune | validation | 1.000 | 1.000 | 0.917 | 0.909 | 0.909 | 0.148 | 0.811 | 0.394 | 0.797 | 0.394 | 0.030 | 6 | 2 | 0.000 | 5.687 |
| v110_103 | test | validation | 1.000 | 0.667 | 0.647 | 0.545 | 0.364 | 0.189 | 0.755 | 0.953 | 0.593 | 0.393 | 0.000 | 4 | 1 | 0.000 | 11.947 |
| v110_3 | tune | validation | 1.000 | 0.667 | 0.846 | 0.909 | 0.909 | 0.050 | 0.681 | 0.121 | 0.378 | 0.394 | 0.030 | 3 | 1 | 0.000 | 11.392 |
| v120_103 | test | validation | 1.000 | 0.333 | 0.467 | 0.714 | 0.571 | 0.226 | 0.764 | 0.934 | 0.680 | 0.250 | 0.050 | 3 | 2 | 448.100 | 12.220 |
| v120_3 | tune | validation | 1.000 | 1.000 | 0.917 | 0.909 | 0.909 | 0.280 | 0.828 | 0.543 | 0.822 | 0.250 | 0.056 | 5 | 1 | 0.000 | 13.989 |

Definitions: see the docstring of `tools/eval_fvs.py`. Per-attack and per-step rows: `<dataset>.attacks.csv`, `<dataset>.steps.csv`; full metrics incl. per-technique recall: `<dataset>.metrics.json`.
