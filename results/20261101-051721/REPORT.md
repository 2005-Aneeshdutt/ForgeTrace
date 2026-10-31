# FVS evaluation 20261101-051721

Datasets: a1, s1, t1, v110_103, v110_3, v120_103, v120_3 (from `Validation dataset/scratch_ref`).
Pipeline unchanged and untuned; it read only the .log files.

## Pooled — All steps

- Attacks detected: 24/24 (1.000); in an incident: 9/24 (0.375)
- By tier: easy: 6/6 detected, 3/6 in incident; hard: 9/9 detected, 1/9 in incident; medium: 9/9 detected, 5/9 in incident
- Step recall: 0.410 of 134 steps
- Line level (alerts): P 0.071 R 0.665 F1 0.128; (incidents): P 0.067 R 0.454 F1 0.116
- Decoys flagged by an alert: 103/298; inside an incident: 32/298
- Incidents: 23, false-alarm incidents: 14

## Pooled — Excluding steps with unverified logids

- Attacks detected: 23/24 (0.958); in an incident: 9/24 (0.375)
- By tier: easy: 5/6 detected, 3/6 in incident; hard: 9/9 detected, 1/9 in incident; medium: 9/9 detected, 5/9 in incident
- Step recall: 0.393 of 112 steps
- Line level (alerts): P 0.070 R 0.674 F1 0.128; (incidents): P 0.067 R 0.462 F1 0.117
- Decoys flagged by an alert: 103/298; inside an incident: 32/298
- Incidents: 23, false-alarm incidents: 14

## Per dataset — all_steps

| dataset | split | profile | attack_detection_rate | attack_in_incident_rate | step_recall | technique_parent_acc | technique_exact_acc | line_alert_p | line_alert_r | line_inc_p | line_inc_r | decoy_fp_alert_rate | decoy_fp_incident_rate | incidents | false_alarm_incidents | latency_min_median | runtime_s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| a1 | test | adversarial | 1.000 | 0.667 | 0.200 | 0.500 | 0.500 | 0.222 | 0.466 | 0.589 | 0.465 | 0.312 | 0.083 | 5 | 3 | 2846.900 | 10.779 |
| s1 | test | stress | 1.000 | 0.167 | 0.452 | 0.357 | 0.143 | 0.025 | 0.678 | 0.006 | 0.138 | 0.325 | 0.163 | 3 | 2 | 425.600 | 12.007 |
| t1 | tune | validation | 1.000 | 0.333 | 0.571 | 0.125 | 0.125 | 0.137 | 0.760 | 0.472 | 0.608 | 0.394 | 0.121 | 3 | 2 | 56.400 | 5.222 |
| v110_103 | test | validation | 1.000 | 0.667 | 0.476 | 0.400 | 0.200 | 0.183 | 0.723 | 0.526 | 0.571 | 0.500 | 0.143 | 4 | 2 | 0.000 | 11.221 |
| v110_3 | tune | validation | 1.000 | 0.333 | 0.333 | 0.400 | 0.200 | 0.021 | 0.277 | 0.003 | 0.007 | 0.364 | 0.030 | 2 | 1 | 448.700 | 10.674 |
| v120_103 | test | validation | 1.000 | 0.333 | 0.368 | 0.429 | 0.286 | 0.223 | 0.760 | 0.580 | 0.676 | 0.275 | 0.075 | 3 | 2 | 448.100 | 11.028 |
| v120_3 | tune | validation | 1.000 | 0.333 | 0.500 | 0.286 | 0.286 | 0.264 | 0.787 | 0.490 | 0.644 | 0.333 | 0.083 | 3 | 2 | 8.800 | 11.035 |

## Per dataset — excl_unverified

| dataset | split | profile | attack_detection_rate | attack_in_incident_rate | step_recall | technique_parent_acc | technique_exact_acc | line_alert_p | line_alert_r | line_inc_p | line_inc_r | decoy_fp_alert_rate | decoy_fp_incident_rate | incidents | false_alarm_incidents | latency_min_median | runtime_s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| a1 | test | adversarial | 0.667 | 0.667 | 0.188 | 0.333 | 0.333 | 0.221 | 0.469 | 0.589 | 0.469 | 0.312 | 0.083 | 5 | 3 | 4484.700 | 10.779 |
| s1 | test | stress | 1.000 | 0.167 | 0.444 | 0.250 | 0.000 | 0.025 | 0.709 | 0.006 | 0.145 | 0.325 | 0.163 | 3 | 2 | 425.600 | 12.007 |
| t1 | tune | validation | 1.000 | 0.333 | 0.500 | 0.000 | 0.000 | 0.136 | 0.758 | 0.472 | 0.612 | 0.394 | 0.121 | 3 | 2 | 56.400 | 5.222 |
| v110_103 | test | validation | 1.000 | 0.667 | 0.471 | 0.250 | 0.000 | 0.182 | 0.724 | 0.525 | 0.573 | 0.500 | 0.143 | 4 | 2 | 0.000 | 11.221 |
| v110_3 | tune | validation | 1.000 | 0.333 | 0.308 | 0.250 | 0.000 | 0.021 | 0.274 | 0.003 | 0.007 | 0.364 | 0.030 | 2 | 1 | 1101.300 | 10.674 |
| v120_103 | test | validation | 1.000 | 0.333 | 0.333 | 0.200 | 0.000 | 0.222 | 0.762 | 0.580 | 0.680 | 0.275 | 0.075 | 3 | 2 | 448.100 | 11.028 |
| v120_3 | tune | validation | 1.000 | 0.333 | 0.500 | 0.167 | 0.167 | 0.263 | 0.787 | 0.490 | 0.646 | 0.333 | 0.083 | 3 | 2 | 8.800 | 11.035 |

Definitions: see the docstring of `tools/eval_fvs.py`. Per-attack and per-step rows: `<dataset>.attacks.csv`, `<dataset>.steps.csv`; full metrics incl. per-technique recall: `<dataset>.metrics.json`.
