# Detector ablation (ablation-20261101-055935)

Datasets: a1, s1, t1, v110_103, v110_3, v120_103, v120_3; same ingested events for every variant; pipeline sees only the .log files.

## tune (t1, v110_3, v120_3) — all steps

| variant | attacks in incident | attacks touched | steps found | technique (parent) | alert-line P / R | incident-line P / R / F1 | decoys alerted | decoys in incident | incidents (false) |
|---|---|---|---|---|---|---|---|---|---|
| rules | 6/9 | 9/9 | 39/43 (0.91) | 0.923 | 0.254 / 0.806 | 1.000 / 0.187 / 0.316 | 27/102 | 0/102 | 6 (0) |
| rules+ueba | 8/9 | 9/9 | 39/43 (0.91) | 0.923 | 0.170 / 0.807 | 0.418 / 0.760 / 0.539 | 34/102 | 4/102 | 14 (3) |
| rules+link | 6/9 | 9/9 | 39/43 (0.91) | 0.923 | 0.247 / 0.806 | 0.991 / 0.187 / 0.315 | 28/102 | 0/102 | 6 (0) |
| full | 8/9 | 9/9 | 39/43 (0.91) | 0.923 | 0.167 / 0.807 | 0.417 / 0.760 / 0.539 | 35/102 | 4/102 | 14 (3) |
| ml_only | 0/9 | 4/9 | 7/43 (0.16) | 0.000 | 0.058 / 0.101 | N/A / 0.000 / N/A | 10/102 | 0/102 | 0 (0) |

## held-out (a1, s1, v110_103, v120_103) — all steps

| variant | attacks in incident | attacks touched | steps found | technique (parent) | alert-line P / R | incident-line P / R / F1 | decoys alerted | decoys in incident | incidents (false) |
|---|---|---|---|---|---|---|---|---|---|
| rules | 7/15 | 15/15 | 55/91 (0.60) | 0.782 | 0.069 / 0.670 | 0.025 / 0.135 / 0.042 | 44/196 | 6/196 | 11 (4) |
| rules+ueba | 9/15 | 15/15 | 56/91 (0.62) | 0.750 | 0.063 / 0.674 | 0.060 / 0.496 / 0.107 | 56/196 | 12/196 | 21 (9) |
| rules+link | 7/15 | 15/15 | 55/91 (0.60) | 0.782 | 0.068 / 0.671 | 0.018 / 0.135 / 0.032 | 46/196 | 9/196 | 10 (3) |
| full | 9/15 | 15/15 | 56/91 (0.62) | 0.750 | 0.062 / 0.674 | 0.059 / 0.496 / 0.106 | 58/196 | 15/196 | 18 (6) |
| ml_only | 0/15 | 7/15 | 12/91 (0.13) | 0.000 | 0.067 / 0.097 | N/A / 0.000 / N/A | 18/196 | 0/196 | 0 (0) |

## all (a1, s1, t1, v110_103, v110_3, v120_103, v120_3) — all steps

| variant | attacks in incident | attacks touched | steps found | technique (parent) | alert-line P / R | incident-line P / R / F1 | decoys alerted | decoys in incident | incidents (false) |
|---|---|---|---|---|---|---|---|---|---|
| rules | 13/24 | 24/24 | 94/134 (0.70) | 0.840 | 0.086 / 0.702 | 0.035 / 0.147 / 0.057 | 71/298 | 6/298 | 17 (4) |
| rules+ueba | 17/24 | 24/24 | 95/134 (0.71) | 0.821 | 0.076 / 0.706 | 0.083 / 0.559 / 0.144 | 90/298 | 16/298 | 35 (12) |
| rules+link | 13/24 | 24/24 | 94/134 (0.70) | 0.840 | 0.085 / 0.703 | 0.026 / 0.147 / 0.044 | 74/298 | 9/298 | 16 (3) |
| full | 17/24 | 24/24 | 95/134 (0.71) | 0.821 | 0.075 / 0.706 | 0.082 / 0.559 / 0.143 | 93/298 | 19/298 | 32 (9) |
| ml_only | 0/24 | 11/24 | 19/134 (0.14) | 0.000 | 0.064 / 0.098 | N/A / 0.000 / N/A | 28/298 | 0/298 | 0 (0) |

## Fusion: ranking alert groups (full variant)

| dataset | groups | attack groups | AP fused p | AP detector prior | P@10 fused | P@10 prior |
|---|---|---|---|---|---|---|
| a1 | 83 | 9 | 0.404 | 0.463 | 0.500 | 0.300 |
| s1 | 1130 | 26 | 0.276 | 0.095 | 0.700 | 0.200 |
| t1 | 59 | 15 | 0.732 | 0.522 | 0.900 | 0.400 |
| v110_103 | 374 | 23 | 0.321 | 0.227 | 0.600 | 0.400 |
| v110_3 | 257 | 13 | 0.471 | 0.190 | 0.600 | 0.200 |
| v120_103 | 99 | 13 | 0.197 | 0.431 | 0.100 | 0.400 |
| v120_3 | 85 | 14 | 0.728 | 0.465 | 0.800 | 0.400 |

ml_only: model alerts cannot form an incident alone (D-92), so its incident columns are 0 by design.
Neo4j and the LLM narrative do not change detection, so they have no row.
