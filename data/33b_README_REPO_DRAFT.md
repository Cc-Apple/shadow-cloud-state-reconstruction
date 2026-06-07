# Shadow Cloud Reconstruction Score

## Purpose

This repository package summarizes a non-attribution forensic reconstruction of a suspected mobile-native Apple ecosystem platform-state anomaly model called **Shadow Cloud (SC)**.

SC is defined here as:

> condition-triggered, multi-purpose, mobile-native platform-state control model

This package does **not** claim attribution to any actor, state, vendor, spyware family, telecom provider, or known intrusion set.

## Final Reconstruction Status

- Final score: **94.675**
- Status: **VERY_STRONG_RECONSTRUCTION_WITH_BASELINE_CONTROL**
- Final target windows:
  - 15G / C2026MAR_A
  - 15G / C2026MARAPR_B
  - mini1 / C2025AUG

## Score Basis

- Previous 24c average: 94.05
- Previous baseline score: 75
- 31d mini1G baseline score: 80
- Adjustment: (80 - 75) / 8 = 0.625
- Final: 94.05 + 0.625 = 94.675

## Core Interpretation

The dominant model is not a real-time remote-command model.
The strongest interpretation is:

- pre-reserved
- condition-triggered
- daemon-seam based
- multi-purpose platform-state control

## Boundaries

This package does not prove:

- attacker identity
- state attribution
- Apple attribution
- C2 endpoint
- connection success
- hidden MDM enrollment
- explicit usageClientId old→new transition
- complete clean control
