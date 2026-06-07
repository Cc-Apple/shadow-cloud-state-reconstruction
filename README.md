# Shadow Cloud Reconstruction Score

## Overview

This repository presents a non-attribution forensic reconstruction package for a suspected mobile-native Apple ecosystem platform-state anomaly model referred to as **Shadow Cloud (SC)**.

SC is defined in this package as:

> condition-triggered, multi-purpose, mobile-native platform-state control model

This repository does **not** claim attribution to any actor, state, government, vendor, spyware family, telecom provider, backup tool, application, or known intrusion set.

## Final Reconstruction Status

| Item | Value |
|---|---|
| Final score | 94.675 |
| Status | VERY_STRONG_RECONSTRUCTION_WITH_BASELINE_CONTROL |
| Model name | Shadow Cloud / SC |
| Reconstruction type | Non-attribution forensic reconstruction |
| Control baseline | low-exposure baseline, not clean control |

## Final Target Windows

| Device | Focus |
|---|---|
| 15G | C2026MAR_A |
| 15G | C2026MARAPR_B |
| mini1 | C2025AUG |

## Core Interpretation

The dominant model is **not** a real-time remote-command model.

The stronger interpretation is:

1. pre-reserved
2. condition-triggered
3. daemon-seam based
4. multi-purpose platform-state control

In this framing, the important forensic question is not “which remote command was sent,” but “which conditions caused legitimate platform components to activate in a repeatable structure.”

## Main Evidence Lines

### 1. Final reconstruction score

The final reconstruction score is **94.675**, derived from the previous 24c reconstruction score and the 31d mini1G baseline update.

Score basis:

```text
24c previous average: 94.05
old baseline score:   75
31d baseline score:   80
adjustment:           (80 - 75) / 8 = 0.625
final score:          94.05 + 0.625 = 94.675
```

### 2. Trigger model

The final model favors pre-reserved / condition-triggered activation over real-time remote command execution.

### 3. Wiring model

The reconstructed upstream wiring is:

```text
15G:
  TELECOM_BASEBAND_UPSTREAM
  Baseband / TelephonyBaseband → CommCenter → account/cloud/policy/resource seam

mini1 / C2025AUG:
  ACCOUNT_CLOUD_TRUST_UPSTREAM
  raw Baseband entry → SFA / CKKS / CloudServices → cloudd / accountsd → policy/resource seam
```

### 4. Evidence-preservation pressure

The resource/victim analysis supports evidence-preservation pressure patterns, including backup/log/file/screenshot-related pressure. This is not treated as a full victim-process proof; it is treated as a structural pressure signal.

### 5. usageClientId

The package preserves concrete UUID values and timeline-derived transition candidates.

Boundary:

```text
usageClientId old→new is not explicitly proven.
The result is timeline-derived, not an explicit old/new OS log record.
```

### 6. Endpoint context

Apple ecosystem endpoint context was de-duplicated and path-owner audited.

Boundary:

```text
No C2 endpoint claim.
No malicious endpoint claim.
No connection-success claim.
```

### 7. Baseline

mini1G is used as a **low-exposure baseline**, not a clean control.

31d result:

```text
hard SC marker hits: 0
baseline verdict: LOW_EXPOSURE_BASELINE_NO_HARD_SC_MARKERS
baseline score: 80
```

## Source Adoption

Adopted sources:

- 22b axis fix
- 24c reconstruction
- 25b strict internal control
- 27 wiring
- 28 victim/resource
- 29f usageClientId final
- 30d endpoint path-owner audit final
- 31d mini1G baseline final
- 32b falsification matrix fixed

Rejected or superseded sources:

- 25 initial internal control
- 30 v1 endpoint de-dup
- 31 / 31b / 31c baseline attempts
- 32 v1 falsification matrix
- 33 v1 final seal

## Falsification

This package is designed to be falsifiable.

The SC hypothesis weakens or collapses if:

1. normal iOS devices frequently produce equivalent 94-point reconstruction scores under the same pipeline;
2. trigger-free daemon activations dominate over condition-triggered patterns;
3. Baseband / CommCenter / SFA / CKKS ordering is shown to be ordinary under the same conditions;
4. evidence-preservation pressure is shown to be regex noise or unrelated;
5. usageClientId changes are shown to be ordinary app usage identifiers unrelated to SC windows;
6. path-owner audit results are shown to be wrong;
7. mini1G or other baseline devices commonly show the same hard SC markers.

## Explicit Non-Claims

This repository does not claim:

- attacker identity
- state attribution
- Apple attribution
- spyware family attribution
- C2 endpoint discovery
- communication success
- hidden MDM enrollment as final proof
- explicit usageClientId old→new transition
- complete clean control

## Repository Layout

```text
README.md
NOTICE.md
docs/
  public_summary_ja.md
  machine_summary.yaml
  final_reconstruction_score.csv
  final_verdict_table.csv
  final_guardrails.csv
  final_falsification_shortlist.csv
data/
  source CSV/JSON/MD/YAML from 33b final package
manifests/
  copied_files_manifest.csv
  skipped_large_or_nonrepo_files_manifest.csv
  repo_lite_package_summary.json
```
## Reproducibility Addendum

This repository includes selected public scripts and evidence indexes.

### Code

See:

```text
scripts/
```

The scripts are the selected final-stage reproducibility and packaging scripts, including endpoint path-owner audit, mini1G baseline, falsification matrix, final reconstruction seal, repo-lite packaging, and README generation.

### Evidence Index

See:

```text
evidence-index/
manifests/
```

The public evidence index includes source audit tables, source file inventory, keyword evidence audit, SHA256 manifests, source adoption register, guardrails, falsification shortlist, and skipped-large-file manifests.

### Raw Artifact Boundary

Raw iOS logs, sysdiagnose archives, iMazing backup artifacts, Manifest.db generations, private screenshots/videos, Apple ID values, BSSID raw values, and banking/OTP records are not included.

Large or sensitive artifacts are represented by SHA256 / file-size / manifest references where appropriate.
