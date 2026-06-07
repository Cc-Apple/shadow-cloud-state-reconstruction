# Scripts

This folder contains the selected reproducibility and packaging scripts used for the final Shadow Cloud state-reconstruction package.

## Included scripts

- `30d_endpoint_path_owner_audit_final.py`
  - Final endpoint path-owner audit.
  - Separates target-only, external support, path-target mismatch, and unknown/review rows.

- `31d_mini1g_baseline_final.py`
  - Final mini1G low-exposure baseline pipeline.
  - Reads only `C:\Users\Administrator\Desktop\mini1G`.

- `32b_falsification_matrix_final_fixed.py`
  - Final falsification matrix builder.
  - Fixes source-resolution issues from 32v1.

- `33b_final_reconstruction_seal_fixed.py`
  - Final reconstruction seal package builder.
  - Fixes 33v1 score mismatch and key-source copy issue.

- `34_repo_lite_package.py`
  - Creates the GitHub lightweight repo package.
  - Excludes large files and records their SHA256 in manifests.

- `35_repo_readme_builder.py`
  - Builds GitHub README / Japanese README / short research summary.

## Boundaries

These scripts do not contain raw personal iOS logs, private screenshots, Apple ID values, BSSID raw data, banking/OTP records, or sysdiagnose archives.

The scripts are provided for reproducibility review of the public package structure and are not proof of attribution, C2, communication success, or hidden MDM enrollment.
