# -*- coding: utf-8 -*-
import csv
import hashlib
import json
import os
import sys
from datetime import datetime
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# ============================================================
# 35_REPO_README_BUILDER
# GitHub用README / docs整形
#
# 入力優先:
#   34 lite packageがあればそれを更新
#   なければ33b finalから生成
#
# 出力:
#   C:\Users\Administrator\Desktop\Result\SC_Repo_35_README_BUILDER
#
# read-only for source. package側READMEは出力生成。
# ============================================================

DESKTOP = Path(r"C:\Users\Administrator\Desktop")
RESULT_BASE = DESKTOP / "Result"

SRC33B = RESULT_BASE / "SC_Final_33b_RECONSTRUCTION_SEAL_FIXED"
SRC34 = RESULT_BASE / "SC_Repo_34_LITE_PACKAGE" / "shadow-cloud-reconstruction-score-lite"
OUT_DIR = RESULT_BASE / "SC_Repo_35_README_BUILDER"

FINAL_SCORE = "94.675"
STATUS = "VERY_STRONG_RECONSTRUCTION_WITH_BASELINE_CONTROL"


def mkdir(p):
    p.mkdir(parents=True, exist_ok=True)


def sha256_file(path, buf_size=1024 * 1024):
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read(buf_size)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def write_csv(path, rows, fields=None):
    mkdir(path.parent)
    if fields is None:
        fields = []
        seen = set()
        for r in rows:
            for k in r.keys():
                if k not in seen:
                    seen.add(k)
                    fields.append(k)
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def write_json(path, obj):
    mkdir(path.parent)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def read_text(path):
    try:
        return path.read_text(encoding="utf-8-sig", errors="replace")
    except Exception:
        try:
            return path.read_text(encoding="cp932", errors="replace")
        except Exception:
            return ""


def read_csv(path):
    if not path.exists():
        return []
    for enc in ["utf-8-sig", "utf-8", "cp932", "cp1252"]:
        try:
            with path.open("r", encoding=enc, errors="replace", newline="") as f:
                return list(csv.DictReader(f))
        except Exception:
            pass
    return []


def source_paths():
    paths = {
        "src33b": SRC33B,
        "src34_pkg": SRC34,
        "src34_exists": SRC34.exists(),
    }
    return paths


def build_readme_en():
    return f"""# Shadow Cloud Reconstruction Score

## Overview

This repository presents a non-attribution forensic reconstruction package for a suspected mobile-native Apple ecosystem platform-state anomaly model referred to as **Shadow Cloud (SC)**.

SC is defined in this package as:

> condition-triggered, multi-purpose, mobile-native platform-state control model

This repository does **not** claim attribution to any actor, state, government, vendor, spyware family, telecom provider, backup tool, application, or known intrusion set.

## Final Reconstruction Status

| Item | Value |
|---|---|
| Final score | {FINAL_SCORE} |
| Status | {STATUS} |
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

The final reconstruction score is **{FINAL_SCORE}**, derived from the previous 24c reconstruction score and the 31d mini1G baseline update.

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
"""


def build_readme_ja():
    return f"""# Shadow Cloud Reconstruction Score 日本語要約

## 概要

このrepoは、保存済みiOS / Apple ecosystemログから、**Shadow Cloud / SC** と呼ぶ制御モデルの骨格を再構成した非帰属型フォレンジックパッケージである。

SCの定義:

```text
condition-triggered, multi-purpose, mobile-native platform-state control model
```

日本語定義:

```text
条件発火型・多目的型・mobile-native platform-state制御モデル
```

## 最終判定

```text
final score:
  {FINAL_SCORE}

status:
  {STATUS}
```

FINAL target:

```text
15G / C2026MAR_A
15G / C2026MARAPR_B
mini1 / C2025AUG
```

## 中心解釈

主役は Remote Command Joker ではない。

本線は以下。

```text
pre-reserved
condition-triggered
daemon-seam based
multi-purpose platform-state control
```

つまり、毎回外部から命令を送るモデルではなく、事前予約された条件が成立したときに正規daemon群が連鎖するモデルとして整理した。

## 主な根拠

### 1. 再構成score

```text
24c旧平均:
  94.05

旧baseline:
  75

31d baseline:
  80

補正:
  (80 - 75) / 8 = 0.625

最終score:
  94.675
```

### 2. 配線

```text
15G:
  TELECOM_BASEBAND_UPSTREAM

mini1 / C2025AUG:
  ACCOUNT_CLOUD_TRUST_UPSTREAM + raw Baseband入口
```

### 3. 証拠保存圧迫

28で、backup/log/file/screenshot関連のresource pressureが構造的に残った。  
ただし、victim process完全確定とは書かない。

### 4. usageClientId

29fで具体UUIDとtimeline-derived from→to候補を確認。  
ただし、明示old→newログではない。

### 5. endpoint

30dでApple ecosystem endpoint contextをpath-owner監査。  
mini1/C2025AUGにはtarget-only endpoint contextが残った。  
15G endpointはPATH_TARGET_MISMATCHで不採用。

C2、悪性通信、通信成立は断定しない。

### 6. baseline

31dでmini1Gをlow-exposure baselineとして処理。

```text
hard SC marker hits:
  0

verdict:
  LOW_EXPOSURE_BASELINE_NO_HARD_SC_MARKERS
```

mini1Gはclean controlではない。

## 採用source

```text
22b_axis_fix
24c_reconstruction
25b_internal_control
27_wiring
28_victim
29f_usageclientid
30d_endpoint
31d_baseline
32b_falsification
```

## 不採用source

```text
25_initial_rejected
30_v1_not_final
31_v1_mixed
31b_no_input
31c_helper_only
32_v1_source_resolution_bug
33_v1_score_mismatch
```

## 断定禁止

```text
攻撃者特定
国家関与断定
Apple関与断定
C2 endpoint発見
通信成立
hidden MDM確定
usageClientId明示old→new確定
mini1G完全clean
外部端末core Joker
```

## 反証条件

SC仮説は以下で弱くなる、または崩れる。

```text
正常端末多数で同等scoreが普通に出る
trigger-free daemon発火が大量に出る
Baseband/CommCenter/SFA/CKKS順序が通常iOSで同型再現する
28のevidence pressureがregex誤爆または無関係と確認される
usageClientId変動がSC窓と無関係と示される
path-owner auditが誤りと示される
mini1G/正常端末多数でhard SC markerが普通に出る
```
"""


def build_short_submission_summary():
    return f"""# Shadow Cloud Short Research Summary

This package presents a non-attribution forensic reconstruction of a suspected mobile-native Apple ecosystem platform-state anomaly model called Shadow Cloud.

Final score: {FINAL_SCORE}
Status: {STATUS}

The model is not framed as a conventional payload/C2-based spyware claim. Instead, it is framed as a condition-triggered platform-state model involving recurring inconsistencies across legitimate Apple ecosystem surfaces: Baseband/CommCenter, SFA/CKKS/CloudServices, usageClientId, endpoint context, backup/log/resource pressure, and baseline contrast.

The strongest interpretation is pre-reserved and condition-triggered rather than real-time remote command based.

Key boundaries:
- no actor attribution
- no C2 claim
- no communication-success claim
- no Apple attribution
- no clean-control claim
- no explicit usageClientId old→new claim

The package includes a falsification matrix describing what evidence would weaken or collapse the Shadow Cloud hypothesis.
"""


def write_outputs():
    mkdir(OUT_DIR)

    readme_en = build_readme_en()
    readme_ja = build_readme_ja()
    summary_short = build_short_submission_summary()

    (OUT_DIR / "README.md").write_text(readme_en, encoding="utf-8")
    (OUT_DIR / "README_ja.md").write_text(readme_ja, encoding="utf-8")
    (OUT_DIR / "SHORT_RESEARCH_SUMMARY.md").write_text(summary_short, encoding="utf-8")

    # 34 packageが存在する場合、READMEも同期
    synced = []
    if SRC34.exists():
        targets = [
            (OUT_DIR / "README.md", SRC34 / "README.md"),
            (OUT_DIR / "README_ja.md", SRC34 / "docs" / "README_ja.md"),
            (OUT_DIR / "SHORT_RESEARCH_SUMMARY.md", SRC34 / "docs" / "SHORT_RESEARCH_SUMMARY.md"),
        ]
        for src, dst in targets:
            mkdir(dst.parent)
            dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
            synced.append({
                "from": str(src),
                "to": str(dst),
                "sha256": sha256_file(dst),
                "size": dst.stat().st_size,
            })

    write_csv(OUT_DIR / "35_synced_to_repo_lite.csv", synced)

    rows = []
    for p in sorted(OUT_DIR.rglob("*")):
        if p.is_file() and p.name != "35_OUTPUT_SHA256_MANIFEST.csv":
            rows.append({
                "relative_path": p.relative_to(OUT_DIR).as_posix(),
                "size": p.stat().st_size,
                "sha256": sha256_file(p),
            })
    write_csv(OUT_DIR / "35_OUTPUT_SHA256_MANIFEST.csv", rows)

    write_json(OUT_DIR / "35_MASTER_SUMMARY.json", {
        "created_at": datetime.now().isoformat(sep=" ", timespec="seconds"),
        "out_dir": str(OUT_DIR),
        "src33b": str(SRC33B),
        "src34_pkg": str(SRC34),
        "src34_exists": SRC34.exists(),
        "final_score": FINAL_SCORE,
        "status": STATUS,
        "files_created": len(rows),
        "synced_to_34": len(synced),
    })

    return rows, synced


def main():
    os.environ["PYTHONIOENCODING"] = "utf-8"
    print("=== 35 REPO README BUILDER ===")
    print("OUT:", OUT_DIR)

    rows, synced = write_outputs()

    print("files_created:", len(rows))
    print("synced_to_34:", len(synced))
    print("summary:", OUT_DIR / "35_MASTER_SUMMARY.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
