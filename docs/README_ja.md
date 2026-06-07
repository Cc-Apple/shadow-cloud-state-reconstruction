# Shadow Cloud Reconstruction Score 日本語要約

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
  94.675

status:
  VERY_STRONG_RECONSTRUCTION_WITH_BASELINE_CONTROL
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
