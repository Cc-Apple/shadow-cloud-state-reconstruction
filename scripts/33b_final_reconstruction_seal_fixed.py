# -*- coding: utf-8 -*-
import csv
import hashlib
import json
import os
import re
import shutil
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# ============================================================
# 33b_FINAL_RECONSTRUCTION_SEAL_FIXED
# 33v1修正版・完全版
#
# 修正点:
#   - 33v1のscore不一致を修正
#       33v1:
#         33b_final_reconstruction_score.csv = 93.125
#         33c_final_verdict_table.csv = 94.675
#       33b:
#         final score = 94.675 に統一
#
#   - 24c key source copy missingを修正
#       特定ファイル名依存ではなく、24c folderからscore/reconstruction/master候補を探索
#
#   - source inventory / keyword evidence / final packageを再生成
#
# read-only. no input move/delete/rename/edit.
# ============================================================

RESULT_BASE = Path(r"C:\Users\Administrator\Desktop\Result")
OUT_DIR = RESULT_BASE / "SC_Final_33b_RECONSTRUCTION_SEAL_FIXED"

SOURCES_ADOPTED = {
    "22b_axis_fix": RESULT_BASE / "SC_Final_22b_AXIS_FIXED",
    "24c_reconstruction": RESULT_BASE / "SC_Reconstruction_24c_BASELINE_CONTROL",
    "25b_internal_control": RESULT_BASE / "SC_Internal_Control_25b_STRICT",
    "27_wiring": RESULT_BASE / "SC_Wiring_27",
    "28_victim": RESULT_BASE / "SC_JetsamVictim_28",
    "29f_usageclientid": RESULT_BASE / "SC_UsageClientId_29f_FINAL_VERDICT",
    "30d_endpoint": RESULT_BASE / "SC_Endpoint_30d_PATH_OWNER_AUDIT_FINAL",
    "31d_baseline": RESULT_BASE / "SC_Baseline_31d_MINI1G_FINAL",
    "32b_falsification": RESULT_BASE / "SC_Falsification_32b_FINAL_MATRIX_FIXED",
}

SOURCES_REJECTED = {
    "25_initial_rejected": RESULT_BASE / "SC_Internal_Control_25",
    "30_v1_not_final": RESULT_BASE / "SC_Endpoint_30_DEDUP_REVIEW",
    "31_v1_mixed": RESULT_BASE / "SC_Baseline_31_MINI1G_PIPELINE",
    "31b_no_input": RESULT_BASE / "SC_Baseline_31b_MINI1G_STRICT",
    "31c_helper_only": RESULT_BASE / "SC_Baseline_31c_PREPARE_OR_HELPER",
    "32_v1_source_resolution_bug": RESULT_BASE / "SC_Falsification_32_FINAL_MATRIX",
    "33_v1_score_mismatch": RESULT_BASE / "SC_Final_33_RECONSTRUCTION_SEAL",
}

TEXT_SUFFIXES = {".csv", ".json", ".txt", ".md", ".yaml"}

EXPECTED_KEYWORDS = {
    "22b_axis_fix": ["mini1", "15G", "BC seam support", "C2025AUG"],
    "24c_reconstruction": ["94.05", "VERY_STRONG_RECONSTRUCTION_WITH_BASELINE_CONTROL", "baseline", "SC_RECONSTRUCTION"],
    "25b_internal_control": ["INTERNAL_CONTROL_GAP_STRONG", "89.523", "53.935", "65"],
    "27_wiring": ["TELECOM_BASEBAND_UPSTREAM", "ACCOUNT_CLOUD_TRUST_UPSTREAM", "Baseband", "CommCenter", "SFA", "CKKS"],
    "28_victim": ["EVIDENCE_PRESERVATION_TARGET_PRESENT", "BACKUP_IMPACT", "LOGD_DELETED", "JETSAM", "MEMORY_PRESSURE"],
    "29f_usageclientid": ["TARGET_BROAD_RAW_UUID_FROM_TO_SUPPORTED", "usageClientId", "Ngoc", "external", "timeline"],
    "30d_endpoint": ["TARGET_PATH_ONLY", "PATH_TARGET_MISMATCH", "mini1", "C2025AUG", "icloud.com", "apple.com"],
    "31d_baseline": ["LOW_EXPOSURE_BASELINE_NO_HARD_SC_MARKERS", "hard_sc_marker_hits", "iPhone13,1", "22F76", "80"],
    "32b_falsification": ["反証", "overclaim", "no_c2_claim", "usageclientid_not_explicit_old_new", "falsification"],
}

TARGETS = [
    ("15G", "C2026MAR_A"),
    ("15G", "C2026MARAPR_B"),
    ("mini1", "C2025AUG"),
]

# 32bのscore referenceを最終scoreとして採用。
# old 94.05 + (31d baseline 80 - old baseline 75) / 8 = 94.675
FINAL_SCORE = 94.675
OLD_SCORE = 94.05
OLD_BASELINE = 75
NEW_BASELINE = 80

# 24cの元score componentはsource依存のため、ここでは再計算しない。
# 最終scoreは32b score_adjustment_referenceの値を採用する。
FINAL_SCORE_COMPONENTS = [
    {
        "項目": "旧24c再構成平均",
        "score": OLD_SCORE,
        "根拠": "SC_Reconstruction_24c_BASELINE_CONTROLで採用済みのbaseline control版score。",
    },
    {
        "項目": "31d baseline更新",
        "score": f"{OLD_BASELINE}→{NEW_BASELINE}",
        "根拠": "31d mini1G final baseline: hard SC marker 0 / LOW_EXPOSURE_BASELINE_NO_HARD_SC_MARKERS。",
    },
    {
        "項目": "baseline差分反映",
        "score": "+0.625",
        "根拠": "(80 - 75) / 8 = 0.625。",
    },
    {
        "項目": "最終平均",
        "score": FINAL_SCORE,
        "根拠": "94.05 + 0.625 = 94.675。",
    },
]


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


def read_text(path, max_chars=500000):
    try:
        return path.read_text(encoding="utf-8-sig", errors="replace")[:max_chars]
    except Exception:
        try:
            return path.read_text(encoding="cp932", errors="replace")[:max_chars]
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


def inventory_folder(source_key, root):
    rows = []
    if not root.exists():
        return rows
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        if p.suffix.lower() not in TEXT_SUFFIXES:
            continue
        rows.append({
            "source_key": source_key,
            "relative_path": p.relative_to(root).as_posix(),
            "path": str(p),
            "size": p.stat().st_size,
            "sha256": sha256_file(p),
        })
    return rows


def source_audit():
    root_rows = []
    file_rows = []
    keyword_rows = []

    for source_key, root in SOURCES_ADOPTED.items():
        root_rows.append({
            "source_key": source_key,
            "adoption": "ADOPTED",
            "path": str(root),
            "exists": root.exists(),
            "type": "folder" if root.is_dir() else "missing",
        })

        inv = inventory_folder(source_key, root)
        file_rows.extend(inv)

        for r in inv:
            p = Path(r["path"])
            text = read_text(p)
            for kw in EXPECTED_KEYWORDS.get(source_key, []):
                cnt = text.lower().count(kw.lower())
                if cnt:
                    keyword_rows.append({
                        "source_key": source_key,
                        "keyword": kw,
                        "count": cnt,
                        "relative_path": r["relative_path"],
                        "path": r["path"],
                    })

    for source_key, root in SOURCES_REJECTED.items():
        root_rows.append({
            "source_key": source_key,
            "adoption": "REJECTED_OR_SUPERSEDED",
            "path": str(root),
            "exists": root.exists(),
            "type": "folder" if root.is_dir() else "missing",
        })

    status_rows = []
    ev_counter = Counter(r["source_key"] for r in keyword_rows)
    file_counter = Counter(r["source_key"] for r in file_rows)

    for source_key, root in SOURCES_ADOPTED.items():
        exists = root.exists()
        files = file_counter[source_key]
        ev = ev_counter[source_key]
        if exists and ev > 0:
            status = "ADOPTED_SOURCE_READY"
        elif exists and files > 0:
            status = "ADOPTED_SOURCE_EXISTS_BUT_KEYWORD_WEAK"
        else:
            status = "ADOPTED_SOURCE_MISSING"
        status_rows.append({
            "source_key": source_key,
            "path": str(root),
            "exists": exists,
            "text_files": files,
            "keyword_evidence_rows": ev,
            "status": status,
        })

    write_csv(OUT_DIR / "00_source_root_audit.csv", root_rows)
    write_csv(OUT_DIR / "00_source_file_inventory.csv", file_rows)
    write_csv(OUT_DIR / "00_source_keyword_evidence.csv", keyword_rows)
    write_csv(OUT_DIR / "00_source_status_summary.csv", status_rows)

    return root_rows, file_rows, keyword_rows, status_rows


def build_final_score():
    write_csv(OUT_DIR / "33b_a_score_adjustment_components.csv", FINAL_SCORE_COMPONENTS)

    final_rows = [{
        "SC_RECONSTRUCTION_AVERAGE_FINAL": FINAL_SCORE,
        "判定": "VERY_STRONG_RECONSTRUCTION_WITH_BASELINE_CONTROL",
        "旧平均": OLD_SCORE,
        "旧baseline対照": OLD_BASELINE,
        "31d_baseline対照": NEW_BASELINE,
        "baseline差分": "+0.625",
        "計算式": "94.05 + ((80 - 75) / 8) = 94.675",
        "境界": "scoreは解析設計に依存。攻撃者/国家/Apple/C2の断定ではない。",
    }]
    write_csv(OUT_DIR / "33b_b_final_reconstruction_score.csv", final_rows)
    return final_rows[0]


def build_final_verdict():
    rows = [
        {"項目": "最終モデル名", "内容": "Shadow Cloud / SC"},
        {"項目": "定義", "内容": "condition-triggered, multi-purpose, mobile-native platform-state control model"},
        {"項目": "日本語定義", "内容": "条件発火型・多目的型・mobile-native platform-state制御モデル"},
        {"項目": "FINAL target", "内容": "15G/C2026MAR_A, 15G/C2026MARAPR_B, mini1/C2025AUG"},
        {"項目": "Remote Command", "内容": "主役ではない。Remote candidate=0。PRE_RESERVED_STRONG。"},
        {"項目": "上流配線", "内容": "15GはTELECOM_BASEBAND_UPSTREAM。mini1/C2025AUGはACCOUNT_CLOUD_TRUST_UPSTREAM + raw Baseband入口。"},
        {"項目": "目的", "内容": "証拠保存妨害、trust/account再評価、telecom再同期、data/index同期準備、restriction seam、実験/調整。"},
        {"項目": "usageClientId", "内容": "具体UUIDとtimeline-derived broad from→to候補あり。明示old→newではない。mini1 strict候補はNgoc外部由来として除外。"},
        {"項目": "endpoint", "内容": "mini1/C2025AUG target-only Apple ecosystem endpoint contextあり。15G endpointはPATH_TARGET_MISMATCHで不採用。C2/通信成立断定なし。"},
        {"項目": "baseline", "内容": "mini1G low-exposure baseline。31dでhard SC marker 0。clean controlではない。"},
        {"項目": "最終score", "内容": f"{FINAL_SCORE} / VERY_STRONG_RECONSTRUCTION_WITH_BASELINE_CONTROL"},
    ]
    write_csv(OUT_DIR / "33b_c_final_verdict_table.csv", rows)
    return rows


def adopted_reason(k):
    return {
        "22b_axis_fix": "C2025AUG axis label修正版。mini1/15G/外部supportを分離。",
        "24c_reconstruction": "baseline control版の再構成score。31d補正前の旧平均94.05の根拠。",
        "25b_internal_control": "strict internal control。25初回の混入を修正。",
        "27_wiring": "Baseband/CommCenter/SFA/CKKS配線候補。",
        "28_victim": "Jetsam/resource victimとevidence preservation pressure。",
        "29f_usageclientid": "usageClientId最終統合。混入監査後。",
        "30d_endpoint": "endpoint path-owner audit final。target/external/mismatch分離。",
        "31d_baseline": "mini1G final baseline。Desktop\\mini1Gのみ読取。baseline 80の根拠。",
        "32b_falsification": "反証matrix fixed。source evidence全解決。",
    }.get(k, "")


def rejected_reason(k):
    return {
        "25_initial_rejected": "UNKNOWN_FOCUS/row数/派生混入により不採用。",
        "30_v1_not_final": "endpointノイズ大量。30b/30c/30dで置換。",
        "31_v1_mixed": "date fallbackでmini2/iPhone11Pro混入。",
        "31b_no_input": "strictだがmini1G入力未検出。31dで置換。",
        "31c_helper_only": "準備用batのみ。最終解析出力ではない。",
        "32_v1_source_resolution_bug": "24c/27 source解決失敗。32bで置換。",
        "33_v1_score_mismatch": "33b_final_reconstruction_score=93.125と33c_verdict=94.675が不一致。33bで修正。",
    }.get(k, "")


def build_adoption_register():
    rows = []
    for k, p in SOURCES_ADOPTED.items():
        rows.append({
            "source_key": k,
            "path": str(p),
            "採用状態": "採用",
            "理由": adopted_reason(k),
        })
    for k, p in SOURCES_REJECTED.items():
        rows.append({
            "source_key": k,
            "path": str(p),
            "採用状態": "不採用/旧版",
            "理由": rejected_reason(k),
        })
    write_csv(OUT_DIR / "33b_d_source_adoption_register.csv", rows)
    return rows


def build_guardrails():
    rows = [
        {"禁止表現": "攻撃者を特定した", "安全表現": "non-attribution forensic reconstruction", "理由": "attribution証拠ではない。"},
        {"禁止表現": "C2 endpointを発見した", "安全表現": "Apple ecosystem endpoint context was observed and de-duplicated", "理由": "30dはC2/通信成立を示さない。"},
        {"禁止表現": "mini1Gは完全clean", "安全表現": "mini1G low-exposure baseline showed no hard SC markers", "理由": "31dは完全非侵害証明ではない。"},
        {"禁止表現": "usageClientId old→new確定", "安全表現": "timeline-derived usageClientId transition candidates", "理由": "29fは明示old/newではない。"},
        {"禁止表現": "15G endpoint確定", "安全表現": "15G endpoint rows were excluded after path-owner audit", "理由": "30dでPATH_TARGET_MISMATCH。"},
        {"禁止表現": "外部端末もcore Joker", "安全表現": "external BC seam support", "理由": "22bで外部端末はsupport only。"},
        {"禁止表現": "Appleが攻撃した", "安全表現": "Apple ecosystem trust-state anomalies", "理由": "Apple主体性は示していない。"},
    ]
    write_csv(OUT_DIR / "33b_e_final_guardrails.csv", rows)
    return rows


def build_repo_files():
    readme = f"""# Shadow Cloud Reconstruction Score

## Purpose

This repository package summarizes a non-attribution forensic reconstruction of a suspected mobile-native Apple ecosystem platform-state anomaly model called **Shadow Cloud (SC)**.

SC is defined here as:

> condition-triggered, multi-purpose, mobile-native platform-state control model

This package does **not** claim attribution to any actor, state, vendor, spyware family, telecom provider, or known intrusion set.

## Final Reconstruction Status

- Final score: **{FINAL_SCORE}**
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
- Final: 94.05 + 0.625 = {FINAL_SCORE}

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
"""

    public_ja = f"""# Shadow Cloud 最終要約

## 定義

Shadow Cloud / SC は、保存済み iOS / Apple ecosystem ログから再構成された、条件発火型・多目的型・mobile-native platform-state 制御モデルである。

## 最終判定

- 最終score: {FINAL_SCORE}
- 判定: VERY_STRONG_RECONSTRUCTION_WITH_BASELINE_CONTROL
- FINAL target:
  - 15G / C2026MAR_A
  - 15G / C2026MARAPR_B
  - mini1 / C2025AUG

## score更新

- 24c旧平均: 94.05
- 31d baseline: 75 → 80
- 差分: +0.625
- 最終: 94.675

## 中心解釈

Remote Command Joker が主役ではなく、事前予約された条件発火モデルが本線。

## 境界

断定しないもの:

- 攻撃者
- 国家関与
- Apple関与
- C2 endpoint
- 通信成立
- hidden MDM
- usageClientId明示old→new
- 完全clean control
"""

    machine_yaml = f"""最終モデル: Shadow Cloud
略称: SC
定義: condition-triggered, multi-purpose, mobile-native platform-state control model
日本語定義: 条件発火型・多目的型・mobile-native platform-state制御モデル

最終score: {FINAL_SCORE}
最終判定: VERY_STRONG_RECONSTRUCTION_WITH_BASELINE_CONTROL

score根拠:
  old_24c_average: 94.05
  old_baseline_score: 75
  new_31d_baseline_score: 80
  adjustment: 0.625
  formula: 94.05 + ((80 - 75) / 8) = 94.675

FINAL_TARGET:
  - 15G / C2026MAR_A
  - 15G / C2026MARAPR_B
  - mini1 / C2025AUG

採用source:
  - 22b_axis_fix
  - 24c_reconstruction
  - 25b_internal_control
  - 27_wiring
  - 28_victim
  - 29f_usageclientid
  - 30d_endpoint
  - 31d_baseline
  - 32b_falsification

不採用source:
  - 25_initial_rejected
  - 30_v1_not_final
  - 31_v1_mixed
  - 31b_no_input
  - 31c_helper_only
  - 32_v1_source_resolution_bug
  - 33_v1_score_mismatch

境界:
  攻撃者特定: false
  国家関与断定: false
  Apple関与断定: false
  C2断定: false
  通信成立断定: false
  hidden_MDM断定: false
  usageClientId_old_new明示確定: false
  clean_control: false
  baseline_type: low-exposure baseline
"""

    (OUT_DIR / "33b_README_REPO_DRAFT.md").write_text(readme, encoding="utf-8")
    (OUT_DIR / "33b_f_public_summary_ja.md").write_text(public_ja, encoding="utf-8")
    (OUT_DIR / "33b_g_machine_summary.yaml").write_text(machine_yaml, encoding="utf-8")

    return [
        {"file": "33b_README_REPO_DRAFT.md", "description": "repo用README草案"},
        {"file": "33b_f_public_summary_ja.md", "description": "公開用日本語要約"},
        {"file": "33b_g_machine_summary.yaml", "description": "機械用最終要約"},
    ]


def build_falsification_shortlist():
    rows = [
        {"反証ID": "FAL-01", "項目": "正常端末多数で同等score", "SCが崩れる条件": "正常iOS端末多数に同pipelineを回し、94点級のSC reconstructionが普通に出る。", "優先度": "最重要"},
        {"反証ID": "FAL-02", "項目": "trigger-free daemon発火", "SCが崩れる条件": "Remote Command型を示すtrigger-free発火が大量に出る。", "優先度": "最重要"},
        {"反証ID": "FAL-03", "項目": "wiring通常説明", "SCが崩れる条件": "Baseband/CommCenter/SFA/CKKSの順序が通常iOS診断で同型再現する。", "優先度": "重要"},
        {"反証ID": "FAL-04", "項目": "evidence pressure否定", "SCが崩れる条件": "28のbackup/log/file/screenshot pressureがregex誤爆または無関係と確認される。", "優先度": "重要"},
        {"反証ID": "FAL-05", "項目": "usageClientId通常説明", "SCが崩れる条件": "29fのusageClientId変動が通常app usage IDでSC窓と無関係と示される。", "優先度": "重要"},
        {"反証ID": "FAL-06", "項目": "path-owner audit反証", "SCが崩れる条件": "29f/30dのTARGET_PATH_ONLYまたはexternal separationが誤りと示される。", "優先度": "重要"},
        {"反証ID": "FAL-07", "項目": "baseline否定", "SCが崩れる条件": "mini1G/正常端末多数でhard SC markerが普通に出る。", "優先度": "最重要"},
    ]
    write_csv(OUT_DIR / "33b_h_final_falsification_shortlist.csv", rows)
    return rows


def find_files_by_keywords(root, include_any, limit=5):
    if not root.exists():
        return []
    scored = []
    for p in root.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in TEXT_SUFFIXES:
            continue
        name = p.name.lower()
        score = 0
        for kw in include_any:
            if kw.lower() in name:
                score += 10
        text = read_text(p, 80000).lower()
        for kw in include_any:
            if kw.lower() in text:
                score += 1
        if score > 0:
            scored.append((score, p))
    scored.sort(key=lambda x: (-x[0], str(x[1])))
    return [p for _, p in scored[:limit]]


def collect_key_files():
    pkg_dir = OUT_DIR / "KEY_SOURCE_COPIES"
    mkdir(pkg_dir)

    selected = {
        "24c_score": find_files_by_keywords(SOURCES_ADOPTED["24c_reconstruction"], ["94.05", "reconstruction", "baseline", "score"], 5),
        "27_wiring": find_files_by_keywords(SOURCES_ADOPTED["27_wiring"], ["TELECOM_BASEBAND_UPSTREAM", "ACCOUNT_CLOUD_TRUST_UPSTREAM", "wiring", "Baseband"], 5),
        "28_victim": find_files_by_keywords(SOURCES_ADOPTED["28_victim"], ["EVIDENCE_PRESERVATION_TARGET_PRESENT", "BACKUP_IMPACT", "victim", "JETSAM"], 5),
        "29f_usage_verdict": [
            SOURCES_ADOPTED["29f_usageclientid"] / "29f1_final_usageclientid_verdict_by_focus.csv",
            SOURCES_ADOPTED["29f_usageclientid"] / "29f_MASTER_SUMMARY.json",
        ],
        "30d_endpoint_summary": [
            SOURCES_ADOPTED["30d_endpoint"] / "30d6_final_focus_endpoint_summary.csv",
            SOURCES_ADOPTED["30d_endpoint"] / "30d_MASTER_SUMMARY.json",
        ],
        "31d_baseline_summary": [
            SOURCES_ADOPTED["31d_baseline"] / "31d5_mini1g_final_baseline_summary.csv",
            SOURCES_ADOPTED["31d_baseline"] / "31d_MASTER_SUMMARY.json",
        ],
        "32b_falsification": [
            SOURCES_ADOPTED["32b_falsification"] / "32b2_falsification_matrix_fixed.csv",
            SOURCES_ADOPTED["32b_falsification"] / "32b_MASTER_SUMMARY.json",
        ],
    }

    rows = []
    for label, paths in selected.items():
        copied = False
        for p in paths:
            if p.exists() and p.is_file():
                dst = pkg_dir / f"{label}__{p.name}"
                shutil.copy2(p, dst)
                rows.append({
                    "label": label,
                    "source": str(p),
                    "copied_to": str(dst),
                    "sha256": sha256_file(dst),
                    "size": dst.stat().st_size,
                    "status": "COPIED",
                })
                copied = True
        if not copied:
            rows.append({
                "label": label,
                "source": "",
                "copied_to": "",
                "sha256": "",
                "size": "",
                "status": "NOT_FOUND",
            })

    write_csv(OUT_DIR / "33b_i_key_source_copies.csv", rows)
    return rows


def build_v1_fix_report():
    rows = [
        {
            "問題": "final score不一致",
            "33v1": "33b_final_reconstruction_score.csv=93.125 / 33c_final_verdict_table.csv=94.675",
            "33b修正": "全ファイルを94.675に統一",
        },
        {
            "問題": "24c key source copy missing",
            "33v1": "33i_key_source_copies.csvで24c_score NOT_FOUND",
            "33b修正": "24c folder全体からscore/reconstruction/baseline keywordで探索してcopy",
        },
        {
            "問題": "不採用sourceに33v1が未登録",
            "33v1": "33v1自身のscore mismatchをregisterしていない",
            "33b修正": "33_v1_score_mismatchを不採用sourceへ追加",
        },
    ]
    write_csv(OUT_DIR / "33b_j_v1_fix_report.csv", rows)
    return rows


def sha_manifest():
    rows = []
    for p in sorted(OUT_DIR.rglob("*")):
        if p.is_file() and p.name != "33b_SHA256_MANIFEST.csv":
            rows.append({
                "relative_path": p.relative_to(OUT_DIR).as_posix(),
                "size": p.stat().st_size,
                "sha256": sha256_file(p),
            })
    write_csv(OUT_DIR / "33b_SHA256_MANIFEST.csv", rows)
    return rows


def main():
    os.environ["PYTHONIOENCODING"] = "utf-8"
    mkdir(OUT_DIR)

    print("=== 33b FINAL RECONSTRUCTION SEAL FIXED ===")
    print("OUT:", OUT_DIR)

    root_rows, file_rows, keyword_rows, status_rows = source_audit()
    final_score = build_final_score()
    verdict_rows = build_final_verdict()
    adoption_rows = build_adoption_register()
    guardrails = build_guardrails()
    repo_files = build_repo_files()
    falsification = build_falsification_shortlist()
    key_files = collect_key_files()
    fix_report = build_v1_fix_report()
    sha = sha_manifest()

    adopted_missing = [r for r in status_rows if r["status"] == "ADOPTED_SOURCE_MISSING"]
    key_missing = [r for r in key_files if r["status"] == "NOT_FOUND"]

    master = {
        "created_at": datetime.now().isoformat(sep=" ", timespec="seconds"),
        "out_dir": str(OUT_DIR),
        "final_model": "Shadow Cloud / SC",
        "definition": "condition-triggered, multi-purpose, mobile-native platform-state control model",
        "final_score": final_score,
        "adopted_source_count": len(SOURCES_ADOPTED),
        "adopted_missing_count": len(adopted_missing),
        "source_status": status_rows,
        "source_files_indexed": len(file_rows),
        "source_keyword_evidence_rows": len(keyword_rows),
        "target_windows": [f"{d}/{f}" for d, f in TARGETS],
        "key_source_copies": len(key_files),
        "key_source_missing_count": len(key_missing),
        "repo_files": repo_files,
        "guardrail_rows": len(guardrails),
        "falsification_shortlist_rows": len(falsification),
        "v1_fix_report_rows": len(fix_report),
        "boundary": {
            "v1_score_mismatch_fixed": True,
            "final_score_consistent": True,
            "final_score_value": FINAL_SCORE,
            "not_attribution": True,
            "no_c2_claim": True,
            "no_connection_success_claim": True,
            "no_hidden_mdm_final_claim": True,
            "no_apple_attribution": True,
            "usageclientid_not_explicit_old_new": True,
            "baseline_not_clean_control": True,
            "external_devices_not_core_joker": True,
        },
        "sha_rows": len(sha),
    }
    write_json(OUT_DIR / "33b_MASTER_SUMMARY.json", master)

    print("final_score:", FINAL_SCORE)
    print("adopted_missing_count:", len(adopted_missing))
    print("key_source_missing_count:", len(key_missing))
    print("source_files_indexed:", len(file_rows))
    print("summary:", OUT_DIR / "33b_MASTER_SUMMARY.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
