# -*- coding: utf-8 -*-
import csv
import hashlib
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# ============================================================
# 32b_FALSIFICATION_MATRIX_FINAL_FIXED
# 32v1修正版。
#
# 修正点:
#   - 24c / 27 の特定ファイル名依存を廃止
#   - 各source folder配下のCSV/JSON/TXTを再帰inventory
#   - keyword evidence auditでsource存在を確認
#   - 反証matrixは固定結論 + source audit根拠で出す
# ============================================================

RESULT_BASE = Path(r"C:\Users\Administrator\Desktop\Result")

SOURCES = {
    "24c_reconstruction": RESULT_BASE / "SC_Reconstruction_24c_BASELINE_CONTROL",
    "27_wiring": RESULT_BASE / "SC_Wiring_27",
    "28_victim": RESULT_BASE / "SC_JetsamVictim_28",
    "29f_usageclientid": RESULT_BASE / "SC_UsageClientId_29f_FINAL_VERDICT",
    "30d_endpoint": RESULT_BASE / "SC_Endpoint_30d_PATH_OWNER_AUDIT_FINAL",
    "31d_baseline": RESULT_BASE / "SC_Baseline_31d_MINI1G_FINAL",
}

OUT_DIR = RESULT_BASE / "SC_Falsification_32b_FINAL_MATRIX_FIXED"

TEXT_SUFFIXES = {".csv", ".json", ".txt", ".log", ".md"}

EXPECTED_EVIDENCE = {
    "24c_reconstruction": [
        "94.05", "VERY_STRONG_RECONSTRUCTION_WITH_BASELINE_CONTROL",
        "baseline", "SC_RECONSTRUCTION"
    ],
    "27_wiring": [
        "TELECOM_BASEBAND_UPSTREAM", "ACCOUNT_CLOUD_TRUST_UPSTREAM",
        "Baseband", "CommCenter", "SFA", "CKKS"
    ],
    "28_victim": [
        "EVIDENCE_PRESERVATION_TARGET_PRESENT", "BACKUP_IMPACT",
        "LOGD_DELETED", "JETSAM", "MEMORY_PRESSURE"
    ],
    "29f_usageclientid": [
        "TARGET_BROAD_RAW_UUID_FROM_TO_SUPPORTED", "usageClientId",
        "timeline", "Ngoc", "external"
    ],
    "30d_endpoint": [
        "TARGET_PATH_ONLY", "PATH_TARGET_MISMATCH",
        "mini1", "C2025AUG", "icloud.com", "apple.com"
    ],
    "31d_baseline": [
        "LOW_EXPOSURE_BASELINE_NO_HARD_SC_MARKERS",
        "hard_sc_marker_hits", "iPhone13,1", "22F76"
    ],
}


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


def read_text(path, max_chars=300000):
    try:
        return path.read_text(encoding="utf-8-sig", errors="replace")[:max_chars]
    except Exception:
        try:
            return path.read_text(encoding="cp932", errors="replace")[:max_chars]
        except Exception:
            return ""


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


def inventory_sources():
    root_rows = []
    file_rows = []
    evidence_rows = []

    for key, root in SOURCES.items():
        root_rows.append({
            "source_key": key,
            "path": str(root),
            "exists": root.exists(),
            "type": "folder" if root.is_dir() else "missing",
        })

        if not root.exists():
            continue

        files = []
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            if p.suffix.lower() not in TEXT_SUFFIXES:
                continue
            files.append(p)

        for p in files:
            text = read_text(p, 300000)
            rel = p.relative_to(root).as_posix()
            file_rows.append({
                "source_key": key,
                "relative_path": rel,
                "path": str(p),
                "size": p.stat().st_size,
                "sha256": sha256_file(p),
            })

            for kw in EXPECTED_EVIDENCE.get(key, []):
                cnt = text.lower().count(kw.lower())
                if cnt:
                    evidence_rows.append({
                        "source_key": key,
                        "keyword": kw,
                        "count": cnt,
                        "relative_path": rel,
                        "path": str(p),
                    })

    write_csv(OUT_DIR / "00_source_root_check.csv", root_rows)
    write_csv(OUT_DIR / "00_source_file_inventory.csv", file_rows)
    write_csv(OUT_DIR / "00_source_keyword_evidence.csv", evidence_rows)

    return root_rows, file_rows, evidence_rows


def source_status(root_rows, evidence_rows):
    root_exists = {r["source_key"]: str(r["exists"]).lower() == "true" or r["exists"] is True for r in root_rows}
    ev_by_source = Counter(r["source_key"] for r in evidence_rows)

    rows = []
    for key in SOURCES.keys():
        exists = root_exists.get(key, False)
        ev = ev_by_source.get(key, 0)
        if exists and ev > 0:
            status = "SOURCE_EVIDENCE_PRESENT"
        elif exists:
            status = "FOLDER_EXISTS_BUT_KEYWORD_EVIDENCE_WEAK"
        else:
            status = "SOURCE_FOLDER_MISSING"

        rows.append({
            "source_key": key,
            "folder_exists": exists,
            "keyword_evidence_rows": ev,
            "source_status": status,
        })

    write_csv(OUT_DIR / "00_source_status_summary.csv", rows)
    return rows


def build_observation_facts():
    rows = [
        {
            "観測ID": "OBS-01",
            "分類": "再構成スコア",
            "観測内容": "24cでSC_RECONSTRUCTION_AVERAGE=94.05 / VERY_STRONG_RECONSTRUCTION_WITH_BASELINE_CONTROL。31d反映後の参考平均は94.675。",
            "SC側説明": "条件発火・daemon seam・raw配線・目的推定・axis・baseline対照が揃う。",
            "正常iOS説が説明すべきこと": "複数窓・複数層にまたがる同一構造が通常iOS挙動だけで高スコアに整列する理由。",
            "崩れる条件": "24c/31dの入力が誤結合、FINAL targetが消える、control群との差が消える。",
            "必要な反証証拠": "正常端末多数で同pipelineを回し同等スコアが普通に出ること。",
            "反証耐性": "高",
            "採用境界": "採用。ただしscoreは解析設計に依存。",
        },
        {
            "観測ID": "OBS-02",
            "分類": "Remote Command不在",
            "観測内容": "19v2系でremote candidate=0、PRE_RESERVED_STRONG。",
            "SC側説明": "リアルタイム遠隔命令ではなく事前予約・条件発火型制御。",
            "正常iOS説が説明すべきこと": "発火が条件に寄り、突発Remote Command候補が出ないことを同時に説明。",
            "崩れる条件": "triggerなしdaemon発火が大量に確認される。",
            "必要な反証証拠": "同じ窓のrawログでtrigger-free発火が多数確認されること。",
            "反証耐性": "高",
            "採用境界": "採用。",
        },
        {
            "観測ID": "OBS-03",
            "分類": "axis",
            "観測内容": "C2025AUG中心=mini1、後続Joker橋=15G、外部端末=BC seam support only。",
            "SC側説明": "中心軸・橋・外部supportを分けたクラスタ構造。",
            "正常iOS説が説明すべきこと": "mini1中心・15G橋・外部supportという分離が偶然成立する理由。",
            "崩れる条件": "外部supportが無関係、またはmini1/15G軸がログ上で逆転。",
            "必要な反証証拠": "ファイル所有・時系列・device owner auditの反証。",
            "反証耐性": "中高",
            "採用境界": "採用。外部端末はcore Joker扱い禁止。",
        },
        {
            "観測ID": "OBS-04",
            "分類": "配線",
            "観測内容": "27で15G=TELECOM_BASEBAND_UPSTREAM、mini1/C2025AUG=ACCOUNT_CLOUD_TRUST_UPSTREAM + raw Baseband入口。",
            "SC側説明": "15GはBaseband/CommCenter寄り、mini1はBaseband入口からSFA/CKKS/CloudServices側へ接続する二段配線。",
            "正常iOS説が説明すべきこと": "Baseband/CommCenter/SFA/CKKS/CloudServicesの整列が通常診断ログで同時に見える理由。",
            "崩れる条件": "launchd/MachServices確認で完全に通常処理として説明可能。",
            "必要な反証証拠": "正常端末で同じdaemon順序・同じ窓・同じresource連鎖の再現。",
            "反証耐性": "中高",
            "採用境界": "採用。ただし因果確定ではない。",
        },
        {
            "観測ID": "OBS-05",
            "分類": "証拠保存圧迫",
            "観測内容": "28で3本すべてEVIDENCE_PRESERVATION_TARGET_PRESENT。backup/log/file/screenshot pressure supported。",
            "SC側説明": "発火後resource pressureが証拠保存・backup/log/file/screenshot領域へ寄る。",
            "正常iOS説が説明すべきこと": "複数窓でbackup/log/file/screenshot圧迫が同型で出る理由。",
            "崩れる条件": "28f手動確認でvictim/resourceが証拠保存と無関係、またはregex誤爆が大半。",
            "必要な反証証拠": "JetsamEvent/stacks/diskwrites原本でbackup/log/file/screenshot関連が否定されること。",
            "反証耐性": "中高",
            "採用境界": "採用。ただしvictim完全確定ではない。",
        },
        {
            "観測ID": "OBS-06",
            "分類": "usageClientId",
            "観測内容": "29fで具体UUIDとtimeline由来from→to候補あり。15G/mini1はtarget broad候補。mini1 strict候補はNgoc外部由来として除外。",
            "SC側説明": "account/trust/state associationの補助証拠。外部混入を分離済み。",
            "正常iOS説が説明すべきこと": "usageClientId UUID群とdaemon/resource窓が同時に出る理由。",
            "崩れる条件": "usageClientId値が当該文脈と無関係な通常app usage IDで相関が消える。",
            "必要な反証証拠": "Apple/iOS内部仕様または正常対照で同じusageClientId変動が普通に出ること。",
            "反証耐性": "中",
            "採用境界": "採用。ただし明示old→newではない。",
        },
        {
            "観測ID": "OBS-07",
            "分類": "endpoint",
            "観測内容": "30dでApple ecosystem endpointをpath-owner監査。mini1/C2025AUG target-only endpoint contextあり。15G endpointはPATH_TARGET_MISMATCHで不採用。",
            "SC側説明": "mini1/C2025AUGではApple ecosystem endpoint文脈がtarget本人pathに残る。HaThao/Ngocは外部supportへ分離。",
            "正常iOS説が説明すべきこと": "endpointがdaemon/resource/cluster窓と同時に並ぶ理由。ただしApple正規通信で説明可能な部分あり。",
            "崩れる条件": "30d target-only endpointが全て通常update/telemetryで、SC窓との時系列関係が消える。",
            "必要な反証証拠": "同一iOS/同一日付/同一環境の正常端末endpoint比較、またはApple正規通信仕様。",
            "反証耐性": "中",
            "採用境界": "採用。ただしC2/悪性通信/通信成立とは言わない。",
        },
        {
            "観測ID": "OBS-08",
            "分類": "baseline",
            "観測内容": "31dでmini1GはDesktop\\mini1Gのみ読取。files_scanned=52、hard_sc_marker_hits=0、LOW_EXPOSURE_BASELINE_NO_HARD_SC_MARKERS、score=80。",
            "SC側説明": "low-exposure baselineではSC hard markerが出ない。FINAL targetとの差分補強。",
            "正常iOS説が説明すべきこと": "同pipelineでmini1G初期baselineにはhard markerが出ず、FINAL targetに構造が集まる理由。",
            "崩れる条件": "mini1G/正常端末多数で同等hard markerが普通に出る。",
            "必要な反証証拠": "mini1G/正常端末多数の同pipeline実行結果。",
            "反証耐性": "高",
            "採用境界": "採用。ただしclean controlではない。",
        },
    ]
    write_csv(OUT_DIR / "32b1_observation_facts_fixed.csv", rows)
    return rows


def build_falsification_matrix(facts):
    rows = []
    for f in facts:
        if f["分類"] in {"再構成スコア", "Remote Command不在", "baseline"}:
            priority = "最重要"
        elif f["分類"] in {"配線", "証拠保存圧迫", "usageClientId", "endpoint"}:
            priority = "重要"
        else:
            priority = "補助"

        burden = "高い" if f["反証耐性"] == "高" else ("中〜高" if f["反証耐性"] == "中高" else "中")

        rows.append({
            "反証ID": f["観測ID"].replace("OBS", "FAL"),
            "優先度": priority,
            "観測分類": f["分類"],
            "現在の観測": f["観測内容"],
            "SC仮説での説明": f["SC側説明"],
            "正常iOS説が成立するための必要説明": f["正常iOS説が説明すべきこと"],
            "SC仮説が崩れる条件": f["崩れる条件"],
            "必要な反証証拠": f["必要な反証証拠"],
            "反証側の負荷": burden,
            "現在の採用境界": f["採用境界"],
        })
    write_csv(OUT_DIR / "32b2_falsification_matrix_fixed.csv", rows)
    return rows


def build_normal_ios_stress():
    rows = [
        {
            "正常iOS説明候補": "通常のAnalytics/diagnostic生成",
            "説明できる部分": "Apple endpoint、timed、triald、SiriSearchFeedback、xp_amp_app_usage等の存在。",
            "説明が苦しい部分": "FINAL 3本への集約、pretrigger率、resource pressure、usageClientId、axis、baseline差分が同時に揃う点。",
            "必要な追加証拠": "正常端末多数で同pipelineを回し、同等SC scoreとFINAL構造が出ること。",
            "現在評価": "単独では不足",
        },
        {
            "正常iOS説明候補": "ストレージ不足/一般的メモリ圧迫",
            "説明できる部分": "Jetsam、stacks、low storage、diskwritesの一部。",
            "説明が苦しい部分": "backup/log/file/screenshot圧迫とtrigger/daemon/usage/endpoint/axisが同一窓に寄る点。",
            "必要な追加証拠": "resource pressure原本が証拠保存系と無関係であること。",
            "現在評価": "部分説明のみ",
        },
        {
            "正常iOS説明候補": "Apple正規cloud/trust処理",
            "説明できる部分": "SFA/CKKS/cloudd/icloud endpointの存在。",
            "説明が苦しい部分": "BC daemon seam、usageClientId変動、Baseband/CommCenter上流、evidence pressureとの同時性。",
            "必要な追加証拠": "Apple内部仕様または正常対照で同じ連鎖が普通に出ること。",
            "現在評価": "重要反証候補だが未成立",
        },
        {
            "正常iOS説明候補": "データ混入/target誤結合",
            "説明できる部分": "一部外部端末混入、mini1 strict usageClientId過大主張。",
            "説明が苦しい部分": "29e/29f/30dで混入分離後も残るtarget broad usage/mini1 endpoint/24c score。",
            "必要な追加証拠": "path-owner audit後のTARGET_PATH_ONLYが誤りであること。",
            "現在評価": "一部成立。全体反証には不足",
        },
        {
            "正常iOS説明候補": "完全clean control不在による過大評価",
            "説明できる部分": "baseline対照の限界。",
            "説明が苦しい部分": "25b strict internal controlと31d mini1G low-exposure baselineで差分が残る点。",
            "必要な追加証拠": "mini1Gや正常端末多数でSC hard markerが普通に出ること。",
            "現在評価": "弱点だが31dで補強済み",
        },
    ]
    write_csv(OUT_DIR / "32b3_normal_ios_stress_table_fixed.csv", rows)
    return rows


def build_guardrails():
    rows = [
        {"禁止表現": "攻撃者を特定した", "理由": "attribution証拠ではない。", "安全表現": "non-attribution forensic reconstruction"},
        {"禁止表現": "C2 endpointを発見した", "理由": "30dは通信成立/C2確定ではない。", "安全表現": "Apple ecosystem endpoint context was observed and de-duplicated"},
        {"禁止表現": "mini1Gは完全clean", "理由": "31dはlow-exposure baseline。", "安全表現": "mini1G low-exposure baseline showed no hard SC markers"},
        {"禁止表現": "usageClientId old→newを確定した", "理由": "29fはtimeline-derived broad from→to。", "安全表現": "timeline-derived usageClientId transition candidates"},
        {"禁止表現": "15G endpointが確定した", "理由": "30dで15G endpointはPATH_TARGET_MISMATCH。", "安全表現": "15G endpoint rows were excluded after path-owner audit"},
        {"禁止表現": "外部端末もcore Joker", "理由": "22bで外部端末はBC seam support only。", "安全表現": "external BC seam support"},
        {"禁止表現": "Appleが攻撃した", "理由": "Apple主体性は示していない。", "安全表現": "Apple ecosystem trust-state anomalies"},
    ]
    write_csv(OUT_DIR / "32b4_overclaim_guardrails_fixed.csv", rows)
    return rows


def build_expert_questions():
    rows = [
        {
            "宛先": "iOS内部仕様専門家",
            "質問": "Baseband/TelephonyBaseband→CommCenter→SFA/CKKS/cloudd系の順序が通常diagnosticで複数窓に同型で出る条件は何か。",
            "目的": "27 wiringの正常説明可能性確認。",
        },
        {
            "宛先": "Apple platform/security expert",
            "質問": "xp_amp_app_usage内のusageClientId複数UUIDとtimeline-derived A→Bの正常意味は何か。",
            "目的": "29fの意味境界確認。",
        },
        {
            "宛先": "iOS diagnostics expert",
            "質問": "backup/log/file/screenshot関連resource pressureが通常iOSで同一窓に集中する既知条件は何か。",
            "目的": "28の正常説明可能性確認。",
        },
        {
            "宛先": "Apple networking/cloud expert",
            "質問": "mesu/apple/icloud/gateway/keyvalueservice系endpointがtimed/SFA/cloudd/triald/suggestd等と同時に出る通常条件は何か。",
            "目的": "30d endpoint contextの正常説明範囲確認。",
        },
        {
            "宛先": "DFIR/statistical reviewer",
            "質問": "24c/25b/31dのscore pipelineで正常端末多数に同等スコアが出るか再現検証できるか。",
            "目的": "SC reconstruction scoreの反証可能性確認。",
        },
    ]
    write_csv(OUT_DIR / "32b5_expert_review_questions_fixed.csv", rows)
    return rows


def build_claim_ladder():
    rows = [
        {"主張レベル": "L1 観測事実", "本文": "FINAL 3窓でdaemon/resource/usage/endpoint/baseline差分が観測された。", "許容": "可"},
        {"主張レベル": "L2 構造推定", "本文": "観測はcondition-triggered, daemon-seam型platform-state制御モデルと整合する。", "許容": "可"},
        {"主張レベル": "L3 設計図再構成", "本文": "SC設計図の骨格は94点級で再構成できる。", "許容": "可。ただしscore前提を明記"},
        {"主張レベル": "L4 攻撃/制御仮説", "本文": "正常iOSだけでは説明困難な多層整列があり、SC仮説が有力。", "許容": "条件付き可"},
        {"主張レベル": "L5 攻撃者/国家/ベンダー断定", "本文": "特定主体が攻撃した。", "許容": "不可"},
    ]
    write_csv(OUT_DIR / "32b6_final_claim_ladder_fixed.csv", rows)
    return rows


def build_score_reference():
    rows = [{
        "old_reconstruction_average": 94.05,
        "old_baseline_score": 75,
        "new_baseline_score_from_31d": 80,
        "estimated_new_reconstruction_average": 94.675,
        "note": "24cの8項目平均にbaseline差分だけ反映した参考値。正式更新は33 final sealで行う。",
    }]
    write_csv(OUT_DIR / "32b7_score_adjustment_reference_fixed.csv", rows)
    return rows


def build_boundary():
    rows = [
        {"項目": "32b修正点", "内容": "32v1でp24/p27が未解決だった問題を修正。特定ファイル名依存を廃止し、source folder inventory + keyword evidence auditに変更。"},
        {"項目": "32の目的", "内容": "SC仮説を強化するためではなく、何が出ればSC仮説が崩れるかを明示する。"},
        {"項目": "採用境界", "内容": "観測事実、構造推定、設計図再構成は主張可。攻撃者/国家/Apple/C2/通信成立の断定は不可。"},
        {"項目": "使い道", "内容": "GitHub反論受付、研究機関レビュー、DFRWS後の質疑応答、専門家への質問表。"},
    ]
    write_csv(OUT_DIR / "32b8_final_boundary_statement_fixed.csv", rows)
    return rows


def sha_manifest():
    rows = []
    for p in sorted(OUT_DIR.rglob("*")):
        if p.is_file() and p.name != "32b_SHA256_MANIFEST.csv":
            rows.append({
                "relative_path": p.relative_to(OUT_DIR).as_posix(),
                "size": p.stat().st_size,
                "sha256": sha256_file(p),
            })
    write_csv(OUT_DIR / "32b_SHA256_MANIFEST.csv", rows)
    return rows


def main():
    os.environ["PYTHONIOENCODING"] = "utf-8"
    mkdir(OUT_DIR)

    print("=== 32b FALSIFICATION MATRIX FINAL FIXED ===")
    print("OUT:", OUT_DIR)

    root_rows, file_rows, evidence_rows = inventory_sources()
    status_rows = source_status(root_rows, evidence_rows)
    facts = build_observation_facts()
    matrix = build_falsification_matrix(facts)
    stress = build_normal_ios_stress()
    guard = build_guardrails()
    questions = build_expert_questions()
    ladder = build_claim_ladder()
    score_ref = build_score_reference()
    boundary = build_boundary()
    sha = sha_manifest()

    unresolved_sources = [r for r in status_rows if r["source_status"] == "SOURCE_FOLDER_MISSING"]

    master = {
        "created_at": datetime.now().isoformat(sep=" ", timespec="seconds"),
        "out_dir": str(OUT_DIR),
        "source_status": status_rows,
        "source_files_indexed": len(file_rows),
        "source_keyword_evidence_rows": len(evidence_rows),
        "unresolved_source_count": len(unresolved_sources),
        "facts_rows": len(facts),
        "falsification_rows": len(matrix),
        "score_reference": score_ref,
        "boundary": {
            "v1_p24_p27_resolution_bug_fixed": True,
            "source_folder_inventory_used": True,
            "keyword_evidence_audit_used": True,
            "not_attribution": True,
            "no_c2_claim": True,
            "no_connection_success_claim": True,
            "no_clean_control_claim": True,
            "usageclientid_not_explicit_old_new": True,
        },
        "sha_rows": len(sha),
    }
    write_json(OUT_DIR / "32b_MASTER_SUMMARY.json", master)

    print("source_files_indexed:", len(file_rows))
    print("source_keyword_evidence_rows:", len(evidence_rows))
    print("unresolved_source_count:", len(unresolved_sources))
    print("facts_rows:", len(facts))
    print("summary:", OUT_DIR / "32b_MASTER_SUMMARY.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
