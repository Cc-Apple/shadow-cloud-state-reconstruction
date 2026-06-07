# -*- coding: utf-8 -*-
import csv
import gzip
import hashlib
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# ============================================================
# 31d_MINI1G_BASELINE_FINAL
# 完全やり直し版。
# 差分ではない。
#
# 入力はこれだけ:
#   C:\Users\Administrator\Desktop\mini1G
#
# 他のDevice-Logs / mini2 / iPhone11Pro / Friend_Device は一切読まない。
# ZIPは読まない。展開済みログだけ読む。
# read-only. no move / delete / rename / edit.
# ============================================================

DESKTOP = Path(r"C:\Users\Administrator\Desktop")
INPUT_ROOT = DESKTOP / "mini1G"
RESULT_BASE = DESKTOP / "Result"
OUT_DIR = RESULT_BASE / "SC_Baseline_31d_MINI1G_FINAL"

MAX_FILE_MB = 300

TEXT_EXTS = {
    ".ips", ".synced", ".txt", ".log", ".session", ".spin", ".plist",
    ".json", ".xml", ".panic", ".csv", ".metriclog", ".awd"
}

DATE_RE = re.compile(r"(20\d{2}-\d{2}-\d{2})")
COMPACT_DATE_RE = re.compile(r"(20\d{2})(\d{2})(\d{2})")

HARD_MARKERS = {
    "CORE_OF_CORE_JOKER_FINAL": [
        "CORE_OF_CORE_JOKER_FINAL", "core_of_core", "final_joker", "joker_final",
    ],
    "BC_DAEMON_SEAM": [
        "BC_DAEMON_SEAM", "bc_daemon_seam", "daemon seam", "daemon_seam",
    ],
    "B_DAEMON_TO_USAGE": [
        "B_DAEMON_TO_USAGE", "daemon_to_usage", "daemon -> usage", "daemon→usage",
    ],
    "C_SIMULTANEOUS": [
        "C_SIMULTANEOUS", "simultaneous", "same_time", "coincident",
    ],
    "REMOTE_COMMAND_CANDIDATE": [
        "remote command", "remote_command", "command joker", "Remote Command Joker",
    ],
}

SOFT_MARKERS = {
    "EVIDENCE_PRESSURE": [
        "BACKUP_IMPACT", "backup impact", "LOGD_DELETED", "low storage",
        "memory pressure", "jetsam", "diskwrites", "screenshot", "FileProvider",
    ],
    "USAGECLIENTID": [
        "usageClientId", "usage_client_id", "usageClient", "xp_amp_app_usage",
    ],
    "ENDPOINT_APPLE_CONTEXT": [
        "apple.com", "icloud.com", "cdn-apple.com", "apple-dns.net",
        "mzstatic.com", "apple-cloudkit.com",
    ],
    "POLICY_CONTEXT": [
        "managedappdistributiond", "dmd", "ScreenTimeAgent", "ManagedSettings", "FamilyControls",
    ],
    "CLOUD_TRUST_CONTEXT": [
        "SFA", "CKKS", "CloudServices", "cloudd", "accountsd", "trustd", "securityd", "akd",
    ],
    "TELECOM_CONTEXT": [
        "CommCenter", "Baseband", "TelephonyBaseband", "CoreTelephony",
    ],
    "RESOURCE_CONTEXT": [
        "JetsamEvent", "stacks", "forceReset", "diskwrites", "lowstorage",
    ],
}

DAEMONS = [
    "Baseband", "TelephonyBaseband", "CommCenter", "CoreTelephony",
    "SFA", "CKKS", "CloudServices", "cloudd", "accountsd", "trustd", "securityd", "akd",
    "managedappdistributiond", "dmd", "ScreenTimeAgent", "ManagedSettings", "FamilyControls",
    "mobilebackupd", "backupd", "logd", "deleted",
    "timed", "locationd", "triald", "duetexpertd",
    "searchd", "suggestd", "parsecd",
    "JetsamEvent", "stacks", "forceReset", "diskwrites", "lowstorage",
]

DEVICE_HINTS = [
    "iPhone13,1",
    "iPhone OS 18.5",
    "22F76",
    "iPhone 12 mini",
    "iPhone12 mini",
    "mini1G",
    "mini1g",
]

ZIP_EXTS = {".zip", ".7z", ".rar"}


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


def extract_dates(text):
    s = str(text)
    out = set()
    for m in DATE_RE.finditer(s):
        out.add(m.group(1))
    for m in COMPACT_DATE_RE.finditer(s):
        out.add(f"{m.group(1)}-{m.group(2)}-{m.group(3)}")
    return sorted(out)


def is_text_log(path):
    name = path.name.lower()
    suffix = path.suffix.lower()

    if suffix in ZIP_EXTS:
        return False, "archive_not_scanned"

    if suffix in TEXT_EXTS:
        return True, "text_ext"

    if name.endswith(".ips.ca.synced") or name.endswith(".ca.synced"):
        return True, "synced_log"

    return False, "not_text_log"


def open_lines(path):
    if path.suffix.lower() == ".gz":
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
            for line in f:
                yield line.rstrip("\n")
        return

    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                yield line.rstrip("\n")
    except Exception:
        with path.open("r", encoding="cp932", errors="replace") as f:
            for line in f:
                yield line.rstrip("\n")


def marker_hits(line):
    low = str(line).lower()
    hard = []
    soft = []

    for marker, kws in HARD_MARKERS.items():
        for kw in kws:
            if kw.lower() in low:
                hard.append(marker)
                break

    for marker, kws in SOFT_MARKERS.items():
        for kw in kws:
            if kw.lower() in low:
                soft.append(marker)
                break

    return hard, soft


def daemon_hits(line):
    low = str(line).lower()
    return [d for d in DAEMONS if d.lower() in low]


def device_hint_hits(line):
    low = str(line).lower()
    return [h for h in DEVICE_HINTS if h.lower() in low]


def collect_files():
    rows = []
    files = []

    if not INPUT_ROOT.exists():
        write_csv(OUT_DIR / "00_file_candidate_index.csv", [{
            "path": str(INPUT_ROOT),
            "scan": False,
            "reason": "INPUT_ROOT_NOT_FOUND",
        }])
        return files, rows

    for p in INPUT_ROOT.rglob("*"):
        if not p.is_file():
            continue

        try:
            size = p.stat().st_size
        except Exception:
            rows.append({
                "path": str(p),
                "scan": False,
                "reason": "stat_error",
            })
            continue

        if size > MAX_FILE_MB * 1024 * 1024:
            rows.append({
                "path": str(p),
                "size": size,
                "scan": False,
                "reason": "too_large",
                "dates": ";".join(extract_dates(str(p))),
            })
            continue

        ok, reason = is_text_log(p)

        row = {
            "path": str(p),
            "size": size,
            "scan": ok,
            "reason": reason,
            "dates": ";".join(extract_dates(str(p))),
        }
        rows.append(row)

        if ok:
            files.append(p)

    write_csv(OUT_DIR / "00_file_candidate_index.csv", rows)
    return files, rows


def scan_files(files):
    file_rows = []
    hard_rows = []
    soft_rows = []
    daemon_rows = []
    errors = []

    for path in files:
        hard_counter = Counter()
        soft_counter = Counter()
        daemon_counter = Counter()
        device_counter = Counter()
        date_counter = Counter(extract_dates(str(path)))

        line_count = 0
        hit_lines = 0

        try:
            for line_no, line in enumerate(open_lines(path), 1):
                line_count += 1

                for d in extract_dates(line):
                    date_counter[d] += 1

                hard, soft = marker_hits(line)
                daemons = daemon_hits(line)
                devh = device_hint_hits(line)

                if hard or soft or daemons or devh:
                    hit_lines += 1

                for h in hard:
                    hard_counter[h] += 1
                for s in soft:
                    soft_counter[s] += 1
                for d in daemons:
                    daemon_counter[d] += 1
                for h in devh:
                    device_counter[h] += 1

                if hard:
                    hard_rows.append({
                        "file": str(path),
                        "line_no": line_no,
                        "hard_markers": ";".join(hard),
                        "soft_markers": ";".join(soft),
                        "daemons": ";".join(daemons),
                        "device_hints": ";".join(devh),
                        "line_short": line[:1200],
                    })
                elif soft and len(soft_rows) < 100000:
                    soft_rows.append({
                        "file": str(path),
                        "line_no": line_no,
                        "soft_markers": ";".join(soft),
                        "daemons": ";".join(daemons),
                        "device_hints": ";".join(devh),
                        "line_short": line[:900],
                    })
                elif (daemons or devh) and len(daemon_rows) < 100000:
                    daemon_rows.append({
                        "file": str(path),
                        "line_no": line_no,
                        "daemons": ";".join(daemons),
                        "device_hints": ";".join(devh),
                        "line_short": line[:800],
                    })

            file_rows.append({
                "file": str(path),
                "size": path.stat().st_size,
                "line_count": line_count,
                "hit_lines": hit_lines,
                "date_counts": ";".join([f"{k}:{v}" for k, v in date_counter.most_common()]),
                "hard_marker_counts": ";".join([f"{k}:{v}" for k, v in hard_counter.most_common()]),
                "soft_marker_counts": ";".join([f"{k}:{v}" for k, v in soft_counter.most_common()]),
                "daemon_counts": ";".join([f"{k}:{v}" for k, v in daemon_counter.most_common()]),
                "device_hint_counts": ";".join([f"{k}:{v}" for k, v in device_counter.most_common()]),
                "sha256": sha256_file(path),
            })

        except Exception as e:
            errors.append({
                "file": str(path),
                "error": str(e),
            })

    write_csv(OUT_DIR / "31d1_file_scan_summary.csv", file_rows)
    write_csv(OUT_DIR / "31d2_hard_marker_rows.csv", hard_rows)
    write_csv(OUT_DIR / "31d3_soft_marker_rows.csv", soft_rows)
    write_csv(OUT_DIR / "31d4_daemon_device_context_rows.csv", daemon_rows)
    write_csv(OUT_DIR / "00_scan_errors.csv", errors)

    return file_rows, hard_rows, soft_rows, daemon_rows, errors


def parse_counts(s):
    c = Counter()
    if not s:
        return c
    for part in str(s).split(";"):
        if not part:
            continue
        if ":" in part:
            k, v = part.rsplit(":", 1)
            try:
                c[k] += int(float(v))
            except Exception:
                c[k] += 1
        else:
            c[part] += 1
    return c


def build_summary(file_rows, hard_rows, soft_rows, daemon_rows, errors, candidate_rows):
    hard_total = Counter()
    soft_total = Counter()
    daemon_total = Counter()
    device_total = Counter()
    dates = Counter()

    total_lines = 0
    total_hit_lines = 0

    for r in file_rows:
        total_lines += int(float(r.get("line_count") or 0))
        total_hit_lines += int(float(r.get("hit_lines") or 0))
        hard_total.update(parse_counts(r.get("hard_marker_counts", "")))
        soft_total.update(parse_counts(r.get("soft_marker_counts", "")))
        daemon_total.update(parse_counts(r.get("daemon_counts", "")))
        device_total.update(parse_counts(r.get("device_hint_counts", "")))
        dates.update(parse_counts(r.get("date_counts", "")))

    hard_hits = sum(hard_total.values())
    soft_hits = sum(soft_total.values())
    scanned = len(file_rows)

    if not INPUT_ROOT.exists():
        verdict = "MINI1G_ROOT_NOT_FOUND"
        strength = "NONE"
        score = 0
    elif scanned == 0:
        verdict = "MINI1G_ROOT_FOUND_BUT_NO_EXTRACTED_LOG_FILES"
        strength = "NONE"
        score = 0
    elif hard_hits == 0:
        verdict = "LOW_EXPOSURE_BASELINE_NO_HARD_SC_MARKERS"
        strength = "STRONG_BASELINE"
        score = 80
    elif hard_hits <= 3:
        verdict = "BASELINE_HAS_FEW_HARD_MARKERS_REVIEW_REQUIRED"
        strength = "MEDIUM_BASELINE_REVIEW"
        score = 65
    else:
        verdict = "BASELINE_CONTAMINATED_OR_NOT_LOW_EXPOSURE"
        strength = "WEAK"
        score = 45

    archive_count = sum(1 for r in candidate_rows if r.get("reason") == "archive_not_scanned")
    nonscan_count = sum(1 for r in candidate_rows if str(r.get("scan")).lower() != "true")

    summary = {
        "baseline_subject": "mini1G",
        "input_root": str(INPUT_ROOT),
        "baseline_type": "low-exposure baseline / not clean control",
        "candidate_files": len(candidate_rows),
        "archive_files_not_scanned": archive_count,
        "non_scanned_files": nonscan_count,
        "files_scanned": scanned,
        "scan_errors": len(errors),
        "total_lines": total_lines,
        "total_hit_lines": total_hit_lines,
        "hard_sc_marker_hits": hard_hits,
        "soft_marker_hits": soft_hits,
        "hard_marker_counts": ";".join([f"{k}:{v}" for k, v in hard_total.most_common()]),
        "soft_marker_counts": ";".join([f"{k}:{v}" for k, v in soft_total.most_common()]),
        "daemon_counts": ";".join([f"{k}:{v}" for k, v in daemon_total.most_common(60)]),
        "device_hint_counts": ";".join([f"{k}:{v}" for k, v in device_total.most_common()]),
        "date_coverage": ";".join([f"{k}:{v}" for k, v in dates.most_common()]),
        "baseline_verdict": verdict,
        "baseline_strength": strength,
        "suggested_baseline_control_score": score,
        "boundary": "clean controlではない。C:\\Users\\Administrator\\Desktop\\mini1G 配下のみを読む完全やり直し版。",
    }

    write_csv(OUT_DIR / "31d5_mini1g_final_baseline_summary.csv", [summary])
    write_csv(OUT_DIR / "31d6_baseline_score_reference.csv", [{
        "baseline_subject": "mini1G",
        "suggested_baseline_control_score": score,
        "verdict": verdict,
        "reason": f"hard_sc_marker_hits={hard_hits}, files_scanned={scanned}",
        "note": "24c/33へ反映する参考。clean controlではない。",
    }])

    return summary


def boundary_statement():
    rows = [
        {
            "項目": "入力",
            "内容": r"C:\Users\Administrator\Desktop\mini1G 配下のみ読む。他のDevice-Logsは一切読まない。",
        },
        {
            "項目": "ZIP扱い",
            "内容": "ZIPは読まない。展開済みログだけ読む。",
        },
        {
            "項目": "採用条件",
            "内容": "CORE_OF_CORE_JOKER_FINAL / BC_DAEMON_SEAM / B_DAEMON_TO_USAGE / C_SIMULTANEOUS / Remote Command候補が出ないこと。",
        },
        {
            "項目": "禁止表現",
            "内容": "clean control / 正常対照 / 完全正常端末とは書かない。",
        },
        {
            "項目": "正しい表現",
            "内容": "low-exposure baseline / initial baseline / baseline control / baseline対照。",
        },
        {
            "項目": "境界",
            "内容": "mini1Gが完全安全・完全非侵害であるとは言わない。初期baselineとして使う。",
        },
    ]
    write_csv(OUT_DIR / "31d7_final_baseline_boundary_statement.csv", rows)
    return rows


def sha_manifest():
    rows = []
    for p in sorted(OUT_DIR.rglob("*")):
        if p.is_file() and p.name != "31d_SHA256_MANIFEST.csv":
            rows.append({
                "relative_path": p.relative_to(OUT_DIR).as_posix(),
                "size": p.stat().st_size,
                "sha256": sha256_file(p),
            })
    write_csv(OUT_DIR / "31d_SHA256_MANIFEST.csv", rows)
    return rows


def main():
    os.environ["PYTHONIOENCODING"] = "utf-8"
    mkdir(OUT_DIR)

    print("=== 31d MINI1G BASELINE FINAL ===")
    print("INPUT:", INPUT_ROOT)
    print("OUT:", OUT_DIR)

    input_check = [{
        "key": "INPUT_ROOT",
        "path": str(INPUT_ROOT),
        "exists": INPUT_ROOT.exists(),
    }]
    write_csv(OUT_DIR / "00_input_check.csv", input_check)

    files, candidate_rows = collect_files()
    file_rows, hard_rows, soft_rows, daemon_rows, errors = scan_files(files)
    summary = build_summary(file_rows, hard_rows, soft_rows, daemon_rows, errors, candidate_rows)
    boundary = boundary_statement()
    sha = sha_manifest()

    master = {
        "created_at": datetime.now().isoformat(sep=" ", timespec="seconds"),
        "out_dir": str(OUT_DIR),
        "input_root": str(INPUT_ROOT),
        "files_scanned": len(files),
        "scan_errors": len(errors),
        "baseline_summary": summary,
        "boundary": {
            "complete_rewrite": True,
            "only_reads_desktop_mini1G": True,
            "does_not_read_Device_Logs": True,
            "does_not_scan_zip": True,
            "clean_control": False,
            "baseline_type": "low-exposure baseline",
            "does_not_prove_device_clean": True,
        },
        "sha_rows": len(sha),
    }
    write_json(OUT_DIR / "31d_MASTER_SUMMARY.json", master)

    print("files_scanned:", len(files))
    print("scan_errors:", len(errors))
    print("hard_sc_marker_hits:", summary.get("hard_sc_marker_hits"))
    print("baseline_verdict:", summary.get("baseline_verdict"))
    print("summary:", OUT_DIR / "31d_MASTER_SUMMARY.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
