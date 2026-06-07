# -*- coding: utf-8 -*-
import csv
import hashlib
import json
import os
import shutil
import sys
import zipfile
from datetime import datetime
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# ============================================================
# 34_REPO_LITE_PACKAGE
# GitHub投入用 lightweight repo package
#
# 入力:
#   C:\Users\Administrator\Desktop\Result\SC_Final_33b_RECONSTRUCTION_SEAL_FIXED
#
# 出力:
#   C:\Users\Administrator\Desktop\Result\SC_Repo_34_LITE_PACKAGE
#
# 方針:
#   - 33b final packageをrepo用に軽量化
#   - 巨大CSV/KEY_SOURCE_COPIESの大容量ファイルはコピーしない
#   - 代わりにmanifestへ source path / size / sha256 を残す
#   - read-only. input側は移動/削除/リネーム/編集しない
# ============================================================

DESKTOP = Path(r"C:\Users\Administrator\Desktop")
RESULT_BASE = DESKTOP / "Result"
SRC33B = RESULT_BASE / "SC_Final_33b_RECONSTRUCTION_SEAL_FIXED"

OUT_DIR = RESULT_BASE / "SC_Repo_34_LITE_PACKAGE"
PKG_DIR = OUT_DIR / "shadow-cloud-reconstruction-score-lite"
ZIP_PATH = OUT_DIR / "shadow-cloud-reconstruction-score-lite.zip"

MAX_COPY_MB = 8
MAX_COPY_BYTES = MAX_COPY_MB * 1024 * 1024

TEXT_EXTS = {".csv", ".json", ".md", ".yaml", ".yml", ".txt"}
ALWAYS_KEEP_NAMES = {
    "33b_README_REPO_DRAFT.md",
    "33b_f_public_summary_ja.md",
    "33b_g_machine_summary.yaml",
    "33b_b_final_reconstruction_score.csv",
    "33b_c_final_verdict_table.csv",
    "33b_d_source_adoption_register.csv",
    "33b_e_final_guardrails.csv",
    "33b_h_final_falsification_shortlist.csv",
    "33b_i_key_source_copies.csv",
    "33b_j_v1_fix_report.csv",
    "33b_MASTER_SUMMARY.json",
}
SKIP_DIR_NAMES = {"__pycache__"}


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


def safe_copy(src, dst):
    mkdir(dst.parent)
    shutil.copy2(src, dst)


def should_copy(src):
    if src.suffix.lower() not in TEXT_EXTS:
        return False, "non_text_extension"

    if any(part in SKIP_DIR_NAMES for part in src.parts):
        return False, "skip_dir"

    try:
        size = src.stat().st_size
    except Exception:
        return False, "stat_error"

    if src.name in ALWAYS_KEEP_NAMES and size <= MAX_COPY_BYTES:
        return True, "always_keep"

    if size > MAX_COPY_BYTES:
        return False, "too_large"

    # KEY_SOURCE_COPIESは小さいものだけ残す
    if "KEY_SOURCE_COPIES" in src.parts:
        return True, "key_source_small_copy"

    return True, "normal_text_copy"


def reset_out():
    if PKG_DIR.exists():
        shutil.rmtree(PKG_DIR)
    mkdir(PKG_DIR)
    mkdir(OUT_DIR)


def write_repo_skeleton():
    (PKG_DIR / ".gitignore").write_text(
        "\n".join([
            "*.zip",
            "__pycache__/",
            "*.pyc",
            "_local/",
            "large_files/",
            "",
        ]),
        encoding="utf-8"
    )

    mkdir(PKG_DIR / "docs")
    mkdir(PKG_DIR / "data")
    mkdir(PKG_DIR / "manifests")

    license_text = """Non-Attribution Forensic Research Package

This repository package is provided for forensic review, reproducibility discussion,
and falsification-oriented analysis. It does not claim attribution to any actor,
state, vendor, spyware family, telecom provider, or known intrusion set.
"""
    (PKG_DIR / "NOTICE.md").write_text(license_text, encoding="utf-8")


def copy_selected_files():
    copied = []
    skipped = []

    if not SRC33B.exists():
        raise RuntimeError(f"SRC33B not found: {SRC33B}")

    for src in sorted(SRC33B.rglob("*")):
        if not src.is_file():
            continue

        rel = src.relative_to(SRC33B)
        ok, reason = should_copy(src)
        size = src.stat().st_size

        if ok:
            dst = PKG_DIR / "data" / rel
            safe_copy(src, dst)
            copied.append({
                "relative_path": rel.as_posix(),
                "copied_to": str(dst.relative_to(PKG_DIR)),
                "size": size,
                "sha256": sha256_file(src),
                "reason": reason,
            })
        else:
            skipped.append({
                "relative_path": rel.as_posix(),
                "source_path": str(src),
                "size": size,
                "sha256": sha256_file(src) if src.exists() else "",
                "reason": reason,
            })

    write_csv(PKG_DIR / "manifests" / "copied_files_manifest.csv", copied)
    write_csv(PKG_DIR / "manifests" / "skipped_large_or_nonrepo_files_manifest.csv", skipped)
    return copied, skipped


def promote_readmes():
    # 33bのREADMEをrepo rootへコピー
    mappings = [
        ("data/33b_README_REPO_DRAFT.md", "README.md"),
        ("data/33b_f_public_summary_ja.md", "docs/public_summary_ja.md"),
        ("data/33b_g_machine_summary.yaml", "docs/machine_summary.yaml"),
        ("data/33b_b_final_reconstruction_score.csv", "docs/final_reconstruction_score.csv"),
        ("data/33b_c_final_verdict_table.csv", "docs/final_verdict_table.csv"),
        ("data/33b_e_final_guardrails.csv", "docs/final_guardrails.csv"),
        ("data/33b_h_final_falsification_shortlist.csv", "docs/final_falsification_shortlist.csv"),
    ]

    promoted = []
    for src_rel, dst_rel in mappings:
        src = PKG_DIR / src_rel
        dst = PKG_DIR / dst_rel
        if src.exists():
            safe_copy(src, dst)
            promoted.append({
                "from": src_rel,
                "to": dst_rel,
                "sha256": sha256_file(dst),
                "size": dst.stat().st_size,
            })

    write_csv(PKG_DIR / "manifests" / "promoted_readme_docs_manifest.csv", promoted)
    return promoted


def write_package_summary(copied, skipped, promoted):
    large_skipped = [r for r in skipped if r["reason"] == "too_large"]

    summary = {
        "created_at": datetime.now().isoformat(sep=" ", timespec="seconds"),
        "package": "shadow-cloud-reconstruction-score-lite",
        "source": str(SRC33B),
        "out_dir": str(OUT_DIR),
        "max_copy_mb": MAX_COPY_MB,
        "copied_files": len(copied),
        "skipped_files": len(skipped),
        "large_skipped_files": len(large_skipped),
        "promoted_docs": len(promoted),
        "boundary": {
            "lite_package": True,
            "large_files_not_copied": True,
            "large_files_recorded_in_manifest": True,
            "not_attribution": True,
            "no_c2_claim": True,
            "no_clean_control_claim": True,
        }
    }
    write_json(PKG_DIR / "manifests" / "repo_lite_package_summary.json", summary)

    rows = [{
        "created_at": summary["created_at"],
        "source": str(SRC33B),
        "package_dir": str(PKG_DIR),
        "zip_path": str(ZIP_PATH),
        "copied_files": len(copied),
        "skipped_files": len(skipped),
        "large_skipped_files": len(large_skipped),
        "max_copy_mb": MAX_COPY_MB,
    }]
    write_csv(OUT_DIR / "34_repo_lite_summary.csv", rows)
    return summary


def zip_package():
    if ZIP_PATH.exists():
        ZIP_PATH.unlink()

    with zipfile.ZipFile(ZIP_PATH, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for p in sorted(PKG_DIR.rglob("*")):
            if p.is_file():
                arc = p.relative_to(PKG_DIR.parent).as_posix()
                z.write(p, arc)

    return {
        "zip_path": str(ZIP_PATH),
        "size": ZIP_PATH.stat().st_size,
        "sha256": sha256_file(ZIP_PATH),
    }


def write_output_manifest(zip_info):
    rows = []
    for p in sorted(OUT_DIR.rglob("*")):
        if p.is_file() and p.name != "34_OUTPUT_SHA256_MANIFEST.csv":
            rows.append({
                "relative_path": p.relative_to(OUT_DIR).as_posix(),
                "size": p.stat().st_size,
                "sha256": sha256_file(p),
            })
    write_csv(OUT_DIR / "34_OUTPUT_SHA256_MANIFEST.csv", rows)
    write_json(OUT_DIR / "34_MASTER_SUMMARY.json", {
        "created_at": datetime.now().isoformat(sep=" ", timespec="seconds"),
        "source": str(SRC33B),
        "package_dir": str(PKG_DIR),
        "zip": zip_info,
        "output_files": len(rows),
    })
    return rows


def main():
    os.environ["PYTHONIOENCODING"] = "utf-8"
    print("=== 34 REPO LITE PACKAGE ===")
    print("SRC:", SRC33B)
    print("OUT:", OUT_DIR)

    mkdir(OUT_DIR)
    reset_out()
    write_repo_skeleton()
    copied, skipped = copy_selected_files()
    promoted = promote_readmes()
    package_summary = write_package_summary(copied, skipped, promoted)
    zip_info = zip_package()
    manifest = write_output_manifest(zip_info)

    print("copied_files:", len(copied))
    print("skipped_files:", len(skipped))
    print("large_skipped_files:", package_summary["large_skipped_files"])
    print("zip:", zip_info["zip_path"])
    print("zip_size:", zip_info["size"])
    print("summary:", OUT_DIR / "34_MASTER_SUMMARY.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
