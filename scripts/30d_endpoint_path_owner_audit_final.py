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

RESULT_BASE = Path(r"C:\Users\Administrator\Desktop\Result")
SRC30B = RESULT_BASE / "SC_Endpoint_30b_STRICT_DEDUP"
SRC30C = RESULT_BASE / "SC_Endpoint_30c_TARGET_REJOIN"
OUT_DIR = RESULT_BASE / "SC_Endpoint_30d_PATH_OWNER_AUDIT_FINAL"

TARGETS = [
    ("15G", "C2026MAR_A"),
    ("15G", "C2026MARAPR_B"),
    ("mini1", "C2025AUG"),
]

TARGET_DEVICE_HINTS = {
    "15G": [
        r"\15g\\", r"/15g/", r"\15-g\\", r"/15-g/", r"\15_g\\", r"/15_g/",
        "15ghost", "15 ghost", "iphone15g"
    ],
    "mini1": [
        r"\mini1\\", r"/mini1/", r"\mini-1\\", r"/mini-1/", r"\mini_1\\", r"/mini_1/",
        "mini1", "mini-1", "mini_1"
    ],
    "mini2": [
        r"\mini2\\", r"/mini2/", r"\mini-2\\", r"/mini-2/", r"\mini_2\\", r"/mini_2/"
    ],
    "12G": [
        r"\12g\\", r"/12g/", r"\12-g\\", r"/12-g/", r"\12_g\\", r"/12_g/",
        "12ghost"
    ],
    "iPhone11Pro": [
        "iphone11pro", "iphone11 pro", "11pro", "11 pro"
    ],
    "iPad": [
        r"\ipad\\", r"/ipad/"
    ],
}

EXTERNAL_HINTS = {
    "Ngoc": [
        r"\ngoc\\", r"/ngoc/", " ngoc ",
        "iphone12 pro max", "iphone12promax",
        "iphone6s plus", "iphone6splus",
    ],
    "HaThao": [
        r"\ha thao\\", r"/ha thao/", r"\hathao\\", r"/hathao/",
        "ha thao", "hathao"
    ],
    "Ibuki": [
        r"\ibuki\\", r"/ibuki/", " ibuki "
    ],
    "Vy": [
        r"\vy\\", r"/vy/", " vy "
    ],
    "HaThao_Mother": [
        "ha thao mother", "hathao mother", "hathaomother"
    ],
}

FOCUS_DATE_RANGES = {
    "C2026MAR_A": ("2026-03-15", "2026-03-21"),
    "C2026MARAPR_B": ("2026-03-28", "2026-04-04"),
    "C2025AUG": ("2025-08-04", "2025-08-10"),
}

DATE_RE = re.compile(r"(20\d{2}-\d{2}-\d{2})")
COMPACT_DATE_RE = re.compile(r"(20\d{2})(\d{2})(\d{2})")
PATH_RE = re.compile(r"([A-Za-z]:\\[^,;\"'\]\)\s]{8,}|/[A-Za-z0-9_\- ./]+/[^\s,;\"'\]\)]{3,})")


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


def row_text(row):
    return " ".join([str(k) + "=" + str(v) for k, v in row.items() if v is not None])


def normalize_text(s):
    return str(s or "").replace("/", "\\").lower()


def extract_dates(text):
    out = set()
    for m in DATE_RE.finditer(text):
        out.add(m.group(1))
    for m in COMPACT_DATE_RE.finditer(text):
        out.add(f"{m.group(1)}-{m.group(2)}-{m.group(3)}")
    return sorted(out)


def extract_paths(text):
    vals = []
    for m in PATH_RE.finditer(text):
        vals.append(m.group(1))
    return vals[:20]


def date_in_focus(date_str, focus):
    if focus not in FOCUS_DATE_RANGES:
        return False
    start, end = FOCUS_DATE_RANGES[focus]
    return start <= date_str <= end


def find_hint_hits(text, hint_map):
    low = normalize_text(text)
    hits = []
    for owner, hints in hint_map.items():
        for h in hints:
            hh = normalize_text(h)
            if hh in low:
                hits.append(owner)
                break
    return sorted(set(hits))


def infer_path_owner(row):
    text = row_text(row)
    candidate_paths = extract_paths(text)
    path_text = " ".join(candidate_paths) if candidate_paths else text

    target_hits = find_hint_hits(path_text, TARGET_DEVICE_HINTS)
    external_hits = find_hint_hits(path_text, EXTERNAL_HINTS)

    # If path extraction missed owner, retry whole row.
    if not target_hits:
        target_hits = find_hint_hits(text, TARGET_DEVICE_HINTS)
    if not external_hits:
        external_hits = find_hint_hits(text, EXTERNAL_HINTS)

    return target_hits, external_hits, candidate_paths


def audit_class(row):
    target_device = row.get("rejoined_target_device") or row.get("target_device") or ""
    focus = row.get("rejoined_focus") or row.get("focus") or ""
    target_hits, external_hits, candidate_paths = infer_path_owner(row)

    target_match = target_device in target_hits
    other_target_hits = [x for x in target_hits if x != target_device]
    has_external = len(external_hits) > 0

    # date check
    dates = extract_dates(row_text(row))
    focus_date_match = any(date_in_focus(d, focus) for d in dates) if focus else False

    if target_match and not has_external and not other_target_hits:
        cls = "TARGET_PATH_ONLY"
        usable = True
    elif has_external and not target_match:
        cls = "EXTERNAL_SUPPORT"
        usable = False
    elif has_external and target_match:
        cls = "MIXED_TARGET_EXTERNAL"
        usable = False
    elif other_target_hits and not target_match:
        cls = "PATH_TARGET_MISMATCH"
        usable = False
    elif not target_hits and not external_hits:
        cls = "UNKNOWN_PATH"
        usable = False
    else:
        cls = "OTHER_REVIEW"
        usable = False

    rr = dict(row)
    rr["audit_target_device"] = target_device
    rr["audit_focus"] = focus
    rr["path_target_hits"] = ";".join(target_hits)
    rr["path_external_hits"] = ";".join(external_hits)
    rr["candidate_paths"] = ";".join(candidate_paths[:5])
    rr["focus_date_match"] = focus_date_match
    rr["path_audit_class"] = cls
    rr["final_target_endpoint_usable"] = usable
    rr["final_cluster_support_only"] = cls in {"EXTERNAL_SUPPORT", "MIXED_TARGET_EXTERNAL"}
    rr["final_reject_or_review"] = cls in {"PATH_TARGET_MISMATCH", "UNKNOWN_PATH", "OTHER_REVIEW"}
    return rr


def split_counts(s):
    c = Counter()
    if not s:
        return c
    for part in str(s).split(";"):
        if not part:
            continue
        if ":" in part:
            k, v = part.rsplit(":", 1)
            try:
                c[k.strip()] += int(float(v))
            except Exception:
                c[k.strip()] += 1
        else:
            c[part.strip()] += 1
    return c


def summarize(audited):
    summary = defaultdict(lambda: {
        "class": Counter(),
        "endpoints": Counter(),
        "daemons": Counter(),
        "external": Counter(),
        "usable_rows": 0,
        "cluster_rows": 0,
        "review_rows": 0,
        "total": 0,
    })

    for r in audited:
        dev = r.get("audit_target_device", "")
        focus = r.get("audit_focus", "")
        key = f"{dev}/{focus}" if dev and focus else "UNRESOLVED"
        a = summary[key]
        a["total"] += 1
        a["class"][r.get("path_audit_class", "")] += 1
        ep = str(r.get("endpoint", "")).lower().strip()
        if ep:
            a["endpoints"][ep] += 1
        for d, n in split_counts(r.get("daemons", "")).items():
            a["daemons"][d] += n
        for e in str(r.get("path_external_hits", "")).split(";"):
            if e:
                a["external"][e] += 1
        if str(r.get("final_target_endpoint_usable")).lower() == "true":
            a["usable_rows"] += 1
        if str(r.get("final_cluster_support_only")).lower() == "true":
            a["cluster_rows"] += 1
        if str(r.get("final_reject_or_review")).lower() == "true":
            a["review_rows"] += 1

    rows = []
    expected = [f"{d}/{f}" for d, f in [(x[0], x[1]) for x in TARGETS]]
    for key in expected + [k for k in sorted(summary.keys()) if k not in expected]:
        a = summary[key]
        rows.append({
            "target_focus": key,
            "total_rows": a["total"],
            "usable_target_rows": a["usable_rows"],
            "cluster_support_rows": a["cluster_rows"],
            "review_or_reject_rows": a["review_rows"],
            "class_counts": ";".join([f"{k}:{v}" for k, v in a["class"].most_common()]),
            "top_usable_or_seen_endpoints": ";".join([f"{k}:{v}" for k, v in a["endpoints"].most_common(30)]),
            "top_daemons": ";".join([f"{k}:{v}" for k, v in a["daemons"].most_common(30)]),
            "external_owners": ";".join([f"{k}:{v}" for k, v in a["external"].most_common()]),
        })
    return rows


def summarize_daemon_endpoint(audited, usable_only=True):
    mx = defaultdict(Counter)
    counts = defaultdict(int)
    for r in audited:
        if usable_only and str(r.get("final_target_endpoint_usable")).lower() != "true":
            continue
        ep = str(r.get("endpoint", "")).lower().strip()
        if not ep:
            continue
        for d, n in split_counts(r.get("daemons", "")).items():
            mx[d][ep] += n
            counts[d] += n

    rows = []
    for d, c in mx.items():
        rows.append({
            "daemon": d,
            "endpoint_refs": counts[d],
            "unique_endpoints": len(c),
            "top_endpoints": ";".join([f"{k}:{v}" for k, v in c.most_common(30)]),
        })
    rows.sort(key=lambda r: int(r["endpoint_refs"]), reverse=True)
    return rows


def summarize_external(audited):
    ext = defaultdict(lambda: {
        "rows": 0,
        "endpoints": Counter(),
        "targets": Counter(),
        "daemons": Counter(),
    })
    for r in audited:
        owners = [x for x in str(r.get("path_external_hits", "")).split(";") if x]
        if not owners:
            continue
        ep = str(r.get("endpoint", "")).lower().strip()
        target = f"{r.get('audit_target_device','')}/{r.get('audit_focus','')}"
        for owner in owners:
            ext[owner]["rows"] += 1
            if ep:
                ext[owner]["endpoints"][ep] += 1
            ext[owner]["targets"][target] += 1
            for d, n in split_counts(r.get("daemons", "")).items():
                ext[owner]["daemons"][d] += n

    rows = []
    for owner, a in ext.items():
        rows.append({
            "external_owner": owner,
            "rows": a["rows"],
            "targets": ";".join([f"{k}:{v}" for k, v in a["targets"].most_common()]),
            "top_endpoints": ";".join([f"{k}:{v}" for k, v in a["endpoints"].most_common(30)]),
            "top_daemons": ";".join([f"{k}:{v}" for k, v in a["daemons"].most_common(30)]),
        })
    rows.sort(key=lambda r: int(r["rows"]), reverse=True)
    return rows


def sha_manifest():
    rows = []
    for p in sorted(OUT_DIR.rglob("*")):
        if p.is_file() and p.name != "30d_SHA256_MANIFEST.csv":
            rows.append({
                "relative_path": p.relative_to(OUT_DIR).as_posix(),
                "size": p.stat().st_size,
                "sha256": sha256_file(p),
            })
    write_csv(OUT_DIR / "30d_SHA256_MANIFEST.csv", rows)
    return rows


def main():
    os.environ["PYTHONIOENCODING"] = "utf-8"
    mkdir(OUT_DIR)

    print("=== SC Endpoint 30d Path Owner Audit Final ===")
    print("SRC30C:", SRC30C)
    print("OUT:", OUT_DIR)

    input_rows = [
        {"key": "SRC30B", "path": str(SRC30B), "exists": SRC30B.exists()},
        {"key": "SRC30C", "path": str(SRC30C), "exists": SRC30C.exists()},
        {"key": "30c1", "path": str(SRC30C / "30c1_rejoined_keep_endpoint_rows.csv"), "exists": (SRC30C / "30c1_rejoined_keep_endpoint_rows.csv").exists()},
    ]
    write_csv(OUT_DIR / "00_input_check.csv", input_rows)

    rows = read_csv(SRC30C / "30c1_rejoined_keep_endpoint_rows.csv")
    if not rows:
        print("[ERROR] 30c1_rejoined_keep_endpoint_rows.csv missing or empty")
        return 1

    audited = [audit_class(r) for r in rows]

    target_only = [r for r in audited if str(r.get("final_target_endpoint_usable")).lower() == "true"]
    cluster_support = [r for r in audited if str(r.get("final_cluster_support_only")).lower() == "true"]
    mismatch = [r for r in audited if r.get("path_audit_class") == "PATH_TARGET_MISMATCH"]
    unknown = [r for r in audited if r.get("path_audit_class") == "UNKNOWN_PATH"]
    review = [r for r in audited if str(r.get("final_reject_or_review")).lower() == "true"]

    write_csv(OUT_DIR / "30d1_path_owner_audited_rows.csv", audited)
    write_csv(OUT_DIR / "30d2_final_target_only_endpoint_rows.csv", target_only)
    write_csv(OUT_DIR / "30d3_external_cluster_support_endpoint_rows.csv", cluster_support)
    write_csv(OUT_DIR / "30d4_path_target_mismatch_rows.csv", mismatch)
    write_csv(OUT_DIR / "30d5_unknown_or_review_rows.csv", review)

    focus_summary = summarize(audited)
    daemon_target = summarize_daemon_endpoint(target_only, usable_only=False)
    daemon_cluster = summarize_daemon_endpoint(cluster_support, usable_only=False)
    external_summary = summarize_external(audited)

    write_csv(OUT_DIR / "30d6_final_focus_endpoint_summary.csv", focus_summary)
    write_csv(OUT_DIR / "30d7_final_target_daemon_endpoint_summary.csv", daemon_target)
    write_csv(OUT_DIR / "30d8_external_support_summary.csv", external_summary)
    write_csv(OUT_DIR / "30d9_external_daemon_endpoint_summary.csv", daemon_cluster)

    boundary = [
        {
            "項目": "目的",
            "内容": "30b/30cでclean化・focus再結合したendpointを、path ownerで最終監査する。",
        },
        {
            "項目": "採用",
            "内容": "TARGET_PATH_ONLYのみtarget本人endpoint文脈として採用。",
        },
        {
            "項目": "外部support",
            "内容": "EXTERNAL_SUPPORT / MIXED_TARGET_EXTERNAL はtarget単体から除外し、C2025AUG外部support等へ回す。",
        },
        {
            "項目": "不採用/要確認",
            "内容": "PATH_TARGET_MISMATCH / UNKNOWN_PATH / OTHER_REVIEW はfinal target endpoint表から除外。",
        },
        {
            "項目": "境界",
            "内容": "Apple ecosystem endpointの文脈整理であり、通信成立・C2・悪性通信・攻撃者endpointの確定ではない。",
        },
    ]
    write_csv(OUT_DIR / "30d10_final_endpoint_boundary_statement.csv", boundary)

    overview = {
        "input_30c_rows": len(rows),
        "audited_rows": len(audited),
        "target_only_rows": len(target_only),
        "external_cluster_support_rows": len(cluster_support),
        "path_target_mismatch_rows": len(mismatch),
        "unknown_or_review_rows": len(review),
        "focus_summary_rows": len(focus_summary),
        "target_daemon_summary_rows": len(daemon_target),
        "external_summary_rows": len(external_summary),
    }
    write_csv(OUT_DIR / "30d0_overview.csv", [overview])

    sha = sha_manifest()

    master = {
        "created_at": datetime.now().isoformat(sep=" ", timespec="seconds"),
        "out_dir": str(OUT_DIR),
        "overview": overview,
        "boundary": {
            "target_only_is_final_endpoint_context": True,
            "external_support_separated": True,
            "mismatch_excluded_from_final_target": True,
            "does_not_prove_c2": True,
            "does_not_prove_connection_success": True,
        },
        "sha_rows": len(sha),
    }
    write_json(OUT_DIR / "30d_MASTER_SUMMARY.json", master)

    print("target_only_rows:", len(target_only))
    print("external_cluster_support_rows:", len(cluster_support))
    print("path_target_mismatch_rows:", len(mismatch))
    print("unknown_or_review_rows:", len(review))
    print("summary:", OUT_DIR / "30d_MASTER_SUMMARY.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
