#!/usr/bin/env python3
"""
Enrichment (Post-Processing) for External Benign Corpus

Re-scans sample texts and enriches metadata.csv with:
- Language detection (langid/fasttext)
- Telemetry features (has_codefence, num_calls, etc.)
- Network API heuristics
- Exec context heuristic

Idempotent, deterministic, read-only on samples.
"""

import csv
import sys
import argparse
import unicodedata
import re
import hashlib
import time
from pathlib import Path

# Optional deps guarded
try:
    import langid  # pip install langid
except Exception:
    langid = None

# Patterns
FENCE_RE = re.compile(r"(^|\n)```[^\n]*\n[\s\S]*?\n```", re.MULTILINE)
CALL_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\s*\(", re.ASCII)
JS_ATTR_RE = re.compile(r"\bon[a-zA-Z]+\s*=", re.IGNORECASE)
URL_SCHEME_RE = re.compile(r"\b(?:https?|javascript):", re.IGNORECASE)
SQL_TOKEN_RE = re.compile(r"\b(select|insert|update|delete|drop|create|alter)\b", re.IGNORECASE)
B64_LIKE_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")

# Light-weight net API hints
NET_API_TOKENS = [
    # HTTP clients
    "fetch(", "XMLHttpRequest(", "axios.", "requests.", "http.client", "curl ",
    # DB/SQL drivers
    "jdbc:", "psycopg2", "mysql.connector", "pymongo", "sqlalchemy", "odbc", "pg_",
    # Cloud SDK hints
    "boto3.", "google.cloud.", "azure.storage.", "kubernetes.client",
]

RISKY_KW = ["alert", "eval", "exec", "system", "javascript", "onload", "onclick"]


def normalize(text: str) -> str:
    """NFKC + zero-width stripping"""
    t = unicodedata.normalize("NFKC", text)
    return t.replace("\u200b", "").replace("\u200c", "").replace("\u200d", "")


def has_codefence(text: str) -> bool:
    return bool(FENCE_RE.search(text))


def count_calls(text: str) -> int:
    return len(CALL_RE.findall(text))


def has_js_attr(text: str) -> bool:
    return bool(JS_ATTR_RE.search(text))


def has_urlscheme(text: str) -> bool:
    return bool(URL_SCHEME_RE.search(text))


def contains_sql_tokens(text: str) -> bool:
    return bool(SQL_TOKEN_RE.search(text))


def contains_base64_like(text: str) -> bool:
    return bool(B64_LIKE_RE.search(text))


def min_distance_to_call(text: str, risky_kw: list) -> int:
    """Minimal char distance from risky keywords to nearest call"""
    idx_calls = [m.start() for m in CALL_RE.finditer(text)]
    if not idx_calls:
        return -1
    best = 10**9
    for kw in risky_kw:
        start = 0
        while True:
            k = text.find(kw, start)
            if k < 0:
                break
            nearest = min(abs(k - c) for c in idx_calls)
            if nearest < best:
                best = nearest
            start = k + len(kw)
    return -1 if best == 10**9 else best


def detect_lang(text: str, fallback: str = "en") -> str:
    """Language detection via langid"""
    if langid is None:
        return fallback
    try:
        code, _ = langid.classify(text[:8000])
        return code or fallback
    except Exception:
        return fallback


def has_net_api(text: str) -> bool:
    """Check for network/DB API patterns"""
    low = text.lower()
    return any(tok in low for tok in NET_API_TOKENS)


def exec_ctx_heuristic(meta: dict) -> int:
    """Exec context heuristic (identical to collection logic)"""
    return int(
        meta["has_codefence"] and (
            meta["has_js_attr"] or 
            meta["contains_urlscheme"] or 
            meta["num_calls"] >= 2 or 
            meta["has_net_api"]
        )
    )


def parse_args():
    ap = argparse.ArgumentParser(description="Enrich external benign metadata")
    ap.add_argument("--root", default="external_benign", help="external_benign root")
    ap.add_argument("--in-csv", default="indexes/metadata.csv", help="relative metadata csv")
    ap.add_argument("--out-csv", default="indexes/metadata_enriched.csv", help="relative output csv")
    ap.add_argument("--recompute-hash", action="store_true", help="recompute tlsh/simhash")
    return ap.parse_args()


def main():
    args = parse_args()
    root = Path(args.root)
    in_csv = root / args.in_csv
    out_csv = root / args.out_csv
    
    if not in_csv.exists():
        print(f"ERROR: {in_csv} not found", file=sys.stderr)
        return 2
    
    rows = []
    processed = 0
    
    print(f"Reading metadata from: {in_csv}")
    
    with in_csv.open("r", encoding="utf-8", newline="") as f:
        rdr = csv.DictReader(f)
        for r in rdr:
            processed += 1
            
            if processed % 100 == 0:
                print(f"  Processed: {processed}")
            
            p = root / r["path"]
            if not p.exists():
                # skip missing
                print(f"  WARNING: Missing file: {p}")
                continue
            
            txt = p.read_text(encoding="utf-8", errors="ignore")
            t = normalize(txt)
            
            # Compute enriched metadata
            meta = {}
            meta["lang"] = detect_lang(t, fallback=(r.get("lang") or "en"))
            meta["has_codefence"] = int(has_codefence(t))
            meta["num_calls"] = count_calls(t)
            meta["has_js_attr"] = int(has_js_attr(t))
            meta["contains_urlscheme"] = int(has_urlscheme(t))
            meta["contains_sql_tokens"] = int(contains_sql_tokens(t))
            meta["contains_base64_like"] = int(contains_base64_like(t))
            meta["min_distance_to_call"] = min_distance_to_call(t, RISKY_KW)
            meta["has_net_api"] = int(has_net_api(t))
            meta["exec_ctx"] = exec_ctx_heuristic(meta)
            
            # Update/override fields
            r["lang"] = meta["lang"]
            for k, v in meta.items():
                r[k] = v
            
            # Recompute length to be safe
            r["bytes"] = len(t.encode("utf-8"))
            r["chars"] = len(t)
            
            rows.append(r)
    
    if not rows:
        print("ERROR: No rows to write.", file=sys.stderr)
        return 3
    
    # Stable field order
    FIELDNAMES = [
        "id", "source", "license", "lang", "class_label", "path",
        "bytes", "chars",
        "has_codefence", "exec_ctx", "has_net_api", "has_js_attr",
        "num_calls", "min_distance_to_call",
        "contains_sql_tokens", "contains_base64_like", "contains_urlscheme",
        "hash_tlsh", "simhash64", "duplicate_group", "excluded_topics", "created_at_utc",
    ]
    
    # Add any extra keys gracefully
    all_keys = set().union(*(r.keys() for r in rows))
    for k in FIELDNAMES:
        all_keys.discard(k)
    FIELDNAMES += sorted(all_keys)
    
    # Write enriched CSV
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDNAMES)
        w.writeheader()
        for r in rows:
            w.writerow(r)
    
    print(f"\nEnrichment complete!")
    print(f"  Processed: {len(rows)} samples")
    print(f"  Output: {out_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

