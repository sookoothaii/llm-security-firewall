#!/usr/bin/env python3
"""
External Benign Corpus Collector

Collects benign samples from external sources for domain-neutral FPR validation.
Sources: Wikipedia (CC-BY-SA), GitHub READMEs (permissive), Stack Overflow (CC-BY-SA)

Target:
- pure_doc: ≥2000 (EN 1200, DE 400, other 400)
- doc_with_codefence: ≥2000 (EN 1200, DE 400, other 400)

Gates (95% Wilson):
- pure_doc: Upper ≤ 1.50%
- doc_with_codefence: Upper ≤ 1.00%

Usage (dump-based, recommended):
    python tools/collect_external_benign.py \
      --source wikipedia \
      --mode dump --dump-path data/wikipedia_en_de_jsonl \
      --out-root external_benign \
      --languages en,de \
      --target 1200 \
      --class-quota pure_doc=600,doc_with_codefence=600 \
      --exclude-topics "security,exploit,xss,ctf,sql-injection" \
      --dedupe tlsh --dedupe-th 35 --save-raw
"""

import argparse
import json
import csv
import hashlib
import time
from pathlib import Path
from typing import Dict, List, Any, Optional, Iterator, Tuple

# Import helpers
try:
    from common_text import (
        normalize, has_codefence, count_calls, has_js_attr,
        has_urlscheme, contains_sql_tokens, contains_base64_like,
        min_distance_to_call, detect_lang
    )
except ImportError:
    # Fallback if run from different directory
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    from common_text import (
        normalize, has_codefence, count_calls, has_js_attr,
        has_urlscheme, contains_sql_tokens, contains_base64_like,
        min_distance_to_call, detect_lang
    )


def compute_tlsh(s: str) -> str:
    """Compute TLSH hash for deduplication"""
    try:
        import tlsh
        return tlsh.hash(s.encode("utf-8"))
    except Exception:
        return ""


def compute_simhash64(s: str) -> str:
    """Very small 64-bit simhash placeholder"""
    h = hashlib.blake2b(s.encode("utf-8"), digest_size=8).hexdigest()
    return h


def classify_sample(text: str) -> Tuple[str, Dict[str, Any]]:
    """
    Classify sample into categories
    
    Returns:
        (label, metadata)
    
    Labels:
    - 'pure_doc': Pure documentation without code
    - 'doc_with_codefence': Documentation with code but no exec markers
    - 'doc_with_exec': Has code + execution markers (DROP from benign)
    """
    t = normalize(text)
    meta = {}
    
    # Compute telemetry
    meta["has_codefence"] = int(has_codefence(t))
    meta["num_calls"] = count_calls(t)
    meta["has_js_attr"] = int(has_js_attr(t))
    meta["contains_urlscheme"] = int(has_urlscheme(t))
    meta["contains_sql_tokens"] = int(contains_sql_tokens(t))
    meta["contains_base64_like"] = int(contains_base64_like(t))
    meta["lang"] = detect_lang(t)
    
    # Risky keywords for distance calculation
    risky = ["alert", "eval", "exec", "system", "javascript", "onload", "onclick"]
    meta["min_distance_to_call"] = min_distance_to_call(t, risky)
    
    # Exec context heuristic
    meta["exec_ctx"] = int(
        meta["has_codefence"] and (
            meta["has_js_attr"] or 
            meta["contains_urlscheme"] or 
            meta["num_calls"] >= 2
        )
    )
    
    # Classification logic
    if meta["has_codefence"] and meta["exec_ctx"] == 0:
        label = "doc_with_codefence"
    elif (not meta["has_codefence"]) and meta["exec_ctx"] == 0 and meta["num_calls"] < 2 and (meta["contains_urlscheme"] == 0 or meta["has_js_attr"] == 0):
        label = "pure_doc"
    else:
        label = "doc_with_exec"  # will be dropped
    
    return label, meta


def candidates_from_dump(dump_path: Path) -> Iterator[Tuple[str, str, str]]:
    """
    Iterate over candidates from dump files
    
    Expects JSONL files with: {"id": ..., "title": ..., "text": ...}
    
    Yields:
        (id, title, text)
    """
    for fp in dump_path.rglob("*.jsonl"):
        print(f"Reading dump: {fp}")
        with fp.open("r", encoding="utf-8") as f:
            for line in f:
                try:
                    obj = json.loads(line)
                    yield (
                        obj.get("id", ""),
                        obj.get("title", ""),
                        obj.get("text", "")
                    )
                except json.JSONDecodeError:
                    continue


def main():
    ap = argparse.ArgumentParser(description="Collect external benign corpus")
    ap.add_argument("--source", required=True, 
                    choices=["wikipedia", "github", "stackoverflow", "from-dir"],
                    help="Data source")
    ap.add_argument("--out-root", required=True, 
                    help="Output root directory")
    ap.add_argument("--languages", default="en,de,other",
                    help="Comma-separated language codes")
    ap.add_argument("--target", type=int, required=True,
                    help="Total number of benign samples to collect")
    ap.add_argument("--class-quota", default="",
                    help="Per-class quotas (e.g. pure_doc=600,doc_with_codefence=600)")
    ap.add_argument("--min-bytes", type=int, default=300,
                    help="Minimum text length in bytes")
    ap.add_argument("--max-bytes", type=int, default=8000,
                    help="Maximum text length in bytes")
    ap.add_argument("--dedupe", choices=["tlsh", "simhash", "none"], default="tlsh",
                    help="Deduplication method")
    ap.add_argument("--dedupe-th", type=int, default=35,
                    help="TLSH distance threshold")
    ap.add_argument("--exclude-topics", default="security,exploit,xss,ctf,sql-injection",
                    help="Comma-separated topic exclusions")
    ap.add_argument("--mode", choices=["live", "dump"], default="dump",
                    help="Collection mode (dump recommended)")
    ap.add_argument("--dump-path", default="",
                    help="Path to dump files (for mode=dump)")
    ap.add_argument("--license-note", default="CC-BY-SA 4.0",
                    help="License string for metadata")
    ap.add_argument("--save-raw", action="store_true",
                    help="Save raw source payloads")
    ap.add_argument("--seed", type=int, default=42,
                    help="Random seed")
    ap.add_argument("--max-per-source", type=int, default=10000,
                    help="Hard cap per source")
    
    args = ap.parse_args()
    
    # Create output structure
    out = Path(args.out_root)
    (out / "raw").mkdir(parents=True, exist_ok=True)
    (out / "samples" / "pure_doc").mkdir(parents=True, exist_ok=True)
    (out / "samples" / "doc_with_codefence").mkdir(parents=True, exist_ok=True)
    (out / "indexes").mkdir(parents=True, exist_ok=True)
    
    # Parse quotas
    quotas = {"pure_doc": args.target // 2, "doc_with_codefence": args.target - args.target // 2}
    if args.class_quota:
        quotas = dict(pair.split("=") for pair in args.class_quota.split(","))
        quotas = {k: int(v) for k, v in quotas.items()}
    
    print(f"Target quotas: {quotas}")
    
    # Parse exclude topics
    exclude = set(t.strip().lower() for t in args.exclude_topics.split(",") if t.strip())
    print(f"Exclude topics: {exclude}")
    
    # Parse languages
    langs = [s.strip() for s in args.languages.split(",")]
    print(f"Languages: {langs}")
    
    # Get candidates iterator
    if args.mode == "dump":
        if not args.dump_path:
            print("ERROR: --dump-path required for mode=dump")
            return 1
        dump_path = Path(args.dump_path)
        if not dump_path.exists():
            print(f"ERROR: Dump path not found: {dump_path}")
            return 1
        candidates_iter = candidates_from_dump(dump_path)
    else:
        print("ERROR: live mode not implemented (use mode=dump)")
        return 1
    
    # Collection loop
    seen_sig = set()
    written = 0
    rows = []
    per_class = {"pure_doc": 0, "doc_with_codefence": 0}
    processed = 0
    
    print("\nCollecting samples...")
    
    for cid, title, text in candidates_iter:
        processed += 1
        
        if processed % 100 == 0:
            print(f"  Processed: {processed}, Collected: {written}/{args.target}")
        
        if not text:
            continue
        
        # Length filter
        text_bytes = len(text.encode("utf-8"))
        if not (args.min_bytes <= text_bytes <= args.max_bytes):
            continue
        
        # Topic exclusion
        t_title = (title or "").lower()
        if any(tok in t_title for tok in exclude):
            continue
        
        # Classify
        label, meta = classify_sample(text)
        
        # Drop exec samples
        if label == "doc_with_exec":
            continue
        
        # Language filter
        if meta["lang"] not in langs:
            continue
        
        # Quota check
        if per_class.get(label, 0) >= quotas.get(label, 0):
            continue
        
        # Deduplication
        tl = compute_tlsh(text) if args.dedupe == "tlsh" else ""
        sh = compute_simhash64(text) if args.dedupe in ("tlsh", "simhash") else ""
        sig = tl or sh
        
        if sig and sig in seen_sig:
            continue
        if sig:
            seen_sig.add(sig)
        
        # Generate sample ID
        sid = cid or hashlib.blake2b((title + str(time.time())).encode("utf-8"), digest_size=8).hexdigest()
        
        # Write sample file
        rel = Path("samples") / label / f"{sid}.txt"
        (out / rel).write_text(text, encoding="utf-8")
        
        # Save raw if requested
        if args.save_raw:
            (out / "raw" / f"{sid}.json").write_text(
                json.dumps({"id": cid, "title": title, "text": text}, ensure_ascii=False),
                encoding="utf-8"
            )
        
        # Create metadata row
        row = {
            "id": sid,
            "source": args.source,
            "license": args.license_note,
            "lang": meta["lang"],
            "class_label": label,
            "path": str(rel).replace("\\", "/"),
            "bytes": text_bytes,
            "chars": len(text),
            "has_codefence": meta["has_codefence"],
            "exec_ctx": meta["exec_ctx"],
            "has_net_api": 0,  # optional enrichment later
            "has_js_attr": meta["has_js_attr"],
            "num_calls": meta["num_calls"],
            "min_distance_to_call": meta["min_distance_to_call"],
            "contains_sql_tokens": int(meta["contains_sql_tokens"]),
            "contains_base64_like": int(meta["contains_base64_like"]),
            "contains_urlscheme": int(meta["contains_urlscheme"]),
            "hash_tlsh": tl,
            "simhash64": sh,
            "duplicate_group": "",
            "excluded_topics": "",
            "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        rows.append(row)
        per_class[label] += 1
        written += 1
        
        if written >= args.target:
            break
        
        if written >= args.max_per_source:
            print(f"Reached max-per-source limit: {args.max_per_source}")
            break
    
    # Write metadata.csv
    if rows:
        meta_fp = out / "indexes" / "metadata.csv"
        with meta_fp.open("w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            for r in rows:
                w.writerow(r)
        
        print(f"\nCollection complete!")
        print(f"  Total collected: {written}/{args.target}")
        print(f"  By class: {per_class}")
        print(f"  Metadata: {meta_fp}")
        return 0
    else:
        print("\nERROR: No samples collected")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
