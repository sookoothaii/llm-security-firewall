#!/usr/bin/env python3
# (content truncated for brevity in this header; full script below)
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, List


def load_json(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        sys.exit(f"[ERROR] Failed to read JSON {p}: {e}")


def save_json(p: Path, obj: Any, backup: bool = False):
    if backup and p.exists():
        p.with_suffix(p.suffix + ".bak").write_text(
            p.read_text(encoding="utf-8"), encoding="utf-8"
        )
    p.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


REQUIRED_REGEX_KEYS = {"id", "regex", "category"}


def parse_flags(flag_str: str) -> int:
    f = 0
    if not flag_str:
        return f
    for ch in flag_str:
        if ch == "i":
            f |= re.IGNORECASE
        elif ch == "m":
            f |= re.MULTILINE
        elif ch == "s":
            f |= re.DOTALL
        elif ch == "x":
            f |= re.VERBOSE
    return f


def validate_regex_items(items: List[dict], strict=False):
    out = []
    for it in items:
        miss = REQUIRED_REGEX_KEYS - set(it.keys())
        if miss:
            out.append(
                (it.get("id", "<no-id>"), "err", f"missing keys: {sorted(miss)}")
            )
            continue
        patt = it["regex"]
        flags = parse_flags(it.get("flags", ""))
        try:
            re.compile(patt, flags)
            out.append((it["id"], "ok", "compiled"))
        except re.error as e:
            status = "err" if strict else "warn"
            out.append((it["id"], status, f"compile issue: {e}"))
    return out


def merge_regex_arrays(base: List[dict], patch: List[dict]):
    by_id = {x["id"]: json.loads(json.dumps(x)) for x in base if "id" in x}
    log = {}
    for it in patch:
        rid = it.get("id")
        if not rid:
            continue
        if rid in by_id:
            if by_id[rid] != it:
                log[rid] = "updated"
            else:
                log[rid] = "noop"
        else:
            log[rid] = "added"
        by_id[rid] = json.loads(json.dumps(it))
    merged = sorted(by_id.values(), key=lambda d: d.get("id", ""))
    return merged, log


def dedup_strings(xs: List[str], casefold=True) -> List[str]:
    seen = set()
    out = []
    for s in xs:
        key = s.casefold() if casefold else s
        if key not in seen:
            seen.add(key)
            out.append(s)
    return out


def merge_cluster(dst: dict, add: dict, casefold=True):
    if "priority" in add:
        dst["priority"] = max(int(dst.get("priority", 0)), int(add.get("priority", 0)))
    syn = dedup_strings(
        list(dst.get("synonyms", [])) + list(add.get("synonyms", [])), casefold=casefold
    )
    dst["synonyms"] = syn
    seed = dedup_strings(
        list(dst.get("seed_sentences", [])) + list(add.get("seed_sentences", [])),
        casefold=False,
    )
    dst["seed_sentences"] = seed
    for k, v in add.items():
        if k in ("id", "priority", "synonyms", "seed_sentences"):
            continue
        if k not in dst:
            dst[k] = v
    return dst


def merge_intents(base_obj: dict, patch_obj: dict, casefold=True):
    base = json.loads(json.dumps(base_obj))
    patch = json.loads(json.dumps(patch_obj))
    if "clusters" not in base or not isinstance(base["clusters"], list):
        base["clusters"] = []
    if "clusters" not in patch or not isinstance(patch["clusters"], list):
        return base, {}
    by_id = {c["id"]: c for c in base["clusters"] if "id" in c}
    log = {}
    for c in patch["clusters"]:
        cid = c.get("id")
        if not cid:
            continue
        if cid in by_id:
            before = json.dumps(by_id[cid], sort_keys=True)
            by_id[cid] = merge_cluster(by_id[cid], c, casefold=casefold)
            after = json.dumps(by_id[cid], sort_keys=True)
            log[cid] = "updated" if before != after else "noop"
        else:
            by_id[cid] = c
            log[cid] = "added"
    base["clusters"] = sorted(by_id.values(), key=lambda d: d.get("id", ""))
    return base, log


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add_common(sp):
        sp.add_argument("--base", required=True)
        sp.add_argument("--patch", required=True)
        sp.add_argument("--out", required=True)
        sp.add_argument("--apply", action="store_true")
        sp.add_argument("--backup", action="store_true")
        sp.add_argument("--no-validate", action="store_true")
        sp.add_argument("--casefold", action="store_true", default=True)

    add_common(sub.add_parser("merge-regex"))
    add_common(sub.add_parser("merge-intents"))
    args = ap.parse_args()
    base_p, patch_p, out_p = Path(args.base), Path(args.patch), Path(args.out)
    if args.cmd == "merge-regex":
        base = load_json(base_p)
        patch = load_json(patch_p)
        if not isinstance(base, list) or not isinstance(patch, list):
            sys.exit("[ERROR] base and patch must be arrays for merge-regex")
        merged, log = merge_regex_arrays(base, patch)
        if not args.no_validate:
            issues = validate_regex_items(merged, strict=False)
            for rid, st, msg in issues:
                print(f"[validate] {rid}: {st} ({msg})")
        print("[merge-regex] changes:")
        for k, v in log.items():
            print(f"  - {k}: {v}")
        if args.apply:
            save_json(out_p, merged, backup=args.backup)
            print(f"[merge-regex] wrote {out_p}")
        else:
            print("[merge-regex] dry-run (use --apply)")
        return
    if args.cmd == "merge-intents":
        base = load_json(base_p)
        patch = load_json(patch_p)
        if not isinstance(base, dict) or not isinstance(patch, dict):
            sys.exit("[ERROR] base and patch must be objects for merge-intents")
        merged, log = merge_intents(base, patch, casefold=args.casefold)
        print("[merge-intents] changes:")
        for k, v in log.items():
            print(f"  - {k}: {v}")
        if args.apply:
            save_json(out_p, merged, backup=args.backup)
            print(f"[merge-intents] wrote {out_p}")
        else:
            print("[merge-intents] dry-run (use --apply)")
        return


if __name__ == "__main__":
    main()
