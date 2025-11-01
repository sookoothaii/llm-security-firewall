#!/usr/bin/env python3
import json
import sys
from pathlib import Path


def check_regex(path: Path) -> int:
    arr = json.loads(path.read_text(encoding="utf-8"))
    ids = [x.get("id") for x in arr if isinstance(x, dict)]
    dups = sorted({i for i in ids if ids.count(i) > 1 and i is not None})
    miss = [
        x.get("id")
        for x in arr
        if isinstance(x, dict) and not {"id", "regex", "category"}.issubset(x.keys())
    ]
    if dups:
        print(f"[regex] duplicate ids in {path}: {dups}")
        return 1
    if miss:
        print(f"[regex] items missing required keys in {path}: {miss}")
        return 1
    print(f"[regex] OK: {path}")
    return 0


def check_intents(path: Path) -> int:
    obj = json.loads(path.read_text(encoding="utf-8"))
    cl = obj.get("clusters", [])
    ids = [x.get("id") for x in cl if isinstance(x, dict)]
    dups = sorted({i for i in ids if ids.count(i) > 1 and i is not None})
    if dups:
        print(f"[intents] duplicate cluster ids in {path}: {dups}")
        return 1
    print(f"[intents] OK: {path}")
    return 0


if __name__ == "__main__":
    code = 0
    for arg in sys.argv[1:]:
        p = Path(arg)
        if "intent" in p.name:
            code |= check_intents(p)
        else:
            code |= check_regex(p)
    sys.exit(code)
