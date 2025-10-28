from __future__ import annotations
import csv, json, math, argparse, sys
from pathlib import Path
from typing import List, Dict

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from llm_firewall.rules.scoring_gpt5 import evaluate
from llm_firewall.text.normalize import canonicalize
from llm_firewall.config import _pick_lex_base

def percentile(xs: List[float], q: float) -> float:
    if not xs: return 0.0
    xs = sorted(xs)
    k = (len(xs)-1) * q
    f = math.floor(k); c = math.ceil(k)
    if f == c: return xs[int(k)]
    return xs[f] * (c-k) + xs[c] * (k-f)

def load_benign(path: Path) -> List[str]:
    out = []
    with path.open("r", encoding="utf-8") as f:
        r = csv.DictReader(f)
        for row in r:
            if int(row["label"]) == 0:
                out.append(row["text"])
    return out

def run(in_csv: Path, out_path: Path, q: float = 0.995, margin: float = 0.05):
    LEX_BASE = _pick_lex_base()
    texts = load_benign(in_csv)
    cats: Dict[str, List[float]] = {}
    for t in texts:
        res = evaluate(canonicalize(t), base_dir=LEX_BASE)
        for k,v in res["pattern"]["by_category"].items():
            cats.setdefault(k, []).append(float(v))
    floors = {}
    for k,vs in cats.items():
        base = percentile(vs, q)
        floors[k] = float(min(0.99, base + margin))
    ev = [*cats.get("obfuscation_encoding", []), *cats.get("unicode_evasion", [])]
    if ev:
        base = percentile(ev, q)
        floors["evasion_floor"] = float(min(0.99, base + margin))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(floors, indent=2))
    print(json.dumps({"floors_written": str(out_path), "keys": list(floors.keys())}, indent=2))

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--benign_csv", required=True)
    ap.add_argument("--out", default="src/artifacts/floors.json")
    ap.add_argument("--quantile", type=float, default=0.995)
    ap.add_argument("--margin", type=float, default=0.05)
    args = ap.parse_args()
    run(Path(args.benign_csv), Path(args.out), q=args.quantile, margin=args.margin)
