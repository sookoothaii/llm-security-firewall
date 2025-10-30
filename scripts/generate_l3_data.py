# -*- coding: utf-8 -*-
"""
Generate balanced DE/EN training data for the L3 mini-classifier.

Classes (8):
  authority, commitment_consistency, liking, reciprocity,
  scarcity_urgency, social_proof, unity_identity, none

Safety:
- Uses benign topics only (summaries, outlines, neutral explanations).
- No procedural/harmful instructions are produced.

Usage:
  python scripts/generate_l3_data.py --per-class 1000 --lang both --out data/l3_train.jsonl --seed 13

Creator: Joerg Bollwahn
License: MIT
"""
from __future__ import annotations
import argparse, json, pathlib, random
from typing import Dict, List

CLASSES = [
    "authority","commitment_consistency","liking","reciprocity",
    "scarcity_urgency","social_proof","unity_identity","none",
]

BLOCKLIST = {
    # keep dataset clean of sensitive procedural topics
    "bomb","weapon","explosive","attack","exploit","malware",
    "drug","synthesize","recipe","poison","dox","hack","bypass"
}

def _load_templates(path: pathlib.Path) -> Dict[str, dict]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _render(template: str, pool: Dict[str, List[str]]) -> str:
    """Simple {placeholder} substitution with random choices"""
    out = template
    for key, vals in pool.items():
        if f"{{{key}}}" in out:
            out = out.replace(f"{{{key}}}", random.choice(vals))
    return out


def _safe_text(text: str) -> bool:
    """Check if text contains blocklist terms"""
    tl = text.lower()
    return not any(term in tl for term in BLOCKLIST)


def generate_samples(templates_path: pathlib.Path, n_per_class: int, lang: str) -> List[dict]:
    """Generate n_per_class samples per class from templates"""
    templates = _load_templates(templates_path)
    if not templates:
        print(f"WARNING: No templates found at {templates_path}")
        return []
    
    samples = []
    pools = templates.get("pools", {})
    
    for cls in CLASSES:
        cls_templates = templates.get(cls, [])
        if not cls_templates:
            continue
        
        for _ in range(n_per_class):
            template = random.choice(cls_templates)
            text = _render(template, pools)
            
            # Safety check
            if not _safe_text(text):
                continue
            
            samples.append({
                "text": text,
                "label": cls,
                "lang": lang
            })
    
    return samples


def main():
    parser = argparse.ArgumentParser(description="Generate L3 training data")
    parser.add_argument("--per-class", type=int, default=100, help="Samples per class")
    parser.add_argument("--lang", choices=["en", "de", "both"], default="both")
    parser.add_argument("--out", type=str, default="data/l3_train.jsonl")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    
    random.seed(args.seed)
    
    root = pathlib.Path(__file__).resolve().parents[1]
    templates_dir = root / "data" / "templates"
    
    all_samples = []
    
    if args.lang in ["en", "both"]:
        print(f"Generating {args.per_class} EN samples per class...")
        en_path = templates_dir / "persuasion_en.json"
        en_samples = generate_samples(en_path, args.per_class, "en")
        all_samples.extend(en_samples)
        print(f"  Generated: {len(en_samples)} EN samples")
    
    if args.lang in ["de", "both"]:
        print(f"Generating {args.per_class} DE samples per class...")
        de_path = templates_dir / "persuasion_de.json"
        de_samples = generate_samples(de_path, args.per_class, "de")
        all_samples.extend(de_samples)
        print(f"  Generated: {len(de_samples)} DE samples")
    
    # Shuffle
    random.shuffle(all_samples)
    
    # Save
    out_path = pathlib.Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(out_path, "w", encoding="utf-8") as f:
        for sample in all_samples:
            f.write(json.dumps(sample, ensure_ascii=False) + "\n")
    
    print(f"\n[OK] Total: {len(all_samples)} samples")
    print(f"[OK] Saved to: {out_path}")
    
    # Class distribution
    from collections import Counter
    counts = Counter(s["label"] for s in all_samples)
    print(f"\nClass distribution:")
    for cls in CLASSES:
        print(f"  {cls:25}: {counts.get(cls, 0):4} samples")


if __name__ == "__main__":
    main()

