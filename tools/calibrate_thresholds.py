"""
Calibrate risk threshold via ROC Youden-J on a dev split.
Input CSV: text,label  (label in {0,1})

Usage:
    python tools/calibrate_thresholds.py data/dev_split.csv
"""
import csv
import json
import sys
from pathlib import Path
from typing import List, Tuple

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from llm_firewall.rules.scoring_gpt5 import evaluate


def load_dataset(path: Path) -> List[Tuple[str, int]]:
    """Load CSV dataset with text and binary labels."""
    rows = []
    with path.open("r", encoding="utf-8") as f:
        r = csv.DictReader(f)
        for row in r:
            rows.append((row["text"], int(row["label"])))
    return rows


def youden_j(fprs: List[float], tprs: List[float], thresholds: List[float]) -> Tuple[float, float]:
    """
    Find optimal threshold via Youden's J statistic.
    J = TPR - FPR (maximizes sensitivity + specificity)
    
    Returns:
        (J_score, optimal_threshold)
    """
    best = (0.0, 0.5)  # Default J=0, threshold=0.5
    for fpr, tpr, thr in zip(fprs, tprs, thresholds):
        J = tpr - fpr
        if J > best[0]:
            best = (J, thr)
    return best


def calibrate(path_csv: Path, max_gap: int = 3):
    """
    Calibrate threshold using ROC Youden-J method.
    
    Args:
        path_csv: Path to CSV with text,label columns
        max_gap: Token gap for intent matcher
    """
    # Load lexicons
    base = Path(__file__).parent.parent / "src" / "llm_firewall" / "lexicons_gpt5"
    if not (base / "intents.json").exists():
        base = Path(__file__).parent.parent / "src" / "llm_firewall" / "lexicons"

    print(f"Loading dataset: {path_csv}")
    data = load_dataset(path_csv)
    print(f"Loaded {len(data)} samples")

    # Compute scores
    print("Computing scores...")
    scores, labels = [], []
    for i, (text, y) in enumerate(data):
        if (i + 1) % 50 == 0:
            print(f"  {i + 1}/{len(data)}")
        try:
            res = evaluate(text, base_dir=base, max_gap=max_gap)
            # Combined score: weighted mix (same as validator)
            s = res["pattern"]["score"] * 0.6 + res["intent"]["lex_score"] * 0.4
            scores.append(s)
            labels.append(y)
        except Exception as e:
            print(f"  Warning: Failed on sample {i}: {e}")
            continue

    print(f"\nProcessed {len(scores)} samples successfully")

    # Compute ROC curve (naive implementation)
    print("Computing ROC curve...")
    pairs = sorted(zip(scores, labels), key=lambda x: x[0])
    thresholds = sorted(set(s for s, _ in pairs))

    P = sum(labels)  # Positives
    N = len(labels) - P  # Negatives

    if P == 0 or N == 0:
        print("ERROR: Dataset must have both positive and negative samples!")
        sys.exit(1)

    tprs, fprs = [], []
    for thr in thresholds:
        tp = sum(1 for s, y in zip(scores, labels) if s >= thr and y == 1)
        fp = sum(1 for s, y in zip(scores, labels) if s >= thr and y == 0)
        fn = P - tp
        tn = N - fp
        tpr = tp / P if P else 0.0
        fpr = fp / N if N else 0.0
        tprs.append(tpr)
        fprs.append(fpr)

    # Find optimal threshold
    J, optimal_thr = youden_j(fprs, tprs, thresholds)

    # Compute metrics at optimal threshold
    tp = sum(1 for s, y in zip(scores, labels) if s >= optimal_thr and y == 1)
    fp = sum(1 for s, y in zip(scores, labels) if s >= optimal_thr and y == 0)
    fn = P - tp
    tn = N - fp

    sensitivity = tp / P if P else 0.0
    specificity = tn / N if N else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = 2 * precision * sensitivity / (precision + sensitivity) if (precision + sensitivity) else 0.0

    # Output results
    result = {
        "youden_j": round(J, 6),
        "optimal_threshold": round(optimal_thr, 6),
        "metrics_at_threshold": {
            "sensitivity_recall": round(sensitivity, 4),
            "specificity": round(specificity, 4),
            "precision": round(precision, 4),
            "f1_score": round(f1, 4),
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn
        },
        "dataset_stats": {
            "total_samples": len(labels),
            "positives": P,
            "negatives": N,
            "prevalence": round(P / len(labels), 4)
        }
    }

    print("\n" + "=" * 60)
    print("CALIBRATION RESULTS")
    print("=" * 60)
    print(json.dumps(result, indent=2))
    print("=" * 60)

    # Save to file
    output_path = Path(__file__).parent.parent / "config" / "calibrated_threshold.json"
    output_path.parent.mkdir(exist_ok=True)
    with output_path.open("w") as f:
        json.dump(result, f, indent=2)
    print(f"\nSaved to: {output_path}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python tools/calibrate_thresholds.py <path_to_csv>")
        print("CSV format: text,label (label in {0,1})")
        sys.exit(1)

    calibrate(Path(sys.argv[1]))




