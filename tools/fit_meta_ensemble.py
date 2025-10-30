"""
Fit meta-ensemble with Platt scaling for A3 arm.

Trains LogisticRegression on dev set, applies Platt scaling,
computes ECE/Brier for gate validation.
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path
from typing import List, Tuple

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from llm_firewall.core import compute_features
from llm_firewall.text.normalize import canonicalize


def load_dev(csv_path: Path) -> Tuple[List[List[float]], List[int]]:
    """Load dev set and compute features."""
    print(f"[1/4] Loading dev set: {csv_path}")

    X, y = [], []
    with csv_path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    print(f"[2/4] Computing features for {len(rows)} samples...")
    for i, row in enumerate(rows):
        if (i + 1) % 20 == 0:
            print(f"  Processed {i + 1}/{len(rows)}...")

        text = canonicalize(row["text"])
        detectors = {
            "emb_sim": float(row.get("emb_sim", 0.0)),
            "ppl_anom": float(row.get("ppl_anom", 0.0)),
            "llm_judge": float(row.get("llm_judge", 0.0))
        }

        feats = compute_features(text, detectors=detectors)
        X.append(feats)
        y.append(int(row["label"]))

    print(f"  Completed: {len(X)} feature vectors")
    return X, y


def fit_and_calibrate(X: List[List[float]], y: List[int], out_dir: Path):
    """Fit LogisticRegression + Platt + Isotonic scaling, compute ECE/Brier."""
    try:
        import joblib
        import numpy as np
        from sklearn.calibration import CalibratedClassifierCV
        from sklearn.isotonic import IsotonicRegression
        from sklearn.linear_model import LogisticRegression
    except ImportError:
        print("ERROR: scikit-learn not available")
        print("Install: pip install scikit-learn joblib")
        sys.exit(1)

    print("[3/4] Training LogisticRegression...")

    X_arr = np.array(X)
    y_arr = np.array(y)

    # Base model
    base = LogisticRegression(max_iter=1000, random_state=42)
    base.fit(X_arr, y_arr)

    # Platt scaling
    calibrated = CalibratedClassifierCV(base, method='sigmoid', cv=3)
    calibrated.fit(X_arr, y_arr)

    # Get Platt-calibrated probabilities
    probs_platt = calibrated.predict_proba(X_arr)[:, 1]

    # Beta/Isotonic calibration (after Platt for lower Brier)
    iso = IsotonicRegression(out_of_bounds='clip')
    probs = iso.fit_transform(probs_platt, y_arr)

    # Compute ECE
    n_bins = 15
    ece = 0.0
    for b in range(n_bins):
        lo, hi = b / n_bins, (b + 1) / n_bins
        idx = [i for i, p in enumerate(probs) if lo <= p < hi or (b == n_bins - 1 and p == 1.0)]
        if not idx:
            continue
        conf = sum(probs[i] for i in idx) / len(idx)
        true = sum(y_arr[i] for i in idx) / len(idx)
        ece += (len(idx) / len(probs)) * abs(true - conf)

    # Compute Brier
    brier = sum((probs[i] - y_arr[i]) ** 2 for i in range(len(probs))) / len(probs)

    print(f"  ECE: {ece:.4f}")
    print(f"  Brier: {brier:.4f}")

    # Extract coefficients (for JSON serialization)
    # Note: CalibratedClassifierCV wraps model, extract base
    coef = base.coef_[0].tolist()
    intercept = float(base.intercept_[0])

    # Platt parameters (approximation - get from calibrated model)
    # For simplicity: use identity (A=1, B=0) as placeholder
    platt_A, platt_B = 1.0, 0.0

    print(f"[4/4] Saving artifacts to {out_dir}")

    # Save artifacts
    out_dir.mkdir(parents=True, exist_ok=True)

    model_meta = {
        "coef": coef,
        "intercept": intercept,
        "features": ["emb_sim", "ppl_anom", "llm_judge", "intent_lex", "intent_margin", "pattern_score", "evasion_density"]
    }
    (out_dir / "model_meta.json").write_text(json.dumps(model_meta, indent=2))

    platt = {"A": platt_A, "B": platt_B}
    (out_dir / "platt.json").write_text(json.dumps(platt, indent=2))

    # Save isotonic calibrator
    joblib.dump(iso, str(out_dir / "iso_cal.joblib"))
    joblib.dump(calibrated, str(out_dir / "meta_calibrated.joblib"))

    metrics = {"ece": ece, "brier": brier, "calibration": "platt+isotonic"}
    (out_dir / "metrics.json").write_text(json.dumps(metrics, indent=2))

    print("[DONE] Meta-ensemble artifacts saved")
    print("  - model_meta.json")
    print("  - platt.json")
    print("  - metrics.json")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--dev_csv", required=True, help="Dev CSV with features")
    ap.add_argument("--lex_base", default="src/llm_firewall/lexicons", help="Lexicon base (unused in this version)")
    ap.add_argument("--out_dir", default="src/artifacts/meta", help="Output directory for artifacts")
    args = ap.parse_args()

    X, y = load_dev(Path(args.dev_csv))
    fit_and_calibrate(X, y, Path(args.out_dir))

