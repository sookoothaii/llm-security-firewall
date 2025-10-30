# -*- coding: utf-8 -*-
"""
Training script for L3 Mini-Classifier (multinomial logistic regression) with hashing features.

Requirements (install locally):
    pip install scikit-learn numpy onnx onnxruntime

Input data format (JSONL): each line -> {"text": "...", "label": "authority"|...|"none"}
Recommended sources: synthetic generation per lexicon templates + curated real prompts.

Outputs:
    - models/persuasion_l3_weights.npz  (W, b)
    - models/persuasion_l3.onnx         (created by build_onnx_logreg.py)

Creator: Joerg Bollwahn
License: MIT
"""
from __future__ import annotations
import json, pathlib, sys
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

# Add parent to path for imports
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from llm_firewall.persuasion.hash_vectorizer import HashVectorizer
from llm_firewall.persuasion.l3_classifier import CLASSES

DATA = ROOT / "data" / "l3_train.jsonl"
MODEL_DIR = ROOT / "models"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

def main():
    if not DATA.exists():
        print(f"ERROR: Training data not found at {DATA}")
        print("Create data/l3_train.jsonl with format: {\"text\": \"...\", \"label\": \"authority\"|...}")
        sys.exit(1)
    
    vec = HashVectorizer(n_features=2**18)
    
    texts, labels = [], []
    with open(DATA, "r", encoding="utf-8") as f:
        for line in f:
            obj = json.loads(line)
            texts.append(obj["text"])  # no harmful content required; use benign paraphrases
            labels.append(obj["label"])  # must be in CLASSES
    
    print(f"Loaded {len(texts)} training samples")
    
    X = vec.transform(texts)
    y = np.array([CLASSES.index(y_) for y_ in labels], dtype=np.int64)
    
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    clf = LogisticRegression(
        penalty="l2", C=2.0, solver="lbfgs", multi_class="multinomial", max_iter=1000, n_jobs=None
    )
    
    print("Training...")
    clf.fit(Xtr, ytr)
    
    y_pred = clf.predict(Xte)
    print("\n=== EVALUATION ===\n")
    print(classification_report(yte, y_pred, target_names=CLASSES))
    
    W = clf.coef_.astype(np.float32)      # shape [K, D]
    b = clf.intercept_.astype(np.float32) # shape [K]
    np.savez(MODEL_DIR / "persuasion_l3_weights.npz", W=W, b=b, classes=np.array(CLASSES))
    
    # Import here to avoid circular dependency
    sys.path.insert(0, str(ROOT / "scripts"))
    from build_onnx_logreg import build_onnx
    
    # Build ONNX graph (features -> softmax probabilities)
    build_onnx(W, b, out_path=MODEL_DIR / "persuasion_l3.onnx")
    print(f"\n✓ Saved: {MODEL_DIR / 'persuasion_l3.onnx'}")
    print(f"✓ Saved: {MODEL_DIR / 'persuasion_l3_weights.npz'}")

if __name__ == "__main__":
    main()

