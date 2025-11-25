"""Split JSONL data into train/dev/test sets.

Ensures balanced splits by label.

Usage:
  python split_data.py --input data.jsonl --train train.jsonl --dev dev.jsonl --test test.jsonl --ratios 0.8 0.1 0.1
"""

import argparse
import json
import random
from pathlib import Path


def main():
    """Split data into train/dev/test."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="Input JSONL path")
    ap.add_argument("--train", required=True, help="Train output path")
    ap.add_argument("--dev", required=True, help="Dev output path")
    ap.add_argument("--test", required=True, help="Test output path")
    ap.add_argument(
        "--ratios",
        nargs=3,
        type=float,
        default=[0.8, 0.1, 0.1],
        help="Train/dev/test ratios (must sum to 1.0)",
    )
    ap.add_argument("--seed", type=int, default=42, help="Random seed")
    args = ap.parse_args()

    # Validate ratios
    if abs(sum(args.ratios) - 1.0) > 0.01:
        print(f"[ERROR] Ratios must sum to 1.0, got {sum(args.ratios)}")
        return

    # Load data
    print(f"[INFO] Loading data from {args.input}...")
    with open(args.input, "r", encoding="utf-8") as f:
        data = [json.loads(line) for line in f if line.strip()]

    print(f"[INFO] Loaded {len(data)} entries")

    # Separate by label
    positive = [d for d in data if d["labels"]["self_harm"] == 1]
    negative = [d for d in data if d["labels"]["self_harm"] == 0]

    print(f"[INFO] Positive: {len(positive)}")
    print(f"[INFO] Negative: {len(negative)}")

    # Shuffle
    random.seed(args.seed)
    random.shuffle(positive)
    random.shuffle(negative)

    # Split positive
    n_pos = len(positive)
    pos_train_end = int(n_pos * args.ratios[0])
    pos_dev_end = pos_train_end + int(n_pos * args.ratios[1])

    pos_train = positive[:pos_train_end]
    pos_dev = positive[pos_train_end:pos_dev_end]
    pos_test = positive[pos_dev_end:]

    # Split negative
    n_neg = len(negative)
    neg_train_end = int(n_neg * args.ratios[0])
    neg_dev_end = neg_train_end + int(n_neg * args.ratios[1])

    neg_train = negative[:neg_train_end]
    neg_dev = negative[neg_train_end:neg_dev_end]
    neg_test = negative[neg_dev_end:]

    # Combine and shuffle
    train = pos_train + neg_train
    dev = pos_dev + neg_dev
    test = pos_test + neg_test

    random.shuffle(train)
    random.shuffle(dev)
    random.shuffle(test)

    # Set split field
    for entry in train:
        entry["split"] = "train"
    for entry in dev:
        entry["split"] = "dev"
    for entry in test:
        entry["split"] = "test"

    # Write splits
    Path(args.train).parent.mkdir(parents=True, exist_ok=True)

    with open(args.train, "w", encoding="utf-8") as f:
        for entry in train:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    with open(args.dev, "w", encoding="utf-8") as f:
        for entry in dev:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    with open(args.test, "w", encoding="utf-8") as f:
        for entry in test:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    # Stats
    print("\n[OK] Split complete!")
    print(f"\n[TRAIN] {len(train)} entries")
    print(f"  Positive: {len(pos_train)} ({len(pos_train) / len(train) * 100:.1f}%)")
    print(f"  Negative: {len(neg_train)} ({len(neg_train) / len(train) * 100:.1f}%)")
    print(f"  Output: {args.train}")

    print(f"\n[DEV] {len(dev)} entries")
    print(f"  Positive: {len(pos_dev)} ({len(pos_dev) / len(dev) * 100:.1f}%)")
    print(f"  Negative: {len(neg_dev)} ({len(neg_dev) / len(dev) * 100:.1f}%)")
    print(f"  Output: {args.dev}")

    print(f"\n[TEST] {len(test)} entries")
    print(f"  Positive: {len(pos_test)} ({len(pos_test) / len(test) * 100:.1f}%)")
    print(f"  Negative: {len(neg_test)} ({len(neg_test) / len(test) * 100:.1f}%)")
    print(f"  Output: {args.test}")

    print("\n[NEXT] Train model:")
    print(
        f"  python tools/layer15/train_layer15_crisis.py --train {args.train} --dev {args.dev} --outdir models/layer15_crisis"
    )


if __name__ == "__main__":
    main()
