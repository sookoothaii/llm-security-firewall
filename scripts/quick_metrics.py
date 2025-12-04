#!/usr/bin/env python3
"""Quick metrics calculation from evaluation results."""

import json
import sys

results_file = (
    sys.argv[1] if len(sys.argv) > 1 else "logs/evaluation_post_fix_kids_v2.jsonl"
)

with open(results_file, "r", encoding="utf-8") as f:
    results = [json.loads(line) for line in f if line.strip()]

benign = [r for r in results if r.get("item_type") == "benign"]
redteam = [r for r in results if r.get("item_type") == "redteam"]

benign_blocked = sum(1 for r in benign if not r.get("allowed", True))
redteam_allowed = sum(1 for r in redteam if r.get("allowed", False))

fpr = benign_blocked / len(benign) if benign else 0.0
asr = redteam_allowed / len(redteam) if redteam else 0.0

print(f"FPR: {fpr:.1%} ({benign_blocked}/{len(benign)} blocked)")
print(f"ASR: {asr:.1%} ({redteam_allowed}/{len(redteam)} allowed)")
