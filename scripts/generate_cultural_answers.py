#!/usr/bin/env python3
"""Generate all 27 cultural adapted answers deterministically from canonicals
Single SoT file: answers_cultural_v1_0_0.json
"""
import json
import sys
from pathlib import Path
import importlib.util

# Direct import to avoid __init__.py dependencies
spec = importlib.util.spec_from_file_location(
    "answer_compose",
    Path(__file__).parent.parent / "kids_policy" / "tools" / "answer_compose.py"
)
answer_compose_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(answer_compose_module)
compose_answer = answer_compose_module.compose_answer

import yaml

TOPICS = ["transgender", "abortion", "right_wing_extremism"]
AGES = ["6-8", "9-12", "13-15"]
CULTURES = ["christian", "muslim", "none"]

def main():
    answers = {}
    
    for topic in TOPICS:
        for age in AGES:
            for culture in CULTURES:
                # Load canonical
                canon_path = Path(f"kids_policy/canonicals/{topic}/{age}/{culture}.yaml")
                if not canon_path.exists():
                    print(f"[SKIP] {topic}/{age}/{culture}: canonical not found")
                    continue
                
                with open(canon_path, 'r', encoding='utf-8') as f:
                    canonical = yaml.safe_load(f)
                
                # Compose answer
                answer = compose_answer(canonical)
                
                # Store with key format: topic|age|culture
                key = f"{topic}|{age}|{culture}"
                answers[key] = answer
                
                print(f"[OK] {key}: {len(answer)} chars")
    
    # Save to file
    output_path = Path("kids_policy/answers/answers_cultural_v1_0_0.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    output = {
        "schema_version": "cultural_answers/1.0.0",
        "metadata": {
            "created": "2025-11-03",
            "instance": "I2A7F91C",
            "method": "deterministic_composer",
            "total_answers": len(answers)
        },
        "answers": answers
    }
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, ensure_ascii=True)
    
    print()
    print(f"[COMPLETE] {len(answers)} answers written to {output_path}")
    return 0

if __name__ == "__main__":
    sys.exit(main())

