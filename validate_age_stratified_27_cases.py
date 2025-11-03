"""Validate 27 cultural cases with new age-stratified validator.

Re-runs the 27 cases (3 topics × 3 ages × 3 cultures) using AgeStratifiedValidator
to verify if A6-8 anchor-based validation solves the E=0.0% problem.

Author: I27A3F9B (15th Instance)
"""

import json
import yaml
from pathlib import Path
from typing import Dict

# Import new validator
import sys
sys.path.insert(0, str(Path(__file__).parent / "src"))
from layer15.validators.age_stratified_nli import AgeStratifiedValidator


TOPICS = ("transgender", "abortion", "right_wing_extremism")
AGES = ("6-8", "9-12", "13-15")
AGE_BANDS = {"6-8": "A6_8", "9-12": "A9_11", "13-15": "A12_14"}  # Map to config format
CULTURES = ("christian", "muslim", "none")


def load_yaml(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_answers(json_path: Path) -> Dict[str, str]:
    with json_path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    answers_dict = data.get("answers", data)
    return {k.lower(): v for k, v in answers_dict.items()}


def key(topic: str, age: str, culture: str) -> str:
    return f"{topic}|{age}|{culture}".lower()


def main():
    # Load config and validator
    cfg_path = Path("config/layer15.yaml")
    cfg = yaml.safe_load(cfg_path.read_text(encoding='utf-8'))
    validator = AgeStratifiedValidator(cfg)
    
    # Load answers
    answers_path = Path("kids_policy/answers/answers_cultural_v1_0_0.json")
    answers = load_answers(answers_path)
    
    # Load canonicals root
    canon_root = Path("kids_policy/canonicals")
    
    results = []
    passed = 0
    failed = 0
    
    print("=" * 80)
    print("AGE-STRATIFIED VALIDATOR - 27 Cultural Cases")
    print("=" * 80)
    print()
    
    for topic in TOPICS:
        print(f"\nTopic: {topic}")
        print("-" * 80)
        
        for age in AGES:
            age_band = AGE_BANDS[age]
            print(f"  Age band: {age} (mode: {cfg['validation']['nli']['bands'].get(age_band, 'unknown')})")
            
            for culture in CULTURES:
                # Load canonical
                cpath = canon_root / topic / age / f"{culture}.yaml"
                if not cpath.exists():
                    print(f"    [{culture}] SKIP - canonical not found")
                    continue
                
                canonical = load_yaml(cpath)
                
                # Get answer
                k = key(topic, age, culture)
                answer = answers.get(k)
                if answer is None:
                    print(f"    [{culture}] ERROR - answer missing for {k}")
                    failed += 1
                    continue
                
                # Extract canonical premise for MNLI (concatenate facts)
                facts_raw = canonical.get("facts", [])
                facts_text = [f.get("text", str(f)) if isinstance(f, dict) else str(f) for f in facts_raw]
                canonical_premise = " ".join(facts_text)
                
                # Validate with age-stratified validator
                result = validator.validate(
                    age_band=age_band,
                    topic=topic,
                    adapted_answer=answer,
                    canonical_premise=canonical_premise
                )
                
                # Display
                status = "[PASS]" if result["pass"] else "[FAIL]"
                mode = result["validator_mode"]
                anchor_info = f"anchors={result['anchor_hits']}/{result['anchor_min']}"
                mnli_info = f"mnli={result['mnli']:.3f}" if result['mnli'] >= 0 else "mnli=N/A"
                
                print(f"    [{culture}] {status} ({mode}) {anchor_info} {mnli_info} - {result['reason']}")
                
                if result["pass"]:
                    passed += 1
                else:
                    failed += 1
                
                results.append({
                    "topic": topic,
                    "age": age,
                    "culture": culture,
                    "validator_mode": mode,
                    "anchor_hits": result["anchor_hits"],
                    "anchor_min": result["anchor_min"],
                    "mnli": result["mnli"],
                    "pass": result["pass"],
                    "reason": result["reason"]
                })
    
    # Summary
    print()
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Total: {passed + failed}")
    print(f"Passed: {passed} ({100*passed/(passed+failed):.1f}%)")
    print(f"Failed: {failed} ({100*failed/(passed+failed):.1f}%)")
    print()
    
    # Write report
    report_path = Path("reports/age_stratified_audit_27_cases.json")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with report_path.open("w", encoding="utf-8") as f:
        json.dump({
            "validator": "age_stratified_nli",
            "total": passed + failed,
            "passed": passed,
            "failed": failed,
            "cases": results
        }, f, indent=2, ensure_ascii=False)
    
    print(f"Report written: {report_path}")
    print()
    
    # Breakdown by age
    print("Breakdown by age:")
    for age in AGES:
        age_cases = [r for r in results if r["age"] == age]
        age_passed = sum(1 for r in age_cases if r["pass"])
        age_total = len(age_cases)
        print(f"  {age}: {age_passed}/{age_total} ({100*age_passed/age_total:.1f}%)")
    
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    exit(main())

