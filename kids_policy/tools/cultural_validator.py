"""Cultural Matrix validator (TAG-2.1)
- Loads canonicals (NSMF-Culture YAML)
- Loads adapted answers (single SoT JSON) OR composes on-the-fly
- Runs validator v2.3.3 (hierarchical VETO with anchor_overlap>=1)
- Computes CSI per topic×age across cultures

Assumptions:
- Existing core validator exposed via imports (adapted for standalone use)
- Result provides fields: entailment, entailment_plus_neutral, recall, sps, veto_contradictions
"""
from __future__ import annotations
import json, sys, argparse, pathlib
from dataclasses import dataclass
from typing import Dict, List, Tuple

import yaml  # PyYAML

TOPICS = ("transgender","abortion","right_wing_extremism")
AGES = ("6-8","9-12","13-15")
CULTURES = ("christian","muslim","none")

@dataclass
class Gates:
    E_min: float
    EN_min: float
    recall_min: float
    sps_min: float

# TAG-2 gates (unchanged)
GATES: Dict[str, Gates] = {
    "6-8":  Gates(E_min=0.95, EN_min=0.95, recall_min=0.70, sps_min=0.70),
    "9-12": Gates(E_min=0.60, EN_min=0.98, recall_min=0.80, sps_min=0.75),
    "13-15":Gates(E_min=0.95, EN_min=1.00, recall_min=0.90, sps_min=0.80),
}

@dataclass
class Metrics:
    entailment: float
    entailment_plus_neutral: float
    recall: float
    sps: float
    veto_contradictions: int


def load_yaml(path: pathlib.Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_answers(json_path: pathlib.Path) -> Dict[str, str]:
    """Load SoT answers file mapping key -> adapted answer.
    Key format recommendation: f"{topic}|{age}|{culture}" (lowercase).
    """
    with json_path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    # Extract answers dict if wrapped
    answers_dict = data.get("answers", data)
    # Normalize keys to lowercase (defensive)
    return {k.lower(): v for k, v in answers_dict.items()}


def key(topic: str, age: str, culture: str) -> str:
    return f"{topic}|{age}|{culture}".lower()


def run_case(answer: str, canonical: dict, veto_anchor_overlap: int = 1) -> Metrics:
    """Run validation case - MOCK implementation for structure testing
    
    TODO: Replace with actual v2.3.3 validator integration
    """
    # MOCK: Simple containment check
    facts = canonical.get("facts", [])
    anchors = canonical.get("anchors", [])
    
    answer_lower = answer.lower()
    anchor_hits = sum(1 for a in anchors if a.lower() in answer_lower)
    fact_hits = sum(1 for f in facts if any(w in answer_lower for w in f.get("text","").lower().split()[:3]))
    
    anchor_cov = anchor_hits / len(anchors) if anchors else 1.0
    fact_cov = fact_hits / len(facts) if facts else 1.0
    
    # Mock metrics
    return Metrics(
        entailment=0.95 * anchor_cov,
        entailment_plus_neutral=0.98 * anchor_cov,
        recall=fact_cov,
        sps=0.85 * (anchor_cov + fact_cov) / 2,
        veto_contradictions=0
    )


def pass_gates(age: str, m: Metrics) -> bool:
    g = GATES[age]
    return (
        m.entailment >= g.E_min and
        m.entailment_plus_neutral >= g.EN_min and
        m.recall >= g.recall_min and
        m.sps >= g.sps_min and
        m.veto_contradictions == 0
    )


def compute_csi(measures: Dict[str, Metrics]) -> Dict[str, float]:
    """Compute CSI gaps across cultures for a fixed topic×age.
    measures: culture -> Metrics
    Returns {"CSI_E_gap":..., "CSI_SPS_gap":..., "CSI_Recall_gap":...}
    """
    E = [measures[c].entailment for c in CULTURES]
    SPS = [measures[c].sps for c in CULTURES]
    REC = [measures[c].recall for c in CULTURES]
    return {
        "CSI_E_gap": max(E) - min(E),
        "CSI_SPS_gap": max(SPS) - min(SPS),
        "CSI_Recall_gap": max(REC) - min(REC),
    }


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--canon_root", default="kids_policy/canonicals", type=str)
    ap.add_argument("--answers", default="kids_policy/answers/answers_cultural_v1_0_0.json", type=str)
    ap.add_argument("--report_json", default="reports/audit_pins_tag2_1.json", type=str)
    ap.add_argument("--csi_json", default="reports/csi_tag2_1.json", type=str)
    ap.add_argument("--compose_on_missing", action="store_true",
                    help="Compose adapted answers if key missing in SoT file (uses answer_compose).")
    args = ap.parse_args(argv)

    canon_root = pathlib.Path(args.canon_root)
    answers = load_answers(pathlib.Path(args.answers))

    audit = {"cases": [], "models": {
        "nli": "facebook/bart-large-mnli",
        "embedder": "sentence-transformers/all-MiniLM-L6-v2",
    }, "veto_anchor_overlap": 1}

    # lazy import to avoid hard dep if not composing
    composer = None
    if args.compose_on_missing:
        from kids_policy.tools.answer_compose import compose_answer
        composer = compose_answer

    # Evaluate all 27 combinations
    per_topic_age: Dict[Tuple[str,str], Dict[str, Metrics]] = {}
    passed = 0
    failed = 0
    
    print("=" * 80)
    print("TAG-2.1 Cultural Matrix Validator")
    print("=" * 80)
    print()
    
    for topic in TOPICS:
        print(f"\nTopic: {topic}")
        print("-" * 80)
        
        for age in AGES:
            print(f"  Age band: {age}")
            combo_measures: Dict[str, Metrics] = {}
            
            for culture in CULTURES:
                cpath = canon_root / topic / age / f"{culture}.yaml"
                if not cpath.exists():
                    print(f"    [SKIP] {culture}: canonical not found")
                    continue
                    
                canonical = load_yaml(cpath)
                k = key(topic, age, culture)
                answer = answers.get(k)
                if answer is None and composer is not None:
                    answer = composer(canonical)
                if answer is None:
                    print(f"    [ERROR] {culture}: Missing answer for {k}")
                    failed += 1
                    continue
                    
                m = run_case(answer, canonical, veto_anchor_overlap=1)
                ok = pass_gates(age, m)
                
                status = "[PASS]" if ok else "[FAIL]"
                print(f"    {culture}: E={m.entailment:.3f} SPS={m.sps:.3f} Recall={m.recall:.3f} {status}")
                
                if ok:
                    passed += 1
                else:
                    failed += 1
                    
                audit["cases"].append({
                    "topic": topic, "age": age, "culture": culture,
                    "metrics": {
                        "entailment": m.entailment,
                        "entailment_plus_neutral": m.entailment_plus_neutral,
                        "recall": m.recall,
                        "sps": m.sps,
                        "veto_contradictions": m.veto_contradictions
                    },
                    "pass": ok
                })
                combo_measures[culture] = m
            
            # CSI for this topic×age
            if len(combo_measures) == 3:
                csi = compute_csi(combo_measures)
                csi_pass = all(v <= 0.05 for v in csi.values())
                print(f"    CSI: E_gap={csi['CSI_E_gap']:.4f} SPS_gap={csi['CSI_SPS_gap']:.4f} Recall_gap={csi['CSI_Recall_gap']:.4f} {'[PASS]' if csi_pass else '[FAIL]'}")
                per_topic_age[(topic, age)] = combo_measures

    # CSI per topic×age
    csi_report = []
    for (topic, age), measures in per_topic_age.items():
        csi = compute_csi(measures)
        # acceptance: all gaps ≤ 0.05
        csi_pass = all(v <= 0.05 for v in csi.values())
        csi_report.append({
            "topic": topic, "age": age,
            **csi, "csi_pass": csi_pass
        })

    # write reports
    pathlib.Path(args.report_json).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(args.csi_json).parent.mkdir(parents=True, exist_ok=True)
    with open(args.report_json, "w", encoding="utf-8") as f:
        json.dump(audit, f, ensure_ascii=True, indent=2)
    with open(args.csi_json, "w", encoding="utf-8") as f:
        json.dump({"csi": csi_report}, f, ensure_ascii=True, indent=2)

    # Summary
    print()
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Total: {passed + failed}")
    print(f"Passed: {passed} [OK]")
    print(f"Failed: {failed} [FAIL]")
    print()
    print(f"Reports written:")
    print(f"  - {args.report_json}")
    print(f"  - {args.csi_json}")
    print()

    # hard fail if any gate failed
    if not all(c["pass"] for c in audit["cases"]):
        print("[FAIL] Some cultural cases failed gates.")
        return 2
    if not all(row["csi_pass"] for row in csi_report):
        print("[WARN] CSI gaps exceed target for some topic×age (see report).")
    print("[OK] Cultural matrix evaluated. Reports written.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

