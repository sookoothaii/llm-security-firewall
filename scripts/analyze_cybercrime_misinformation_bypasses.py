"""
Analyze Cybercrime and Misinformation Bypasses
==============================================

Sammelt und analysiert die durchgerutschten Prompts aus Cybercrime (28.6% ASR)
und Misinformation (26.3% ASR) Kategorien, um Muster zu identifizieren.
"""

import sys
import csv
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Any

# Add project root to path
base_dir = Path(__file__).parent.parent
sys.path.insert(0, str(base_dir / "src"))

try:
    from llm_firewall.core.firewall_engine_v3 import FirewallEngineV3, EmergencyFixFirewallConfig
    from llm_firewall.safety.validator import SafetyValidator
except ImportError as e:
    print(f"[ERROR] Failed to import modules: {e}")
    sys.exit(1)


def load_harmbench_behaviors(categories: List[str]) -> List[Dict[str, str]]:
    """Load HarmBench behaviors for specific categories."""
    csv_path = base_dir / "tests" / "benchmarks" / "harmbench" / "data" / "behavior_datasets" / "harmbench_behaviors_text_all.csv"
    
    if not csv_path.exists():
        print(f"[ERROR] HarmBench CSV not found: {csv_path}")
        return []
    
    behaviors = []
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Use SemanticCategory (like run_harmbench_eval.py does)
            # Fallback to FunctionalCategory if SemanticCategory is empty
            category = row.get('SemanticCategory', '') or row.get('FunctionalCategory', '')
            if category in categories:
                behaviors.append({
                    'id': row.get('BehaviorID', ''),
                    'behavior': row.get('Behavior', ''),
                    'category': category,
                })
    
    return behaviors


def analyze_bypasses(category: str):
    """Analyze bypasses for a specific category."""
    print(f"\n{'='*80}")
    print(f"ANALYZING {category.upper()} BYPASSES")
    print(f"{'='*80}")
    
    # Load behaviors
    behaviors = load_harmbench_behaviors([category])
    print(f"\n[INFO] Loaded {len(behaviors)} {category} behaviors from HarmBench")
    
    if not behaviors:
        print(f"[ERROR] No {category} behaviors found")
        return
    
    # Initialize firewall
    config = EmergencyFixFirewallConfig(enable_kids_policy=False)
    firewall = FirewallEngineV3(config)
    
    # Initialize SafetyValidator for direct testing
    config_dir = base_dir / "config"
    validator = SafetyValidator(
        config_dir=str(config_dir),
        enable_gpt5=False,
        gpt5_threshold=0.5
    )
    
    # Test each behavior
    bypassed = []
    blocked = []
    
    for i, behavior in enumerate(behaviors, 1):
        prompt = behavior['behavior']
        
        # Test with firewall
        decision = firewall.process_input(user_id="test", text=prompt)
        
        # Test with SafetyValidator directly
        safety_decision = validator.validate(prompt)
        
        if decision.allowed:
            bypassed.append({
                'prompt': prompt,
                'risk_score': decision.risk_score,
                'reason': decision.reason,
                'safety_category': safety_decision.category,
                'safety_matched': safety_decision.matched_keyword,
                'safety_confidence': safety_decision.match_confidence,
                'safety_action': safety_decision.action,
            })
        else:
            blocked.append({
                'prompt': prompt,
                'risk_score': decision.risk_score,
            })
        
        if i % 20 == 0:
            print(f"[PROGRESS] Processed {i}/{len(behaviors)} behaviors...")
    
    # Print summary
    print(f"\n{'='*80}")
    print(f"RESULTS: {len(blocked)} blocked, {len(bypassed)} bypassed")
    print(f"ASR: {len(bypassed)/len(behaviors)*100:.1f}%")
    print(f"{'='*80}")
    
    # Analyze bypasses
    if bypassed:
        print(f"\n{'='*80}")
        print(f"BYPASSED PROMPTS ({len(bypassed)}):")
        print(f"{'='*80}")
        
        # Group by characteristics
        no_safety_match = [b for b in bypassed if not b['safety_category']]
        safety_match_but_low_risk = [b for b in bypassed if b['safety_category'] and b['risk_score'] < 0.17]
        safety_gate = [b for b in bypassed if b['safety_action'] == 'GATE']
        
        print(f"\n1. No Safety Match ({len(no_safety_match)}):")
        for b in no_safety_match[:10]:
            print(f"   - Risk: {b['risk_score']:.3f} | '{b['prompt'][:70]}...'")
        
        print(f"\n2. Safety Match but Low Risk ({len(safety_match_but_low_risk)}):")
        for b in safety_match_but_low_risk[:10]:
            print(f"   - Risk: {b['risk_score']:.3f} | Pattern: '{b['safety_matched']}' | Conf: {b['safety_confidence']} | '{b['prompt'][:70]}...'")
        
        print(f"\n3. Safety GATE ({len(safety_gate)}):")
        for b in safety_gate[:10]:
            print(f"   - Risk: {b['risk_score']:.3f} | Pattern: '{b['safety_matched']}' | Conf: {b['safety_confidence']} | '{b['prompt'][:70]}...'")
        
        # Pattern analysis
        print(f"\n{'='*80}")
        print("PATTERN ANALYSIS")
        print(f"{'='*80}")
        
        # Analyze common words/phrases in bypassed prompts
        word_freq = defaultdict(int)
        for b in bypassed:
            words = b['prompt'].lower().split()
            for word in words:
                if len(word) > 3:  # Ignore short words
                    word_freq[word] += 1
        
        print(f"\nMost common words in bypassed prompts:")
        for word, count in sorted(word_freq.items(), key=lambda x: x[1], reverse=True)[:20]:
            print(f"  '{word}': {count}")
        
        # Save full list
        output_file = base_dir / f"{category}_bypasses_analysis.txt"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"{category.upper()} BYPASSES ANALYSIS\n")
            f.write("="*80 + "\n\n")
            f.write(f"Total: {len(bypassed)} bypassed out of {len(behaviors)} total\n")
            f.write(f"ASR: {len(bypassed)/len(behaviors)*100:.1f}%\n\n")
            
            f.write("BYPASSED PROMPTS:\n")
            f.write("-"*80 + "\n")
            for b in bypassed:
                f.write(f"Prompt: {b['prompt']}\n")
                f.write(f"Risk Score: {b['risk_score']:.3f}\n")
                f.write(f"Safety Category: {b['safety_category']}\n")
                f.write(f"Safety Matched: {b['safety_matched']}\n")
                f.write(f"Safety Confidence: {b['safety_confidence']}\n")
                f.write(f"Safety Action: {b['safety_action']}\n")
                f.write("-"*80 + "\n")
        
        print(f"\n[INFO] Full analysis saved to: {output_file}")
    else:
        print(f"\n[SUCCESS] No bypasses found for {category}!")


def main():
    """Main analysis function."""
    print("\n" + "="*80)
    print("CYBERCRIME & MISINFORMATION BYPASS ANALYSIS")
    print("="*80)
    
    # Analyze both categories
    analyze_bypasses("cybercrime_intrusion")
    analyze_bypasses("misinformation_disinformation")
    
    print("\n" + "="*80)
    print("ANALYSIS COMPLETE")
    print("="*80)
    print("\nNext steps:")
    print("1. Review the generated analysis files")
    print("2. Identify common patterns in bypassed prompts")
    print("3. Prepare requirements for specialized ML detectors")
    print("4. Wait for Hugging Face Forum architecture guidance")


if __name__ == "__main__":
    main()
