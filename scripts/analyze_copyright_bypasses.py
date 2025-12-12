"""
Analyze Copyright Bypasses
===========================

Analysiert die HarmBench-Copyright-Prompts, die durchgelassen werden,
um fehlende Patterns zu identifizieren.
"""

import sys
from pathlib import Path

# Add project root to path
base_dir = Path(__file__).parent.parent
sys.path.insert(0, str(base_dir / "src"))

try:
    from llm_firewall.core.firewall_engine_v3 import FirewallEngineV3, EmergencyFixFirewallConfig
    from llm_firewall.safety.validator import SafetyValidator
except ImportError as e:
    print(f"[ERROR] Failed to import modules: {e}")
    sys.exit(1)


def load_harmbench_behaviors():
    """Load HarmBench behaviors from CSV."""
    csv_path = base_dir / "tests" / "benchmarks" / "harmbench" / "data" / "behavior_datasets" / "harmbench_behaviors_text_all.csv"
    
    if not csv_path.exists():
        print(f"[ERROR] HarmBench CSV not found: {csv_path}")
        return []
    
    import csv
    behaviors = []
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get('FunctionalCategory') == 'copyright':
                behaviors.append({
                    'id': row.get('BehaviorID', ''),
                    'behavior': row.get('Behavior', ''),
                    'category': row.get('FunctionalCategory', ''),
                })
    
    return behaviors


def analyze_bypasses():
    """Analyze which copyright prompts bypass detection."""
    print("\n" + "="*80)
    print("ANALYZING COPYRIGHT BYPASSES")
    print("="*80)
    
    # Load behaviors
    behaviors = load_harmbench_behaviors()
    print(f"\n[INFO] Loaded {len(behaviors)} copyright behaviors from HarmBench")
    
    if not behaviors:
        print("[ERROR] No copyright behaviors found")
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
    
    print(f"[INFO] Aho-Corasick Trie: {'Available' if validator.category_trie is not None else 'NOT Available'}")
    print(f"[INFO] Copyright patterns: {len([p for p in validator.threat_config.get('signals', {}).get('category_lexicon', {}).get('copyright_violation', [])])}")
    
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
    print(f"{'='*80}")
    
    # Analyze bypasses
    if bypassed:
        print(f"\n{'='*80}")
        print(f"BYPASSED PROMPTS ({len(bypassed)}):")
        print(f"{'='*80}")
        
        # Group by safety validator result
        no_safety_match = [b for b in bypassed if not b['safety_category']]
        safety_match_but_low_risk = [b for b in bypassed if b['safety_category'] and b['risk_score'] < 0.17]
        safety_gate = [b for b in bypassed if b['safety_action'] == 'GATE']
        
        print(f"\n1. No Safety Match ({len(no_safety_match)}):")
        for b in no_safety_match[:10]:  # Show first 10
            print(f"   - Risk: {b['risk_score']:.3f} | '{b['prompt'][:60]}...'")
        
        print(f"\n2. Safety Match but Low Risk ({len(safety_match_but_low_risk)}):")
        for b in safety_match_but_low_risk[:10]:
            print(f"   - Risk: {b['risk_score']:.3f} | Pattern: '{b['safety_matched']}' | Conf: {b['safety_confidence']} | '{b['prompt'][:60]}...'")
        
        print(f"\n3. Safety GATE ({len(safety_gate)}):")
        for b in safety_gate[:10]:
            print(f"   - Risk: {b['risk_score']:.3f} | Pattern: '{b['safety_matched']}' | Conf: {b['safety_confidence']} | '{b['prompt'][:60]}...'")
        
        # Save full list
        output_file = base_dir / "copyright_bypasses_analysis.txt"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("COPYRIGHT BYPASSES ANALYSIS\n")
            f.write("="*80 + "\n\n")
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
        print("\n[SUCCESS] No bypasses found!")


if __name__ == "__main__":
    analyze_bypasses()
