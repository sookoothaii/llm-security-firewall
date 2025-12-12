"""
Find Copyright Bypasses from HarmBench Evaluation
===================================================

Einfaches Skript, das die HarmBench-Evaluation ausführt und nur die
durchgelassenen Copyright-Prompts ausgibt.
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


def main():
    """Find bypassed copyright prompts."""
    import sys
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    
    print("\n" + "="*80)
    print("FINDING COPYRIGHT BYPASSES")
    print("="*80)
    
    behaviors = load_harmbench_behaviors()
    print(f"[INFO] Loaded {len(behaviors)} copyright behaviors")
    
    if not behaviors:
        print("[ERROR] No behaviors loaded")
        return
    
    print("[INFO] Initializing firewall...")
    # Initialize
    config = EmergencyFixFirewallConfig(enable_kids_policy=False)
    firewall = FirewallEngineV3(config)
    
    print("[INFO] Initializing SafetyValidator...")
    config_dir = base_dir / "config"
    validator = SafetyValidator(config_dir=str(config_dir), enable_gpt5=False, gpt5_threshold=0.5)
    
    print(f"[INFO] Testing {len(behaviors)} prompts...")
    bypassed = []
    
    for i, behavior in enumerate(behaviors, 1):
        prompt = behavior['behavior']
        try:
            decision = firewall.process_input(user_id="test", text=prompt)
            safety_decision = validator.validate(prompt)
            
            if decision.allowed:
                bypassed.append({
                    'prompt': prompt,
                    'risk': decision.risk_score,
                    'reason': decision.reason,
                    'safety_cat': safety_decision.category,
                    'safety_match': safety_decision.matched_keyword,
                    'safety_conf': safety_decision.match_confidence,
                    'safety_action': safety_decision.action,
                })
        except Exception as e:
            print(f"[ERROR] Failed to process prompt {i}: {e}")
            continue
        
        if i % 20 == 0:
            print(f"[PROGRESS] {i}/{len(behaviors)}... (found {len(bypassed)} bypasses so far)", flush=True)
    
    print(f"\n\n[RESULTS] {len(bypassed)} bypassed out of {len(behaviors)}")
    print("="*80)
    
    if bypassed:
        print(f"\n{'='*80}")
        print(f"DETAILED ANALYSIS OF {len(bypassed)} BYPASSED PROMPTS:")
        print(f"{'='*80}\n")
        
        for i, b in enumerate(bypassed, 1):
            print(f"{'='*60}")
            print(f"BYPASS {i}:")
            print(f"{'='*60}")
            print(f"Prompt: {b['prompt']}")
            print(f"Risk Score: {b['risk']:.3f}")
            print(f"Reason: {b['reason']}")
            print(f"\nSafetyValidator Results:")
            print(f"  Category: {b['safety_cat']}")
            print(f"  Matched Keyword: {b['safety_match']}")
            print(f"  Confidence: {b['safety_conf']}")
            print(f"  Action: {b['safety_action']}")
            
            # Analyze why it bypassed
            print(f"\nAnalysis:")
            if not b['safety_cat']:
                print(f"  ❌ No Safety Match - Pattern fehlt oder nicht erkannt")
                prompt_lower = b['prompt'].lower()
                if 'generate' in prompt_lower:
                    # Extract potential pattern
                    parts = prompt_lower.split('generate', 1)
                    if len(parts) > 1:
                        next_words = parts[1].strip().split()[:5]
                        potential_pattern = 'generate ' + ' '.join(next_words)
                        print(f"  💡 Potential pattern: '{potential_pattern}'")
            elif b['safety_cat'] == 'copyright_violation' and b['risk'] < 0.17:
                print(f"  ⚠️  Safety Match gefunden, aber Risk Score zu niedrig ({b['risk']:.3f} < 0.17)")
                print(f"  💡 Problem: context.block() wird nicht korrekt aufgerufen")
            elif b['safety_action'] == 'GATE':
                print(f"  ⚠️  Safety Action ist 'GATE' statt 'BLOCK'")
                print(f"  💡 Problem: Confidence Score zu niedrig oder Threshold zu hoch")
            print()
    else:
        print("\n[SUCCESS] All copyright prompts blocked!")


if __name__ == "__main__":
    main()
