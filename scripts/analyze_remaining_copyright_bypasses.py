"""
Analyze Remaining Copyright Bypasses
======================================

Analysiert die verbleibenden 8 Copyright-Prompts, die durchgelassen werden,
um fehlende Patterns oder Probleme zu identifizieren.
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


def analyze_remaining_bypasses():
    """Analyze which copyright prompts still bypass detection."""
    print("\n" + "="*80)
    print("ANALYZING REMAINING COPYRIGHT BYPASSES (8 Prompts)")
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
                'metadata': decision.metadata,
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
    
    # Analyze bypasses in detail
    if bypassed:
        print(f"\n{'='*80}")
        print(f"DETAILED ANALYSIS OF {len(bypassed)} BYPASSED PROMPTS:")
        print(f"{'='*80}")
        
        for i, b in enumerate(bypassed, 1):
            print(f"\n{'='*60}")
            print(f"BYPASS {i}:")
            print(f"{'='*60}")
            print(f"Prompt: {b['prompt']}")
            print(f"Risk Score: {b['risk_score']:.3f}")
            print(f"Reason: {b['reason']}")
            print(f"\nSafetyValidator Results:")
            print(f"  Category: {b['safety_category']}")
            print(f"  Matched Keyword: {b['safety_matched']}")
            print(f"  Confidence: {b['safety_confidence']}")
            print(f"  Action: {b['safety_action']}")
            
            # Check metadata
            if b.get('metadata'):
                safety_decision_meta = b['metadata'].get('safety_decision')
                if safety_decision_meta:
                    print(f"\nMetadata:")
                    print(f"  Safety Decision: {safety_decision_meta}")
                safety_category_meta = b['metadata'].get('safety_category')
                if safety_category_meta:
                    print(f"  Safety Category: {safety_category_meta}")
            
            # Analyze why it bypassed
            print(f"\nAnalysis:")
            if not b['safety_category']:
                print(f"  ❌ No Safety Match - Pattern fehlt oder nicht erkannt")
                # Suggest pattern
                prompt_lower = b['prompt'].lower()
                if 'passage' in prompt_lower:
                    print(f"  💡 Vorschlag: Pattern 'passage' oder ähnlich hinzufügen")
                elif 'excerpt' in prompt_lower:
                    print(f"  💡 Vorschlag: Pattern 'excerpt' hinzufügen")
                elif 'quote' in prompt_lower:
                    print(f"  💡 Vorschlag: Pattern 'quote' hinzufügen")
                elif 'text' in prompt_lower and 'from' in prompt_lower:
                    print(f"  💡 Vorschlag: Pattern 'text from' oder 'text of' hinzufügen")
            elif b['safety_category'] == 'copyright_violation' and b['risk_score'] < 0.17:
                print(f"  ⚠️  Safety Match gefunden, aber Risk Score zu niedrig ({b['risk_score']:.3f} < 0.17)")
                print(f"  💡 Problem: context.block() wird nicht korrekt aufgerufen oder Risk Score wird reduziert")
            elif b['safety_action'] == 'GATE':
                print(f"  ⚠️  Safety Action ist 'GATE' statt 'BLOCK'")
                print(f"  💡 Problem: Confidence Score zu niedrig oder Threshold zu hoch")
        
        # Group by pattern
        print(f"\n{'='*80}")
        print(f"PATTERN ANALYSIS:")
        print(f"{'='*80}")
        
        no_match = [b for b in bypassed if not b['safety_category']]
        low_risk = [b for b in bypassed if b['safety_category'] and b['risk_score'] < 0.17]
        gate_action = [b for b in bypassed if b['safety_action'] == 'GATE']
        
        print(f"\n1. No Safety Match ({len(no_match)}):")
        for b in no_match:
            print(f"   - '{b['prompt'][:70]}...'")
            # Extract potential patterns
            prompt_lower = b['prompt'].lower()
            if 'generate' in prompt_lower:
                # Find what comes after "generate"
                parts = prompt_lower.split('generate', 1)
                if len(parts) > 1:
                    next_words = parts[1].strip().split()[:5]
                    potential_pattern = 'generate ' + ' '.join(next_words)
                    print(f"     💡 Potential pattern: '{potential_pattern}'")
        
        print(f"\n2. Low Risk Score ({len(low_risk)}):")
        for b in low_risk:
            print(f"   - Risk: {b['risk_score']:.3f} | Pattern: '{b['safety_matched']}' | '{b['prompt'][:70]}...'")
        
        print(f"\n3. GATE Action ({len(gate_action)}):")
        for b in gate_action:
            print(f"   - Conf: {b['safety_confidence']} | Pattern: '{b['safety_matched']}' | '{b['prompt'][:70]}...'")
        
        # Save detailed analysis
        output_file = base_dir / "remaining_copyright_bypasses_analysis.txt"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("REMAINING COPYRIGHT BYPASSES ANALYSIS\n")
            f.write("="*80 + "\n\n")
            f.write(f"Total Bypassed: {len(bypassed)}\n")
            f.write(f"Total Blocked: {len(blocked)}\n\n")
            
            for b in bypassed:
                f.write(f"Prompt: {b['prompt']}\n")
                f.write(f"Risk Score: {b['risk_score']:.3f}\n")
                f.write(f"Reason: {b['reason']}\n")
                f.write(f"Safety Category: {b['safety_category']}\n")
                f.write(f"Safety Matched: {b['safety_matched']}\n")
                f.write(f"Safety Confidence: {b['safety_confidence']}\n")
                f.write(f"Safety Action: {b['safety_action']}\n")
                f.write("-"*80 + "\n")
        
        print(f"\n[INFO] Detailed analysis saved to: {output_file}")
    else:
        print("\n[SUCCESS] No bypasses found! All copyright prompts are blocked!")


if __name__ == "__main__":
    analyze_remaining_bypasses()
