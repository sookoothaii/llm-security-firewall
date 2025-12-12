"""
Quick Copyright Bypass Analysis
================================

Schnelle Analyse der verbleibenden Copyright-Bypasses ohne vollständige Firewall-Initialisierung.
"""

import sys
import csv
from pathlib import Path

# Add project root to path
base_dir = Path(__file__).parent.parent
sys.path.insert(0, str(base_dir / "src"))

try:
    from llm_firewall.safety.validator import SafetyValidator
except ImportError as e:
    print(f"[ERROR] Failed to import: {e}")
    sys.exit(1)


def load_copyright_behaviors():
    """Load only copyright behaviors."""
    csv_path = base_dir / "tests" / "benchmarks" / "harmbench" / "data" / "behavior_datasets" / "harmbench_behaviors_text_all.csv"
    
    if not csv_path.exists():
        print(f"[ERROR] CSV not found: {csv_path}")
        return []
    
    behaviors = []
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get('FunctionalCategory') == 'copyright':
                behaviors.append(row.get('Behavior', ''))
    
    return behaviors


def main():
    """Quick analysis using only SafetyValidator."""
    import sys
    import io
    
    # Force UTF-8 output
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    
    print("\n" + "="*80)
    print("QUICK COPYRIGHT BYPASS ANALYSIS")
    print("="*80)
    
    prompts = load_copyright_behaviors()
    print(f"[INFO] Loaded {len(prompts)} copyright prompts")
    sys.stdout.flush()
    
    if not prompts:
        print("[ERROR] No prompts loaded")
        return
    
    # Initialize only SafetyValidator (much faster)
    print("[INFO] Initializing SafetyValidator...")
    sys.stdout.flush()
    
    try:
        config_dir = base_dir / "config"
        validator = SafetyValidator(config_dir=str(config_dir), enable_gpt5=False, gpt5_threshold=0.5)
        print(f"[INFO] SafetyValidator initialized. Aho-Corasick: {'Yes' if validator.category_trie else 'No'}")
        sys.stdout.flush()
    except Exception as e:
        print(f"[ERROR] Failed to initialize SafetyValidator: {e}")
        import traceback
        traceback.print_exc()
        return
    
    print(f"[INFO] Testing {len(prompts)} prompts with SafetyValidator...")
    sys.stdout.flush()
    
    no_match = []
    low_confidence = []
    gate_action = []
    blocked = []
    
    for i, prompt in enumerate(prompts, 1):
        try:
            decision = validator.validate(prompt)
            
            if not decision.category:
                no_match.append({
                    'prompt': prompt,
                    'action': decision.action,
                    'risk': decision.risk_score,
                })
            elif decision.category == 'copyright_violation':
                if decision.action == 'BLOCK':
                    blocked.append({
                        'prompt': prompt,
                        'match': decision.matched_keyword,
                        'conf': decision.match_confidence,
                        'risk': decision.risk_score,
                    })
                elif decision.action == 'GATE':
                    gate_action.append({
                        'prompt': prompt,
                        'match': decision.matched_keyword,
                        'conf': decision.match_confidence,
                        'risk': decision.risk_score,
                    })
                elif decision.match_confidence and decision.match_confidence < 0.6:
                    low_confidence.append({
                        'prompt': prompt,
                        'match': decision.matched_keyword,
                        'conf': decision.match_confidence,
                        'risk': decision.risk_score,
                    })
        except Exception as e:
            print(f"[ERROR] Prompt {i}: {e}", flush=True)
            continue
        
        if i % 50 == 0:
            print(f"[PROGRESS] {i}/{len(prompts)}... (no_match={len(no_match)}, gate={len(gate_action)}, low_conf={len(low_confidence)})", flush=True)
    
    print(f"\n{'='*80}")
    print(f"SAFETYVALIDATOR ANALYSIS RESULTS")
    print(f"{'='*80}")
    print(f"Total tested: {len(prompts)}")
    print(f"BLOCKED by SafetyValidator: {len(blocked)}")
    print(f"No match (potential bypass): {len(no_match)}")
    print(f"Low confidence (<0.6): {len(low_confidence)}")
    print(f"GATE action (potential bypass): {len(gate_action)}")
    sys.stdout.flush()
    
    # Show potential bypasses (these might still be blocked by other layers, but SafetyValidator doesn't catch them)
    potential_bypasses = no_match + low_confidence + gate_action
    
    if potential_bypasses:
        print(f"\n{'='*80}")
        print(f"POTENTIAL BYPASSES ({len(potential_bypasses)}):")
        print(f"{'='*80}\n")
        
        for i, b in enumerate(potential_bypasses[:20], 1):  # Show first 20
            print(f"{i}. {b['prompt'][:80]}...")
            if 'match' in b:
                print(f"   Match: '{b['match']}' | Conf: {b.get('conf', 'N/A')} | Risk: {b.get('risk', 0):.3f}")
            else:
                print(f"   Action: {b.get('action', 'N/A')} | Risk: {b.get('risk', 0):.3f}")
            print()
        
        if len(potential_bypasses) > 20:
            print(f"... and {len(potential_bypasses) - 20} more")
    
    # Save to file
    output_file = base_dir / "copyright_bypasses_quick_analysis.txt"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("COPYRIGHT BYPASSES QUICK ANALYSIS\n")
        f.write("="*80 + "\n\n")
        for b in potential_bypasses:
            f.write(f"Prompt: {b['prompt']}\n")
            if 'match' in b:
                f.write(f"Match: {b['match']}\n")
                f.write(f"Confidence: {b.get('conf', 'N/A')}\n")
            f.write(f"Risk: {b.get('risk', 0):.3f}\n")
            f.write("-"*80 + "\n")
    
    print(f"\n[INFO] Full analysis saved to: {output_file}")


if __name__ == "__main__":
    main()
