"""
FP Deep Analysis Tool - Detailed Telemetry for Surgical Gate Design

Analyzes the 8 remaining FPs from N=1020 pure benign corpus with full context:
- ctx, exec_ctx, has_codefence, has_net_api, has_js_attr
- distance_to_call, decoded_out_has_exec_tokens, fence_lang
- Simulates flag gates to predict FPR reduction

GPT-5 Recommendation: A (FP Deep Analysis) before B (External Corpus)
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Any
from collections import Counter

# Import detection functions
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from llm_firewall.pipeline.context import (
    detect_documentation_context,
    is_exec_context,
    is_exploit_context
)


def analyze_file(filepath: Path) -> Dict[str, Any]:
    """Analyze single file with full telemetry"""
    try:
        content = filepath.read_text(encoding='utf-8', errors='ignore')
        
        # Context detection
        ctx_meta = detect_documentation_context(content)
        ctx = ctx_meta['ctx']
        exec_ctx = is_exec_context(content, ctx)
        exploit_ctx = is_exploit_context(content, ctx)
        
        # Code fence detection
        has_codefence = bool(re.search(r'```\w*', content))
        fence_langs = re.findall(r'```(\w+)', content)
        
        # Network/JS detection (simple patterns)
        net_api_keywords = ['http://', 'https://', 'fetch(', 'XMLHttpRequest', 'axios', 'request(', '.get(', '.post(']
        has_net_api = any(kw in content for kw in net_api_keywords)
        
        js_event_attrs = ['onclick=', 'onload=', 'onerror=', 'onmouseover=', 'onfocus=', 'onchange=']
        has_js_attr = any(attr in content for attr in js_event_attrs)
        
        # Distance to function call (simplified)
        # Look for attack keywords and measure distance to nearest ()
        attack_keywords = ['DROP', 'TABLE', 'DELETE', 'SELECT', 'INSERT', 'UPDATE', 'UNION', 'exec', 'eval']
        min_distance = 999
        for kw in attack_keywords:
            for match in re.finditer(r'\b' + kw + r'\b', content, re.IGNORECASE):
                pos = match.start()
                # Find nearest function call
                after_text = content[pos:pos+100]
                call_match = re.search(r'\(', after_text)
                if call_match:
                    dist = call_match.start()
                    min_distance = min(min_distance, dist)
        
        distance_to_call = min_distance if min_distance < 999 else None
        
        # Base64 decoding check (simplified)
        b64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        b64_matches = re.findall(b64_pattern, content)
        decoded_has_exec = False
        if b64_matches:
            import base64
            for match in b64_matches[:5]:  # Check first 5
                try:
                    decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                    if any(token in decoded.lower() for token in ['<script>', 'on', 'javascript:', 'eval(', 'exec(']):
                        decoded_has_exec = True
                        break
                except Exception:
                    pass
        
        return {
            'file': str(filepath.name),
            'ctx': ctx,
            'ctx_score': ctx_meta['score'],
            'exec_ctx': exec_ctx,
            'exploit_ctx': exploit_ctx,
            'has_codefence': has_codefence,
            'fence_langs': fence_langs,
            'has_net_api': has_net_api,
            'has_js_attr': has_js_attr,
            'distance_to_call': distance_to_call,
            'decoded_has_exec': decoded_has_exec,
            'num_b64_strings': len(b64_matches),
            'content_length': len(content),
        }
    
    except Exception as e:
        return {
            'file': str(filepath.name),
            'error': str(e)
        }


def simulate_gate(telemetry: Dict[str, Any], signal: str) -> bool:
    """
    Simulate flag gates - returns True if signal should FIRE (FP remains)
    Returns False if gate would SUPPRESS signal (FP eliminated)
    
    Gate logic from flags.yaml:
    - attack_keyword_with_encoding: Only fire if (codefence AND (net_api OR js_attr)) OR distance<=6
    - chain_decoded_1_stages: Telemetry only unless decoded_has_exec=True
    - encoding_near_attack_keyword: Require code proximity AND distance<=8
    - indirect_function_constructor: Require exec proof (call pattern OR event handler)
    """
    
    if signal == 'attack_keyword_with_encoding':
        # Gate: (codefence AND (net_api OR js_attr)) OR distance_to_call <= 6
        if telemetry.get('has_codefence') and (telemetry.get('has_net_api') or telemetry.get('has_js_attr')):
            return True  # Fire (legitimate risk)
        if telemetry.get('distance_to_call') is not None and telemetry['distance_to_call'] <= 6:
            return True  # Fire (close to call)
        return False  # Suppress (no exec context)
    
    elif signal == 'chain_decoded_1_stages':
        # Gate: Only fire if decoded_has_exec=True (contains exec tokens)
        return telemetry.get('decoded_has_exec', False)
    
    elif signal == 'encoding_near_attack_keyword':
        # Gate: Require codefence OR js_attr AND distance<=8
        if not (telemetry.get('has_codefence') or telemetry.get('has_js_attr')):
            return False  # Suppress (no code context)
        if telemetry.get('distance_to_call') is not None and telemetry['distance_to_call'] > 8:
            return False  # Suppress (too far)
        return True  # Fire (code proximity confirmed)
    
    elif signal == 'indirect_function_constructor':
        # Gate: Require call pattern () OR event handler attribute
        if telemetry.get('distance_to_call') is not None and telemetry['distance_to_call'] <= 10:
            return True  # Fire (has call pattern)
        if telemetry.get('has_js_attr'):
            return True  # Fire (event handler)
        return False  # Suppress (no exec proof)
    
    else:
        return True  # Unknown signal, fire by default


def main():
    # Load stratified FPR report
    report_path = Path('benign_fpr_stratified_1020samples_20251101_220159.json')
    if not report_path.exists():
        print(f"ERROR: {report_path} not found")
        return
    
    report = json.loads(report_path.read_text())
    
    # Collect all FPs
    all_fps = []
    for stratum, data in report['strata'].items():
        for fp in data['false_positives']:
            fp['stratum'] = stratum
            all_fps.append(fp)
    
    print(f"=" * 80)
    print(f"FP DEEP ANALYSIS - SURGICAL GATE SIMULATION")
    print(f"=" * 80)
    print(f"\nTotal FPs: {len(all_fps)} from N=1020")
    print(f"FPR: {report['overall']['fpr']:.2f}%")
    print(f"Wilson Upper: {report['overall']['wilson_upper']:.2f}%")
    print(f"\n" + "=" * 80)
    
    # Analyze each FP
    detailed_fps = []
    base_path = Path('benign_pure')
    
    for fp in all_fps:
        filename = Path(fp['file']).name
        filepath = base_path / filename
        
        if not filepath.exists():
            print(f"\nWARNING: {filename} not found in {base_path}")
            continue
        
        print(f"\n{'='*80}")
        print(f"FILE: {filename}")
        print(f"STRATUM: {fp['stratum']}")
        print(f"REASON: {fp['reason']}")
        print(f"{'='*80}")
        
        # Get detailed telemetry
        telemetry = analyze_file(filepath)
        
        # Extract signals from reason
        signals = []
        if 'attack_keyword_with_encoding' in fp['reason']:
            signals.append('attack_keyword_with_encoding')
        if 'chain_decoded_1_stages' in fp['reason']:
            signals.append('chain_decoded_1_stages')
        if 'encoding_near_attack_keyword' in fp['reason']:
            signals.append('encoding_near_attack_keyword')
        if 'indirect_function_constructor' in fp['reason']:
            signals.append('indirect_function_constructor')
        
        telemetry['signals'] = signals
        
        # Print telemetry
        print(f"\nTELEMETRY:")
        print(f"  ctx: {telemetry.get('ctx')}, score: {telemetry.get('ctx_score'):.2f}")
        print(f"  exec_ctx: {telemetry.get('exec_ctx')}")
        print(f"  exploit_ctx: {telemetry.get('exploit_ctx')}")
        print(f"  has_codefence: {telemetry.get('has_codefence')}")
        print(f"  fence_langs: {telemetry.get('fence_langs', [])}")
        print(f"  has_net_api: {telemetry.get('has_net_api')}")
        print(f"  has_js_attr: {telemetry.get('has_js_attr')}")
        print(f"  distance_to_call: {telemetry.get('distance_to_call')}")
        print(f"  decoded_has_exec: {telemetry.get('decoded_has_exec')}")
        print(f"  num_b64_strings: {telemetry.get('num_b64_strings')}")
        
        # Simulate gates
        print(f"\nGATE SIMULATION:")
        gates_suppressed = []
        gates_fired = []
        
        for signal in signals:
            should_fire = simulate_gate(telemetry, signal)
            if should_fire:
                gates_fired.append(signal)
                print(f"  {signal}: FIRE (FP remains)")
            else:
                gates_suppressed.append(signal)
                print(f"  {signal}: SUPPRESS (FP eliminated) [OK]")
        
        # Aggregate decision: FP eliminated if ALL signals suppressed
        fp_eliminated = len(gates_suppressed) == len(signals)
        telemetry['fp_eliminated'] = fp_eliminated
        telemetry['gates_suppressed'] = gates_suppressed
        telemetry['gates_fired'] = gates_fired
        
        print(f"\nOVERALL: FP {'ELIMINATED [OK]' if fp_eliminated else 'REMAINS'}")
        
        detailed_fps.append(telemetry)
    
    # Summary
    print(f"\n{'='*80}")
    print(f"SUMMARY - GATE SIMULATION RESULTS")
    print(f"{'='*80}")
    
    eliminated = sum(1 for fp in detailed_fps if fp.get('fp_eliminated'))
    remaining = len(detailed_fps) - eliminated
    
    print(f"\nBASELINE (flags=false):")
    print(f"  FPs: {len(detailed_fps)}/1020")
    print(f"  FPR: {report['overall']['fpr']:.2f}%")
    print(f"  Wilson Upper: {report['overall']['wilson_upper']:.2f}%")
    
    print(f"\nWITH GATES (flags=true, simulated):")
    print(f"  FPs eliminated: {eliminated}")
    print(f"  FPs remaining: {remaining}/1020")
    new_fpr = (remaining / 1020) * 100
    print(f"  FPR (estimated): {new_fpr:.2f}%")
    
    # Wilson score calculation for new FPR (simplified)
    if remaining > 0:
        from scipy import stats
        p = remaining / 1020
        n = 1020
        z = stats.norm.ppf(0.975)  # 95% CI
        denominator = 1 + z**2/n
        center = (p + z**2/(2*n)) / denominator
        margin = z * ((p*(1-p)/n + z**2/(4*n**2))**0.5) / denominator
        new_upper = (center + margin) * 100
        print(f"  Wilson Upper (estimated): {new_upper:.2f}%")
        
        if new_upper < 1.50:
            print(f"\n  STATUS: GATE PASS [OK] (Upper <1.50%)")
        else:
            print(f"\n  STATUS: Gate fail (Upper {new_upper:.2f}% >= 1.50%)")
    else:
        print(f"  Wilson Upper (estimated): 0.00%")
        print(f"\n  STATUS: PERFECT [OK]")
    
    reduction_pct = (eliminated / len(detailed_fps)) * 100 if detailed_fps else 0
    print(f"\nREDUCTION: {reduction_pct:.1f}% FPs eliminated")
    
    # Signal statistics
    print(f"\n{'='*80}")
    print(f"SIGNAL STATISTICS")
    print(f"{'='*80}")
    
    all_suppressed = []
    all_fired = []
    for fp in detailed_fps:
        all_suppressed.extend(fp.get('gates_suppressed', []))
        all_fired.extend(fp.get('gates_fired', []))
    
    suppressed_counts = Counter(all_suppressed)
    fired_counts = Counter(all_fired)
    
    print(f"\nSuppressed (FP eliminated):")
    for signal, count in suppressed_counts.most_common():
        print(f"  {signal}: {count}x")
    
    print(f"\nStill Fired (FP remains):")
    for signal, count in fired_counts.most_common():
        print(f"  {signal}: {count}x")
    
    # Save detailed report
    output = {
        'timestamp': report['timestamp'],
        'baseline': {
            'total': 1020,
            'fps': len(detailed_fps),
            'fpr': report['overall']['fpr'],
            'wilson_upper': report['overall']['wilson_upper']
        },
        'simulated_gates': {
            'fps_eliminated': eliminated,
            'fps_remaining': remaining,
            'fpr_estimated': new_fpr,
            'reduction_percent': reduction_pct
        },
        'detailed_fps': detailed_fps
    }
    
    output_path = Path('fp_telemetry_analysis.json')
    output_path.write_text(json.dumps(output, indent=2))
    print(f"\nDetailed report saved to: {output_path}")


if __name__ == '__main__':
    main()

