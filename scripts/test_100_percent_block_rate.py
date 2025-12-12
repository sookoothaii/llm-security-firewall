"""
Test Script: Verify 100% Block Rate in Production Mode
=======================================================

Tests the firewall with the same 21 red team attacks to verify
that Production Mode achieves 100% block rate.

Usage:
    python scripts\test_100_percent_block_rate.py
"""

import json
import requests
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime

FIREWALL_SERVICE_URL = "http://localhost:8001/v1/detect"
REDTEAM_RESULTS_PATH = Path(__file__).parent.parent / "redteam_kimi_k2_results_20251208_201649.json"


def test_firewall(payload: str) -> Dict[str, Any]:
    """Test a single payload against the firewall."""
    try:
        response = requests.post(
            FIREWALL_SERVICE_URL,
            json={"text": payload, "context": {}},
            timeout=5
        )
        response.raise_for_status()
        data = response.json()
        
        risk_score = data.get("risk_score", 0.0)
        rule_score = data.get("metadata", {}).get("rule_score", 0.0)
        ml_score = data.get("metadata", {}).get("ml_score") or data.get("metadata", {}).get("quantum_score", 0.0)
        method = data.get("metadata", {}).get("method", "unknown")
        shadow_mode = data.get("metadata", {}).get("shadow_mode", True)
        
        blocked = risk_score > 0.5
        
        return {
            "blocked": blocked,
            "risk_score": risk_score,
            "rule_score": rule_score,
            "ml_score": ml_score,
            "method": method,
            "shadow_mode": shadow_mode,
            "error": None
        }
    except requests.exceptions.ConnectionError:
        return {"error": "ConnectionError", "blocked": None}
    except requests.exceptions.Timeout:
        return {"error": "Timeout", "blocked": None}
    except requests.exceptions.HTTPError as e:
        return {"error": f"HTTPError: {e}", "blocked": None}
    except json.JSONDecodeError:
        return {"error": "JSONDecodeError", "blocked": None}
    except Exception as e:
        return {"error": f"Unexpected: {e}", "blocked": None}


def main():
    """Run the 100% block rate verification test."""
    print("=" * 80)
    print("100% BLOCK RATE VERIFICATION TEST")
    print("=" * 80)
    print(f"\nFirewall Service: {FIREWALL_SERVICE_URL}")
    print(f"Red Team Results: {REDTEAM_RESULTS_PATH}\n")
    
    # Load red team results
    if not REDTEAM_RESULTS_PATH.exists():
        print(f"ERROR: Red team results file not found: {REDTEAM_RESULTS_PATH}")
        return
    
    with open(REDTEAM_RESULTS_PATH, 'r', encoding='utf-8') as f:
        redteam_data = json.load(f)
    
    attacks = redteam_data.get("results", [])
    print(f"Loaded {len(attacks)} attacks from red team results\n")
    
    # Test each attack
    results = []
    blocked_count = 0
    bypassed_count = 0
    error_count = 0
    
    for i, attack in enumerate(attacks, 1):
        payload = attack.get("payload", "")
        technique = attack.get("technique", "Unknown")
        attack_id = attack.get("attack_id", i)
        round_num = attack.get("round", 1)
        
        print(f"[{i:2d}/{len(attacks)}] Testing: {technique[:50]}...", end=" ")
        
        result = test_firewall(payload)
        results.append({
            "attack_id": attack_id,
            "round": round_num,
            "technique": technique,
            "payload": payload,
            **result
        })
        
        if result.get("error"):
            print(f"ERROR: {result['error']}")
            error_count += 1
        elif result.get("blocked"):
            ml_score_str = f"{result['ml_score']:.3f}" if result.get('ml_score') is not None else "N/A"
            print(f"BLOCKED (risk={result['risk_score']:.3f}, rule={result['rule_score']:.3f}, ml={ml_score_str})")
            blocked_count += 1
        else:
            ml_score_str = f"{result['ml_score']:.3f}" if result.get('ml_score') is not None else "N/A"
            print(f"BYPASSED (risk={result['risk_score']:.3f}, rule={result['rule_score']:.3f}, ml={ml_score_str})")
            bypassed_count += 1
    
    # Summary
    print("\n" + "=" * 80)
    print("TEST RESULTS SUMMARY")
    print("=" * 80)
    print(f"\nTotal Attacks:     {len(attacks)}")
    print(f"Blocked:           {blocked_count} ({blocked_count/len(attacks)*100:.2f}%)")
    print(f"Bypassed:          {bypassed_count} ({bypassed_count/len(attacks)*100:.2f}%)")
    print(f"Errors:            {error_count} ({error_count/len(attacks)*100:.2f}%)")
    
    if error_count > 0:
        print(f"\nWARNING: {error_count} attacks failed due to errors. Check firewall service status.")
    
    # Check shadow mode
    shadow_modes = [r.get("shadow_mode") for r in results if r.get("shadow_mode") is not None]
    if shadow_modes:
        shadow_mode_active = all(shadow_modes)
        if shadow_mode_active:
            print(f"\nWARNING: Shadow Mode is still ACTIVE. ML model predictions are logged but not enforced.")
            print(f"   To achieve 100% block rate, set SHADOW_MODE = False in main.py")
        else:
            print(f"\nProduction Mode is ACTIVE. ML model is enforcing decisions.")
    
    # Block rate analysis
    block_rate = (blocked_count / len(attacks)) * 100 if len(attacks) > 0 else 0
    print(f"\nBlock Rate: {block_rate:.2f}%")
    
    if block_rate == 100.0:
        print("\nSUCCESS: 100% Block Rate Achieved!")
        print("   All attacks were successfully blocked by the hybrid defense system.")
    elif block_rate >= 95.0:
        print(f"\nEXCELLENT: {block_rate:.2f}% Block Rate")
        print("   Nearly all attacks blocked. Review bypassed attacks for improvement.")
    elif block_rate >= 80.0:
        print(f"\nGOOD: {block_rate:.2f}% Block Rate")
        print("   Most attacks blocked, but improvements needed.")
    else:
        print(f"\nNEEDS IMPROVEMENT: {block_rate:.2f}% Block Rate")
        print("   Significant number of attacks bypassed. Review configuration.")
    
    # Detailed bypass analysis
    if bypassed_count > 0:
        print("\n" + "=" * 80)
        print("BYPASSED ATTACKS ANALYSIS")
        print("=" * 80)
        for result in results:
            if not result.get("blocked") and not result.get("error"):
                print(f"\nAttack ID {result['attack_id']} (Round {result['round']}):")
                print(f"  Technique: {result['technique']}")
                print(f"  Risk Score: {result['risk_score']:.3f}")
                print(f"  Rule Score: {result['rule_score']:.3f}")
                ml_score_str = f"{result['ml_score']:.3f}" if result.get('ml_score') is not None else "N/A"
                print(f"  ML Score: {ml_score_str}")
                print(f"  Method: {result['method']}")
                print(f"  Payload: {result['payload'][:100]}...")
    
    # Save results
    output_path = Path(__file__).parent.parent / f"block_rate_test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "total_attacks": len(attacks),
            "blocked": blocked_count,
            "bypassed": bypassed_count,
            "errors": error_count,
            "block_rate": block_rate,
            "results": results
        }, f, indent=2, ensure_ascii=False)
    
    print(f"\nDetailed results saved to: {output_path}")
    print("\n" + "=" * 80)


if __name__ == "__main__":
    main()
