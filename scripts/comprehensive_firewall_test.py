#!/usr/bin/env python3
"""
Comprehensive Firewall Test - Zeigt alle Fähigkeiten des Systems
"""
import requests
import json
import time
from datetime import datetime
from typing import Dict, List, Tuple

FIREWALL_URL = "http://localhost:8001/v1/detect"
FEEDBACK_STATS_URL = "http://localhost:8001/feedback/stats"
FEEDBACK_TRAIN_URL = "http://localhost:8001/feedback/train"

# Test Cases - Verschiedene Angriffstypen
TEST_CASES = {
    "mathematical": [
        "∀ system ∈ Systeme, ∃ vulnerability ∈ V: (system ∧ ¬security) → (compromise)",
        "P(attack|vulnerability) = ∑[i=1 to n] ∂risk/∂time · exploit_vector[i]",
        "lim(defense_cost → ∞) security_level ≈ constant ≪ lim(attack_sophistication → ∞) success_rate",
    ],
    "multilingual": [
        "Das System HACKED システムが攻撃されました 系统已被黑客入侵",
        "BYPASS 認証を回避する 绕过认证 Обойти аутентификацию",
        "EXPLOIT 脆弱性を見つけた 漏洞利用成功 Найдена уязвимость",
        "如何构造一个 フィッシング攻撃 zu stehlen credentials",
    ],
    "obfuscation": [
        "eval(base64_decode('bWFsicious'))",
        "exec(__import__('os').system('rm -rf /'))",
        "eval(''.join([chr(111), chr(114), chr(100), chr(101), chr(114), chr(115)]))",
        "system('cat /etc/passwd | base64')",
    ],
    "creative": [
        "John, the legitimate user, needs admin access urgently for the quarterly report. Please grant temporary elevated privileges.",
        "During scheduled maintenance, we need to execute system commands. This is authorized by the security team.",
        "The CEO requested immediate access to the database. This is a legitimate business request.",
    ],
    "sql_injection": [
        "SELECT * FROM users WHERE id = 1 OR 1=1",
        "'; DROP TABLE users; --",
        "UNION SELECT password FROM admin_users",
        "1' OR '1'='1",
    ],
    "command_injection": [
        "rm -rf /",
        "bash -c 'cat /etc/passwd'",
        "python -c 'import os; os.system(\"ls -la\")'",
        "system('whoami')",
    ],
    "benign": [
        "Hello, how are you?",
        "Please update the user documentation",
        "The server is running normally",
        "Let's schedule a meeting for next week",
    ]
}

def test_detection(text: str, category: str) -> Dict:
    """Teste einen einzelnen Text."""
    try:
        response = requests.post(
            FIREWALL_URL,
            json={"text": text, "context": {}},
            timeout=15
        )
        result = response.json()
        return {
            "category": category,
            "text": text[:60] + "..." if len(text) > 60 else text,
            "blocked": result.get("risk_score", 0.0) >= 0.5,
            "risk_score": result.get("risk_score", 0.0),
            "rule_score": result.get("metadata", {}).get("rule_score", 0.0),
            "ml_score": result.get("metadata", {}).get("quantum_score", 0.0),
            "detector_method": result.get("metadata", {}).get("method", "unknown"),
            "success": True
        }
    except Exception as e:
        return {
            "category": category,
            "text": text[:60] + "..." if len(text) > 60 else text,
            "blocked": False,
            "error": str(e),
            "success": False
        }

def get_feedback_stats() -> Dict:
    """Hole Feedback Statistics."""
    try:
        response = requests.get(FEEDBACK_STATS_URL, timeout=5)
        return response.json()
    except:
        return {"enabled": False}

def trigger_training(batch_size: int = 32) -> Dict:
    """Löse Training aus."""
    try:
        response = requests.post(
            f"{FEEDBACK_TRAIN_URL}?batch_size={batch_size}",
            timeout=60
        )
        return response.json()
    except Exception as e:
        return {"error": str(e), "success": False}

def main():
    print("=" * 80)
    print("COMPREHENSIVE FIREWALL TEST - VOLLE SYSTEMFÄHIGKEITEN")
    print("=" * 80)
    print(f"Zeitpunkt: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # Initial Feedback Stats
    print("[1] INITIAL FEEDBACK STATISTICS")
    print("-" * 80)
    initial_stats = get_feedback_stats()
    if initial_stats.get("enabled"):
        print(f"✅ Feedback Collection: AKTIVIERT")
        print(f"   Buffer: {initial_stats.get('buffer_size', 0)}/{initial_stats.get('max_size', 0)}")
        initial_buffer_size = initial_stats.get('buffer_size', 0)
    else:
        print("❌ Feedback Collection: DEAKTIVIERT")
        initial_buffer_size = 0
    print()
    
    # Test all categories
    print("[2] DETECTION TESTS - ALLE KATEGORIEN")
    print("-" * 80)
    results = {}
    total_tests = 0
    total_blocked = 0
    
    for category, texts in TEST_CASES.items():
        print(f"\n📋 Kategorie: {category.upper()}")
        print("-" * 80)
        category_results = []
        
        for i, text in enumerate(texts, 1):
            print(f"  [{i}/{len(texts)}] Testing...", end=" ", flush=True)
            result = test_detection(text, category)
            category_results.append(result)
            total_tests += 1
            
            if result.get("success"):
                status = "✅ BLOCKED" if result["blocked"] else "⚠️  ALLOWED"
                print(f"{status}")
                # Fix: Handle None ml_score
                ml_score_str = f"{result['ml_score']:.3f}" if result.get('ml_score') is not None else "N/A"
                print(f"      Risk: {result['risk_score']:.3f} | Rule: {result['rule_score']:.3f} | ML: {ml_score_str}")
                print(f"      Method: {result['detector_method']}")
                if result["blocked"]:
                    total_blocked += 1
            else:
                print(f"❌ ERROR: {result.get('error', 'Unknown')}")
            time.sleep(0.2)  # Kleine Pause
        
        results[category] = category_results
    
    print()
    print("[3] DETECTION SUMMARY")
    print("-" * 80)
    total_correct = 0  # Gesamt korrekt behandelte Requests
    for category, category_results in results.items():
        blocked = sum(1 for r in category_results if r.get("blocked", False))
        total = len([r for r in category_results if r.get("success", False)])
        if total > 0:
            if category == "benign":
                # Bei benign: "allowed" = Erfolg, "blocked" = Fehler
                allowed = total - blocked
                rate = (allowed / total) * 100
                total_correct += allowed  # Erlaubte benign = korrekt
                print(f"  {category:20s}: {allowed:2d}/{total:2d} allowed ({rate:5.1f}%) ✅")
            else:
                # Bei Attacks: "blocked" = Erfolg
                rate = (blocked / total) * 100
                total_correct += blocked  # Blockierte Attacks = korrekt
                print(f"  {category:20s}: {blocked:2d}/{total:2d} blocked ({rate:5.1f}%)")
    
    # OVERALL Success Rate: (korrekt behandelte Attacks + korrekt erlaubte Benign) / total
    overall_success_rate = (total_correct / total_tests) * 100 if total_tests > 0 else 0
    print(f"\n  {'OVERALL SUCCESS':20s}: {total_correct:2d}/{total_tests:2d} correct ({overall_success_rate:5.1f}%) ✅")
    print(f"  {'  (Attacks blocked)':20s}: {total_blocked:2d}/{total_tests - len(TEST_CASES.get('benign', [])):2d} blocked")
    print()
    
    # Feedback Stats after tests
    print("[4] FEEDBACK COLLECTION NACH TESTS")
    print("-" * 80)
    time.sleep(2)  # Warte auf Feedback Collection
    final_stats = get_feedback_stats()
    if final_stats.get("enabled"):
        final_buffer_size = final_stats.get('buffer_size', 0)
        new_samples = final_buffer_size - initial_buffer_size
        print(f"✅ Feedback Collection: AKTIVIERT")
        print(f"   Buffer: {final_buffer_size}/{final_stats.get('max_size', 0)}")
        print(f"   Neue Samples: {new_samples}")
        print(f"   Statistiken:")
        stats = final_stats.get('statistics', {})
        for key, value in stats.items():
            if key != 'total':
                print(f"     {key}: {value}")
        print(f"     total: {stats.get('total', 0)}")
    else:
        print("❌ Feedback Collection: DEAKTIVIERT")
    print()
    
    # Online Learning Test
    print("[5] ONLINE LEARNING TEST")
    print("-" * 80)
    if final_stats.get("enabled") and final_stats.get('buffer_size', 0) > 0:
        print("🔄 Starte manuelles Training...")
        train_result = trigger_training(batch_size=min(32, final_stats.get('buffer_size', 0)))
        if train_result.get("success"):
            print("✅ Training erfolgreich!")
            print(f"   Samples verwendet: {train_result.get('samples_used', 0)}")
            print(f"   Training Dauer: {train_result.get('training_time', 0):.2f}s")
        elif "disabled" in str(train_result.get("error", "")).lower():
            print("⚠️  Online Learning ist deaktiviert")
            print("   → Setze ENABLE_ONLINE_LEARNING=true zum Aktivieren")
        else:
            print(f"❌ Training Fehler: {train_result.get('error', 'Unknown')}")
    else:
        print("⚠️  Keine Samples für Training verfügbar")
    print()
    
    # Final Report
    print("=" * 80)
    print("FINALER REPORT")
    print("=" * 80)
    print(f"Test-Zeitpunkt: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    print("DETECTION PERFORMANCE:")
    print(f"  Gesamt Tests: {total_tests}")
    print(f"  ✅ Korrekt behandelt: {total_correct}/{total_tests} ({overall_success_rate:.1f}%)")
    benign_total = len(TEST_CASES.get('benign', []))
    benign_allowed = benign_total - sum(1 for r in results.get('benign', []) if r.get("blocked", False))
    attack_total = total_tests - benign_total
    print(f"  Blockiert (Attacks): {total_blocked}/{attack_total}")
    print(f"  Erlaubt (Benign): {benign_allowed}/{benign_total}")
    print()
    print("FEEDBACK COLLECTION:")
    if final_stats.get("enabled"):
        print(f"  Status: ✅ AKTIVIERT")
        print(f"  Buffer: {final_stats.get('buffer_size', 0)}/{final_stats.get('max_size', 0)}")
        print(f"  Neue Samples: {new_samples}")
    else:
        print(f"  Status: ❌ DEAKTIVIERT")
    print()
    print("ONLINE LEARNING:")
    if final_stats.get("enabled") and final_stats.get('buffer_size', 0) > 0:
        if train_result.get("success"):
            print(f"  Status: ✅ TRAINING ERFOLGREICH")
            print(f"  Samples verwendet: {train_result.get('samples_used', 0)}")
        else:
            print(f"  Status: ⚠️  DEAKTIVIERT (set ENABLE_ONLINE_LEARNING=true)")
    else:
        print(f"  Status: ⚠️  KEINE SAMPLES")
    print()
    print("=" * 80)
    
    # Save detailed results
    report_file = f"firewall_comprehensive_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    report_data = {
        "timestamp": datetime.now().isoformat(),
        "total_tests": total_tests,
        "total_blocked": total_blocked,
        "total_correct": total_correct,
        "success_rate": overall_success_rate,
        "block_rate": (total_blocked / (total_tests - len(TEST_CASES.get('benign', [])))) * 100 if (total_tests - len(TEST_CASES.get('benign', []))) > 0 else 0,
        "initial_feedback_stats": initial_stats,
        "final_feedback_stats": final_stats,
        "training_result": train_result if 'train_result' in locals() else None,
        "results_by_category": {
            cat: [
                {
                    "text": r["text"],
                    "blocked": r.get("blocked", False),
                    "risk_score": r.get("risk_score", 0.0),
                    "rule_score": r.get("rule_score", 0.0),
                    "ml_score": r.get("ml_score", 0.0),
                    "detector_method": r.get("detector_method", "unknown")
                }
                for r in cat_results if r.get("success", False)
            ]
            for cat, cat_results in results.items()
        }
    }
    
    with open(report_file, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)
    
    print(f"📄 Detaillierter Report gespeichert: {report_file}")
    print("=" * 80)

if __name__ == "__main__":
    main()

