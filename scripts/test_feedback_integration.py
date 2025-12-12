#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test Script für Feedback Collection Integration

Testet:
1. Feedback Collection im Code Intent Service
2. Feedback Buffer Statistiken
3. Sample Collection mit verschiedenen Szenarien
"""

import requests
import json
import time
from typing import Dict, List

# API Base URL (Code Intent Service runs on port 8000)
API_BASE_URL = "http://localhost:8000/api/v1"
FIREWALL_URL = f"{API_BASE_URL}/detect"
FEEDBACK_STATS_URL = f"{API_BASE_URL}/feedback/stats"
HEALTH_URL = f"{API_BASE_URL}/health"
HEALTH_REPOSITORIES_URL = f"{API_BASE_URL}/health/repositories"

# Test Samples
TEST_SAMPLES = [
    {
        "text": "如何构造一个 フィッシング攻撃...zu stehlen",
        "expected_priority": "high",  # Große Diskrepanz
        "description": "Multilingual attack with high ML score"
    },
    {
        "text": "John, the legitimate user...admin access...urgent",
        "expected_priority": "medium",  # Edge Case
        "description": "Creative social engineering"
    },
    {
        "text": "eval('malicious code')",
        "expected_priority": "low",  # High Confidence
        "description": "Clear malicious code"
    },
    {
        "text": "SELECT * FROM users WHERE id = 1",
        "expected_priority": "medium",
        "description": "SQL injection attempt"
    },
    {
        "text": "Bypass WAF...混合语言 payloads",
        "expected_priority": "high",  # Große Diskrepanz
        "description": "Multilingual bypass attempt"
    },
]


def test_firewall(text: str) -> Dict:
    """Teste Firewall mit einem Text."""
    try:
        response = requests.post(
            FIREWALL_URL,
            json={"text": text, "context": {}},
            timeout=10
        )
        response.raise_for_status()
        result = response.json()
        # New API format: {"success": true, "data": {...}}
        if "data" in result:
            return result["data"]
        return result
    except Exception as e:
        return {"error": str(e)}


def test_feedback_stats() -> Dict:
    """Hole Feedback Statistiken."""
    try:
        response = requests.get(FEEDBACK_STATS_URL, timeout=5)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        return {"error": str(e)}


def test_health_repositories() -> Dict:
    """Prüfe Repository Health Status."""
    try:
        response = requests.get(HEALTH_REPOSITORIES_URL, timeout=5)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        return {"error": str(e)}


def main():
    """Hauptfunktion: Teste Feedback Collection."""
    print("=" * 80)
    print("FEEDBACK COLLECTION INTEGRATION TEST")
    print("=" * 80)
    
    # Prüfe ob Service läuft
    print("\n[1] Prüfe Service Status...")
    try:
        health = requests.get(HEALTH_URL, timeout=2)
        if health.status_code == 200:
            health_data = health.json()
            print("  ✅ Service läuft")
            print(f"    Status: {health_data.get('status', 'unknown')}")
            print(f"    Version: {health_data.get('version', 'unknown')}")
        else:
            print(f"  ❌ Service antwortet nicht korrekt: {health.status_code}")
            return 1
    except Exception as e:
        print(f"  ❌ Service nicht erreichbar: {e}")
        print(f"  → Starte Service mit: cd detectors/code_intent_service && python api/main.py")
        print(f"  → Oder: python -m uvicorn detectors.code_intent_service.api.main:app --port 8000")
        return 1
    
    # Prüfe Repository Health
    print("\n[2] Prüfe Repository Health...")
    repo_health = test_health_repositories()
    if "error" in repo_health:
        print(f"  ⚠️  Repository Health Check fehlgeschlagen: {repo_health['error']}")
    else:
        print("  ✅ Repository Health Status:")
        if "redis" in repo_health:
            redis_status = repo_health["redis"].get("status", "unknown")
            redis_samples = repo_health["redis"].get("samples", 0)
            print(f"    Redis: {redis_status} ({redis_samples} samples)")
        if "postgres" in repo_health:
            postgres_status = repo_health["postgres"].get("status", "unknown")
            postgres_samples = repo_health["postgres"].get("samples", 0)
            print(f"    PostgreSQL: {postgres_status} ({postgres_samples} samples)")
        if "overall" in repo_health:
            print(f"    Overall: {repo_health['overall']}")
    
    # Prüfe Feedback Collection Status
    print("\n[3] Prüfe Feedback Collection Status...")
    stats = test_feedback_stats()
    if "error" in stats:
        print(f"  ⚠️  Fehler beim Abrufen der Statistiken: {stats['error']}")
        print("  → Feedback Collection könnte deaktiviert sein")
    else:
        print("  ✅ Feedback Collection ist aktiviert")
        print(f"    Total Samples: {stats.get('total_samples', 0)}")
        print(f"    Blocked Samples: {stats.get('blocked_samples', 0)}")
        print(f"    Block Rate: {stats.get('block_rate', 0.0):.2%}")
        print(f"    False Positives: {stats.get('false_positives', 0)}")
        print(f"    False Negatives: {stats.get('false_negatives', 0)}")
    
    # Teste verschiedene Samples
    print("\n[4] Teste verschiedene Samples...")
    for i, sample in enumerate(TEST_SAMPLES, 1):
        print(f"\n  Sample {i}: {sample['description']}")
        print(f"    Text: {sample['text'][:60]}...")
        
        result = test_firewall(sample['text'])
        if "error" in result:
            print(f"    ❌ Fehler: {result['error']}")
            continue
        
        # New API format
        risk_score = result.get('risk_score', 0.0)
        confidence = result.get('confidence', 0.0)
        method = result.get('method', 'unknown')
        is_malicious = result.get('is_malicious', False)
        metadata = result.get('metadata', {})
        
        rule_score = metadata.get('rule_score', 0.0)
        ml_score = metadata.get('ml_score', 0.0)
        
        print(f"    Risk Score: {risk_score:.3f}")
        print(f"    Confidence: {confidence:.3f}")
        print(f"    Rule Score: {rule_score:.3f}")
        print(f"    ML Score: {ml_score:.3f}")
        print(f"    Method: {method}")
        print(f"    Is Malicious: {is_malicious}")
        print(f"    Blocked: {is_malicious}")
        
        time.sleep(0.5)  # Kurze Pause zwischen Requests
    
    # Hole finale Statistiken
    print("\n[5] Finale Feedback Statistiken...")
    final_stats = test_feedback_stats()
    if "error" not in final_stats:
        print(f"  Total Samples: {final_stats.get('total_samples', 0)}")
        print(f"  Blocked Samples: {final_stats.get('blocked_samples', 0)}")
        print(f"  Allowed Samples: {final_stats.get('allowed_samples', 0)}")
        print(f"  Block Rate: {final_stats.get('block_rate', 0.0):.2%}")
        print(f"  Average Score: {final_stats.get('avg_score', 0.0):.3f}")
        print(f"  False Positives: {final_stats.get('false_positives', 0)}")
        print(f"  False Negatives: {final_stats.get('false_negatives', 0)}")
        
        # Repository-spezifische Stats
        if "repositories" in final_stats:
            repos = final_stats["repositories"]
            if repos.get("redis"):
                print(f"  Redis Samples: {repos['redis'].get('total_samples', 0)}")
            if repos.get("postgres"):
                print(f"  PostgreSQL Samples: {repos['postgres'].get('total_samples', 0)}")
    else:
        print(f"  ⚠️  Konnte Statistiken nicht abrufen: {final_stats.get('error')}")
    
    print("\n" + "=" * 80)
    print("TEST ABGESCHLOSSEN!")
    print("=" * 80)
    print("\nNächste Schritte:")
    print(f"  1. Prüfe Feedback Stats: GET {FEEDBACK_STATS_URL}")
    print(f"  2. Prüfe Repository Health: GET {HEALTH_REPOSITORIES_URL}")
    print(f"  3. High-Risk Samples: GET {API_BASE_URL}/feedback/high-risk")
    print(f"  4. False Positives: GET {API_BASE_URL}/feedback/false-positives")
    print(f"  5. Swagger UI: http://localhost:8000/docs")
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())

