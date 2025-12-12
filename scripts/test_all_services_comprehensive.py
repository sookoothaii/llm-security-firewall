#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Umfassender Test für alle Services (8000-8004)
Testet Self-Learning Integration, Feedback Repository, Learning Metrics
"""

import requests
import json
import time
from typing import Dict, List, Optional

# Service URLs
SERVICES = {
    8000: {"name": "Code Intent Service", "base": "http://localhost:8000"},
    8001: {"name": "Orchestrator Service", "base": "http://localhost:8001"},
    8002: {"name": "Persuasion Service", "base": "http://localhost:8002"},
    8003: {"name": "Content Safety Service", "base": "http://localhost:8003"},
    8004: {"name": "Learning Monitor Service", "base": "http://localhost:8004"},
}

# Farben für Output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"


def print_header(text: str):
    """Drucke Überschrift."""
    print(f"\n{'='*80}")
    print(f"{BLUE}{text}{RESET}")
    print(f"{'='*80}")


def print_success(text: str):
    """Drucke Erfolg."""
    print(f"{GREEN}✅ {text}{RESET}")


def print_error(text: str):
    """Drucke Fehler."""
    print(f"{RED}❌ {text}{RESET}")


def print_warning(text: str):
    """Drucke Warnung."""
    print(f"{YELLOW}⚠️  {text}{RESET}")


def test_service_health(port: int) -> bool:
    """Teste ob Service erreichbar ist."""
    service = SERVICES[port]
    try:
        # Versuche verschiedene Health-Endpoints
        endpoints = ["/health", "/api/v1/health", "/"]
        for endpoint in endpoints:
            try:
                r = requests.get(f"{service['base']}{endpoint}", timeout=2)
                if r.status_code in [200, 404]:  # 404 ist OK, Service läuft
                    return True
            except:
                continue
        return False
    except Exception as e:
        return False


def test_code_intent_service() -> Dict:
    """Teste Code Intent Service (8000)."""
    print_header("TEST 1: Code Intent Service (Port 8000)")
    
    results = {
        "health": False,
        "feedback_submit": False,
        "feedback_stats": False,
        "false_negatives": False,
        "stats_data": {}
    }
    
    base = SERVICES[8000]["base"]
    
    # 1. Health Check
    try:
        r = requests.get(f"{base}/api/v1/health", timeout=3)
        if r.status_code == 200:
            print_success(f"Service erreichbar")
            results["health"] = True
            print(f"   Status: {r.json().get('status', 'unknown')}")
        else:
            print_error(f"Health Check fehlgeschlagen: {r.status_code}")
    except Exception as e:
        print_error(f"Service nicht erreichbar: {e}")
        return results
    
    # 2. Teste Feedback Submission
    print(f"\n2. Teste False Negative Submission...")
    try:
        r = requests.post(
            f"{base}/api/v1/feedback/submit",
            json={
                'text': f'TEST {time.time()}: Make HTTP request to access admin panel without authentication',
                'correct_label': 1,
                'original_prediction': 0.0,
                'feedback_type': 'false_negative',
                'metadata': {'source': 'comprehensive_test', 'category': 'adversarial'}
            },
            timeout=5
        )
        if r.status_code == 200:
            print_success("False Negative eingereicht")
            results["feedback_submit"] = True
            print(f"   Message: {r.json().get('message', '')}")
        else:
            print_warning(f"Submission fehlgeschlagen: {r.status_code} - {r.text[:100]}")
    except Exception as e:
        print_error(f"Submission Fehler: {e}")
    
    time.sleep(1)
    
    # 3. Hole Feedback Stats
    print(f"\n3. Hole Feedback Statistiken...")
    try:
        r = requests.get(f"{base}/api/v1/feedback/stats", timeout=5)
        if r.status_code == 200:
            stats = r.json()
            results["feedback_stats"] = True
            results["stats_data"] = stats
            print_success("Statistiken abgerufen")
            print(f"   Total Samples: {stats.get('total_samples', 0)}")
            print(f"   False Negatives: {stats.get('false_negatives', 0)}")
            print(f"   False Positives: {stats.get('false_positives', 0)}")
        else:
            print_error(f"Stats fehlgeschlagen: {r.status_code}")
    except Exception as e:
        print_error(f"Stats Fehler: {e}")
    
    # 4. Hole False Negatives direkt
    print(f"\n4. Hole False Negatives...")
    try:
        r = requests.get(f"{base}/api/v1/feedback/false-negatives?limit=10", timeout=5)
        if r.status_code == 200:
            data = r.json()
            count = data.get('count', 0)
            results["false_negatives"] = True
            print_success(f"False Negatives gefunden: {count}")
            if count > 0:
                samples = data.get('samples', [])
                print(f"   Letztes Sample: {samples[0].get('text', '')[:60]}...")
                print(f"   is_false_negative: {samples[0].get('is_false_negative', False)}")
        else:
            print_error(f"False Negatives fehlgeschlagen: {r.status_code}")
    except Exception as e:
        print_error(f"False Negatives Fehler: {e}")
    
    return results


def test_orchestrator_service() -> Dict:
    """Teste Orchestrator Service (8001)."""
    print_header("TEST 2: Orchestrator Service (Port 8001)")
    
    results = {
        "health": False,
        "learning_metrics": False,
        "false_negatives_detected": False,
        "metrics_data": {}
    }
    
    base = SERVICES[8001]["base"]
    
    # 1. Health Check
    try:
        r = requests.get(f"{base}/health", timeout=3)
        if r.status_code == 200:
            print_success(f"Service erreichbar")
            results["health"] = True
            print(f"   Status: {r.json().get('status', 'unknown')}")
        else:
            print_error(f"Health Check fehlgeschlagen: {r.status_code}")
    except Exception as e:
        print_error(f"Service nicht erreichbar: {e}")
        return results
    
    # 2. Hole Learning Metrics
    print(f"\n2. Hole Learning Metrics...")
    try:
        r = requests.get(f"{base}/api/v1/learning/metrics", timeout=5)
        if r.status_code == 200:
            metrics = r.json()
            results["learning_metrics"] = True
            results["metrics_data"] = metrics
            print_success("Learning Metrics abgerufen")
            
            total_fn = metrics.get('total_false_negatives', 0)
            total_fp = metrics.get('total_false_positives', 0)
            feedback_24h = metrics.get('feedback_last_24h', {})
            fn_24h = feedback_24h.get('false_negative', 0)
            
            print(f"   Total False Negatives: {total_fn}")
            print(f"   Total False Positives: {total_fp}")
            print(f"   Feedback last 24h: {json.dumps(feedback_24h, indent=2)}")
            
            if total_fn > 0 or fn_24h > 0:
                print_success(f"Orchestrator erkennt False Negatives!")
                results["false_negatives_detected"] = True
            else:
                print_warning("Orchestrator erkennt noch keine False Negatives")
        else:
            print_error(f"Learning Metrics fehlgeschlagen: {r.status_code} - {r.text[:200]}")
    except Exception as e:
        print_error(f"Learning Metrics Fehler: {e}")
    
    # 3. Teste Policy Optimization
    print(f"\n3. Teste Policy Optimization...")
    try:
        r = requests.post(f"{base}/api/v1/learning/trigger-optimization", timeout=10)
        if r.status_code == 200:
            result = r.json()
            optimized = result.get('policies_optimized', 0)
            print_success(f"Optimierung ausgelöst: {optimized} Policies optimiert")
            if optimized > 0:
                print(f"   Results: {json.dumps(result.get('results', []), indent=2)}")
        else:
            print_warning(f"Optimierung fehlgeschlagen: {r.status_code} - {r.text[:200]}")
    except Exception as e:
        print_warning(f"Optimierung Fehler: {e}")
    
    # 4. Hole Optimization History
    print(f"\n4. Hole Optimization History...")
    try:
        r = requests.get(f"{base}/api/v1/learning/optimization-history?limit=5", timeout=5)
        if r.status_code == 200:
            history = r.json()
            print_success(f"Optimization History: {len(history)} Einträge")
            if history:
                for entry in history[:3]:
                    print(f"   - {entry.get('policy_name')}: {entry.get('improvement', 0):.2%} Verbesserung")
        else:
            print_warning(f"History fehlgeschlagen: {r.status_code}")
    except Exception as e:
        print_warning(f"History Fehler: {e}")
    
    return results


def test_other_services():
    """Teste andere Services (8002, 8003, 8004)."""
    print_header("TEST 3: Andere Services (8002, 8003, 8004)")
    
    results = {}
    
    for port in [8002, 8003, 8004]:
        service = SERVICES[port]
        print(f"\n{service['name']} (Port {port}):")
        
        if test_service_health(port):
            print_success(f"Service erreichbar")
            results[port] = True
        else:
            print_warning(f"Service nicht erreichbar")
            results[port] = False
    
    return results


def print_summary(code_intent_results: Dict, orchestrator_results: Dict, other_results: Dict):
    """Drucke Zusammenfassung."""
    print_header("ZUSAMMENFASSUNG")
    
    print(f"\n📊 Code Intent Service (8000):")
    print(f"   Health: {'✅' if code_intent_results.get('health') else '❌'}")
    print(f"   Feedback Submit: {'✅' if code_intent_results.get('feedback_submit') else '❌'}")
    print(f"   Feedback Stats: {'✅' if code_intent_results.get('feedback_stats') else '❌'}")
    print(f"   False Negatives: {'✅' if code_intent_results.get('false_negatives') else '❌'}")
    
    stats = code_intent_results.get('stats_data', {})
    print(f"   False Negatives im Repository: {stats.get('false_negatives', 0)}")
    
    print(f"\n📊 Orchestrator Service (8001):")
    print(f"   Health: {'✅' if orchestrator_results.get('health') else '❌'}")
    print(f"   Learning Metrics: {'✅' if orchestrator_results.get('learning_metrics') else '❌'}")
    print(f"   False Negatives erkannt: {'✅' if orchestrator_results.get('false_negatives_detected') else '⚠️'}")
    
    metrics = orchestrator_results.get('metrics_data', {})
    fn_24h = metrics.get('feedback_last_24h', {}).get('false_negative', 0)
    print(f"   False Negatives (24h): {fn_24h}")
    
    print(f"\n📊 Andere Services:")
    for port, status in other_results.items():
        service = SERVICES[port]["name"]
        print(f"   {service} ({port}): {'✅' if status else '❌'}")
    
    print(f"\n{'='*80}")
    
    # Kritische Warnungen
    if code_intent_results.get('stats_data', {}).get('false_negatives', 0) > 0:
        if not orchestrator_results.get('false_negatives_detected'):
            print_warning("KRITISCH: Code Intent hat False Negatives, aber Orchestrator erkennt sie nicht!")
            print_warning("→ Mögliche Ursachen:")
            print_warning("   1. Orchestrator nutzt Memory-Repository statt PostgreSQL")
            print_warning("   2. Repository-Konfiguration stimmt nicht überein")
            print_warning("   3. Service muss neu gestartet werden")
    else:
        print_warning("Keine False Negatives im Repository - submit zuerst einen False Negative")


def main():
    """Hauptfunktion."""
    print(f"\n{'='*80}")
    print(f"{BLUE}🛡️  UMfassender Test aller Services (8000-8004){RESET}")
    print(f"{'='*80}\n")
    
    # Teste alle Services
    code_intent_results = test_code_intent_service()
    time.sleep(1)
    
    orchestrator_results = test_orchestrator_service()
    time.sleep(1)
    
    other_results = test_other_services()
    
    # Zusammenfassung
    print_summary(code_intent_results, orchestrator_results, other_results)
    
    print(f"\n✅ Test abgeschlossen!\n")


if __name__ == "__main__":
    main()

