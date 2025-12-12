"""
Analyse-Script für Shadow Mode Logs
====================================

Analysiert A/B Testing Logs aus dem Shadow Mode und berechnet:
- Übereinstimmungsrate zwischen Rule Engine und Quantum-CNN
- Diskrepanzanalyse (CNN-Advantage vs. False Positives)
- Performance-Overhead (Latenz)
- Go/No-Go Kriterien für Production Mode

Creator: HAK_GAL (Joerg Bollwahn)
Date: 2025-12-08
License: MIT
"""

import json
import glob
from pathlib import Path
from typing import List, Dict, Any
from collections import defaultdict
import statistics

def load_logs(log_dir: str = "logs/ab_testing") -> List[Dict[str, Any]]:
    """Lade alle A/B Testing Logs."""
    log_path = Path(log_dir)
    if not log_path.exists():
        print(f"Log-Verzeichnis nicht gefunden: {log_dir}")
        return []
    
    log_files = list(log_path.glob("ab_test_*.jsonl"))
    if not log_files:
        print(f"Keine Log-Dateien gefunden in {log_dir}")
        return []
    
    logs = []
    for log_file in log_files:
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        logs.append(json.loads(line))
        except Exception as e:
            print(f"Fehler beim Lesen von {log_file}: {e}")
    
    return logs

def analyze_agreement(logs: List[Dict[str, Any]], threshold: float = 0.60) -> Dict[str, Any]:
    """Analysiere Übereinstimmung zwischen Rule Engine und Quantum-CNN."""
    total = 0
    agreements = 0
    rule_block = 0
    rule_allow = 0
    cnn_block = 0
    cnn_allow = 0
    both_block = 0
    both_allow = 0
    
    discrepancies = []
    
    for log in logs:
        metadata = log.get('metadata', {})
        rule_score = metadata.get('rule_score', 0.0)
        quantum_score = metadata.get('quantum_score')
        
        if quantum_score is None:
            continue
        
        total += 1
        
        # Entscheidungen
        rule_decision = "block" if rule_score > 0.5 else "allow"
        cnn_decision = "block" if quantum_score > threshold else "allow"
        
        if rule_decision == "block":
            rule_block += 1
        else:
            rule_allow += 1
        
        if cnn_decision == "block":
            cnn_block += 1
        else:
            cnn_allow += 1
        
        if rule_decision == cnn_decision:
            agreements += 1
            if rule_decision == "block":
                both_block += 1
            else:
                both_allow += 1
        else:
            # Diskrepanz
            discrepancies.append({
                'text': log.get('text', '')[:100],
                'rule_score': rule_score,
                'quantum_score': quantum_score,
                'rule_decision': rule_decision,
                'cnn_decision': cnn_decision,
                'timestamp': log.get('timestamp', 'N/A')
            })
    
    agreement_rate = (agreements / total * 100) if total > 0 else 0.0
    
    return {
        'total_requests': total,
        'agreement_rate': agreement_rate,
        'agreements': agreements,
        'discrepancies': len(discrepancies),
        'rule_block': rule_block,
        'rule_allow': rule_allow,
        'cnn_block': cnn_block,
        'cnn_allow': cnn_allow,
        'both_block': both_block,
        'both_allow': both_allow,
        'discrepancy_details': discrepancies
    }

def analyze_cnn_advantage(logs: List[Dict[str, Any]], threshold: float = 0.60) -> Dict[str, Any]:
    """Analysiere Fälle, in denen CNN Vorteile bietet (Gray Zone Detection)."""
    gray_zone_cases = []
    cnn_advantage_cases = []
    false_positive_risks = []
    
    for log in logs:
        metadata = log.get('metadata', {})
        rule_score = metadata.get('rule_score', 0.0)
        quantum_score = metadata.get('quantum_score')
        
        if quantum_score is None:
            continue
        
        # Gray Zone: Rule Score zwischen 0.2 und 0.8
        if 0.2 <= rule_score <= 0.8:
            gray_zone_cases.append({
                'text': log.get('text', '')[:100],
                'rule_score': rule_score,
                'quantum_score': quantum_score,
                'rule_decision': "block" if rule_score > 0.5 else "allow",
                'cnn_decision': "block" if quantum_score > threshold else "allow"
            })
            
            # CNN-Advantage: CNN hat klare Entscheidung (>0.6 oder <0.4), Rule Engine unsicher
            if (quantum_score > 0.6 and rule_score < 0.5) or (quantum_score < 0.4 and rule_score > 0.5):
                cnn_advantage_cases.append({
                    'text': log.get('text', '')[:100],
                    'rule_score': rule_score,
                    'quantum_score': quantum_score,
                    'advantage': 'cnn_blocked' if quantum_score > 0.6 else 'cnn_allowed'
                })
        
        # False Positive Risk: Rule erlaubt, CNN blockiert (muss manuell prüfen)
        if rule_score < 0.5 and quantum_score > threshold:
            false_positive_risks.append({
                'text': log.get('text', '')[:100],
                'rule_score': rule_score,
                'quantum_score': quantum_score
            })
    
    return {
        'gray_zone_total': len(gray_zone_cases),
        'cnn_advantage_cases': len(cnn_advantage_cases),
        'false_positive_risks': len(false_positive_risks),
        'gray_zone_details': gray_zone_cases[:20],  # Erste 20 für Review
        'cnn_advantage_details': cnn_advantage_cases[:20],
        'false_positive_risk_details': false_positive_risks[:20]
    }

def analyze_performance(logs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analysiere Performance-Overhead."""
    latencies = []
    inference_times = []
    
    for log in logs:
        latency = log.get('latency_ms', 0)
        if latency > 0:
            latencies.append(latency)
        
        metadata = log.get('metadata', {})
        inference_time = metadata.get('inference_time_ms')
        if inference_time:
            inference_times.append(inference_time)
    
    return {
        'total_requests': len(latencies),
        'avg_latency_ms': statistics.mean(latencies) if latencies else 0.0,
        'median_latency_ms': statistics.median(latencies) if latencies else 0.0,
        'p95_latency_ms': statistics.quantiles(latencies, n=20)[18] if len(latencies) >= 20 else (max(latencies) if latencies else 0.0),
        'avg_inference_time_ms': statistics.mean(inference_times) if inference_times else 0.0,
        'median_inference_time_ms': statistics.median(inference_times) if inference_times else 0.0
    }

def evaluate_go_no_go(agreement: Dict[str, Any], advantage: Dict[str, Any], 
                     performance: Dict[str, Any], threshold: float = 0.60) -> Dict[str, Any]:
    """Bewerte Go/No-Go Kriterien für Production Mode."""
    criteria = {
        'agreement_rate_acceptable': agreement['agreement_rate'] >= 85.0,
        'cnn_advantage_detected': advantage['cnn_advantage_cases'] > 0,
        'latency_acceptable': performance['p95_latency_ms'] < 100.0,
        'sufficient_data': agreement['total_requests'] >= 100
    }
    
    go_recommendation = all([
        criteria['agreement_rate_acceptable'],
        criteria['latency_acceptable'],
        criteria['sufficient_data']
    ])
    
    return {
        'go_recommendation': go_recommendation,
        'criteria': criteria,
        'summary': {
            'agreement_rate': agreement['agreement_rate'],
            'cnn_advantage_cases': advantage['cnn_advantage_cases'],
            'p95_latency_ms': performance['p95_latency_ms'],
            'total_requests': agreement['total_requests']
        }
    }

def print_report(agreement: Dict[str, Any], advantage: Dict[str, Any], 
                 performance: Dict[str, Any], go_no_go: Dict[str, Any]):
    """Drucke Analyse-Report."""
    print("=" * 80)
    print("SHADOW MODE ANALYSE REPORT")
    print("=" * 80)
    print()
    
    print("1. ÜBEREINSTIMMUNGSANALYSE")
    print("-" * 80)
    print(f"Total Requests: {agreement['total_requests']}")
    print(f"Übereinstimmungsrate: {agreement['agreement_rate']:.2f}%")
    print(f"Übereinstimmungen: {agreement['agreements']}")
    print(f"Diskrepanzen: {agreement['discrepancies']}")
    print()
    print(f"Rule Engine Entscheidungen:")
    print(f"  Block: {agreement['rule_block']}, Allow: {agreement['rule_allow']}")
    print(f"Quantum-CNN Entscheidungen:")
    print(f"  Block: {agreement['cnn_block']}, Allow: {agreement['cnn_allow']}")
    print(f"Beide blockieren: {agreement['both_block']}")
    print(f"Beide erlauben: {agreement['both_allow']}")
    print()
    
    if agreement['discrepancies'] > 0:
        print("Diskrepanzen (erste 10):")
        for i, disc in enumerate(agreement['discrepancy_details'][:10], 1):
            print(f"  {i}. Rule: {disc['rule_decision']} ({disc['rule_score']:.3f}), "
                  f"CNN: {disc['cnn_decision']} ({disc['quantum_score']:.3f})")
            print(f"     Text: {disc['text']}")
        print()
    
    print("2. CNN-ADVANTAGE ANALYSE")
    print("-" * 80)
    print(f"Gray Zone Fälle (Rule Score 0.2-0.8): {advantage['gray_zone_total']}")
    print(f"CNN-Advantage Fälle: {advantage['cnn_advantage_cases']}")
    print(f"False Positive Risiken: {advantage['false_positive_risks']}")
    print()
    
    if advantage['cnn_advantage_cases'] > 0:
        print("CNN-Advantage Fälle (erste 10):")
        for i, case in enumerate(advantage['cnn_advantage_details'][:10], 1):
            print(f"  {i}. Rule: {case['rule_score']:.3f}, CNN: {case['quantum_score']:.3f} "
                  f"({case['advantage']})")
            print(f"     Text: {case['text']}")
        print()
    
    print("3. PERFORMANCE ANALYSE")
    print("-" * 80)
    print(f"Average Latency: {performance['avg_latency_ms']:.2f} ms")
    print(f"Median Latency: {performance['median_latency_ms']:.2f} ms")
    print(f"P95 Latency: {performance['p95_latency_ms']:.2f} ms")
    print(f"Average Inference Time: {performance['avg_inference_time_ms']:.2f} ms")
    print()
    
    print("4. GO/NO-GO BEWERTUNG")
    print("-" * 80)
    criteria = go_no_go['criteria']
    print(f"Übereinstimmungsrate akzeptabel (>=85%): {criteria['agreement_rate_acceptable']} "
          f"({agreement['agreement_rate']:.2f}%)")
    print(f"CNN-Advantage erkannt: {criteria['cnn_advantage_detected']} "
          f"({advantage['cnn_advantage_cases']} Fälle)")
    print(f"Latenz akzeptabel (P95 <100ms): {criteria['latency_acceptable']} "
          f"({performance['p95_latency_ms']:.2f} ms)")
    print(f"Ausreichend Daten (>=100 Requests): {criteria['sufficient_data']} "
          f"({agreement['total_requests']} Requests)")
    print()
    
    recommendation = "GO" if go_no_go['go_recommendation'] else "NO-GO"
    print(f"EMPFEHLUNG: {recommendation}")
    print()
    
    if go_no_go['go_recommendation']:
        print("Empfohlene Aktion: SHADOW_MODE = False setzen und Production Mode aktivieren")
    else:
        print("Empfohlene Aktion: Weitere Daten sammeln oder Probleme beheben")
    print()

def main():
    """Hauptfunktion."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Analysiere Shadow Mode Logs")
    parser.add_argument("--log-dir", default="logs/ab_testing", 
                       help="Verzeichnis mit A/B Testing Logs")
    parser.add_argument("--threshold", type=float, default=0.60,
                       help="Quantum-CNN Threshold (default: 0.60)")
    parser.add_argument("--output", help="Output JSON Datei für detaillierte Ergebnisse")
    
    args = parser.parse_args()
    
    print("Lade Logs...")
    logs = load_logs(args.log_dir)
    
    if not logs:
        print("Keine Logs gefunden. Bitte stellen Sie sicher, dass der Service im Shadow Mode läuft.")
        return
    
    print(f"Geladene Logs: {len(logs)} Einträge")
    print()
    
    # Analysen durchführen
    agreement = analyze_agreement(logs, args.threshold)
    advantage = analyze_cnn_advantage(logs, args.threshold)
    performance = analyze_performance(logs)
    go_no_go = evaluate_go_no_go(agreement, advantage, performance, args.threshold)
    
    # Report drucken
    print_report(agreement, advantage, performance, go_no_go)
    
    # Optional: JSON Output
    if args.output:
        results = {
            'agreement': agreement,
            'advantage': advantage,
            'performance': performance,
            'go_no_go': go_no_go
        }
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"Detaillierte Ergebnisse gespeichert in: {args.output}")

if __name__ == "__main__":
    main()
