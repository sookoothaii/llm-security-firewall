#!/usr/bin/env python3
"""
Test Pipeline für Attack-Generator: Testet generierte Angriffe gegen die Firewall.

Liest JSONL-Datei mit Angriffen ein, schickt jeden durch die Firewall,
loggt Ergebnisse und generiert Statistiken.

Usage:
    # Mit Code Intent Service (Port 8001)
    python scripts/test_attacks_pipeline.py --input attacks.jsonl --service-url http://localhost:8001/v1/detect
    
    # Mit FirewallEngineV2 direkt
    python scripts/test_attacks_pipeline.py --input attacks.jsonl --use-engine
"""

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from collections import Counter, defaultdict
from datetime import datetime

# Import requests if available
try:
    import requests
except ImportError:
    requests = None

# Add parent directory to path
base_dir = Path(__file__).parent.parent
sys.path.insert(0, str(base_dir / "src"))

try:
    from llm_firewall.core.firewall_engine_v2 import FirewallEngineV2, FirewallDecision
except ImportError as e:
    print(f"[ERROR] Failed to import FirewallEngineV2: {e}")
    print("[INFO] Make sure you're running from the project root directory")
    sys.exit(1)

try:
    import requests
except ImportError:
    requests = None


def load_attacks(jsonl_path: Path) -> List[Dict[str, Any]]:
    """Lädt Angriffe aus JSONL-Datei."""
    attacks = []
    print(f"[1] Loading attacks from {jsonl_path}...")
    
    if not jsonl_path.exists():
        print(f"[ERROR] File not found: {jsonl_path}")
        sys.exit(1)
    
    with open(jsonl_path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            try:
                attack = json.loads(line.strip())
                if "prompt" in attack:
                    attacks.append(attack)
            except json.JSONDecodeError as e:
                print(f"[WARN] Skipping invalid JSON line {i + 1}: {e}")
                continue
    
    print(f"[OK] Loaded {len(attacks)} attacks")
    return attacks


def test_via_service(prompt: str, service_url: str) -> Dict[str, Any]:
    """Testet einen Prompt über den Code Intent Service (HTTP API)."""
    if requests is None:
        raise RuntimeError("requests library not available")
    
    try:
        response = requests.post(
            service_url,
            json={"text": prompt, "context": {}},
            timeout=10
        )
        response.raise_for_status()
        
        # Parse JSON response
        result = response.json()
        
        # Normalisiere Response-Format für Code Intent Service
        # Der Service gibt: {"risk_score": ..., "category": ..., "metadata": {...}}
        # Wir müssen das in unser Format konvertieren
        
        # Prüfe ob es bereits unser Format ist
        if "blocked" not in result:
            # Konvertiere Code Intent Service Format
            risk_score = result.get("risk_score", 0.0)
            blocked = risk_score > 0.5  # Code Intent Service verwendet 0.5 als Threshold
            
            # Extrahiere Metadaten
            metadata = result.get("metadata", {})
            rule_score = metadata.get("rule_score", 0.0)
            ml_score = metadata.get("quantum_score") or metadata.get("ml_score")
            
            # Extrahiere detected threats
            detected_threats = result.get("detected_threats", [])
            category = result.get("category")
            
            return {
                "blocked": blocked,
                "risk_score": risk_score,
                "rule_score": rule_score,
                "ml_score": ml_score,
                "reason": result.get("reason", ""),
                "rule_hit": detected_threats,
                "detected_threats": detected_threats,
                "category": category,
                "metadata": metadata,
            }
        
        return result
        
    except requests.exceptions.ConnectionError as e:
        return {"error": f"Connection error: {str(e)}"}
    except requests.exceptions.Timeout:
        return {"error": "Timeout"}
    except requests.exceptions.HTTPError as e:
        error_msg = f"HTTP error {e.response.status_code if hasattr(e, 'response') else 'unknown'}"
        try:
            error_detail = e.response.json() if hasattr(e, 'response') and e.response else {}
            error_msg += f": {error_detail}"
        except:
            error_msg += f": {str(e)}"
        return {"error": error_msg}
    except json.JSONDecodeError as e:
        return {"error": f"JSON decode error: {str(e)} - Response text: {response.text[:200] if 'response' in locals() else 'N/A'}"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)} (type: {type(e).__name__})"}


def test_via_engine(prompt: str, engine: FirewallEngineV2, user_id: str = "test_user") -> Dict[str, Any]:
    """Testet einen Prompt direkt über FirewallEngineV2."""
    try:
        decision = engine.process_input(user_id=user_id, text=prompt)
        
        # Extrahiere Metadaten
        metadata = decision.metadata or {}
        
        # Versuche rule_score und ml_score aus Metadaten zu extrahieren
        rule_score = metadata.get("rule_score", 0.0)
        ml_score = metadata.get("ml_score") or metadata.get("quantum_score")
        
        # Extrahiere detected patterns/rules
        rule_hits = []
        if decision.detected_threats:
            rule_hits = decision.detected_threats
        
        # Prüfe reason für Rule Engine Indikatoren
        reason = decision.reason or ""
        if "RegexGate" in reason or "Pattern" in reason:
            # Rule Engine hat getroffen
            if rule_score == 0.0:
                rule_score = 0.8  # Default für Rule Engine Hit
        
        return {
            "blocked": not decision.allowed,
            "risk_score": decision.risk_score,
            "rule_score": rule_score,
            "ml_score": ml_score,
            "reason": reason,
            "rule_hit": rule_hits,
            "detected_threats": decision.detected_threats or [],
            "metadata": metadata,
        }
    except Exception as e:
        return {
            "error": str(e),
            "blocked": True,  # Fail-closed
            "risk_score": 1.0,
        }


def extract_scores(result: Dict[str, Any]) -> Tuple[float, Optional[float]]:
    """Extrahiert rule_score und ml_score aus Ergebnis."""
    rule_score = result.get("rule_score", 0.0)
    ml_score = result.get("ml_score") or result.get("quantum_score")
    
    # Fallback: Versuche aus Metadaten zu extrahieren
    if rule_score == 0.0 and "metadata" in result:
        metadata = result["metadata"]
        if isinstance(metadata, dict):
            rule_score = metadata.get("rule_score", 0.0)
            ml_score = ml_score or metadata.get("quantum_score") or metadata.get("ml_score")
    
    return rule_score, ml_score


def run_pipeline(
    attacks: List[Dict[str, Any]],
    service_url: Optional[str] = None,
    use_engine: bool = False,
    verbose: bool = False,
) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Führt die Test-Pipeline aus."""
    print("\n" + "=" * 80)
    print("ATTACK TEST PIPELINE")
    print("=" * 80)
    
    if use_engine:
        print("[MODE] Using FirewallEngineV2 directly")
        engine = FirewallEngineV2()
    elif service_url:
        print(f"[MODE] Using Code Intent Service: {service_url}")
        if requests is None:
            print("[ERROR] requests library required for service mode")
            sys.exit(1)
    else:
        print("[ERROR] Either --service-url or --use-engine must be specified")
        sys.exit(1)
    
    results = []
    total_latency = 0.0
    
    # Kategorien-Tracking
    category_stats = defaultdict(lambda: {"total": 0, "blocked": 0, "bypassed": 0})
    subcategory_stats = defaultdict(lambda: {"total": 0, "blocked": 0, "bypassed": 0})
    
    # Score-Verteilung
    near_threshold = []  # ML Score nahe 0.60
    
    print(f"\n[TESTING] Testing {len(attacks)} attacks...")
    print("-" * 80)
    
    for i, attack in enumerate(attacks, 1):
        attack_id = attack.get("id", f"attack_{i}")
        category = attack.get("category", "unknown")
        subcategory = attack.get("subcategory", "unknown")
        prompt = attack.get("prompt", "")
        
        if not prompt:
            print(f"[SKIP] Attack {i}: No prompt")
            continue
        
        # Teste gegen Firewall
        start_time = time.time()
        
        if use_engine:
            result = test_via_engine(prompt, engine, user_id=f"test_{i}")
        else:
            result = test_via_service(prompt, service_url)
        
        latency_ms = (time.time() - start_time) * 1000
        total_latency += latency_ms
        
        # Verarbeite Ergebnis
        if result is None:
            print(f"[ERROR] Attack {i} ({attack_id}): Service returned None")
            blocked = True  # Fail-closed
            risk_score = 1.0
            rule_score = 0.0
            ml_score = None
            rule_hits = []
        elif "error" in result:
            error_msg = result.get("error", "Unknown error")
            if error_msg is None:
                error_msg = "Service returned error: None"
            print(f"[ERROR] Attack {i} ({attack_id}): {error_msg}")
            blocked = True  # Fail-closed
            risk_score = 1.0
            rule_score = 0.0
            ml_score = None
            rule_hits = []
        else:
            blocked = result.get("blocked", False)
            risk_score = result.get("risk_score", 0.0)
            rule_score, ml_score = extract_scores(result)
            rule_hits = result.get("rule_hit", []) or result.get("detected_threats", [])
        
        # Erstelle Ergebnis-Eintrag
        result_entry = {
            "id": attack_id,
            "category": category,
            "subcategory": subcategory,
            "blocked": blocked,
            "risk_score": risk_score,
            "rule_score": rule_score,
            "ml_score": ml_score,
            "rule_hit": rule_hits,
            "latency_ms": round(latency_ms, 1),
            "timestamp": datetime.now().isoformat(),
        }
        
        results.append(result_entry)
        
        # Update Statistiken
        category_stats[category]["total"] += 1
        subcategory_stats[subcategory]["total"] += 1
        
        if blocked:
            category_stats[category]["blocked"] += 1
            subcategory_stats[subcategory]["blocked"] += 1
        else:
            category_stats[category]["bypassed"] += 1
            subcategory_stats[subcategory]["bypassed"] += 1
            print(f"[BYPASS] Attack {i} ({attack_id}) - Category: {category}/{subcategory}")
            if verbose:
                print(f"  Risk: {risk_score:.3f}, Rule: {rule_score:.3f}, ML: {ml_score}")
        
        # Track near-threshold cases
        if ml_score is not None and 0.55 <= ml_score <= 0.65:
            near_threshold.append(result_entry)
        
        # Progress update
        if i % 20 == 0:
            blocked_count = sum(1 for r in results if r.get("blocked", False))
            block_rate = (blocked_count / len(results)) * 100
            if verbose:
                print(f"  Progress: {i}/{len(attacks)} | Blocked: {blocked_count} ({block_rate:.1f}%)")
    
    # Berechne Zusammenfassung
    total_attacks = len(results)
    total_blocked = sum(1 for r in results if r.get("blocked", False))
    total_bypassed = total_attacks - total_blocked
    block_rate = (total_blocked / total_attacks * 100) if total_attacks > 0 else 0.0
    avg_latency = total_latency / total_attacks if total_attacks > 0 else 0.0
    
    summary = {
        "timestamp": datetime.now().isoformat(),
        "total_attacks": total_attacks,
        "total_blocked": total_blocked,
        "total_bypassed": total_bypassed,
        "block_rate": block_rate,
        "avg_latency_ms": round(avg_latency, 1),
        "category_stats": {
            cat: {
                "total": stats["total"],
                "blocked": stats["blocked"],
                "bypassed": stats["bypassed"],
                "block_rate": (stats["blocked"] / stats["total"] * 100) if stats["total"] > 0 else 0.0,
            }
            for cat, stats in category_stats.items()
        },
        "subcategory_stats": {
            subcat: {
                "total": stats["total"],
                "blocked": stats["blocked"],
                "bypassed": stats["bypassed"],
                "block_rate": (stats["blocked"] / stats["total"] * 100) if stats["total"] > 0 else 0.0,
            }
            for subcat, stats in subcategory_stats.items()
        },
        "near_threshold_count": len(near_threshold),
    }
    
    return results, summary


def print_summary(summary: Dict[str, Any], results: List[Dict[str, Any]]):
    """Druckt Zusammenfassung der Ergebnisse."""
    print("\n" + "=" * 80)
    print("TEST RESULTS SUMMARY")
    print("=" * 80)
    
    print(f"\nOverall Statistics:")
    print(f"  Total Attacks: {summary['total_attacks']}")
    print(f"  Blocked: {summary['total_blocked']} ({summary['block_rate']:.2f}%)")
    print(f"  Bypassed: {summary['total_bypassed']}")
    print(f"  Avg Latency: {summary['avg_latency_ms']:.1f} ms")
    print(f"  Near Threshold (0.55-0.65): {summary['near_threshold_count']}")
    
    print(f"\nCategory Statistics:")
    for category, stats in summary["category_stats"].items():
        print(f"  {category}:")
        print(f"    Total: {stats['total']}")
        print(f"    Blocked: {stats['blocked']} ({stats['block_rate']:.2f}%)")
        print(f"    Bypassed: {stats['bypassed']}")
    
    print(f"\nSubcategory Statistics:")
    for subcategory, stats in summary["subcategory_stats"].items():
        print(f"  {subcategory}:")
        print(f"    Total: {stats['total']}")
        print(f"    Blocked: {stats['blocked']} ({stats['block_rate']:.2f}%)")
        print(f"    Bypassed: {stats['bypassed']}")
    
    # Zeige Bypasses
    bypasses = [r for r in results if not r.get("blocked", False)]
    if bypasses:
        print(f"\n⚠️  BYPASSES ({len(bypasses)}):")
        for bypass in bypasses[:10]:  # Zeige erste 10
            print(f"  [{bypass['id']}] {bypass['category']}/{bypass['subcategory']}")
            print(f"    Risk: {bypass.get('risk_score', 0):.3f}, Rule: {bypass.get('rule_score', 0):.3f}, ML: {bypass.get('ml_score', 'N/A')}")
        if len(bypasses) > 10:
            print(f"  ... and {len(bypasses) - 10} more")


def main():
    parser = argparse.ArgumentParser(description="Test attack prompts against firewall")
    parser.add_argument("--input", type=str, required=True, help="Input JSONL file with attacks")
    parser.add_argument("--output", type=str, default=None, help="Output JSON file for results (default: auto-generated)")
    parser.add_argument("--service-url", type=str, default=None, help="Code Intent Service URL (e.g., http://localhost:8001/v1/detect)")
    parser.add_argument("--use-engine", action="store_true", help="Use FirewallEngineV2 directly instead of service")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()
    
    # Lade Angriffe
    attacks = load_attacks(Path(args.input))
    
    if not attacks:
        print("[ERROR] No attacks loaded")
        sys.exit(1)
    
    # Führe Pipeline aus
    results, summary = run_pipeline(
        attacks,
        service_url=args.service_url,
        use_engine=args.use_engine,
        verbose=args.verbose,
    )
    
    # Zeige Zusammenfassung
    print_summary(summary, results)
    
    # Speichere Ergebnisse
    if args.output:
        output_path = Path(args.output)
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = Path(f"attack_test_results_{timestamp}.json")
    
    output_data = {
        "summary": summary,
        "results": results,
    }
    
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)
    
    print(f"\n[OK] Results saved to: {output_path}")


if __name__ == "__main__":
    main()
