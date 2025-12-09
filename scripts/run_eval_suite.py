#!/usr/bin/env python3
"""
Evaluation Suite Runner
=======================

Lädt YAML/JSON Test-Suites und führt sie gegen die Firewall aus.
Generiert einheitliche Result-JSONs mit Metriken.

Creator: HAK_GAL Security Team
Date: 2025-12-10
"""

import yaml
import json
import time
import requests
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict

import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class AttackResult:
    """Result of a single attack test case."""
    attack_id: str
    category: str
    subcategory: str
    expected_blocked: bool
    actual_blocked: bool
    correct: bool
    risk_score: float
    latency_ms: float
    detector_method: str
    matched_patterns: List[str]
    error: Optional[str] = None


@dataclass
class SuiteResult:
    """Result of a complete test suite execution."""
    suite_name: str
    description: str
    timestamp: str
    total_attacks: int
    correct: int
    incorrect: int
    detection_rate: float
    false_positives: int
    false_negatives: int
    average_latency_ms: float
    results: List[AttackResult]


class EvalSuiteRunner:
    """Runner for evaluation test suites."""
    
    def __init__(self, endpoint: Optional[str] = None):
        self.endpoint = endpoint
        self.results: List[AttackResult] = []
    
    def load_suite(self, suite_path: Path) -> Dict:
        """Load test suite from YAML or JSON file."""
        if not suite_path.exists():
            raise FileNotFoundError(f"Suite not found: {suite_path}")
        
        with open(suite_path, "r", encoding="utf-8") as f:
            if suite_path.suffix == ".yaml" or suite_path.suffix == ".yml":
                return yaml.safe_load(f)
            elif suite_path.suffix == ".json":
                return json.load(f)
            else:
                raise ValueError(f"Unsupported file format: {suite_path.suffix}")
    
    def run_attack(self, attack: Dict, endpoint: str, timeout: int = 10) -> AttackResult:
        """Execute a single attack test case against the firewall."""
        attack_id = attack.get("id", "unknown")
        category = attack.get("category", "unknown")
        subcategory = attack.get("subcategory", "unknown")
        expected_blocked = attack.get("expected_blocked", True)
        template = attack.get("template", "").strip()
        
        start_time = time.time()
        
        try:
            response = requests.post(
                endpoint,
                json={"text": template, "context": {}},
                timeout=timeout
            )
            
            latency_ms = (time.time() - start_time) * 1000
            
            if response.status_code != 200:
                return AttackResult(
                    attack_id=attack_id,
                    category=category,
                    subcategory=subcategory,
                    expected_blocked=expected_blocked,
                    actual_blocked=False,
                    correct=False,
                    risk_score=0.0,
                    latency_ms=latency_ms,
                    detector_method="error",
                    matched_patterns=[],
                    error=f"HTTP {response.status_code}"
                )
            
            result = response.json()
            risk_score = result.get("risk_score", 0.0)
            block_threshold = 0.55  # Standard threshold
            actual_blocked = risk_score >= block_threshold
            
            metadata = result.get("metadata", {})
            detector_method = metadata.get("detector_method", "unknown")
            matched_patterns = metadata.get("matched_patterns", [])
            
            correct = actual_blocked == expected_blocked
            
            return AttackResult(
                attack_id=attack_id,
                category=category,
                subcategory=subcategory,
                expected_blocked=expected_blocked,
                actual_blocked=actual_blocked,
                correct=correct,
                risk_score=risk_score,
                latency_ms=latency_ms,
                detector_method=detector_method,
                matched_patterns=matched_patterns
            )
            
        except requests.exceptions.Timeout:
            return AttackResult(
                attack_id=attack_id,
                category=category,
                subcategory=subcategory,
                expected_blocked=expected_blocked,
                actual_blocked=False,
                correct=False,
                risk_score=0.0,
                latency_ms=(time.time() - start_time) * 1000,
                detector_method="timeout",
                matched_patterns=[],
                error="Request timeout"
            )
        except Exception as e:
            return AttackResult(
                attack_id=attack_id,
                category=category,
                subcategory=subcategory,
                expected_blocked=expected_blocked,
                actual_blocked=False,
                correct=False,
                risk_score=0.0,
                latency_ms=(time.time() - start_time) * 1000,
                detector_method="error",
                matched_patterns=[],
                error=str(e)
            )
    
    def run_suite(self, suite_path: Path, output_dir: Optional[Path] = None) -> SuiteResult:
        """Execute complete test suite."""
        print("=" * 80)
        print("EVALUATION SUITE RUNNER")
        print("=" * 80)
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        # Load suite
        suite = self.load_suite(suite_path)
        suite_name = suite.get("suite_name", "unknown")
        description = suite.get("description", "")
        endpoint = self.endpoint or suite.get("target_endpoint", "http://localhost:8001/v1/detect")
        timeout = suite.get("timeout", 10)
        metrics_config = suite.get("metrics", {})
        block_threshold = metrics_config.get("block_threshold", 0.55)
        
        print(f"Suite: {suite_name}")
        print(f"Description: {description}")
        print(f"Endpoint: {endpoint}")
        print(f"Total Attacks: {len(suite.get('attacks', []))}\n")
        
        # Execute attacks
        attacks = suite.get("attacks", [])
        results: List[AttackResult] = []
        
        for i, attack in enumerate(attacks, 1):
            attack_id = attack.get("id", f"attack_{i}")
            print(f"[{i}/{len(attacks)}] Testing: {attack_id}")
            
            result = self.run_attack(attack, endpoint, timeout)
            results.append(result)
            
            status = "PASS" if result.correct else "FAIL"
            if not result.correct:
                if result.expected_blocked and not result.actual_blocked:
                    status += " (BYPASS)"
                else:
                    status += " (FALSE_POSITIVE)"
            
            print(f"  {status}: Risk={result.risk_score:.3f}, Latency={result.latency_ms:.1f}ms")
            
            time.sleep(0.1)  # Rate limiting
        
        # Calculate metrics
        total = len(results)
        correct = sum(1 for r in results if r.correct)
        incorrect = total - correct
        
        false_positives = sum(1 for r in results if not r.expected_blocked and r.actual_blocked)
        false_negatives = sum(1 for r in results if r.expected_blocked and not r.actual_blocked)
        
        detection_rate = (correct / total * 100) if total > 0 else 0.0
        average_latency = sum(r.latency_ms for r in results) / total if total > 0 else 0.0
        
        suite_result = SuiteResult(
            suite_name=suite_name,
            description=description,
            timestamp=datetime.now().isoformat(),
            total_attacks=total,
            correct=correct,
            incorrect=incorrect,
            detection_rate=detection_rate,
            false_positives=false_positives,
            false_negatives=false_negatives,
            average_latency_ms=average_latency,
            results=results
        )
        
        # Summary
        print("\n" + "=" * 80)
        print("SUMMARY")
        print("=" * 80)
        print(f"Total Attacks: {total}")
        print(f"Correct: {correct}/{total} ({detection_rate:.1f}%)")
        print(f"Incorrect: {incorrect}/{total}")
        print(f"False Positives: {false_positives}")
        print(f"False Negatives (Bypasses): {false_negatives}")
        print(f"Average Latency: {average_latency:.1f}ms")
        
        if false_negatives > 0:
            print("\nWARNING: Bypasses detected:")
            for result in results:
                if result.expected_blocked and not result.actual_blocked:
                    print(f"  - [{result.attack_id}] Risk={result.risk_score:.3f}")
        
        # Save result
        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = output_dir / f"{suite_name}_{timestamp}.json"
            
            # Convert to dict for JSON
            result_dict = {
                "suite_name": suite_result.suite_name,
                "description": suite_result.description,
                "timestamp": suite_result.timestamp,
                "total_attacks": suite_result.total_attacks,
                "correct": suite_result.correct,
                "incorrect": suite_result.incorrect,
                "detection_rate": suite_result.detection_rate,
                "false_positives": suite_result.false_positives,
                "false_negatives": suite_result.false_negatives,
                "average_latency_ms": suite_result.average_latency_ms,
                "results": [asdict(r) for r in suite_result.results]
            }
            
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(result_dict, f, indent=2, ensure_ascii=False)
            
            print(f"\nReport saved: {output_file}")
        
        print("=" * 80)
        
        return suite_result


def main():
    parser = argparse.ArgumentParser(description="Run Evaluation Suite")
    parser.add_argument("suite", type=Path, help="Path to suite YAML/JSON file")
    parser.add_argument("--endpoint", type=str, default=None,
                       help="Override endpoint from suite config")
    parser.add_argument("--output-dir", type=Path, default=Path("eval_results"),
                       help="Output directory for results")
    
    args = parser.parse_args()
    
    runner = EvalSuiteRunner(endpoint=args.endpoint)
    result = runner.run_suite(args.suite, args.output_dir)
    
    # Exit code: 0 wenn keine Bypasses, 1 wenn Bypasses gefunden
    return 0 if result.false_negatives == 0 else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())

