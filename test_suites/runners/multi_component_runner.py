#!/usr/bin/env python3
"""
Multi-Component Test Runner
============================

Führt Tests gegen alle 5 Test-Komponenten aus:
1. Holdout Test Set
2. Production A/B Test Suite
3. Data Drift Simulation Set
4. Adversarial & Edge Case Set
5. Segmented Performance Set

Usage:
    python test_suites/runners/multi_component_runner.py --components all
    python test_suites/runners/multi_component_runner.py --components holdout,adversarial --services 8001
"""

import asyncio
import json
import argparse
import sys
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, asdict
from enum import Enum

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

import aiohttp

# Try to import tqdm for progress bars, fallback to simple print if not available
try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    tqdm = None

# Simple progress indicator as fallback
class SimpleProgress:
    def __init__(self, total, desc=""):
        self.total = total
        self.desc = desc
        self.current = 0
        self.start_time = time.time()
        print(f"{desc}: 0/{total} (0.0%)", end="", flush=True)
    
    def update(self, n=1):
        self.current += n
        elapsed = time.time() - self.start_time
        percent = (self.current / self.total * 100) if self.total > 0 else 0
        rate = self.current / elapsed if elapsed > 0 else 0
        eta = (self.total - self.current) / rate if rate > 0 and self.current > 0 else 0
        print(f"\r{self.desc}: {self.current}/{self.total} ({percent:.1f}%) | {rate:.1f} tests/s | ETA: {eta:.0f}s", end="", flush=True)
    
    def close(self):
        elapsed = time.time() - self.start_time
        print(f"\r{self.desc}: {self.current}/{self.total} completed in {elapsed:.1f}s ({self.current/elapsed:.1f} tests/s)")
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        self.close()


class TestComponent(Enum):
    HOLDOUT = "holdout"
    PRODUCTION_AB = "production_ab"
    DATA_DRIFT = "data_drift"
    ADVERSARIAL = "adversarial"
    SEGMENTED = "segmented"


@dataclass
class TestCase:
    """Single test case."""
    text: str
    expected_blocked: bool
    category: Optional[str] = None
    metadata: Optional[Dict] = None


@dataclass
class ComponentResult:
    """Results for a single test component."""
    component: str
    service: str
    port: int
    total_tests: int
    passed: int
    failed: int
    true_positives: int = 0
    true_negatives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    duration: float = 0.0
    errors: List[str] = None
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []
    
    @property
    def tpr(self) -> float:
        """True Positive Rate / Recall."""
        total_positives = self.true_positives + self.false_negatives
        return self.true_positives / total_positives if total_positives > 0 else 0.0
    
    @property
    def tnr(self) -> float:
        """True Negative Rate / Specificity."""
        total_negatives = self.true_negatives + self.false_positives
        return self.true_negatives / total_negatives if total_negatives > 0 else 0.0
    
    @property
    def fpr(self) -> float:
        """False Positive Rate."""
        total_negatives = self.true_negatives + self.false_positives
        return self.false_positives / total_negatives if total_negatives > 0 else 0.0
    
    @property
    def fnr(self) -> float:
        """False Negative Rate."""
        total_positives = self.true_positives + self.false_negatives
        return self.false_negatives / total_positives if total_positives > 0 else 0.0
    
    @property
    def precision(self) -> float:
        """Precision."""
        total_predicted_positives = self.true_positives + self.false_positives
        return self.true_positives / total_predicted_positives if total_predicted_positives > 0 else 0.0
    
    @property
    def f1_score(self) -> float:
        """F1 Score."""
        p = self.precision
        r = self.tpr
        return 2 * (p * r) / (p + r) if (p + r) > 0 else 0.0
    
    @property
    def accuracy(self) -> float:
        """Accuracy."""
        return (self.true_positives + self.true_negatives) / self.total_tests if self.total_tests > 0 else 0.0


class ComponentLoader:
    """Loads test cases from different components."""
    
    def __init__(self, test_suites_dir: Path):
        self.test_suites_dir = test_suites_dir
    
    def load_holdout_set(self) -> List[TestCase]:
        """Load holdout test set."""
        data_file = self.test_suites_dir / "holdout" / "data" / "holdout_set.jsonl"
        if not data_file.exists():
            return []
        
        test_cases = []
        with open(data_file, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    try:
                        data = json.loads(line)
                        test_cases.append(TestCase(
                            text=data['text'],
                            expected_blocked=data.get('expected_blocked', True),
                            category=data.get('category'),
                            metadata=data.get('metadata')
                        ))
                    except (json.JSONDecodeError, KeyError):
                        continue
        
        return test_cases
    
    def load_production_ab_set(self) -> List[TestCase]:
        """Load production A/B test suite."""
        data_file = self.test_suites_dir / "production_ab" / "data" / "production_ab_set.jsonl"
        if not data_file.exists():
            return []
        
        test_cases = []
        with open(data_file, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    try:
                        data = json.loads(line)
                        test_cases.append(TestCase(
                            text=data['text'],
                            expected_blocked=data.get('expected_blocked'),
                            category=data.get('category', 'production'),
                            metadata=data.get('metadata')
                        ))
                    except (json.JSONDecodeError, KeyError):
                        continue
        
        return test_cases
    
    def load_data_drift_set(self) -> List[TestCase]:
        """Load data drift simulation set."""
        data_dir = self.test_suites_dir / "data_drift" / "data"
        test_cases = []
        
        for drift_file in data_dir.glob("*.jsonl"):
            with open(drift_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        try:
                            data = json.loads(line)
                            test_cases.append(TestCase(
                                text=data['text'],
                                expected_blocked=data.get('expected_blocked', True),
                                category=f"drift_{drift_file.stem}",
                                metadata=data.get('metadata')
                            ))
                        except (json.JSONDecodeError, KeyError):
                            continue
        
        return test_cases
    
    def load_adversarial_set(self) -> List[TestCase]:
        """Load adversarial and edge case set."""
        data_dir = self.test_suites_dir / "adversarial" / "data"
        test_cases = []
        
        for adv_file in data_dir.glob("*.jsonl"):
            with open(adv_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        try:
                            data = json.loads(line)
                            test_cases.append(TestCase(
                                text=data['text'],
                                expected_blocked=data.get('expected_blocked', True),
                                category=adv_file.stem,
                                metadata=data.get('metadata')
                            ))
                        except (json.JSONDecodeError, KeyError):
                            continue
        
        return test_cases
    
    def load_segmented_set(self) -> List[TestCase]:
        """Load segmented performance set."""
        data_dir = self.test_suites_dir / "segmented" / "data"
        test_cases = []
        
        # Load from subdirectories or main file
        for seg_file in data_dir.rglob("*.jsonl"):
            with open(seg_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        try:
                            data = json.loads(line)
                            # Extract segment info from path or metadata
                            segment = seg_file.parent.name if seg_file.parent != data_dir else data.get('segment', 'unknown')
                            test_cases.append(TestCase(
                                text=data['text'],
                                expected_blocked=data.get('expected_blocked'),
                                category=segment,
                                metadata=data.get('metadata', {})
                            ))
                        except (json.JSONDecodeError, KeyError):
                            continue
        
        return test_cases


class MultiComponentRunner:
    """Runs tests across multiple test components."""
    
    def __init__(self, test_suites_dir: Path, output_dir: Path = None):
        self.test_suites_dir = test_suites_dir
        self.output_dir = output_dir or project_root / "results"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.loader = ComponentLoader(test_suites_dir)
        self.services = {
            8000: {"name": "Code Intent", "health": "/api/v1/health", "detect": "/api/v1/detect"},
            8001: {"name": "Orchestrator", "health": "/health", "detect": "/api/v1/route-and-detect"},  # /api/v1/health gibt 500, /health funktioniert
            8002: {"name": "Persuasion", "health": "/health", "detect": "/v1/detect"},
            8003: {"name": "Content Safety", "health": "/health", "detect": "/v1/detect"},
            8004: {"name": "Learning Monitor", "health": "/health", "detect": None}
        }
        self.results: List[ComponentResult] = []
    
    async def check_service_health(self, port: int) -> bool:
        """Check if service is available."""
        try:
            service = self.services[port]
            async with aiohttp.ClientSession() as session:
                url = f"http://localhost:{port}{service['health']}"
                # Increase timeout for orchestrator which might check other services
                timeout_seconds = 10 if port == 8001 else 5
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout_seconds)) as response:
                    return response.status == 200
        except asyncio.TimeoutError:
            print(f"  [WARN] Health check timeout for {service['name']} (Port {port})")
            return False
        except Exception as e:
            print(f"  [WARN] Health check error for {service['name']} (Port {port}): {type(e).__name__}")
            return False
    
    async def detect_text(self, port: int, text: str, context: Dict = None) -> Dict:
        """Send detection request to service."""
        service = self.services[port]
        if not service['detect']:
            return {"error": "Service has no detection endpoint"}
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"http://localhost:{port}{service['detect']}"
                payload = {"text": text}
                if context:
                    payload["context"] = context
                
                # Longer timeout for orchestrator which may call other services
                timeout_seconds = 60 if port == 8001 else 30
                async with session.post(
                    url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=timeout_seconds)
                ) as response:
                    if response.status == 200:
                        json_data = await response.json()
                        return json_data
                    else:
                        error_text = await response.text()
                        return {"error": f"HTTP {response.status}: {error_text[:100]}"}
        except asyncio.TimeoutError:
            return {"error": "Request timeout"}
        except Exception as e:
            return {"error": f"{type(e).__name__}: {str(e)}"}
    
    def is_blocked(self, response: Dict, service_name: str) -> bool:
        """Determine if response indicates blocking."""
        try:
            if not response or not isinstance(response, dict):
                return False
            
            # Code Intent Service uses nested format: {success: true, data: {...}}
            if "data" in response:
                data = response.get("data")
                if data is None:
                    # data is None, check flattened format
                    pass
                elif isinstance(data, dict):
                    # Check explicit flags in data
                    if data.get("blocked") or data.get("should_block") or data.get("is_malicious"):
                        return True
                    
                    # Check risk score in data
                    risk_score = data.get("risk_score", 0.0)
                    if isinstance(risk_score, (int, float)):
                        threshold = 0.7 if service_name == "Code Intent" else 0.5
                        if risk_score >= threshold:
                            return True
            
            # Flattened format (for older services or direct responses)
            # Check explicit flags
            if response.get("blocked") or response.get("should_block") or response.get("is_malicious"):
                return True
            
            # Check risk score
            risk_score = response.get("risk_score", 0.0)
            if isinstance(risk_score, (int, float)):
                threshold = 0.7 if service_name == "Code Intent" else 0.5
                if risk_score >= threshold:
                    return True
            
            # Check decision
            decision = response.get("decision", "")
            if decision and isinstance(decision, str):
                if decision.lower() in ["block", "reject", "deny"]:
                    return True
            
            return False
        except Exception as e:
            # Log error but return False to continue testing
            print(f"    [WARN] Error in is_blocked: {e}")
            return False
    
    async def test_component(
        self,
        component: TestComponent,
        test_cases: List[TestCase],
        port: int,
        batch_size: int = 10,
        show_progress: bool = True
    ) -> ComponentResult:
        """Run tests for a single component with progress tracking."""
        service = self.services[port]
        start_time = time.time()
        
        result = ComponentResult(
            component=component.value,
            service=service['name'],
            port=port,
            total_tests=len(test_cases),
            passed=0,
            failed=0
        )
        
        # Progress indicator
        if show_progress:
            if HAS_TQDM:
                progress = tqdm(
                    total=len(test_cases),
                    desc=f"  Testing {service['name']}",
                    unit="test",
                    ncols=100,
                    leave=True
                )
            else:
                progress = SimpleProgress(len(test_cases), f"  Testing {service['name']}")
        else:
            progress = None
        
        try:
            # Process in batches for better feedback
            for batch_start in range(0, len(test_cases), batch_size):
                batch = test_cases[batch_start:batch_start + batch_size]
                batch_num = (batch_start // batch_size) + 1
                total_batches = (len(test_cases) + batch_size - 1) // batch_size
                
                if show_progress and not HAS_TQDM:
                    print(f"  Batch {batch_num}/{total_batches} ({len(batch)} tests)...")
                
                # Process batch
                for i, test_case in enumerate(batch):
                    test_num = batch_start + i + 1
                    
                    try:
                        response = await self.detect_text(port, test_case.text)
                        
                        if not response:
                            error_msg = f"Test {test_num}/{len(test_cases)}: Empty response"
                            result.errors.append(error_msg)
                            result.failed += 1
                            if show_progress and not HAS_TQDM:
                                print(f"    [FAIL] Test {test_num}: ERROR - Empty response")
                        elif "error" in response and response.get("error"):
                            error_text = str(response['error'])[:100]
                            error_msg = f"Test {test_num}/{len(test_cases)}: {error_text}"
                            result.errors.append(error_msg)
                            result.failed += 1
                            if show_progress and not HAS_TQDM:
                                print(f"    [FAIL] Test {test_num}: ERROR - {error_text}")
                        else:
                            blocked = self.is_blocked(response, service['name'])
                            expected_blocked = test_case.expected_blocked
                            
                            # Count confusion matrix
                            if expected_blocked and blocked:
                                result.true_positives += 1
                                result.passed += 1
                                status = "✓"
                            elif not expected_blocked and not blocked:
                                result.true_negatives += 1
                                result.passed += 1
                                status = "✓"
                            elif not expected_blocked and blocked:
                                result.false_positives += 1
                                result.failed += 1
                                status = "[FP]"
                            elif expected_blocked and not blocked:
                                result.false_negatives += 1
                                result.failed += 1
                                status = "[FN]"
                            
                            if show_progress and not HAS_TQDM and (i == 0 or i == len(batch) - 1):
                                # Show first and last of batch
                                print(f"    {status} Test {test_num}: {'PASS' if '[OK]' in status else 'FAIL'}")
                        
                        if progress:
                            progress.update(1)
                    
                    except Exception as e:
                        import traceback
                        error_detail = f"{type(e).__name__}: {str(e)}"
                        error_trace = traceback.format_exc()
                        error_msg = f"Test {test_num}/{len(test_cases)}: {error_detail[:100]}"
                        result.errors.append(error_msg)
                        result.failed += 1
                        if show_progress and not HAS_TQDM:
                            print(f"\n    [FAIL] Test {test_num}: EXCEPTION - {error_detail[:100]}")
                        # Log full traceback for first error only
                        if test_num == 1:
                            print(f"\n    Full traceback (first error only):")
                            print(error_trace[:500])
                        if progress:
                            progress.update(1)
        
        finally:
            if progress:
                if HAS_TQDM:
                    progress.close()
                else:
                    progress.close()
        
        result.duration = time.time() - start_time
        return result
    
    async def run_components(
        self,
        components: Set[TestComponent],
        ports: List[int]
    ) -> Dict:
        """Run specified components against specified services."""
        print(f"\n{'='*80}")
        print(f"Multi-Component Test Runner")
        print(f"{'='*80}\n")
        
        # Check service availability
        available_ports = []
        for port in ports:
            if await self.check_service_health(port):
                print(f"[OK] {self.services[port]['name']} (Port {port}): AVAILABLE")
                available_ports.append(port)
            else:
                print(f"[FAIL] {self.services[port]['name']} (Port {port}): NOT AVAILABLE")
        
        if not available_ports:
            print("ERROR: No services available!")
            return {}
        
        print(f"\nTesting {len(components)} component(s) against {len(available_ports)} service(s)\n")
        
        # Load test cases for each component
        component_loaders = {
            TestComponent.HOLDOUT: self.loader.load_holdout_set,
            TestComponent.PRODUCTION_AB: self.loader.load_production_ab_set,
            TestComponent.DATA_DRIFT: self.loader.load_data_drift_set,
            TestComponent.ADVERSARIAL: self.loader.load_adversarial_set,
            TestComponent.SEGMENTED: self.loader.load_segmented_set
        }
        
        # Run tests
        for component in components:
            print(f"\n{'='*80}")
            print(f"Component: {component.value.upper()}")
            print(f"{'='*80}")
            
            test_cases = component_loaders[component]()
            if not test_cases:
                print(f"  WARNING: No test cases found for {component.value}")
                continue
            
            print(f"  Loaded {len(test_cases)} test cases")
            
            for port in available_ports:
                print(f"\n  Testing {self.services[port]['name']} (Port {port})...")
                print(f"  Total test cases: {len(test_cases)}")
                result = await self.test_component(component, test_cases, port, batch_size=20, show_progress=True)
                self.results.append(result)
                
                print(f"\n  Results for {self.services[port]['name']}:")
                print(f"    Total: {result.total_tests}, Passed: {result.passed}, Failed: {result.failed}")
                print(f"    TP: {result.true_positives}, TN: {result.true_negatives}, FP: {result.false_positives}, FN: {result.false_negatives}")
                print(f"    TPR: {result.tpr:.3f}, FPR: {result.fpr:.3f}, F1: {result.f1_score:.3f}, Accuracy: {result.accuracy:.3f}")
                print(f"    Duration: {result.duration:.2f}s ({result.total_tests/result.duration:.1f} tests/s)")
                if result.errors:
                    print(f"    Errors: {len(result.errors)} (showing first 3)")
                    for err in result.errors[:3]:
                        print(f"      - {err}")
        
        # Generate summary report
        return self.generate_report()
    
    def generate_report(self) -> Dict:
        """Generate comprehensive test report."""
        report = {
            "timestamp": datetime.now().isoformat(),
            "components_tested": list(set(r.component for r in self.results)),
            "services_tested": list(set(r.service for r in self.results)),
            "results": [asdict(r) for r in self.results],
            "summary": {}
        }
        
        # Component-level summary
        for component in set(r.component for r in self.results):
            component_results = [r for r in self.results if r.component == component]
            report["summary"][component] = {
                "total_tests": sum(r.total_tests for r in component_results),
                "avg_tpr": sum(r.tpr for r in component_results) / len(component_results) if component_results else 0,
                "avg_fpr": sum(r.fpr for r in component_results) / len(component_results) if component_results else 0,
                "avg_f1": sum(r.f1_score for r in component_results) / len(component_results) if component_results else 0
            }
        
        return report
    
    def save_report(self, report: Dict, filename: str = None):
        """Save test report to file."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"multi_component_test_{timestamp}.json"
        
        output_file = self.output_dir / filename
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"\n{'='*80}")
        print(f"Report saved to: {output_file}")
        print(f"{'='*80}\n")
        
        return output_file


async def main():
    parser = argparse.ArgumentParser(description="Multi-Component Test Runner")
    parser.add_argument(
        "--components",
        type=str,
        default="all",
        help="Comma-separated list of components: holdout,production_ab,data_drift,adversarial,segmented,all"
    )
    parser.add_argument(
        "--services",
        type=str,
        default="8000,8001,8002,8003",
        help="Comma-separated list of service ports"
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Output filename for report (default: auto-generated)"
    )
    parser.add_argument(
        "--test-suites-dir",
        type=str,
        default=None,
        help="Path to test_suites directory (default: project_root/test_suites)"
    )
    
    args = parser.parse_args()
    
    # Parse components
    if args.components.lower() == "all":
        components = set(TestComponent)
    else:
        components = set()
        for comp_str in args.components.split(','):
            try:
                components.add(TestComponent(comp_str.strip()))
            except ValueError:
                print(f"WARNING: Unknown component '{comp_str}', skipping")
    
    # Parse services
    ports = [int(p.strip()) for p in args.services.split(',')]
    
    # Setup paths
    test_suites_dir = Path(args.test_suites_dir) if args.test_suites_dir else project_root / "test_suites"
    
    # Create runner
    runner = MultiComponentRunner(test_suites_dir)
    
    # Run tests
    report = await runner.run_components(components, ports)
    
    # Save report
    if report:
        runner.save_report(report, args.output)


if __name__ == "__main__":
    asyncio.run(main())

