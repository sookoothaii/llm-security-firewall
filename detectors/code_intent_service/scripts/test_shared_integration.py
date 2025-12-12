"""
Integration Tests für Shared Components Migration

Testet die Integration der Shared Components im Code Intent Service.
Validiert, dass alle Komponenten korrekt zusammenarbeiten.

Datum: 2025-12-11
Status: Phase 2 Validation
"""

import sys
import time
import json
from pathlib import Path
from typing import Dict, Any

# Add paths
service_dir = Path(__file__).parent.parent
detectors_dir = service_dir.parent
project_root = detectors_dir.parent
sys.path.insert(0, str(detectors_dir))
sys.path.insert(0, str(service_dir))
sys.path.insert(0, str(project_root / "src"))

import httpx
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Test Configuration
BASE_URL = "http://localhost:8000"
TIMEOUT = 30.0


class IntegrationTestRunner:
    """Runner für Integration Tests"""
    
    def __init__(self):
        self.results = []
        self.client = httpx.Client(timeout=TIMEOUT, base_url=BASE_URL)
    
    def test_health_check(self) -> bool:
        """Test 1: Service Startup und Health Check"""
        logger.info("=" * 60)
        logger.info("TEST 1: Service Startup und Health Check")
        logger.info("=" * 60)
        
        try:
            response = self.client.get("/api/v1/health")
            response.raise_for_status()
            
            data = response.json()
            logger.info(f"✓ Health Check Response: {json.dumps(data, indent=2)}")
            
            # Validierung
            assert data.get("status") == "healthy", f"Expected 'healthy', got '{data.get('status')}'"
            assert "components" in data, "Missing 'components' in response"
            
            components = data["components"]
            assert components.get("detection_service") == "operational", "Detection service not operational"
            
            logger.info("✅ TEST 1 PASSED: Service ist healthy und alle Komponenten operational")
            return True
            
        except httpx.RequestError as e:
            logger.error(f"❌ TEST 1 FAILED: Service nicht erreichbar - {e}")
            return False
        except AssertionError as e:
            logger.error(f"❌ TEST 1 FAILED: Validierung fehlgeschlagen - {e}")
            return False
        except Exception as e:
            logger.error(f"❌ TEST 1 FAILED: Unerwarteter Fehler - {e}")
            return False
    
    def test_malicious_detection(self) -> bool:
        """Test 2: Malicious Detection Pipeline"""
        logger.info("=" * 60)
        logger.info("TEST 2: Malicious Detection Pipeline")
        logger.info("=" * 60)
        
        test_cases = [
            {
                "name": "Destructive Command (rm -rf /)",
                "text": "rm -rf /",
                "expected_blocked": True,
                "expected_min_score": 0.6,  # Narrative intent detection gibt 0.6
            },
            {
                "name": "SQL Injection (DROP TABLE)",
                "text": "DROP TABLE users;",
                "expected_blocked": True,
                "expected_min_score": 0.7,
            },
            {
                "name": "Code Execution (eval)",
                "text": "eval('malicious_code()')",
                "expected_blocked": True,
                "expected_min_score": 0.6,
            },
        ]
        
        all_passed = True
        
        for test_case in test_cases:
            try:
                logger.info(f"\nTesting: {test_case['name']}")
                logger.info(f"Input: {test_case['text']}")
                
                response = self.client.post(
                    "/api/v1/detect",
                    json={
                        "text": test_case["text"],
                        "context": {"test": True}
                    }
                )
                response.raise_for_status()
                
                data = response.json()
                logger.info(f"Response: {json.dumps(data, indent=2)}")
                
                # Validierung
                assert data.get("success") == True, "Request sollte erfolgreich sein"
                assert "data" in data, "Missing 'data' in response"
                
                result_data = data["data"]
                is_blocked = result_data.get("is_blocked", result_data.get("should_block", False))
                risk_score = result_data.get("risk_score", 0.0)
                
                assert is_blocked == test_case["expected_blocked"], \
                    f"Expected blocked={test_case['expected_blocked']}, got {is_blocked}"
                assert risk_score >= test_case["expected_min_score"], \
                    f"Expected risk_score >= {test_case['expected_min_score']}, got {risk_score}"
                
                logger.info(f"✅ {test_case['name']}: PASSED (blocked={is_blocked}, score={risk_score:.3f})")
                
            except AssertionError as e:
                logger.error(f"❌ {test_case['name']}: FAILED - {e}")
                all_passed = False
            except Exception as e:
                logger.error(f"❌ {test_case['name']}: FAILED - {e}")
                all_passed = False
        
        if all_passed:
            logger.info("\n✅ TEST 2 PASSED: Alle malicious Detection Tests bestanden")
        else:
            logger.error("\n❌ TEST 2 FAILED: Einige Tests fehlgeschlagen")
        
        return all_passed
    
    def test_benign_detection(self) -> bool:
        """Test 3: Benign Detection Pipeline"""
        logger.info("=" * 60)
        logger.info("TEST 3: Benign Detection Pipeline")
        logger.info("=" * 60)
        
        test_cases = [
            {
                "name": "Greeting",
                "text": "Hello, how are you?",
                "expected_blocked": False,
                "expected_max_score": 0.3,
            },
            {
                "name": "Question about command",
                "text": "What does the ls command do?",
                "expected_blocked": False,
                "expected_max_score": 0.3,
            },
            {
                "name": "Technical discussion",
                "text": "Can you explain how SQL queries work?",
                "expected_blocked": False,
                "expected_max_score": 0.3,
            },
        ]
        
        all_passed = True
        
        for test_case in test_cases:
            try:
                logger.info(f"\nTesting: {test_case['name']}")
                logger.info(f"Input: {test_case['text']}")
                
                response = self.client.post(
                    "/api/v1/detect",
                    json={
                        "text": test_case["text"],
                        "context": {"test": True}
                    }
                )
                response.raise_for_status()
                
                data = response.json()
                logger.info(f"Response: {json.dumps(data, indent=2)}")
                
                # Validierung
                assert data.get("success") == True, "Request sollte erfolgreich sein"
                assert "data" in data, "Missing 'data' in response"
                
                result_data = data["data"]
                is_blocked = result_data.get("is_blocked", result_data.get("should_block", True))
                risk_score = result_data.get("risk_score", 1.0)
                
                assert is_blocked == test_case["expected_blocked"], \
                    f"Expected blocked={test_case['expected_blocked']}, got {is_blocked}"
                assert risk_score <= test_case["expected_max_score"], \
                    f"Expected risk_score <= {test_case['expected_max_score']}, got {risk_score}"
                
                logger.info(f"✅ {test_case['name']}: PASSED (blocked={is_blocked}, score={risk_score:.3f})")
                
            except AssertionError as e:
                logger.error(f"❌ {test_case['name']}: FAILED - {e}")
                all_passed = False
            except Exception as e:
                logger.error(f"❌ {test_case['name']}: FAILED - {e}")
                all_passed = False
        
        if all_passed:
            logger.info("\n✅ TEST 3 PASSED: Alle benign Detection Tests bestanden")
        else:
            logger.error("\n❌ TEST 3 FAILED: Einige Tests fehlgeschlagen")
        
        return all_passed
    
    def test_composition_root(self) -> bool:
        """Test 4: Composition Root Validierung"""
        logger.info("=" * 60)
        logger.info("TEST 4: Composition Root Validierung")
        logger.info("=" * 60)
        
        try:
            from infrastructure.app.composition_root import CodeIntentCompositionRoot
            from shared.domain.value_objects import RiskScore
            
            logger.info("Creating Composition Root...")
            composition = CodeIntentCompositionRoot()
            logger.info("✓ Composition Root erstellt")
            
            logger.info("Creating Detection Service...")
            service = composition.create_detection_service()
            logger.info("✓ Detection Service erstellt")
            
            logger.info("Testing Service Detection...")
            result = service.detect("Test input", context={"test": True})
            
            # Validierung
            assert hasattr(result, "risk_score"), "Result sollte risk_score haben"
            assert isinstance(result.risk_score, RiskScore), "risk_score sollte RiskScore Value Object sein"
            
            # DetectionResult hat 'blocked' nicht 'is_blocked'
            assert hasattr(result, "blocked") or hasattr(result, "is_blocked"), "Result sollte blocked/is_blocked haben"
            blocked_value = getattr(result, "blocked", getattr(result, "is_blocked", None))
            assert isinstance(blocked_value, bool), "blocked sollte boolean sein"
            
            logger.info(f"✓ Service antwortet: blocked={blocked_value}, score={result.risk_score.value:.3f}")
            
            logger.info("✅ TEST 4 PASSED: Composition Root erstellt Service erfolgreich")
            return True
            
        except ImportError as e:
            logger.error(f"❌ TEST 4 FAILED: Import-Fehler - {e}")
            return False
        except AssertionError as e:
            logger.error(f"❌ TEST 4 FAILED: Validierung fehlgeschlagen - {e}")
            return False
        except Exception as e:
            logger.error(f"❌ TEST 4 FAILED: Unerwarteter Fehler - {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False
    
    def test_shared_components(self) -> bool:
        """Test 5: Shared Components Validierung"""
        logger.info("=" * 60)
        logger.info("TEST 5: Shared Components Validierung")
        logger.info("=" * 60)
        
        try:
            # Test RiskScore aus Shared
            from shared.domain.value_objects import RiskScore
            
            logger.info("Testing RiskScore Value Object...")
            risk = RiskScore.create(value=0.85, confidence=0.9, source="test")
            assert risk.value == 0.85, "RiskScore value sollte korrekt sein"
            assert risk.confidence == 0.9, "RiskScore confidence sollte korrekt sein"
            assert risk.source == "test", "RiskScore source sollte korrekt sein"
            logger.info("✓ RiskScore Value Object funktioniert")
            
            # Test BaseCompositionRoot
            from shared.infrastructure.composition import BaseCompositionRoot
            
            logger.info("Testing BaseCompositionRoot...")
            base_root = BaseCompositionRoot(enable_cache=False, enable_normalization=False)
            logger.info("✓ BaseCompositionRoot erstellt")
            
            # Test BaseDetectionRequest
            from shared.api.models import BaseDetectionRequest
            
            logger.info("Testing BaseDetectionRequest...")
            request = BaseDetectionRequest(text="Test", context={"test": True})
            assert request.text == "Test", "Request text sollte korrekt sein"
            logger.info("✓ BaseDetectionRequest funktioniert")
            
            logger.info("✅ TEST 5 PASSED: Alle Shared Components funktionieren korrekt")
            return True
            
        except ImportError as e:
            logger.error(f"❌ TEST 5 FAILED: Import-Fehler - {e}")
            return False
        except AssertionError as e:
            logger.error(f"❌ TEST 5 FAILED: Validierung fehlgeschlagen - {e}")
            return False
        except Exception as e:
            logger.error(f"❌ TEST 5 FAILED: Unerwarteter Fehler - {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Führt alle Tests aus und gibt Ergebnisse zurück"""
        logger.info("\n" + "=" * 60)
        logger.info("INTEGRATION TESTS - Shared Components Migration")
        logger.info("=" * 60)
        logger.info(f"Base URL: {BASE_URL}")
        logger.info(f"Timeout: {TIMEOUT}s")
        logger.info("")
        
        results = {
            "test_1_health_check": self.test_health_check(),
            "test_2_malicious_detection": self.test_malicious_detection(),
            "test_3_benign_detection": self.test_benign_detection(),
            "test_4_composition_root": self.test_composition_root(),
            "test_5_shared_components": self.test_shared_components(),
        }
        
        # Zusammenfassung
        logger.info("\n" + "=" * 60)
        logger.info("TEST ZUSAMMENFASSUNG")
        logger.info("=" * 60)
        
        total = len(results)
        passed = sum(1 for v in results.values() if v)
        failed = total - passed
        
        for test_name, result in results.items():
            status = "✅ PASSED" if result else "❌ FAILED"
            logger.info(f"{test_name}: {status}")
        
        logger.info("")
        logger.info(f"Gesamt: {passed}/{total} Tests bestanden")
        
        if passed == total:
            logger.info("🎉 ALLE TESTS BESTANDEN!")
        else:
            logger.warning(f"⚠️  {failed} Test(s) fehlgeschlagen")
        
        return {
            "total": total,
            "passed": passed,
            "failed": failed,
            "results": results,
            "success": passed == total
        }


def main():
    """Main entry point"""
    runner = IntegrationTestRunner()
    results = runner.run_all_tests()
    
    # Exit code basierend auf Ergebnissen
    sys.exit(0 if results["success"] else 1)


if __name__ == "__main__":
    main()

