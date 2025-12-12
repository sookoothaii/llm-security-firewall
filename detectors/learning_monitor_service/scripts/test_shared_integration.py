"""
Integration Tests für Shared Components Migration - Learning Monitor Service

Testet die Integration der Shared Components im Learning Monitor Service.
Validiert, dass alle Komponenten korrekt zusammenarbeiten.

Datum: 2025-12-11
Status: Phase 4 Validation (Option A: Monitoring Service)
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
BASE_URL = "http://localhost:8004"  # Learning Monitor Service Port
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
            response = self.client.get("/health")
            response.raise_for_status()
            
            data = response.json()
            logger.info(f"✓ Health Check Response: {json.dumps(data, indent=2)}")
            
            # Validierung
            assert data.get("status") == "healthy", f"Expected 'healthy', got '{data.get('status')}'"
            assert data.get("service") == "learning_monitor", "Service name should be 'learning_monitor'"
            
            logger.info("✅ TEST 1 PASSED: Service ist healthy")
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
    
    def test_status_endpoint(self) -> bool:
        """Test 2: Status Endpoint"""
        logger.info("=" * 60)
        logger.info("TEST 2: Status Endpoint")
        logger.info("=" * 60)
        
        try:
            response = self.client.get("/status")
            response.raise_for_status()
            
            data = response.json()
            logger.info(f"✓ Status Response: {json.dumps(data, indent=2)}")
            
            # Validierung
            assert "services" in data, "Missing 'services' in response"
            assert "alerts" in data, "Missing 'alerts' in response"
            assert "alert_count" in data, "Missing 'alert_count' in response"
            
            # Services should be a dictionary
            assert isinstance(data["services"], dict), "Services should be a dictionary"
            
            logger.info("✅ TEST 2 PASSED: Status endpoint funktioniert")
            return True
            
        except httpx.RequestError as e:
            logger.error(f"❌ TEST 2 FAILED: Service nicht erreichbar - {e}")
            return False
        except AssertionError as e:
            logger.error(f"❌ TEST 2 FAILED: Validierung fehlgeschlagen - {e}")
            return False
        except Exception as e:
            logger.error(f"❌ TEST 2 FAILED: Unerwarteter Fehler - {e}")
            return False
    
    def test_alerts_endpoint(self) -> bool:
        """Test 3: Alerts Endpoint"""
        logger.info("=" * 60)
        logger.info("TEST 3: Alerts Endpoint")
        logger.info("=" * 60)
        
        try:
            response = self.client.get("/alerts")
            response.raise_for_status()
            
            data = response.json()
            logger.info(f"✓ Alerts Response: {json.dumps(data, indent=2)}")
            
            # Validierung
            assert "alerts" in data, "Missing 'alerts' in response"
            assert "count" in data, "Missing 'count' in response"
            assert "critical" in data, "Missing 'critical' in response"
            assert "warning" in data, "Missing 'warning' in response"
            
            assert isinstance(data["alerts"], list), "Alerts should be a list"
            assert data["count"] == len(data["alerts"]), "Count should match alerts length"
            
            logger.info("✅ TEST 3 PASSED: Alerts endpoint funktioniert")
            return True
            
        except httpx.RequestError as e:
            logger.error(f"❌ TEST 3 FAILED: Service nicht erreichbar - {e}")
            return False
        except AssertionError as e:
            logger.error(f"❌ TEST 3 FAILED: Validierung fehlgeschlagen - {e}")
            return False
        except Exception as e:
            logger.error(f"❌ TEST 3 FAILED: Unerwarteter Fehler - {e}")
            return False
    
    def test_history_endpoint(self) -> bool:
        """Test 4: History Endpoint"""
        logger.info("=" * 60)
        logger.info("TEST 4: History Endpoint")
        logger.info("=" * 60)
        
        try:
            response = self.client.get("/history?limit=10")
            response.raise_for_status()
            
            data = response.json()
            logger.info(f"✓ History Response: {json.dumps(data, indent=2)}")
            
            # Validierung
            assert "history" in data, "Missing 'history' in response"
            assert "total" in data, "Missing 'total' in response"
            
            assert isinstance(data["history"], list), "History should be a list"
            assert len(data["history"]) <= 10, "History limit should be respected"
            
            logger.info("✅ TEST 4 PASSED: History endpoint funktioniert")
            return True
            
        except httpx.RequestError as e:
            logger.error(f"❌ TEST 4 FAILED: Service nicht erreichbar - {e}")
            return False
        except AssertionError as e:
            logger.error(f"❌ TEST 4 FAILED: Validierung fehlgeschlagen - {e}")
            return False
        except Exception as e:
            logger.error(f"❌ TEST 4 FAILED: Unerwarteter Fehler - {e}")
            return False
    
    def test_composition_root(self) -> bool:
        """Test 5: Composition Root Validierung"""
        logger.info("=" * 60)
        logger.info("TEST 5: Composition Root Validierung")
        logger.info("=" * 60)
        
        try:
            from infrastructure.app.composition_root import LearningMonitorCompositionRoot
            from domain.value_objects import ServiceStatus, Alert
            
            logger.info("Creating Composition Root...")
            composition = LearningMonitorCompositionRoot(history_max_size=100)
            logger.info("✓ Composition Root erstellt")
            
            logger.info("Creating Monitor Service...")
            service = composition.create_monitor_service()
            logger.info("✓ Monitor Service erstellt")
            
            logger.info("Testing Service Components...")
            assert service.service_monitor is not None, "Service monitor should be initialized"
            assert service.alert_analyzer is not None, "Alert analyzer should be initialized"
            assert service.websocket_manager is not None, "WebSocket manager should be initialized"
            assert service.history_repository is not None, "History repository should be initialized"
            
            logger.info("✓ Alle Komponenten initialisiert")
            
            logger.info("✅ TEST 5 PASSED: Composition Root erstellt Service erfolgreich")
            return True
            
        except ImportError as e:
            logger.error(f"❌ TEST 5 FAILED: Import-Fehler - {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False
        except AssertionError as e:
            logger.error(f"❌ TEST 5 FAILED: Validierung fehlgeschlagen - {e}")
            return False
        except Exception as e:
            logger.error(f"❌ TEST 5 FAILED: Unerwarteter Fehler - {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False
    
    def test_shared_components(self) -> bool:
        """Test 6: Shared Components Validierung"""
        logger.info("=" * 60)
        logger.info("TEST 6: Shared Components Validierung")
        logger.info("=" * 60)
        
        try:
            # Test BaseCompositionRoot (inherited)
            from shared.infrastructure.composition import BaseCompositionRoot
            
            logger.info("Testing BaseCompositionRoot...")
            base_root = BaseCompositionRoot(enable_cache=False, enable_normalization=False)
            logger.info("✓ BaseCompositionRoot erstellt")
            
            # Test LearningMonitorCompositionRoot extends BaseCompositionRoot
            from infrastructure.app.composition_root import LearningMonitorCompositionRoot
            
            logger.info("Testing LearningMonitorCompositionRoot extends BaseCompositionRoot...")
            monitor_root = LearningMonitorCompositionRoot()
            assert isinstance(monitor_root, BaseCompositionRoot), "Should extend BaseCompositionRoot"
            logger.info("✓ LearningMonitorCompositionRoot erbt von BaseCompositionRoot")
            
            # Test Shared Middleware
            from shared.api.middleware import LoggingMiddleware, ErrorHandlerMiddleware
            
            logger.info("Testing Shared Middleware...")
            logger.info("✓ LoggingMiddleware verfügbar")
            logger.info("✓ ErrorHandlerMiddleware verfügbar")
            
            logger.info("✅ TEST 6 PASSED: Alle Shared Components funktionieren korrekt")
            return True
            
        except ImportError as e:
            logger.error(f"❌ TEST 6 FAILED: Import-Fehler - {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False
        except AssertionError as e:
            logger.error(f"❌ TEST 6 FAILED: Validierung fehlgeschlagen - {e}")
            return False
        except Exception as e:
            logger.error(f"❌ TEST 6 FAILED: Unerwarteter Fehler - {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Führt alle Tests aus und gibt Ergebnisse zurück"""
        logger.info("\n" + "=" * 60)
        logger.info("INTEGRATION TESTS - Shared Components Migration (Learning Monitor Service)")
        logger.info("=" * 60)
        logger.info(f"Base URL: {BASE_URL}")
        logger.info(f"Timeout: {TIMEOUT}s")
        logger.info("")
        
        results = {
            "test_1_health_check": self.test_health_check(),
            "test_2_status_endpoint": self.test_status_endpoint(),
            "test_3_alerts_endpoint": self.test_alerts_endpoint(),
            "test_4_history_endpoint": self.test_history_endpoint(),
            "test_5_composition_root": self.test_composition_root(),
            "test_6_shared_components": self.test_shared_components(),
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

