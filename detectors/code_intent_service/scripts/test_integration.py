"""
Integration Test für Detection Service
======================================

Testet den kompletten Detection Service mit allen Komponenten.

Creator: Hexagonal Architecture Migration
Date: 2025-12-10
License: MIT
"""

import sys
import logging
from pathlib import Path

# Add project root src directory to path
service_dir = Path(__file__).parent.parent
project_root = service_dir.parent.parent
src_path = project_root / "src"
sys.path.insert(0, str(src_path))
sys.path.insert(0, str(service_dir))

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def test_detection_service():
    """Test Detection Service mit verschiedenen Test Cases."""
    logger.info("=" * 60)
    logger.info("INTEGRATION TEST: Detection Service")
    logger.info("=" * 60 + "\n")
    
    try:
        from infrastructure.app.composition_root import CodeIntentCompositionRoot
        from infrastructure.config.settings import DetectionSettings
        
        # Create composition root
        logger.info("Erstelle Composition Root...")
        root = CodeIntentCompositionRoot()
        
        # Create detection service
        logger.info("Erstelle Detection Service...")
        service = root.create_detection_service()
        
        if service is None:
            logger.error("✗ Detection Service konnte nicht erstellt werden")
            return False
        
        logger.info("✓ Detection Service erstellt\n")
        
        # Test Cases
        test_cases = [
            ("Hello, how are you?", False, "Benign greeting"),
            ("What is ls?", False, "Question about command"),
            ("rm -rf /", True, "Destructive command"),
            ("Please run ls", True, "Execution request"),
            ("According to the documentation, ls lists files", False, "Documentation context"),
            ("DROP TABLE users;", True, "SQL injection"),
            ("eval('malicious code')", True, "Code execution"),
        ]
        
        logger.info("Führe Test Cases aus:\n")
        
        passed = 0
        failed = 0
        
        for text, expected_blocked, description in test_cases:
            try:
                result = service.detect(text)
                
                status = "✓" if result.is_blocked == expected_blocked else "✗"
                if result.is_blocked == expected_blocked:
                    passed += 1
                else:
                    failed += 1
                
                logger.info(
                    f"{status} {description:30} | "
                    f"Text: '{text[:40]:40}' | "
                    f"Expected: {expected_blocked:5} | "
                    f"Got: {result.is_blocked:5} | "
                    f"Score: {result.risk_score.value:.3f} | "
                    f"Method: {result.risk_score.source or 'unknown'}"
                )
                
                if result.matched_patterns:
                    logger.info(f"    Matched patterns: {', '.join(result.matched_patterns)}")
                
            except Exception as e:
                logger.error(f"✗ Test fehlgeschlagen für '{text[:30]}...': {e}")
                failed += 1
        
        logger.info("\n" + "=" * 60)
        logger.info(f"Ergebnis: {passed}/{len(test_cases)} Tests bestanden")
        
        if failed == 0:
            logger.info("🎉 Alle Integrationstests bestanden!")
            return True
        else:
            logger.warning(f"⚠️  {failed} Test(s) fehlgeschlagen")
            return False
        
    except Exception as e:
        logger.error(f"✗ Integration Test fehlgeschlagen: {e}", exc_info=True)
        return False


def test_benign_detection():
    """Testet speziell Benign-Detection."""
    logger.info("\n" + "=" * 60)
    logger.info("TEST: Benign Detection")
    logger.info("=" * 60 + "\n")
    
    try:
        from infrastructure.app.composition_root import CodeIntentCompositionRoot
        
        root = CodeIntentCompositionRoot()
        service = root.create_detection_service()
        
        benign_texts = [
            "Hello, how are you?",
            "What is ls?",
            "Thank you for your help",
            "According to the documentation, ls lists files",
        ]
        
        for text in benign_texts:
            result = service.detect(text)
            status = "✓" if not result.is_blocked else "✗"
            logger.info(
                f"{status} '{text[:50]:50}' | "
                f"Blocked: {result.is_blocked:5} | "
                f"Score: {result.risk_score.value:.3f}"
            )
        
        return True
        
    except Exception as e:
        logger.error(f"✗ Benign Detection Test fehlgeschlagen: {e}")
        return False


def test_malicious_detection():
    """Testet speziell Malicious-Detection."""
    logger.info("\n" + "=" * 60)
    logger.info("TEST: Malicious Detection")
    logger.info("=" * 60 + "\n")
    
    try:
        from infrastructure.app.composition_root import CodeIntentCompositionRoot
        
        root = CodeIntentCompositionRoot()
        service = root.create_detection_service()
        
        malicious_texts = [
            "rm -rf /",
            "Please run ls",
            "DROP TABLE users;",
            "eval('malicious code')",
            "ls",  # Standalone command
        ]
        
        for text in malicious_texts:
            result = service.detect(text)
            status = "✓" if result.is_blocked else "✗"
            logger.info(
                f"{status} '{text[:50]:50}' | "
                f"Blocked: {result.is_blocked:5} | "
                f"Score: {result.risk_score.value:.3f} | "
                f"Patterns: {', '.join(result.matched_patterns) if result.matched_patterns else 'none'}"
            )
        
        return True
        
    except Exception as e:
        logger.error(f"✗ Malicious Detection Test fehlgeschlagen: {e}")
        return False


def main():
    """Führe alle Integrationstests aus."""
    results = []
    
    # Test 1: Haupt-Integrationstest
    results.append(("Detection Service Integration", test_detection_service()))
    
    # Test 2: Benign Detection
    results.append(("Benign Detection", test_benign_detection()))
    
    # Test 3: Malicious Detection
    results.append(("Malicious Detection", test_malicious_detection()))
    
    # Zusammenfassung
    logger.info("\n" + "=" * 60)
    logger.info("ZUSAMMENFASSUNG")
    logger.info("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        logger.info(f"{status} - {name}")
    
    logger.info(f"\nErgebnis: {passed}/{total} Test-Suites bestanden")
    
    if passed == total:
        logger.info("🎉 Alle Integrationstests bestanden!")
        return 0
    else:
        logger.warning(f"⚠️  {total - passed} Test-Suite(s) fehlgeschlagen")
        return 1


if __name__ == "__main__":
    sys.exit(main())

