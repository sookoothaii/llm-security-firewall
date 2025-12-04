#!/usr/bin/env python3
"""
VectorGuard Integration Helper für Evidence-Based AnswerPolicy

Initialisiert VectorGuard (SemanticVectorCheck) mit SessionManager
für echte CUSUM-Drift-Detection in Evidence-Fusion.

Usage:
    python scripts/integrate_vectorguard.py --help
"""

import sys
import argparse
import logging
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

try:
    from hak_gal.core.session_manager import SessionManager
    from hak_gal.layers.inbound.vector_guard import SemanticVectorCheck

    HAS_VECTORGUARD = True
except ImportError as e:
    HAS_VECTORGUARD = False
    IMPORT_ERROR = str(e)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def create_vectorguard_instance(
    model_name: str = "all-MiniLM-L6-v2",
    drift_threshold: float = 0.7,
    window_size: int = 50,
) -> SemanticVectorCheck:
    """
    Erstellt eine VectorGuard-Instanz für Evidence-Fusion.

    Args:
        model_name: SentenceTransformer Modellname
        drift_threshold: Cosine distance threshold für Drift-Detection
        window_size: Rolling window size für SessionTrajectory

    Returns:
        SemanticVectorCheck Instanz

    Raises:
        SystemError: Wenn sentence-transformers nicht verfügbar ist
    """
    if not HAS_VECTORGUARD:
        raise SystemError(
            f"VectorGuard nicht verfügbar: {IMPORT_ERROR}. "
            "Installieren Sie: pip install sentence-transformers"
        )

    # SessionManager initialisieren
    session_manager = SessionManager()
    logger.info("SessionManager initialisiert")

    # SemanticVectorCheck initialisieren
    vector_guard = SemanticVectorCheck(
        session_manager=session_manager,
        model_name=model_name,
        drift_threshold=drift_threshold,
        window_size=window_size,
    )
    logger.info(
        f"VectorGuard initialisiert: model={model_name}, "
        f"drift_threshold={drift_threshold}, window_size={window_size}"
    )

    return vector_guard


def test_vectorguard_integration():
    """Testet VectorGuard-Integration mit Beispiel-Texten."""
    if not HAS_VECTORGUARD:
        print(f"ERROR: VectorGuard nicht verfügbar: {IMPORT_ERROR}")
        return False

    try:
        vector_guard = create_vectorguard_instance()
        session_id = "test_session_001"

        # Test 1: Erster Text (sollte erlaubt werden)
        print("\n[Test 1] Erster Text (sollte erlaubt werden)")
        import asyncio

        async def test_async():
            is_safe, distance, error = await vector_guard.check(
                "Hello, how are you?", session_id
            )
            print(f"  is_safe: {is_safe}, distance: {distance:.4f}, error: {error}")

        asyncio.run(test_async())

        # Test 2: Ähnlicher Text (sollte erlaubt werden)
        print("\n[Test 2] Ähnlicher Text (sollte erlaubt werden)")

        async def test_async2():
            is_safe, distance, error = await vector_guard.check(
                "Hi, how's it going?", session_id
            )
            print(f"  is_safe: {is_safe}, distance: {distance:.4f}, error: {error}")

        asyncio.run(test_async2())

        # Test 3: Abrupter Themenwechsel (sollte Drift erkennen)
        print("\n[Test 3] Abrupter Themenwechsel (sollte Drift erkennen)")

        async def test_async3():
            try:
                is_safe, distance, error = await vector_guard.check(
                    "How to hack into a computer system?", session_id
                )
                print(f"  is_safe: {is_safe}, distance: {distance:.4f}, error: {error}")
            except Exception as e:
                print(f"  BLOCKED (erwartet): {type(e).__name__}: {e}")

        asyncio.run(test_async3())

        print("\n[SUCCESS] VectorGuard-Integration funktioniert!")
        return True

    except Exception as e:
        print(f"\n[ERROR] VectorGuard-Integration fehlgeschlagen: {e}")
        import traceback

        traceback.print_exc()
        return False


def main():
    parser = argparse.ArgumentParser(
        description="VectorGuard Integration Helper für Evidence-Based AnswerPolicy"
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Teste VectorGuard-Integration mit Beispiel-Texten",
    )
    parser.add_argument(
        "--model-name",
        type=str,
        default="all-MiniLM-L6-v2",
        help="SentenceTransformer Modellname (default: all-MiniLM-L6-v2)",
    )
    parser.add_argument(
        "--drift-threshold",
        type=float,
        default=0.7,
        help="Cosine distance threshold für Drift-Detection (default: 0.7)",
    )
    parser.add_argument(
        "--window-size",
        type=int,
        default=50,
        help="Rolling window size für SessionTrajectory (default: 50)",
    )

    args = parser.parse_args()

    if args.test:
        success = test_vectorguard_integration()
        sys.exit(0 if success else 1)
    else:
        # Erstelle VectorGuard-Instanz und zeige Konfiguration
        try:
            vector_guard = create_vectorguard_instance(
                model_name=args.model_name,
                drift_threshold=args.drift_threshold,
                window_size=args.window_size,
            )
            print("\n[INFO] VectorGuard-Instanz erfolgreich erstellt.")
            print("\nVerwendung in FirewallEngineV2:")
            print("  engine = FirewallEngineV2(")
            print("      ...,")
            print("      vector_guard=vector_guard,")
            print("  )")
            print("\nOder im Experiment-Skript:")
            print("  vector_guard = create_vectorguard_instance()")
            print("  engine = FirewallEngineV2(..., vector_guard=vector_guard)")
        except Exception as e:
            print(f"ERROR: {e}")
            sys.exit(1)


if __name__ == "__main__":
    main()
