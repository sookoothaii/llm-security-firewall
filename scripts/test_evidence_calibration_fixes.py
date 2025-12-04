#!/usr/bin/env python3
"""
Testet die neuen Evidence-Kalibrierungs-Korrekturen:
1. Optimierte Mass-Kalibrierung
2. Alternative p_correct-Formeln
3. Konservativere Parameter

Führt schnelle Tests auf core_suite_smoke.jsonl durch.
"""

import sys
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
SMOKE_DATASET = BASE_DIR / "datasets" / "core_suite_smoke.jsonl"
LOGS_DIR = BASE_DIR / "logs"


def run_test(name: str, args: list):
    """Führt einen Test mit gegebenen Argumenten durch."""
    output_file = LOGS_DIR / f"test_{name}.jsonl"

    cmd = [
        sys.executable,
        str(BASE_DIR / "scripts" / "run_answerpolicy_experiment.py"),
        "--policy",
        "kids",
        "--input",
        str(SMOKE_DATASET),
        "--output",
        str(output_file),
        "--use-evidence-based-p-correct",
        "--num-workers",
        "2",
    ] + args

    print(f"\n{'=' * 80}")
    print(f"Test: {name}")
    print(f"Command: {' '.join(cmd)}")
    print(f"{'=' * 80}\n")

    result = subprocess.run(cmd, cwd=str(BASE_DIR), capture_output=True, text=True)

    if result.returncode == 0:
        print(f"✓ Test '{name}' erfolgreich")
        return output_file
    else:
        print(f"✗ Test '{name}' fehlgeschlagen:")
        print(result.stderr)
        return None


def main():
    """Führt alle Kalibrierungs-Tests durch."""
    tests = [
        # Test 1: Optimierte Mass-Kalibrierung + konservative Parameter
        (
            "optimized_mass_conservative",
            [
                "--uncertainty-boost-factor",
                "0.2",
                "--p-correct-stretch-factor",
                "1.5",
                # Note: use_optimized_mass_calibration muss im Code gesetzt werden
                # (noch nicht als CLI-Parameter verfügbar)
            ],
        ),
        # Test 2: Keine Transformation
        (
            "no_transform",
            [
                "--uncertainty-boost-factor",
                "0.0",
                "--p-correct-stretch-factor",
                "1.0",
            ],
        ),
        # Test 3: Gewichtete p_correct-Formel
        (
            "weighted_formula",
            [
                "--uncertainty-boost-factor",
                "0.2",
                "--p-correct-stretch-factor",
                "1.5",
                # Note: p_correct_formula muss im Code gesetzt werden
            ],
        ),
    ]

    print("=" * 80)
    print("EVIDENCE-KALIBRIERUNGS-TESTS")
    print("=" * 80)
    print(f"\nTest-Dataset: {SMOKE_DATASET}")
    print(f"Anzahl Tests: {len(tests)}\n")

    results = []
    for name, args in tests:
        output_file = run_test(name, args)
        if output_file:
            results.append((name, output_file))

    print("\n" + "=" * 80)
    print("ZUSAMMENFASSUNG")
    print("=" * 80)
    print(f"\nErfolgreiche Tests: {len(results)}/{len(tests)}")
    for name, output_file in results:
        print(f"  ✓ {name}: {output_file}")

    if results:
        print("\nNächste Schritte:")
        print("1. Analysieren Sie die Ergebnisse mit:")
        print("   python scripts/analyze_full_evaluation.py logs/test_<name>.jsonl")
        print("2. Vergleichen Sie mit Baseline:")
        print(
            "   python scripts/compare_experiments.py logs/kids_heuristic_smoke.jsonl logs/test_<name>.jsonl"
        )


if __name__ == "__main__":
    main()
