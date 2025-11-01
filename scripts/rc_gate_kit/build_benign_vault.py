#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Build Benign Motif Vault from FPR measurement results
Learns from PASS samples to reduce future FPR
"""
import sys
from pathlib import Path

repo_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(repo_root / "src"))

from llm_firewall.gates.benign_vault import BenignVault


def build_vault_from_benign_corpus(corpus_path: str,
                                   output_path: str = "artifacts/benign_vault.json",
                                   min_frequency: int = 2):
    """
    Build vault from benign corpus
    
    Args:
        corpus_path: Path to benign corpus file
        output_path: Output vault JSON path
        min_frequency: Minimum occurrence to keep pattern
    """
    print("\n=== Building Benign Motif Vault ===")
    print(f"Corpus: {corpus_path}")
    print(f"Output: {output_path}\n")

    if not Path(corpus_path).exists():
        print(f"ERROR: Corpus not found: {corpus_path}")
        return

    vault = BenignVault()

    # Load corpus
    with open(corpus_path, 'r', encoding='utf-8') as f:
        samples = [line.strip() for line in f if line.strip()]

    total = len(samples)
    print(f"Processing {total} samples...")

    for idx, text in enumerate(samples):
        if idx % 100 == 0:
            print(f"  Progress: {idx}/{total} ({100*idx/total:.1f}%)")

        vault.add_text(text)

    print(f"  Progress: {total}/{total} (100.0%)\n")
    print(f"Patterns stored: {len(vault.hashes)}\n")

    # Save vault
    output_file = Path(output_path)
    vault.save(output_file)
    print(f"✓ Vault saved: {output_path}\n")


def build_vault_from_attrib_csv(attrib_csv: str,
                                output_path: str = "artifacts/benign_vault.json"):
    """
    Build vault from FPR attribution CSV (learn from PASS samples only)
    
    Args:
        attrib_csv: Path to fpr_attrib.csv
        output_path: Output vault JSON path
    """
    print("\n=== Building Vault from Attribution CSV ===")
    print(f"CSV: {attrib_csv}")
    print(f"Output: {output_path}\n")

    if not Path(attrib_csv).exists():
        print(f"ERROR: CSV not found: {attrib_csv}")
        return

    vault = BenignVault()

    # Note: CSV contains FALSE POSITIVES, so we need the BENIGN corpus
    # This function is for future use when we have PASS samples logged
    print("Note: This function expects PASS samples, not FPs.")
    print("Use build_vault_from_benign_corpus() instead.\n")


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Build Benign Motif Vault')
    parser.add_argument('--corpus', default='data/benign_corpus.txt',
                       help='Benign corpus path')
    parser.add_argument('--output', default='artifacts/benign_vault.json',
                       help='Output vault path')
    parser.add_argument('--min-freq', type=int, default=2,
                       help='Minimum frequency to keep')
    args = parser.parse_args()

    build_vault_from_benign_corpus(args.corpus, args.output, args.min_freq)

