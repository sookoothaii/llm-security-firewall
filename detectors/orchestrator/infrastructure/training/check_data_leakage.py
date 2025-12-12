"""
⚠️ KRITISCHER DATA LEAKAGE CHECK

Überprüft auf Data Leakage zwischen:
- Whitelist Classifier Train/Validation Sets
- True Validation Set (code_intent_true_validation.jsonl)
- V2 False Positives (Quelle für Whitelist Positives)

Usage:
    python -m detectors.orchestrator.infrastructure.training.check_data_leakage \
        --whitelist-train data/adversarial_training/whitelist_module/train.jsonl \
        --whitelist-val data/adversarial_training/whitelist_module/validation.jsonl \
        --true-validation data/adversarial_training/code_intent_true_validation.jsonl \
        --v2-fps data/adversarial_training/v3_preparation/v2_false_positives_analysis_v3_training.json \
        --output results/data_leakage_check.json
"""

import sys
import json
import logging
import argparse
from pathlib import Path
from typing import List, Dict, Set, Any
from collections import defaultdict
import hashlib

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(project_root))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def normalize_text(text: str) -> str:
    """Normalize text for comparison."""
    return text.strip().lower()


def text_hash(text: str) -> str:
    """Create hash of normalized text."""
    return hashlib.md5(normalize_text(text).encode()).hexdigest()


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    """Load JSONL file."""
    samples = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                samples.append(json.loads(line))
    return samples


def load_json(path: Path) -> Dict[str, Any]:
    """Load JSON file."""
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def extract_texts(samples: List[Dict]) -> Set[str]:
    """Extract normalized texts and hashes."""
    texts = set()
    for sample in samples:
        text = sample.get('text', sample.get('input', ''))
        if text:
            texts.add(text_hash(text))
    return texts


def check_overlap(
    set1: Set[str],
    set2: Set[str],
    name1: str,
    name2: str
) -> Dict[str, Any]:
    """Check overlap between two sets."""
    overlap = set1.intersection(set2)
    overlap_pct_1 = (len(overlap) / len(set1) * 100) if set1 else 0
    overlap_pct_2 = (len(overlap) / len(set2) * 100) if set2 else 0
    
    return {
        'overlap_count': len(overlap),
        'set1_size': len(set1),
        'set2_size': len(set2),
        'overlap_pct_set1': overlap_pct_1,
        'overlap_pct_set2': overlap_pct_2,
        'name1': name1,
        'name2': name2,
        'is_critical': overlap_pct_1 > 5.0 or overlap_pct_2 > 5.0
    }


def find_duplicate_samples(
    samples1: List[Dict],
    samples2: List[Dict],
    name1: str,
    name2: str
) -> List[Dict[str, Any]]:
    """Find actual duplicate samples."""
    texts1 = {}
    for i, sample in enumerate(samples1):
        text = sample.get('text', sample.get('input', ''))
        if text:
            h = text_hash(text)
            if h not in texts1:
                texts1[h] = []
            texts1[h].append({
                'index': i,
                'sample': sample,
                'source': name1
            })
    
    duplicates = []
    for i, sample in enumerate(samples2):
        text = sample.get('text', sample.get('input', ''))
        if text:
            h = text_hash(text)
            if h in texts1:
                for match in texts1[h]:
                    duplicates.append({
                        'text': text[:100] + '...' if len(text) > 100 else text,
                        'text_hash': h,
                        'source1': match['source'],
                        'index1': match['index'],
                        'source2': name2,
                        'index2': i
                    })
    
    return duplicates


def main():
    parser = argparse.ArgumentParser(description="Check Data Leakage")
    parser.add_argument(
        "--whitelist-train",
        type=str,
        required=True,
        help="Path to Whitelist Classifier training set"
    )
    parser.add_argument(
        "--whitelist-val",
        type=str,
        required=True,
        help="Path to Whitelist Classifier validation set"
    )
    parser.add_argument(
        "--true-validation",
        type=str,
        required=True,
        help="Path to True Validation Set (code_intent_true_validation.jsonl)"
    )
    parser.add_argument(
        "--v2-fps",
        type=str,
        help="Path to V2 False Positives JSON (optional)"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="results/data_leakage_check.json",
        help="Output JSON path"
    )
    parser.add_argument(
        "--detailed",
        action="store_true",
        help="Show detailed duplicate samples"
    )
    
    args = parser.parse_args()
    
    logger.info("="*80)
    logger.info("⚠️  DATA LEAKAGE CHECK - KRITISCH")
    logger.info("="*80)
    
    # Load datasets
    logger.info("\n📂 Loading datasets...")
    
    whitelist_train = load_jsonl(Path(args.whitelist_train))
    whitelist_val = load_jsonl(Path(args.whitelist_val))
    true_validation = load_jsonl(Path(args.true_validation))
    
    logger.info(f"  Whitelist Train: {len(whitelist_train)} samples")
    logger.info(f"  Whitelist Val: {len(whitelist_val)} samples")
    logger.info(f"  True Validation: {len(true_validation)} samples")
    
    v2_fps = None
    if args.v2_fps:
        v2_fps_data = load_json(Path(args.v2_fps))
        v2_fps = v2_fps_data.get('v2_false_positives', [])
        logger.info(f"  V2 False Positives: {len(v2_fps)} samples")
    
    # Extract text hashes
    logger.info("\n🔍 Extracting text hashes...")
    whitelist_train_texts = extract_texts(whitelist_train)
    whitelist_val_texts = extract_texts(whitelist_val)
    true_val_texts = extract_texts(true_validation)
    v2_fps_texts = extract_texts(v2_fps) if v2_fps else set()
    
    # Check overlaps
    logger.info("\n🔎 Checking for overlaps...")
    results = {
        'checks': [],
        'summary': {},
        'critical_issues': [],
        'warnings': []
    }
    
    # Check 1: Whitelist Train vs Whitelist Val
    check1 = check_overlap(
        whitelist_train_texts,
        whitelist_val_texts,
        "Whitelist Train",
        "Whitelist Val"
    )
    results['checks'].append(check1)
    
    if check1['overlap_count'] > 0:
        results['critical_issues'].append(
            f"❌ KRITISCH: {check1['overlap_count']} Samples überlappen zwischen "
            f"Whitelist Train und Val ({check1['overlap_pct_set1']:.2f}% von Train, "
            f"{check1['overlap_pct_set2']:.2f}% von Val)"
        )
        if args.detailed:
            duplicates = find_duplicate_samples(
                whitelist_train, whitelist_val,
                "Whitelist Train", "Whitelist Val"
            )
            results['checks'][-1]['duplicate_samples'] = duplicates[:10]  # First 10
    
    # Check 2: Whitelist Train vs True Validation
    check2 = check_overlap(
        whitelist_train_texts,
        true_val_texts,
        "Whitelist Train",
        "True Validation"
    )
    results['checks'].append(check2)
    
    if check2['overlap_count'] > 0:
        results['critical_issues'].append(
            f"❌ KRITISCH: {check2['overlap_count']} Samples überlappen zwischen "
            f"Whitelist Train und True Validation ({check2['overlap_pct_set1']:.2f}% von Train, "
            f"{check2['overlap_pct_set2']:.2f}% von True Val)"
        )
        if args.detailed:
            duplicates = find_duplicate_samples(
                whitelist_train, true_validation,
                "Whitelist Train", "True Validation"
            )
            results['checks'][-1]['duplicate_samples'] = duplicates[:10]
    
    # Check 3: Whitelist Val vs True Validation
    check3 = check_overlap(
        whitelist_val_texts,
        true_val_texts,
        "Whitelist Val",
        "True Validation"
    )
    results['checks'].append(check3)
    
    if check3['overlap_count'] > 0:
        results['warnings'].append(
            f"⚠️  WARNUNG: {check3['overlap_count']} Samples überlappen zwischen "
            f"Whitelist Val und True Validation ({check3['overlap_pct_set1']:.2f}% von Val, "
            f"{check3['overlap_pct_set2']:.2f}% von True Val)"
        )
        if args.detailed:
            duplicates = find_duplicate_samples(
                whitelist_val, true_validation,
                "Whitelist Val", "True Validation"
            )
            results['checks'][-1]['duplicate_samples'] = duplicates[:10]
    
    # Check 4: V2 FPs vs True Validation (if available)
    if v2_fps_texts:
        check4 = check_overlap(
            v2_fps_texts,
            true_val_texts,
            "V2 False Positives",
            "True Validation"
        )
        results['checks'].append(check4)
        
        if check4['overlap_count'] > 0:
            results['warnings'].append(
                f"⚠️  WARNUNG: {check4['overlap_count']} V2 FPs sind auch im True Validation Set "
                f"({check4['overlap_pct_set2']:.2f}% von True Val)"
            )
    
    # Summary
    total_critical = len(results['critical_issues'])
    total_warnings = len(results['warnings'])
    
    results['summary'] = {
        'total_critical_issues': total_critical,
        'total_warnings': total_warnings,
        'status': 'CRITICAL' if total_critical > 0 else 'WARNING' if total_warnings > 0 else 'OK'
    }
    
    # Print results
    logger.info("\n" + "="*80)
    logger.info("📊 RESULTS")
    logger.info("="*80)
    
    for check in results['checks']:
        status = "❌" if check['is_critical'] else "⚠️" if check['overlap_count'] > 0 else "✅"
        logger.info(f"\n{status} {check['name1']} vs {check['name2']}:")
        logger.info(f"   Overlap: {check['overlap_count']} samples")
        logger.info(f"   {check['name1']}: {check['overlap_pct_set1']:.2f}%")
        logger.info(f"   {check['name2']}: {check['overlap_pct_set2']:.2f}%")
    
    logger.info("\n" + "="*80)
    logger.info("🚨 CRITICAL ISSUES")
    logger.info("="*80)
    
    if results['critical_issues']:
        for issue in results['critical_issues']:
            logger.error(issue)
    else:
        logger.info("✅ Keine kritischen Issues gefunden")
    
    logger.info("\n" + "="*80)
    logger.info("⚠️  WARNINGS")
    logger.info("="*80)
    
    if results['warnings']:
        for warning in results['warnings']:
            logger.warning(warning)
    else:
        logger.info("✅ Keine Warnungen")
    
    logger.info("\n" + "="*80)
    logger.info(f"📋 SUMMARY: {results['summary']['status']}")
    logger.info("="*80)
    logger.info(f"   Critical Issues: {total_critical}")
    logger.info(f"   Warnings: {total_warnings}")
    
    # Save results
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    logger.info(f"\n💾 Results saved to: {output_path}")
    
    # Final verdict
    logger.info("\n" + "="*80)
    if total_critical > 0:
        logger.error("❌ DATA LEAKAGE ERKANNT - DEPLOYMENT NICHT EMPFOHLEN!")
        logger.error("   Bitte Data Leakage beheben bevor Sie deployen.")
        return 1
    elif total_warnings > 0:
        logger.warning("⚠️  WARNUNGEN ERKANNT - Weitere Validierung empfohlen")
        logger.warning("   Cross-Validation und OOD Tests durchführen.")
        return 0
    else:
        logger.info("✅ Keine Data Leakage erkannt")
        logger.info("   ABER: 100% Accuracy ist immer noch verdächtig!")
        logger.info("   Cross-Validation und OOD Tests trotzdem empfohlen.")
        return 0


if __name__ == "__main__":
    exit(main())

