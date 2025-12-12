"""
Generiere erweiterte Trainingsdaten basierend auf Weakness-Analyse
===================================================================

Generiert zusätzliche Trainings-Samples für:
- Context-Benign-Wrapper (KRITISCH)
- Obfuscation-Varianten (HIGH)
- eval() Patterns (HIGH)
- SQL-Destructive Commands (MEDIUM)

Creator: HAK_GAL (Joerg Bollwahn)
Date: 2025-12-08
License: MIT
"""

import argparse
import json
import random
from pathlib import Path
from typing import List, Dict
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ============================================================================
# AUGMENTATION FUNCTIONS
# ============================================================================

def add_benign_context_wrapper(text: str) -> str:
    """Füge benignen Kontext hinzu, um malicious Code zu verschleiern."""
    benign_prefixes = [
        "This is a harmless example: ",
        "Educational purpose only: ",
        "For testing: ",
        "Example code: ",
        "This is safe: ",
        "Just an example: ",
        "Demo code: ",
        "Learning example: ",
        "Tutorial: ",
        "Sample code: "
    ]
    benign_suffixes = [
        " # educational purpose only",
        " # harmless",
        " # safe example",
        " // test only",
        " # demo",
        " # example",
        " // harmless",
        " # tutorial"
    ]
    
    prefix = random.choice(benign_prefixes)
    suffix = random.choice(benign_suffixes)
    return f"{prefix}{text}{suffix}"


def obfuscate_case_variation(text: str) -> str:
    """Variiere Groß-/Kleinschreibung."""
    # Verschiedene Strategien
    strategy = random.choice(['alternating', 'random', 'first_upper', 'all_upper'])
    
    if strategy == 'alternating':
        return ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(text))
    elif strategy == 'random':
        return ''.join(c.upper() if random.random() < 0.5 else c.lower() for c in text)
    elif strategy == 'first_upper':
        words = text.split()
        return ' '.join(word.capitalize() if i == 0 else word.lower() for i, word in enumerate(words))
    else:  # all_upper
        return text.upper()


def obfuscate_comment_injection(text: str) -> str:
    """Füge Kommentare ein, um Muster zu verschleiern."""
    words = text.split()
    if len(words) < 2:
        return text
    
    # Verschiedene Kommentar-Stile
    comment_styles = [
        "# harmless comment",
        "# test",
        "// harmless",
        "/* harmless */",
        "# safe",
        "// test only"
    ]
    
    # Füge Kommentar an verschiedenen Positionen ein
    insert_pos = random.randint(1, len(words) - 1)
    comment = random.choice(comment_styles)
    words.insert(insert_pos, comment)
    
    return ' '.join(words)


def obfuscate_whitespace_variation(text: str) -> str:
    """Variiere Whitespace."""
    # Verschiedene Strategien
    strategy = random.choice(['ifs', 'dash', 'mixed', 'tabs'])
    
    if strategy == 'ifs':
        return text.replace(' ', '${IFS}').replace('-', '${DASH}')
    elif strategy == 'dash':
        return text.replace('-', '${DASH}')
    elif strategy == 'mixed':
        return text.replace(' ', random.choice(['${IFS}', '\t', '  ']))
    else:  # tabs
        return text.replace(' ', '\t')


def obfuscate_text(text: str, apply_all: bool = False) -> str:
    """Erstelle Obfuscation-Varianten (kombiniert mehrere Techniken)."""
    if apply_all:
        # Wende alle Obfuscation-Techniken an
        text = obfuscate_case_variation(text)
        text = obfuscate_comment_injection(text)
        text = obfuscate_whitespace_variation(text)
    else:
        # Wende zufällig eine Technik an
        technique = random.choice([
            obfuscate_case_variation,
            obfuscate_comment_injection,
            obfuscate_whitespace_variation
        ])
        text = technique(text)
    
    return text


# ============================================================================
# PATTERN GENERATION
# ============================================================================

def generate_eval_patterns() -> List[Dict]:
    """Generiere eval()-Pattern-Varianten."""
    patterns = []
    
    # PHP eval()
    php_variants = [
        "eval($_GET['cmd'])",
        "eval($_POST['cmd'])",
        "eval($_REQUEST['cmd'])",
        "eval(${'cmd'})",
        "eval($cmd)",
        "eval(base64_decode($_GET['payload']))",
    ]
    
    # Python eval()
    python_variants = [
        "eval(input())",
        "eval(sys.argv[1])",
        "eval(user_input)",
        "exec(eval(code))",
        "__import__('os').system(eval(cmd))",
    ]
    
    # JavaScript eval()
    js_variants = [
        "eval(document.cookie)",
        "eval(window.location.search)",
        "eval(prompt())",
        "Function(eval(code))()",
        "setTimeout(eval, 100, code)",
    ]
    
    all_variants = php_variants + python_variants + js_variants
    
    for variant in all_variants:
        patterns.append({
            'text': variant,
            'label': 1,
            'source': 'eval_pattern',
            'augmentation': 'none'
        })
        
        # Obfuscation-Varianten
        patterns.append({
            'text': obfuscate_case_variation(variant),
            'label': 1,
            'source': 'eval_pattern',
            'augmentation': 'case_variation'
        })
        
        patterns.append({
            'text': obfuscate_comment_injection(variant),
            'label': 1,
            'source': 'eval_pattern',
            'augmentation': 'comment_injection'
        })
    
    return patterns


def generate_sql_destructive_patterns() -> List[Dict]:
    """Generiere SQL-Destructive-Command-Varianten."""
    patterns = []
    
    # DROP TABLE Varianten
    drop_variants = [
        "DROP TABLE users",
        "DROP TABLE IF EXISTS users",
        "DROP TABLE users CASCADE",
        "DROP TABLE users, logs, sessions",
        "DROP DATABASE production",
        "DROP SCHEMA public CASCADE",
    ]
    
    # TRUNCATE Varianten
    truncate_variants = [
        "TRUNCATE TABLE users",
        "TRUNCATE users",
        "TRUNCATE TABLE users CASCADE",
        "TRUNCATE users, logs",
    ]
    
    # DELETE Varianten (destructive)
    delete_variants = [
        "DELETE FROM users",
        "DELETE FROM users WHERE 1=1",
        "DELETE FROM users; DROP TABLE logs",
    ]
    
    # ALTER TABLE DROP
    alter_variants = [
        "ALTER TABLE users DROP COLUMN password",
        "ALTER TABLE users DROP CONSTRAINT pk_users",
    ]
    
    all_variants = drop_variants + truncate_variants + delete_variants + alter_variants
    
    for variant in all_variants:
        patterns.append({
            'text': variant,
            'label': 1,
            'source': 'sql_destructive',
            'augmentation': 'none'
        })
        
        # Case Variation
        patterns.append({
            'text': obfuscate_case_variation(variant),
            'label': 1,
            'source': 'sql_destructive',
            'augmentation': 'case_variation'
        })
        
        # Comment Injection
        patterns.append({
            'text': obfuscate_comment_injection(variant),
            'label': 1,
            'source': 'sql_destructive',
            'augmentation': 'comment_injection'
        })
    
    return patterns


def generate_context_wrapper_samples(base_samples: List[Dict], count: int = 300) -> List[Dict]:
    """Generiere Context-Benign-Wrapper Samples aus bestehenden malicious Samples."""
    augmented = []
    
    # Filtere nur malicious Samples
    malicious_samples = [s for s in base_samples if s.get('label') == 1]
    
    if not malicious_samples:
        logger.warning("No malicious samples found for context wrapping!")
        return []
    
    for _ in range(count):
        # Wähle zufälliges malicious Sample
        base = random.choice(malicious_samples)
        text = base['text']
        
        # Füge benignen Kontext hinzu
        wrapped_text = add_benign_context_wrapper(text)
        
        augmented.append({
            'text': wrapped_text,
            'label': 1,  # Immer noch malicious!
            'source': base.get('source', 'unknown'),
            'augmentation': 'context_benign_wrapper',
            'original_text': text
        })
    
    return augmented


def generate_obfuscation_samples(base_samples: List[Dict], count: int = 600) -> List[Dict]:
    """Generiere Obfuscation-Varianten aus bestehenden Samples."""
    augmented = []
    
    # Filtere nur malicious Samples
    malicious_samples = [s for s in base_samples if s.get('label') == 1]
    
    if not malicious_samples:
        logger.warning("No malicious samples found for obfuscation!")
        return []
    
    for _ in range(count):
        # Wähle zufälliges malicious Sample
        base = random.choice(malicious_samples)
        text = base['text']
        
        # Wende Obfuscation an
        obfuscated_text = obfuscate_text(text, apply_all=random.random() < 0.2)
        
        augmented.append({
            'text': obfuscated_text,
            'label': 1,  # Immer noch malicious!
            'source': base.get('source', 'unknown'),
            'augmentation': 'obfuscation',
            'original_text': text
        })
    
    return augmented


# ============================================================================
# MAIN GENERATION
# ============================================================================

def load_existing_training_data(data_path: str) -> List[Dict]:
    """Lade bestehende Trainingsdaten."""
    samples = []
    
    if not Path(data_path).exists():
        logger.warning(f"Training data file not found: {data_path}")
        return samples
    
    with open(data_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                samples.append(item)
            except json.JSONDecodeError:
                continue
    
    logger.info(f"Loaded {len(samples)} existing samples from {data_path}")
    return samples


def generate_augmented_data(
    existing_data_path: str,
    output_path: str,
    context_wrapper_count: int = 300,
    obfuscation_count: int = 600,
    eval_pattern_count: int = 150,
    sql_destructive_count: int = 100
):
    """Generiere erweiterte Trainingsdaten."""
    
    logger.info("=" * 80)
    logger.info("GENERATING AUGMENTED TRAINING DATA")
    logger.info("=" * 80)
    logger.info("")
    
    # Lade bestehende Daten
    existing_samples = load_existing_training_data(existing_data_path)
    
    all_samples = existing_samples.copy()
    
    # 1. Context-Benign-Wrapper (KRITISCH)
    logger.info(f"Generating {context_wrapper_count} context-benign-wrapper samples...")
    context_samples = generate_context_wrapper_samples(existing_samples, context_wrapper_count)
    all_samples.extend(context_samples)
    logger.info(f"✓ Generated {len(context_samples)} context-wrapper samples")
    
    # 2. Obfuscation-Varianten (HIGH)
    logger.info(f"Generating {obfuscation_count} obfuscation samples...")
    obfuscation_samples = generate_obfuscation_samples(existing_samples, obfuscation_count)
    all_samples.extend(obfuscation_samples)
    logger.info(f"✓ Generated {len(obfuscation_samples)} obfuscation samples")
    
    # 3. eval() Patterns (HIGH)
    logger.info(f"Generating {eval_pattern_count} eval() pattern samples...")
    eval_samples = generate_eval_patterns()
    # Erweitere auf gewünschte Anzahl
    while len(eval_samples) < eval_pattern_count:
        eval_samples.extend(generate_eval_patterns())
    eval_samples = eval_samples[:eval_pattern_count]
    all_samples.extend(eval_samples)
    logger.info(f"✓ Generated {len(eval_samples)} eval() pattern samples")
    
    # 4. SQL-Destructive Commands (MEDIUM)
    logger.info(f"Generating {sql_destructive_count} SQL-destructive samples...")
    sql_samples = generate_sql_destructive_patterns()
    # Erweitere auf gewünschte Anzahl
    while len(sql_samples) < sql_destructive_count:
        sql_samples.extend(generate_sql_destructive_patterns())
    sql_samples = sql_samples[:sql_destructive_count]
    all_samples.extend(sql_samples)
    logger.info(f"✓ Generated {len(sql_samples)} SQL-destructive samples")
    
    # Statistiken
    malicious_count = sum(1 for s in all_samples if s.get('label') == 1)
    benign_count = sum(1 for s in all_samples if s.get('label') == 0)
    
    logger.info("")
    logger.info("=" * 80)
    logger.info("GENERATION SUMMARY")
    logger.info("=" * 80)
    logger.info(f"Total samples: {len(all_samples)}")
    logger.info(f"  Malicious: {malicious_count}")
    logger.info(f"  Benign: {benign_count}")
    logger.info(f"  New samples: {len(all_samples) - len(existing_samples)}")
    logger.info("")
    
    # Speichere erweiterte Daten
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        for sample in all_samples:
            f.write(json.dumps(sample, ensure_ascii=False) + '\n')
    
    logger.info(f"✓ Augmented training data saved to: {output_path}")
    
    return all_samples


def main():
    parser = argparse.ArgumentParser(
        description="Generate augmented training data based on weakness analysis"
    )
    parser.add_argument(
        "--input",
        type=str,
        default="./data/train/quantum_cnn_training.jsonl",
        help="Path to existing training data JSONL"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="./data/train/quantum_cnn_training_augmented.jsonl",
        help="Output path for augmented training data"
    )
    parser.add_argument(
        "--context_wrapper",
        type=int,
        default=300,
        help="Number of context-benign-wrapper samples to generate"
    )
    parser.add_argument(
        "--obfuscation",
        type=int,
        default=600,
        help="Number of obfuscation samples to generate"
    )
    parser.add_argument(
        "--eval_patterns",
        type=int,
        default=150,
        help="Number of eval() pattern samples to generate"
    )
    parser.add_argument(
        "--sql_destructive",
        type=int,
        default=100,
        help="Number of SQL-destructive samples to generate"
    )
    
    args = parser.parse_args()
    
    generate_augmented_data(
        existing_data_path=args.input,
        output_path=args.output,
        context_wrapper_count=args.context_wrapper,
        obfuscation_count=args.obfuscation,
        eval_pattern_count=args.eval_patterns,
        sql_destructive_count=args.sql_destructive
    )


if __name__ == "__main__":
    main()
