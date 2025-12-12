"""
V3 Training Preparation - Automatische Vorbereitung

Führt V2 FP Analyse aus und generiert automatisch Training-Samples für V3
basierend auf den identifizierten Critical Categories.

Usage:
    python -m detectors.orchestrator.infrastructure.training.prepare_v3_training \
        --validation-set data/adversarial_training/code_intent_true_validation.jsonl \
        --v1-model models/code_intent_adversarial_v1/best_model.pt \
        --v2-model models/code_intent_adversarial_v2/best_model.pt \
        --output-dir data/adversarial_training/v3_preparation
"""

import sys
import json
import logging
import argparse
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Tuple
from datetime import datetime
import random

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(project_root))

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def generate_benign_samples_by_category(category: str, subcategory: str, count: int) -> List[Dict[str, Any]]:
    """
    Generiere benign Training-Samples basierend auf Kategorie.
    
    Diese Samples werden verwendet, um V2's False Positives zu korrigieren.
    """
    samples = []
    
    if category == "technical_question":
        if subcategory == "sql_related":
            sql_questions = [
                "What is the purpose of the SELECT statement in SQL?",
                "How do I use SELECT to query a database?",
                "Explain the difference between SELECT and SELECT DISTINCT",
                "What does the WHERE clause do in SQL?",
                "How do I filter results with WHERE?",
                "What is the purpose of JOIN in SQL?",
                "Explain INNER JOIN vs LEFT JOIN",
                "How do I use GROUP BY in SQL?",
                "What is the difference between HAVING and WHERE?",
                "How do I sort results with ORDER BY?",
                "What is a database index and why is it useful?",
                "Explain the concept of database normalization",
                "How do I create a table in SQL?",
                "What is the purpose of PRIMARY KEY?",
                "Explain FOREIGN KEY constraints",
            ]
            samples = [{"text": q, "label": 0, "category": "technical_question_sql"} for q in sql_questions[:count]]
        
        elif subcategory == "programming_concept":
            programming_questions = [
                "What is a for loop in Python?",
                "How do I write a for loop in JavaScript?",
                "Explain the concept of functions in programming",
                "What is the difference between a function and a method?",
                "How do I handle errors in Python?",
                "What is exception handling?",
                "Explain try-except blocks",
                "How do I create a class in Python?",
                "What is object-oriented programming?",
                "Explain inheritance in programming",
                "How do I use git to create a new branch?",
                "What is the difference between git merge and rebase?",
                "How do I commit changes in git?",
                "Explain the concept of version control",
                "What is a pull request?",
            ]
            samples = [{"text": q, "label": 0, "category": "technical_question_programming"} for q in programming_questions[:count]]
        
        else:  # general_tech
            general_tech_questions = [
                "What is Docker and how does it work?",
                "Explain containerization",
                "What are the benefits of using Docker?",
                "How does REST API work?",
                "What is the difference between REST and SOAP?",
                "Explain HTTP vs HTTPS",
                "What is caching and how does it improve performance?",
                "How do environment variables work?",
                "What is the purpose of environment variables?",
                "Explain the concept of dependency injection",
                "What is the difference between synchronous and asynchronous code?",
                "How does authentication work?",
                "What is the purpose of API keys?",
                "Explain microservices architecture",
                "What are best practices for API design?",
            ]
            samples = [{"text": q, "label": 0, "category": "technical_question_general"} for q in general_tech_questions[:count]]
    
    elif category == "code_example_request":
        code_example_requests = [
            "Show me how to write a for loop in JavaScript",
            "Can you show me an example of a Python function?",
            "How do I write a simple SQL query?",
            "Show me an example of error handling in Python",
            "Can you demonstrate how to use git?",
            "Show me how to create a REST API endpoint",
            "What is an example of object-oriented programming?",
            "Show me how to use Docker",
            "Can you show me a code example?",
            "How do I write a basic Python script?",
            "Show me an example of async/await in JavaScript",
            "Can you demonstrate dependency injection?",
            "Show me how to use environment variables",
            "What is an example of caching?",
            "Show me a code snippet for authentication",
        ]
        samples = [{"text": q, "label": 0, "category": "code_example_request"} for q in code_example_requests[:count]]
    
    elif category == "security_education":
        security_questions = [
            "What is a firewall and how does it work?",
            "Explain the concept of encryption",
            "What is the difference between authentication and authorization?",
            "How do I secure my API?",
            "What are common security vulnerabilities?",
            "Explain SQL injection attacks",
            "What is XSS and how do I prevent it?",
            "How does HTTPS provide security?",
            "What is a security vulnerability?",
            "Explain the concept of penetration testing",
            "What are security best practices?",
            "How do I protect against malware?",
            "What is the purpose of a security audit?",
            "Explain the concept of threat modeling",
            "What is defense in depth?",
        ]
        samples = [{"text": q, "label": 0, "category": "security_education"} for q in security_questions[:count]]
    
    elif category == "system_question":
        if subcategory == "infrastructure":
            infrastructure_questions = [
                "What is Kubernetes and how does it work?",
                "Explain container orchestration",
                "What are the benefits of using Kubernetes?",
                "How does Docker differ from Kubernetes?",
                "What is a microservice architecture?",
                "Explain DevOps practices",
                "What is CI/CD?",
                "How do I deploy an application?",
                "What is infrastructure as code?",
                "Explain the concept of scaling",
            ]
            samples = [{"text": q, "label": 0, "category": "system_question_infrastructure"} for q in infrastructure_questions[:count]]
        
        else:  # api
            api_questions = [
                "What is a REST API?",
                "How do I design a REST API?",
                "What are REST API best practices?",
                "Explain HTTP methods (GET, POST, PUT, DELETE)",
                "What is the difference between REST and GraphQL?",
                "How do I authenticate API requests?",
                "What is API versioning?",
                "Explain API rate limiting",
                "What is an API endpoint?",
                "How do I document an API?",
            ]
            samples = [{"text": q, "label": 0, "category": "system_question_api"} for q in api_questions[:count]]
    
    elif category == "best_practice_question":
        best_practice_questions = [
            "What are best practices for Python programming?",
            "What are REST API best practices?",
            "Tell me about software development best practices",
            "What are security best practices?",
            "What are database design best practices?",
            "What are code review best practices?",
            "What are testing best practices?",
            "What are deployment best practices?",
            "What are documentation best practices?",
            "What are version control best practices?",
        ]
        samples = [{"text": q, "label": 0, "category": "best_practice_question"} for q in best_practice_questions[:count]]
    
    elif category == "comparison_question":
        comparison_questions = [
            "What is the difference between HTTP and HTTPS?",
            "What is the difference between synchronous and asynchronous code?",
            "What is the difference between SQL and NoSQL?",
            "What is the difference between Docker and Kubernetes?",
            "What is the difference between REST and GraphQL?",
            "What is the difference between authentication and authorization?",
            "What is the difference between git merge and rebase?",
            "What is the difference between list and tuple in Python?",
            "What is the difference between class and instance?",
            "What is the difference between function and method?",
        ]
        samples = [{"text": q, "label": 0, "category": "comparison_question"} for q in comparison_questions[:count]]
    
    # Fallback: Generische technische Fragen
    if not samples:
        generic_questions = [
            "Can you help me with programming?",
            "How do I learn programming?",
            "What is programming?",
            "Explain software development",
            "What is computer science?",
        ]
        samples = [{"text": q, "label": 0, "category": "generic"} for q in generic_questions[:count]]
    
    return samples


def load_existing_training_data() -> Tuple[List[Dict], List[Dict]]:
    """Lade bestehende Training-Daten (malicious und benign)."""
    malicious_samples = []
    benign_samples = []
    
    # Lade V1/V2 Training-Daten
    train_paths = [
        "data/adversarial_training/code_intent_train_adversarial.jsonl",
        "data/adversarial_training/code_intent_train_adversarial_v2.jsonl",
    ]
    
    for path in train_paths:
        full_path = project_root / path
        if full_path.exists():
            with open(full_path, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        record = json.loads(line)
                        if record.get('label') == 1:
                            malicious_samples.append(record)
                        else:
                            benign_samples.append(record)
    
    return malicious_samples, benign_samples


def create_v3_dataset(
    fp_analysis: Dict[str, Any],
    existing_malicious: List[Dict],
    existing_benign: List[Dict],
    output_dir: Path
) -> Dict[str, Any]:
    """
    Erstelle ausgewogenes V3 Dataset basierend auf FP-Analyse.
    
    Strategie:
    - 50% Malicious: Bestehende adversarial samples
    - 50% Benign: 
      - 30% Original benign samples
      - 20% V2 False Positives (als negative Beispiele)
      - 50% Neue benign Samples basierend auf Critical Categories
    """
    logger.info("\n" + "="*80)
    logger.info("CREATING V3 DATASET")
    logger.info("="*80)
    
    # 1. Sammle V2 False Positives
    v2_fps = fp_analysis.get('all_categorized_fps', [])
    v2_fp_samples = [
        {
            "text": fp['text'],
            "label": 0,  # Benign!
            "category": f"v2_fp_{fp['category']}",
            "source": "v2_false_positive",
            "original_confidence": fp['malicious_probability']
        }
        for fp in v2_fps if fp['is_false_positive']
    ]
    
    logger.info(f"V2 False Positives: {len(v2_fp_samples)}")
    
    # 2. Generiere neue benign Samples basierend auf Critical Categories
    recommendations = fp_analysis.get('v3_training_recommendations', {})
    critical_categories = recommendations.get('critical_categories', [])
    training_samples_needed = recommendations.get('training_samples_needed', {})
    
    new_benign_samples = []
    for cat_info in critical_categories:
        category = cat_info['category']
        count = cat_info['count']
        # Generiere 2-3x mehr Samples als FPs in dieser Kategorie
        samples_to_generate = max(20, count * 2)
        
        # Finde Subcategory aus category_stats
        category_stats = fp_analysis.get('category_statistics', {})
        subcategory = "general"
        if category in category_stats:
            # Versuche Subcategory aus Beispielen zu extrahieren
            examples = category_stats[category].get('examples', [])
            if examples:
                # Verwende erste Beispiel-Kategorie als Hinweis
                pass  # Wir verwenden die category direkt
        
        generated = generate_benign_samples_by_category(category, subcategory, samples_to_generate)
        new_benign_samples.extend(generated)
        logger.info(f"Generated {len(generated)} samples for category '{category}'")
    
    logger.info(f"New benign samples generated: {len(new_benign_samples)}")
    
    # 3. Kombiniere alle benign Samples
    # Strategie: 30% original, 20% V2 FPs, 50% neue
    total_benign_needed = len(existing_malicious)  # 50/50 Balance
    
    original_benign_count = int(total_benign_needed * 0.3)
    v2_fp_count = int(total_benign_needed * 0.2)
    new_benign_count = total_benign_needed - original_benign_count - v2_fp_count
    
    # Sample aus bestehenden benign
    random.shuffle(existing_benign)
    selected_original_benign = existing_benign[:min(original_benign_count, len(existing_benign))]
    
    # Sample aus V2 FPs
    random.shuffle(v2_fp_samples)
    selected_v2_fps = v2_fp_samples[:min(v2_fp_count, len(v2_fp_samples))]
    
    # Sample aus neuen benign
    random.shuffle(new_benign_samples)
    selected_new_benign = new_benign_samples[:min(new_benign_count, len(new_benign_samples))]
    
    # Kombiniere
    all_benign = selected_original_benign + selected_v2_fps + selected_new_benign
    
    logger.info(f"\nBenign Sample Distribution:")
    logger.info(f"  Original: {len(selected_original_benign)}")
    logger.info(f"  V2 FPs: {len(selected_v2_fps)}")
    logger.info(f"  New (generated): {len(selected_new_benign)}")
    logger.info(f"  Total benign: {len(all_benign)}")
    
    # 4. Erstelle finales Dataset
    # 50/50 Balance
    final_malicious = existing_malicious[:len(all_benign)]
    final_benign = all_benign
    
    # Shuffle
    random.shuffle(final_malicious)
    random.shuffle(final_benign)
    
    # Split: 80% train, 20% val
    train_malicious = final_malicious[:int(len(final_malicious) * 0.8)]
    val_malicious = final_malicious[int(len(final_malicious) * 0.8):]
    
    train_benign = final_benign[:int(len(final_benign) * 0.8)]
    val_benign = final_benign[int(len(final_benign) * 0.8):]
    
    # Kombiniere train und val
    train_samples = train_malicious + train_benign
    val_samples = val_malicious + val_benign
    
    random.shuffle(train_samples)
    random.shuffle(val_samples)
    
    logger.info(f"\nFinal Dataset:")
    logger.info(f"  Train: {len(train_samples)} ({sum(1 for s in train_samples if s['label']==1)} malicious, {sum(1 for s in train_samples if s['label']==0)} benign)")
    logger.info(f"  Val: {len(val_samples)} ({sum(1 for s in val_samples if s['label']==1)} malicious, {sum(1 for s in val_samples if s['label']==0)} benign)")
    
    # 5. Speichere Datasets
    output_dir.mkdir(parents=True, exist_ok=True)
    
    train_path = output_dir / "code_intent_train_v3.jsonl"
    val_path = output_dir / "code_intent_val_v3.jsonl"
    
    with open(train_path, 'w', encoding='utf-8') as f:
        for sample in train_samples:
            f.write(json.dumps(sample, ensure_ascii=False) + '\n')
    
    with open(val_path, 'w', encoding='utf-8') as f:
        for sample in val_samples:
            f.write(json.dumps(sample, ensure_ascii=False) + '\n')
    
    logger.info(f"\n💾 Datasets saved:")
    logger.info(f"  Train: {train_path}")
    logger.info(f"  Val: {val_path}")
    
    return {
        'train_samples': len(train_samples),
        'val_samples': len(val_samples),
        'train_malicious': sum(1 for s in train_samples if s['label']==1),
        'train_benign': sum(1 for s in train_samples if s['label']==0),
        'val_malicious': sum(1 for s in val_samples if s['label']==1),
        'val_benign': sum(1 for s in val_samples if s['label']==0),
        'train_path': str(train_path),
        'val_path': str(val_path),
    }


def main():
    parser = argparse.ArgumentParser(description="Prepare V3 Training Dataset")
    parser.add_argument(
        "--validation-set",
        type=str,
        required=True,
        help="Path to true validation set JSONL"
    )
    parser.add_argument(
        "--v1-model",
        type=str,
        required=True,
        help="Path to V1 model checkpoint"
    )
    parser.add_argument(
        "--v2-model",
        type=str,
        required=True,
        help="Path to V2 model checkpoint"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="data/adversarial_training/v3_preparation",
        help="Output directory for V3 preparation"
    )
    parser.add_argument(
        "--skip-analysis",
        action="store_true",
        help="Skip FP analysis if already done (use existing analysis file)"
    )
    parser.add_argument(
        "--analysis-file",
        type=str,
        help="Path to existing FP analysis file (if --skip-analysis)"
    )
    
    args = parser.parse_args()
    
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 1. Führe V2 FP Analyse aus (oder lade bestehende)
    if args.skip_analysis and args.analysis_file:
        logger.info(f"Loading existing analysis from: {args.analysis_file}")
        with open(args.analysis_file, 'r', encoding='utf-8') as f:
            fp_analysis = json.load(f)
    else:
        logger.info("="*80)
        logger.info("STEP 1: RUNNING V2 FALSE POSITIVE ANALYSIS")
        logger.info("="*80)
        
        analysis_output = output_dir / "v2_false_positives_analysis.json"
        
        # Führe Analyse-Skript aus
        cmd = [
            sys.executable,
            "-m", "detectors.orchestrator.infrastructure.training.analyze_v2_false_positives",
            "--validation-set", args.validation_set,
            "--v1-model", args.v1_model,
            "--v2-model", args.v2_model,
            "--output", str(analysis_output),
        ]
        
        logger.info(f"Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            logger.error(f"FP Analysis failed: {result.stderr}")
            sys.exit(1)
        
        logger.info("FP Analysis completed successfully")
        
        # Lade Analyse-Ergebnisse
        with open(analysis_output, 'r', encoding='utf-8') as f:
            fp_analysis = json.load(f)
    
    # 2. Lade bestehende Training-Daten
    logger.info("\n" + "="*80)
    logger.info("STEP 2: LOADING EXISTING TRAINING DATA")
    logger.info("="*80)
    
    existing_malicious, existing_benign = load_existing_training_data()
    logger.info(f"Existing malicious samples: {len(existing_malicious)}")
    logger.info(f"Existing benign samples: {len(existing_benign)}")
    
    # 3. Erstelle V3 Dataset
    logger.info("\n" + "="*80)
    logger.info("STEP 3: CREATING V3 DATASET")
    logger.info("="*80)
    
    dataset_info = create_v3_dataset(
        fp_analysis,
        existing_malicious,
        existing_benign,
        output_dir
    )
    
    # 4. Speichere Zusammenfassung
    summary = {
        'timestamp': datetime.now().isoformat(),
        'fp_analysis_summary': fp_analysis.get('summary', {}),
        'dataset_info': dataset_info,
        'recommendations': fp_analysis.get('v3_training_recommendations', {}),
    }
    
    summary_path = output_dir / "v3_preparation_summary.json"
    with open(summary_path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    
    logger.info("\n" + "="*80)
    logger.info("✅ V3 PREPARATION COMPLETE")
    logger.info("="*80)
    logger.info(f"\n📊 Summary:")
    logger.info(f"  Train samples: {dataset_info['train_samples']}")
    logger.info(f"  Val samples: {dataset_info['val_samples']}")
    logger.info(f"  Train balance: {dataset_info['train_malicious']} malicious, {dataset_info['train_benign']} benign")
    logger.info(f"  Val balance: {dataset_info['val_malicious']} malicious, {dataset_info['val_benign']} benign")
    logger.info(f"\n📁 Files created:")
    logger.info(f"  Train dataset: {dataset_info['train_path']}")
    logger.info(f"  Val dataset: {dataset_info['val_path']}")
    logger.info(f"  Summary: {summary_path}")
    logger.info("\n🎯 Next step: Train V3 model with these datasets!")
    logger.info("="*80)


if __name__ == "__main__":
    main()

