"""
Automatic Extraction Script
============================

Copies all Evidence/Safety modules from HAK_GAL to standalone package.
Adjusts import paths automatically.

Usage:
    python extract_all.py
"""

import shutil
from pathlib import Path

# Source and target paths
HAK_GAL_ROOT = Path(__file__).parent.parent.parent
SOURCE_BASE = HAK_GAL_ROOT / "src_hexagonal" / "services" / "honesty"
TARGET_BASE = Path(__file__).parent / "src" / "llm_firewall"

# Module mapping (source file → target directory)
MODULE_MAPPING = {
    # Evidence
    "evidence_validator.py": "evidence/validator.py",
    "evidence_pipeline.py": "evidence/pipeline.py",
    "ground_truth_scorer.py": "evidence/ground_truth_scorer.py",
    "source_verifier.py": "evidence/source_verifier.py",

    # Safety
    "safety_validator.py": "safety/validator.py",
    "text_preproc.py": "safety/text_preproc.py",

    # Trust
    "domain_trust_scorer.py": "trust/domain_scorer.py",
    "nli_consistency.py": "trust/nli_consistency.py",
    "content_hasher.py": "trust/content_hasher.py",

    # Fusion
    "dempster_shafer_fusion.py": "fusion/dempster_shafer.py",
    "adaptive_threshold.py": "fusion/adaptive_threshold.py",
    "robbins_monro_controller.py": "fusion/robbins_monro.py",

    # Monitoring
    "snapshot_canaries.py": "monitoring/canaries.py",
    "shingle_hasher.py": "monitoring/shingle_hasher.py",
    "influence_budget.py": "monitoring/influence_budget.py",
    "influence_budget_repo.py": "monitoring/influence_budget_repo.py",
    "explain_why.py": "monitoring/explain_why.py",

    # Engines
    "decision_engine_complete.py": "engines/decision_engine.py",
    "explanation_formatter.py": "engines/explanation_formatter.py",
    "feedback_learner.py": "engines/feedback_learner.py",
    "statistics_tracker.py": "engines/statistics_tracker.py",

    # Utils
    "types.py": "utils/types.py",
}


def adjust_imports(content: str) -> str:
    """
    Adjust import paths from HAK_GAL to standalone.

    Changes:
    - from .types → from llm_firewall.utils.types
    - from .evidence_validator → from llm_firewall.evidence.validator
    - etc.
    """
    # Replace relative imports with absolute
    replacements = {
        "from .types import": "from llm_firewall.utils.types import",
        "from .evidence_validator import": "from llm_firewall.evidence.validator import",
        "from .ground_truth_scorer import": "from llm_firewall.evidence.ground_truth_scorer import",
        "from .source_verifier import": "from llm_firewall.evidence.source_verifier import",
        "from .domain_trust_scorer import": "from llm_firewall.trust.domain_scorer import",
        "from .nli_consistency import": "from llm_firewall.trust.nli_consistency import",
        "from .content_hasher import": "from llm_firewall.trust.content_hasher import",
        "from .dempster_shafer_fusion import": "from llm_firewall.fusion.dempster_shafer import",
        "from .adaptive_threshold import": "from llm_firewall.fusion.adaptive_threshold import",
        "from .robbins_monro_controller import": "from llm_firewall.fusion.robbins_monro import",
        "from .text_preproc import": "from llm_firewall.safety.text_preproc import",
        "from .decision_engine": "from llm_firewall.engines.decision_engine",
        "from .explanation_formatter import": "from llm_firewall.engines.explanation_formatter import",
        "from .feedback_learner import": "from llm_firewall.engines.feedback_learner import",
    }

    for old, new in replacements.items():
        content = content.replace(old, new)

    return content


def copy_module(source_name: str, target_path: str):
    """Copy and adjust a single module."""
    source_file = SOURCE_BASE / source_name
    target_file = TARGET_BASE / target_path

    if not source_file.exists():
        print(f"  ⚠️  Source not found: {source_name}")
        return

    # Read source
    with open(source_file, 'r', encoding='utf-8') as f:
        content = f.read()

    # Adjust imports
    content = adjust_imports(content)

    # Write target
    target_file.parent.mkdir(parents=True, exist_ok=True)
    with open(target_file, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"  ✓ {source_name} → {target_path}")


def create_init_files():
    """Create __init__.py files for all packages."""
    init_files = [
        "src/llm_firewall/__init__.py",
        "src/llm_firewall/evidence/__init__.py",
        "src/llm_firewall/safety/__init__.py",
        "src/llm_firewall/trust/__init__.py",
        "src/llm_firewall/fusion/__init__.py",
        "src/llm_firewall/monitoring/__init__.py",
        "src/llm_firewall/engines/__init__.py",
        "src/llm_firewall/utils/__init__.py",
        "src/llm_firewall/db/__init__.py",
        "tests/__init__.py",
    ]

    for init_path in init_files:
        init_file = Path(__file__).parent / init_path
        init_file.parent.mkdir(parents=True, exist_ok=True)

        if not init_file.exists():
            init_file.write_text('"""Package initialization."""\n')

    print("  ✓ All __init__.py files created")


def main():
    """Main extraction process."""
    print("=== LLM Security Firewall Extraction ===\n")

    print("Step 1: Creating __init__.py files...")
    create_init_files()

    print("\nStep 2: Copying modules...")
    for source_name, target_path in MODULE_MAPPING.items():
        copy_module(source_name, target_path)

    print("\nStep 3: Copying configs...")
    config_files = [
        "safety_blacklist.yaml",
        "threat_detection_config.yaml",
        "evidence_pipeline.yaml",
        "honesty_defaults.yaml",
    ]

    config_source = HAK_GAL_ROOT / "config"
    config_target = Path(__file__).parent / "config"

    for config_file in config_files:
        source = config_source / config_file
        target = config_target / config_file

        if source.exists():
            shutil.copy2(source, target)
            print(f"  ✓ {config_file}")

    print("\nStep 4: Copying migrations...")
    migration_mapping = {
        "018_memory_poisoning_defense.sql": "001_evidence_tables.sql",
        "019_evidence_pipeline_caches.sql": "002_caches.sql",
        "019_add_stored_procedures.sql": "003_procedures.sql",
        "020_influence_budget.sql": "004_influence_budget.sql",
    }

    migration_source = HAK_GAL_ROOT / "migrations"
    migration_target = Path(__file__).parent / "migrations" / "postgres"

    for source_name, target_name in migration_mapping.items():
        source = migration_source / source_name
        target = migration_target / target_name

        if source.exists():
            shutil.copy2(source, target)
            print(f"  ✓ {source_name} → {target_name}")

    print("\nStep 5: Copying tools...")
    tool_files = [
        "kill_switch.py",
        "generate_coverage_report.py",
    ]

    tools_source = HAK_GAL_ROOT / "tools"
    tools_target = Path(__file__).parent / "tools"

    for tool_file in tool_files:
        source = tools_source / tool_file
        target = tools_target / tool_file

        if source.exists():
            shutil.copy2(source, target)
            print(f"  ✓ {tool_file}")

    print("\nStep 6: Copying monitoring...")
    monitoring_files = [
        "alert_rules.yaml",
        "sql_health_checks.sql",
        "defense_coverage_matrix.csv",
    ]

    monitoring_source = HAK_GAL_ROOT / "monitoring"
    monitoring_target = Path(__file__).parent / "monitoring"

    for mon_file in monitoring_files:
        source = monitoring_source / mon_file
        target = monitoring_target / mon_file

        if source.exists():
            shutil.copy2(source, target)
            print(f"  ✓ {mon_file}")

    print("\n" + "="*50)
    print("✅ EXTRACTION COMPLETE!")
    print("="*50)
    print("\nNext steps:")
    print("1. Copy test files (adjust imports)")
    print("2. Create CLI tool (llm-firewall command)")
    print("3. Write examples")
    print("4. Write docs")
    print("5. Test: python -m pytest tests/")
    print("\nThen:")
    print("- cd standalone_packages/llm-security-firewall")
    print("- git init")
    print("- git add .")
    print("- git commit -m 'Initial commit: LLM Security Firewall v1.0.0'")
    print("- Create GitHub repo")
    print("- git push")


if __name__ == "__main__":
    main()








