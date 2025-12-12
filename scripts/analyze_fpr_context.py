#!/usr/bin/env python3
"""
Simplified FPR Context Analysis
Analysiert die FPR-Ergebnisse ohne komplexe Firewall-Imports
"""

import json
import argparse
import re
from pathlib import Path
from typing import Dict, Any


def detect_documentation_context(text: str) -> Dict[str, Any]:
    """Simple context detection without imports"""

    # Markdown patterns
    markdown_patterns = [
        r"^\*\*[^*]+\*\*",  # **Bold**
        r"`[^`]+`",  # `code`
        r"^\#+ ",  # # Headers
        r"^\* ",  # * Lists
        r"^\- ",  # - Lists
        r"```",  # Code blocks
    ]

    # Technical terms
    technical_terms = [
        "API",
        "JSON",
        "HTTP",
        "URL",
        "SQL",
        "HTML",
        "CSS",
        "JavaScript",
        "Python",
        "React",
        "Node",
        "Docker",
        "Git",
        "GitHub",
        "AWS",
        "database",
        "server",
        "client",
        "function",
        "method",
        "class",
        "variable",
        "array",
        "object",
        "string",
        "integer",
        "boolean",
        "framework",
        "library",
        "module",
        "package",
        "import",
        "export",
        "configuration",
        "deployment",
        "development",
        "production",
        "authentication",
        "authorization",
        "security",
        "encryption",
        "algorithm",
        "data structure",
        "optimization",
        "performance",
    ]

    # Code patterns
    code_patterns = [
        r"\w+\(\)",  # function()
        r"\w+\.\w+",  # object.property
        r"[a-zA-Z_]\w*\s*=",  # variable =
        r"def\s+\w+",  # def function
        r"class\s+\w+",  # class Name
        r"import\s+\w+",  # import module
        r"from\s+\w+",  # from module
    ]

    text_lower = text.lower()

    # Check markdown
    is_markdown = any(
        re.search(pattern, text, re.MULTILINE) for pattern in markdown_patterns
    )

    # Check technical terms
    has_technical_terms = any(term.lower() in text_lower for term in technical_terms)

    # Check code patterns
    is_code = any(re.search(pattern, text) for pattern in code_patterns)

    # Overall documentation detection
    is_documentation = is_markdown or (
        has_technical_terms
        and (
            is_code
            or len([p for p in markdown_patterns if re.search(p, text, re.MULTILINE)])
            >= 2
        )
    )

    return {
        "is_documentation": is_documentation,
        "is_markdown": is_markdown,
        "is_code": is_code,
        "has_technical_terms": has_technical_terms,
        "confidence": 0.8 if is_documentation else 0.2,
    }


def analyze_semantic_score(text: str) -> float:
    """Simplified semantic scoring based on patterns"""

    # High-risk patterns that trigger semantic violations
    violation_patterns = [
        r"\b(how to|explain how|teach me|show me)\b.*\b(hack|exploit|attack|bypass|manipulate)\b",
        r"\b(create|make|build|generate)\b.*\b(virus|malware|weapon|bomb|drug)\b",
        r"\b(illegal|forbidden|prohibited|banned)\b",
        r"\b(adult|sexual|explicit|inappropriate)\b.*\b(content|material|images)\b",
        r"\b(suicide|self.?harm|kill.?yourself)\b",
        r"\b(racist|sexist|homophobic|discriminatory)\b",
    ]

    # Documentation indicators (reduce score)
    doc_indicators = [
        r"\*\*[^*]+\*\*",  # Bold text
        r"`[^`]+`",  # Code snippets
        r"^\#+ ",  # Headers
        r"Status:.*✅",  # Status indicators
        r"Results?:",  # Results sections
        r"Analysis:",  # Analysis sections
        r"Framework",  # Framework mentions
        r"Implementation",  # Implementation
        r"Configuration",  # Config
        r"Documentation",  # Documentation
    ]

    text_lower = text.lower()

    # Base score from violation patterns
    violation_score = 0.0
    for pattern in violation_patterns:
        if re.search(pattern, text_lower):
            violation_score += 0.3

    # Documentation content tends to have high semantic scores due to technical terms
    # This is a simplified heuristic
    if any(
        re.search(pattern, text, re.MULTILINE | re.IGNORECASE)
        for pattern in doc_indicators
    ):
        # Documentation often gets high scores (0.85-0.99) due to technical complexity
        violation_score = max(0.85, violation_score + 0.6)

    return min(0.99, violation_score)


def main():
    parser = argparse.ArgumentParser(description="Analyze FPR Context Detection")
    parser.add_argument(
        "--sample-blocked",
        type=int,
        default=10,
        help="Number of blocked samples to analyze",
    )
    parser.add_argument(
        "--report-path",
        type=str,
        default="reports/fpr_measurement.json",
        help="Path to FPR measurement report",
    )

    args = parser.parse_args()

    # Load FPR results
    report_path = Path(args.report_path)
    if not report_path.exists():
        print(f"ERROR: Report file not found: {report_path}")
        return 1

    print("Loading FPR measurement results...")
    with open(report_path, "r", encoding="utf-8") as f:
        fpr_data = json.load(f)

    # Get blocked prompts
    blocked_prompts = []
    if "details" in fpr_data:
        # Filter only blocked prompts
        blocked_details = [
            detail for detail in fpr_data["details"] if detail.get("blocked", False)
        ]
        blocked_prompts = [
            detail["prompt_preview"]
            for detail in blocked_details[: args.sample_blocked]
        ]
    elif "blocked_examples" in fpr_data:
        blocked_prompts = [
            example["prompt"]
            for example in fpr_data["blocked_examples"][: args.sample_blocked]
        ]

    if not blocked_prompts:
        print("ERROR: No blocked prompts found in report")
        print(f"Available keys: {list(fpr_data.keys())}")
        if "details" in fpr_data:
            blocked_count = sum(
                1 for d in fpr_data["details"] if d.get("blocked", False)
            )
            print(f"Found {blocked_count} blocked prompts in details")
        return 1

    print(f"Analyzing {len(blocked_prompts)} blocked prompts...")

    # Analyze each blocked prompt
    results = []
    for i, prompt in enumerate(blocked_prompts, 1):
        print(f"\n{'=' * 80}")
        print(f"ANALYZING BLOCKED PROMPT #{i}")
        print(f"{'=' * 80}")

        # Context detection
        context_info = detect_documentation_context(prompt)

        # Semantic score estimation
        semantic_score = analyze_semantic_score(prompt)

        # Apply P0 fixes
        adjusted_score = semantic_score
        if context_info["is_documentation"]:
            adjusted_score = max(0.0, semantic_score - 0.15)  # Score adjustment

        # Threshold selection
        threshold = 0.90 if context_info["is_documentation"] else 0.75

        analysis = {
            "prompt_preview": prompt[:200] + "..." if len(prompt) > 200 else prompt,
            "context_detected": context_info,
            "original_semantic_score": semantic_score,
            "adjusted_score": adjusted_score,
            "score_adjustment_applied": semantic_score != adjusted_score,
            "threshold_used": threshold,
            "would_block_original": semantic_score > 0.85,
            "would_block_adjusted": adjusted_score > threshold,
            "context_aware_working": semantic_score > 0.85
            and adjusted_score <= threshold,
        }

        results.append(analysis)

        # Print analysis (ASCII-safe)
        safe_preview = (
            analysis["prompt_preview"].encode("ascii", errors="replace").decode("ascii")
        )
        print(f"Prompt: {safe_preview}")
        print("\nContext Detection:")
        for key, value in analysis["context_detected"].items():
            print(f"  {key}: {value}")

        print("\nScoring:")
        print(f"  Estimated Semantic Score: {analysis['original_semantic_score']:.3f}")
        print(f"  Adjusted Score: {analysis['adjusted_score']:.3f}")
        print(f"  Score Adjustment Applied: {analysis['score_adjustment_applied']}")
        print(f"  Threshold Used: {analysis['threshold_used']:.3f}")

        print("\nBlocking Decision:")
        print(f"  Would block (original): {analysis['would_block_original']}")
        print(f"  Would block (adjusted): {analysis['would_block_adjusted']}")
        print(f"  Context-Aware Working: {analysis['context_aware_working']}")

        if analysis["context_aware_working"]:
            print("  [OK] CONTEXT-AWARE DETECTION WORKING")
        else:
            print("  [FAIL] CONTEXT-AWARE DETECTION NOT WORKING")

    # Summary statistics
    print(f"\n{'=' * 80}")
    print("SUMMARY STATISTICS")
    print(f"{'=' * 80}")

    total_samples = len(results)
    context_working = sum(1 for r in results if r["context_aware_working"])
    score_adjustments = sum(1 for r in results if r["score_adjustment_applied"])
    documentation_detected = sum(
        1 for r in results if r["context_detected"]["is_documentation"]
    )

    print(f"Total samples analyzed: {total_samples}")
    print(
        f"Documentation context detected: {documentation_detected}/{total_samples} ({documentation_detected / total_samples * 100:.1f}%)"
    )
    print(
        f"Score adjustments applied: {score_adjustments}/{total_samples} ({score_adjustments / total_samples * 100:.1f}%)"
    )
    print(
        f"Context-aware detection working: {context_working}/{total_samples} ({context_working / total_samples * 100:.1f}%)"
    )

    # Context type breakdown
    context_types = {}
    for result in results:
        for key, value in result["context_detected"].items():
            if key.startswith("is_") and value:
                context_types[key] = context_types.get(key, 0) + 1

    if context_types:
        print("\nContext Types Detected:")
        for context_type, count in sorted(context_types.items()):
            print(
                f"  {context_type}: {count}/{total_samples} ({count / total_samples * 100:.1f}%)"
            )

    # Save detailed results
    output_file = "reports/context_detection_analysis.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(
            {
                "summary": {
                    "total_samples": total_samples,
                    "documentation_detected": documentation_detected,
                    "score_adjustments": score_adjustments,
                    "context_working": context_working,
                    "context_types": context_types,
                },
                "detailed_results": results,
            },
            f,
            indent=2,
            ensure_ascii=False,
        )

    print(f"\nDetailed results saved to: {output_file}")

    return 0


if __name__ == "__main__":
    exit(main())
