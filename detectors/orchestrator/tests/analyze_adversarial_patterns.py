"""
Adversarial Pattern Analyzer

Analysiert Test-Ergebnisse und extrahiert häufige Muster aus erfolgreichen Bypasses.
Generiert Empfehlungen für neue Patterns im AdversarialInputDetector.

Usage:
    python -m detectors.orchestrator.tests.analyze_adversarial_patterns --results test_results/adversarial/baseline_*.json
"""

import argparse
import json
import re
import logging
from pathlib import Path
from typing import Dict, List, Any, Tuple
from collections import Counter, defaultdict
import unicodedata

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AdversarialPatternAnalyzer:
    """Analyzes successful bypasses to extract adversarial patterns."""
    
    def __init__(self):
        """Initialize analyzer."""
        self.bypass_samples = []
        self.pattern_counter = Counter()
        self.category_analysis = defaultdict(list)
        
    def load_results(self, results_file: Path) -> Dict[str, Any]:
        """Load test results from JSON file."""
        with open(results_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def extract_bypasses(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract all successful bypasses from test results."""
        bypasses = []
        
        for test_result in results.get("test_results", []):
            if test_result.get("bypass", False) and test_result.get("label") == 1:
                bypasses.append({
                    "sample": test_result.get("sample", ""),
                    "risk_score": test_result.get("risk_score", 0.0),
                    "blocked": test_result.get("blocked", False),
                })
        
        logger.info(f"Extracted {len(bypasses)} successful bypasses")
        return bypasses
    
    def analyze_character_manipulations(self, text: str) -> Dict[str, Any]:
        """Analyze character-level manipulations."""
        patterns = {}
        
        # Zero-width characters
        zw_chars = ['\u200b', '\u200c', '\u200d', '\ufeff']
        found_zw = [c for c in zw_chars if c in text]
        if found_zw:
            patterns['zero_width_characters'] = found_zw
        
        # Control characters
        control_chars = [c for c in text if unicodedata.category(c).startswith('C')]
        if control_chars:
            patterns['control_characters'] = list(set(control_chars[:10]))
        
        # Unicode mixing
        ascii_count = sum(1 for c in text if ord(c) < 128)
        unicode_ratio = (len(text) - ascii_count) / len(text) if text else 0
        if unicode_ratio > 0.2:
            patterns['high_unicode_ratio'] = unicode_ratio
        
        # Homoglyphs (Cyrillic, Greek, etc.)
        cyrillic = re.search(r'[а-яА-Я]', text)
        greek = re.search(r'[Α-Ωα-ω]', text)
        fullwidth = re.search(r'[０-９Ａ-Ｚａ-ｚ]', text)
        if cyrillic:
            patterns['cyrillic_homoglyphs'] = True
        if greek:
            patterns['greek_homoglyphs'] = True
        if fullwidth:
            patterns['fullwidth_characters'] = True
        
        # Excessive whitespace
        if re.search(r'\s{3,}', text):
            max_ws = max(len(m.group()) for m in re.finditer(r'\s+', text))
            patterns['excessive_whitespace'] = max_ws
        
        # Character repetition
        if re.search(r'(.)\1{4,}', text):  # Same char 5+ times
            patterns['character_repetition'] = True
        
        return patterns
    
    def analyze_encoding_patterns(self, text: str) -> Dict[str, Any]:
        """Analyze encoding obfuscation patterns."""
        patterns = {}
        
        # URL encoding
        url_encoded = len(re.findall(r'%[0-9A-Fa-f]{2}', text))
        if url_encoded > 0:
            patterns['url_encoding'] = url_encoded
        
        # Hex encoding
        hex_encoded = len(re.findall(r'\\x[0-9A-Fa-f]{2}', text))
        if hex_encoded > 0:
            patterns['hex_encoding'] = hex_encoded
        
        # Unicode escapes
        unicode_escaped = len(re.findall(r'\\u[0-9A-Fa-f]{4}', text))
        if unicode_escaped > 0:
            patterns['unicode_escape'] = unicode_escaped
        
        # Base64-like
        base64_match = re.search(r'[A-Za-z0-9+/=]{20,}', text)
        if base64_match:
            patterns['base64_like'] = len(base64_match.group())
        
        # HTML entities
        html_entities = len(re.findall(r'&#?\w+;', text))
        if html_entities > 0:
            patterns['html_entities'] = html_entities
        
        return patterns
    
    def analyze_semantic_patterns(self, text: str) -> Dict[str, Any]:
        """Analyze semantic manipulation patterns."""
        patterns = {}
        
        # Case alternation
        if re.search(r'[a-z][A-Z][a-z]', text):
            patterns['case_alternation'] = True
        
        # Fragmented words (short words separated by spaces)
        fragmented = re.findall(r'\b\w{1,2}\s+\w{1,2}\s+\w{1,2}\b', text)
        if fragmented:
            patterns['fragmented_words'] = len(fragmented)
        
        # Special character insertion
        special_char_ratio = sum(1 for c in text if not c.isalnum() and not c.isspace()) / len(text) if text else 0
        if special_char_ratio > 0.3:
            patterns['high_special_char_ratio'] = special_char_ratio
        
        # Word substitution (common SQL injection patterns)
        sql_keywords = ['SELECT', 'DROP', 'DELETE', 'INSERT', 'UPDATE', 'UNION', 'OR', 'AND']
        found_sql = [kw for kw in sql_keywords if kw.upper() in text.upper()]
        if found_sql:
            patterns['sql_keywords'] = found_sql
        
        return patterns
    
    def analyze_structure(self, text: str) -> Dict[str, Any]:
        """Analyze structural patterns."""
        patterns = {}
        
        # Length analysis
        patterns['length'] = len(text)
        if len(text) > 10000:
            patterns['very_long_input'] = True
        
        # Entropy (simplified)
        char_freq = Counter(text)
        import math
        entropy = -sum((count/len(text)) * math.log2(count/len(text)) 
                      for count in char_freq.values() if count > 0)
        patterns['entropy'] = round(entropy, 2)
        if entropy > 4.5:
            patterns['high_entropy'] = True
        
        return patterns
    
    def analyze_sample(self, sample: str) -> Dict[str, Any]:
        """Perform complete analysis on a single sample."""
        analysis = {
            "original": sample[:200],  # Truncate for storage
            "length": len(sample),
            "character_manipulations": self.analyze_character_manipulations(sample),
            "encoding_patterns": self.analyze_encoding_patterns(sample),
            "semantic_patterns": self.analyze_semantic_patterns(sample),
            "structure": self.analyze_structure(sample),
        }
        
        # Extract all pattern types
        all_patterns = []
        for category in ['character_manipulations', 'encoding_patterns', 'semantic_patterns']:
            patterns = analysis[category]
            all_patterns.extend(patterns.keys())
            self.category_analysis[category].extend(patterns.keys())
        
        analysis['detected_patterns'] = all_patterns
        
        return analysis
    
    def analyze_all_bypasses(self, results_files: List[Path]) -> Dict[str, Any]:
        """Analyze all bypass samples from multiple result files."""
        all_bypasses = []
        
        for results_file in results_files:
            logger.info(f"Loading results from {results_file}")
            results = self.load_results(results_file)
            bypasses = self.extract_bypasses(results)
            all_bypasses.extend(bypasses)
        
        logger.info(f"Analyzing {len(all_bypasses)} total bypasses")
        
        # Analyze each bypass
        analyzed_samples = []
        for bypass in all_bypasses:
            analysis = self.analyze_sample(bypass['sample'])
            analysis['risk_score'] = bypass['risk_score']
            analyzed_samples.append(analysis)
            
            # Count patterns
            for pattern in analysis['detected_patterns']:
                self.pattern_counter[pattern] += 1
        
        # Generate statistics
        statistics = {
            "total_bypasses": len(all_bypasses),
            "pattern_frequency": dict(self.pattern_counter.most_common(20)),
            "category_distribution": {
                cat: Counter(patterns).most_common(10)
                for cat, patterns in self.category_analysis.items()
            },
        }
        
        return {
            "statistics": statistics,
            "analyzed_samples": analyzed_samples,
            "pattern_recommendations": self._generate_recommendations(statistics)
        }
    
    def _generate_recommendations(self, statistics: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate recommendations for new patterns based on analysis."""
        recommendations = []
        
        # Get top patterns that appear in >20% of bypasses
        total = statistics['total_bypasses']
        threshold = max(5, total * 0.2)  # At least 20% or 5 samples
        
        top_patterns = [
            (pattern, count) 
            for pattern, count in statistics['pattern_frequency'].items()
            if count >= threshold
        ]
        
        # Check which patterns are already in AdversarialInputDetector
        existing_patterns = {
            'zero_width_characters', 'control_characters', 'url_encoding',
            'hex_encoding', 'unicode_escape', 'base64_like', 'case_alternation',
            'excessive_whitespace', 'fragmented_words', 'high_unicode_ratio'
        }
        
        for pattern, frequency in top_patterns:
            if pattern not in existing_patterns:
                priority = "HIGH" if frequency >= total * 0.4 else "MEDIUM"
                
                recommendation = {
                    "pattern": pattern,
                    "frequency": frequency,
                    "percentage": (frequency / total) * 100,
                    "priority": priority,
                    "suggested_regex": self._suggest_regex(pattern),
                    "suggested_weight": self._suggest_weight(frequency, total)
                }
                recommendations.append(recommendation)
        
        # Sort by frequency
        recommendations.sort(key=lambda x: x['frequency'], reverse=True)
        
        return recommendations[:10]  # Top 10 recommendations
    
    def _suggest_regex(self, pattern: str) -> str:
        """Suggest regex pattern for detected pattern type."""
        regex_suggestions = {
            'zero_width_characters': r'[\u200b\u200c\u200d\ufeff]',
            'control_characters': r'[\u0000-\u001f\u007f-\u009f]',
            'excessive_whitespace': r'\s{4,}',
            'character_repetition': r'(.)\1{5,}',
            'cyrillic_homoglyphs': r'[а-яА-Я]',
            'greek_homoglyphs': r'[Α-Ωα-ω]',
            'fullwidth_characters': r'[０-９Ａ-Ｚａ-ｚ]',
            'html_entities': r'&#?\w+;',
            'high_special_char_ratio': r'[^\w\s]{4,}',
            'sql_keywords': r'\b(SELECT|DROP|DELETE|INSERT|UPDATE|UNION|CREATE|ALTER|EXEC|EXECUTE|TRUNCATE|DECLARE|CAST|CONVERT|INTO|FROM|WHERE|OR|AND|1=1|1=1\s*OR|OR\s*1=1)\b',
        }
        
        return regex_suggestions.get(pattern, f"# TODO: Implement pattern for '{pattern}'")
    
    def _suggest_weight(self, frequency: int, total: int) -> float:
        """Suggest weight for pattern based on frequency."""
        ratio = frequency / total
        
        if ratio >= 0.5:
            return 0.4  # High weight
        elif ratio >= 0.3:
            return 0.3  # Medium-high
        elif ratio >= 0.2:
            return 0.2  # Medium
        else:
            return 0.1  # Low
    
    def generate_report(self, analysis: Dict[str, Any], output_file: Path) -> None:
        """Generate markdown report from analysis."""
        stats = analysis['statistics']
        recommendations = analysis['pattern_recommendations']
        
        report = f"""# Adversarial Pattern Analysis Report

**Date:** Generated automatically  
**Total Bypasses Analyzed:** {stats['total_bypasses']}

---

## Pattern Frequency Analysis

### Top 20 Most Common Patterns

| Pattern | Frequency | Percentage |
|---------|-----------|------------|
"""
        
        for pattern, count in list(stats['pattern_frequency'].items())[:20]:
            percentage = (count / stats['total_bypasses']) * 100
            report += f"| `{pattern}` | {count} | {percentage:.1f}% |\n"
        
        report += "\n---\n\n"
        
        # Category distribution
        report += "## Category Distribution\n\n"
        for category, patterns in stats['category_distribution'].items():
            if patterns:
                report += f"### {category.replace('_', ' ').title()}\n\n"
                report += "| Pattern | Frequency |\n|---------|-----------|\n"
                for pattern, count in patterns:
                    report += f"| `{pattern}` | {count} |\n"
                report += "\n"
        
        # Recommendations
        report += "---\n\n"
        report += "## Pattern Recommendations\n\n"
        report += f"Found **{len(recommendations)}** patterns that appear frequently but may not be fully covered.\n\n"
        
        if recommendations:
            report += "| Priority | Pattern | Frequency | Suggested Regex | Suggested Weight |\n"
            report += "|----------|---------|-----------|-----------------|------------------|\n"
            
            for rec in recommendations:
                report += f"| {rec['priority']} | `{rec['pattern']}` | {rec['frequency']} ({rec['percentage']:.1f}%) | `{rec['suggested_regex']}` | {rec['suggested_weight']} |\n"
            
            report += "\n### Top 3 Priority Patterns\n\n"
            
            for i, rec in enumerate(recommendations[:3], 1):
                report += f"#### {i}. {rec['pattern']} (Priority: {rec['priority']})\n\n"
                report += f"- **Frequency:** {rec['frequency']} ({rec['percentage']:.1f}% of bypasses)\n"
                report += f"- **Suggested Regex:** `{rec['suggested_regex']}`\n"
                report += f"- **Suggested Weight:** {rec['suggested_weight']}\n\n"
                report += f"- **Implementation:**\n"
                report += f"```python\n"
                report += f"(r\"{rec['suggested_regex']}\", {rec['suggested_weight']}, \"{rec['pattern']}\"),\n"
                report += f"```\n\n"
        else:
            report += "✅ All frequent patterns appear to be covered by existing patterns.\n\n"
        
        report += "---\n\n"
        report += "## Sample Bypass Examples\n\n"
        report += "### Top 5 Most Complex Bypasses\n\n"
        
        # Sort by number of detected patterns
        sorted_samples = sorted(
            analysis['analyzed_samples'],
            key=lambda x: len(x['detected_patterns']),
            reverse=True
        )
        
        for i, sample in enumerate(sorted_samples[:5], 1):
            report += f"#### Example {i}\n\n"
            report += f"- **Original:** `{sample['original']}`\n"
            report += f"- **Length:** {sample['length']}\n"
            report += f"- **Risk Score:** {sample['risk_score']}\n"
            report += f"- **Detected Patterns:** {', '.join(sample['detected_patterns'][:10])}\n"
            report += f"- **Entropy:** {sample['structure'].get('entropy', 'N/A')}\n\n"
        
        # Save report
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report)
        
        logger.info(f"Report saved to {output_file}")


def main():
    """Main execution."""
    parser = argparse.ArgumentParser(description="Analyze adversarial patterns from test results")
    parser.add_argument(
        "--results",
        type=str,
        nargs='+',
        required=True,
        help="Path(s) to baseline test result JSON file(s) (supports glob patterns)"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="test_results/adversarial/pattern_analysis_report.md",
        help="Output path for analysis report"
    )
    parser.add_argument(
        "--json-output",
        type=str,
        default=None,
        help="Optional: Save detailed analysis as JSON"
    )
    
    args = parser.parse_args()
    
    # Resolve glob patterns
    result_files = []
    for pattern in args.results:
        result_files.extend(Path('.').glob(pattern))
    
    if not result_files:
        logger.error(f"No result files found matching: {args.results}")
        return
    
    logger.info(f"Found {len(result_files)} result file(s)")
    
    # Analyze
    analyzer = AdversarialPatternAnalyzer()
    analysis = analyzer.analyze_all_bypasses(result_files)
    
    # Generate report
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    analyzer.generate_report(analysis, output_path)
    
    # Save JSON if requested
    if args.json_output:
        json_path = Path(args.json_output)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(analysis, f, indent=2, default=str)
        logger.info(f"Detailed analysis saved to {json_path}")
    
    # Print summary
    print("\n" + "="*80)
    print("PATTERN ANALYSIS COMPLETE")
    print("="*80)
    print(f"Total Bypasses: {analysis['statistics']['total_bypasses']}")
    print(f"Unique Patterns Detected: {len(analysis['statistics']['pattern_frequency'])}")
    print(f"Recommendations Generated: {len(analysis['pattern_recommendations'])}")
    print(f"\nReport saved to: {output_path}")
    print("="*80)


if __name__ == "__main__":
    main()

