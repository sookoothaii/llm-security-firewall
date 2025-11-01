#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RC7: Context Poisoning Detection
Detects payloads hidden in documentation/example contexts
DeepSeek Gap: Doc-comments masking actual attacks
"""

import re
from typing import List


def detect_doc_payload_mismatch(text: str) -> List[str]:
    """Detect attack payloads in documentation contexts"""
    hits = []

    # Check if in documentation context
    doc_markers = [
        r"/\*",  # JSDoc (/* or /**)
        r"@example",
        r"@test",
        r"@description",
        r'"""',  # Python docstring
        r"'''",
        r"<!--",  # HTML comment
        r"#\s*Example:",
        r"#\s*Test:",
        r"//\s*Example",  # Single-line comment
    ]

    in_doc_context = any(re.search(marker, text) for marker in doc_markers)

    if in_doc_context:
        # Look for attack patterns inside docs
        attack_patterns = [
            (r"alert\s*\(", "alert_in_doc"),
            (r"eval\s*\(", "eval_in_doc"),
            (r"exec\s*\(", "exec_in_doc"),
            (r"javascript:", "javascript_scheme_in_doc"),
            (r"data:text/javascript", "data_uri_in_doc"),
            (r"<script", "script_tag_in_doc"),
            (r"onerror\s*=", "event_handler_in_doc"),
            (r"onload\s*=", "onload_in_doc"),
        ]

        for pattern, signal in attack_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                hits.append(f"context_poison_{signal}")

    return hits


def detect_example_code_exploitation(text: str) -> List[str]:
    """Detect real attacks disguised as example/test code"""
    hits = []

    # Example markers + real execution keywords together
    has_example = bool(
        re.search(r"(example|test|demo|sample|illustration)", text, re.IGNORECASE)
    )

    if has_example:
        # But has actual execution keywords
        if re.search(r"\bFunction\s*\(", text):
            hits.append("example_with_function_constructor")

        if re.search(r"\bimport\s*\(", text):
            hits.append("example_with_dynamic_import")

        if re.search(r'setTimeout\s*\(\s*[\'"]', text):
            hits.append("example_with_timer_string")

        if re.search(r"location\.(href|replace)", text):
            hits.append("example_with_navigation")

    return hits


def detect_code_comment_split(text: str) -> List[str]:
    """Detect attacks split across code and comments"""
    hits = []

    # Pattern: Code fragment + Comment + Code fragment
    # Example:
    # const x = 'al';
    # // harmless comment
    # const y = 'ert'; eval(x+y);

    # Check for suspicious variable names near comments
    if re.search(r"(const|let|var)\s+\w+\s*=\s*['\"][a-z]{1,3}['\"]\s*;?\s*//", text):
        # And another variable assignment shortly after
        if re.search(
            r"//.*?\n.*(const|let|var)\s+\w+\s*=\s*['\"][a-z]{1,3}['\"]",
            text,
            re.DOTALL,
        ):
            hits.append("code_comment_split_suspicious")

    # Pattern: Multiple short string literals + concat
    short_strings = re.findall(r"['\"]([a-z]{1,4})['\"]", text)
    if len(short_strings) >= 3:
        # Check if they could form dangerous keywords
        joined = "".join(short_strings)
        dangerous = ["alert", "eval", "exec", "function", "script", "import"]
        if any(d in joined.lower() for d in dangerous):
            hits.append("code_split_fragment_dangerous")

    return hits


def scan_context_poisoning(text: str) -> List[str]:
    """Combined context poisoning scanner"""
    hits = []
    hits.extend(detect_doc_payload_mismatch(text))
    hits.extend(detect_example_code_exploitation(text))
    hits.extend(detect_code_comment_split(text))
    return hits


if __name__ == "__main__":
    import io
    import sys

    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

    tests = [
        (
            """
        /**
         * @example alert('legitimate')
         */
        function test() {
            eval('malicious');
        }
        """,
            "Doc with eval",
        ),
        (
            """
        <!-- Example: harmless -->
        <script>alert(1)</script>
        """,
            "HTML comment + script",
        ),
        (
            """
        const x = 'al';
        // harmless comment
        const y = 'ert';
        window[x+y]('xss');
        """,
            "Code-comment split",
        ),
        ("normal code without docs", "Benign"),
    ]

    print("Context Poisoning Detection Test")
    print("=" * 60)

    for i, (test, desc) in enumerate(tests, 1):
        hits = scan_context_poisoning(test)
        print(f"\n[{i}] {desc}")
        print(f"    Signals: {hits if hits else 'NONE'}")
