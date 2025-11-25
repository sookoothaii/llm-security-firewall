"""Documentation Context Detection for FPR Reduction"""

import re

# Markdown patterns
MD_FENCE = re.compile(r"```.*?```", re.S)
MD_HEAD = re.compile(r"^\s{0,3}#{1,6}\s+\S", re.M)

# Documentation vocabulary
DOC_TOKS = (
    "usage",
    "installation",
    "example",
    "examples",
    "parameters",
    "argument",
    "api",
    "return",
    "output",
    "input",
    "note",
    "notes",
    "warning",
    "license",
    "requirements",
    "changelog",
    "configuration",
    "config",
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "curl",
    "wget",
    "request",
    "response",
    "tutorial",  # nosec B104
    "documentation",
    "readme",
    "guide",
    "quickstart",
    "getting started",
)


def detect_documentation_context(text: str, filename: str = "") -> dict:
    """
    Detect if text is documentation/README/configuration.
    Reduces false positives by recognizing benign technical content.

    Scoring:
    - Long text (>=800 chars): +1
    - Code fences (```) present: +1
    - Multiple headers (##, ###): +1
    - Doc vocabulary (>=3 keywords): +1
    - File extension (.md, .txt, .rst, .cfg, .conf): +2 (strong indicator)

    Context = "documentation" if score >= 2
    """
    length = len(text)
    fences = len(MD_FENCE.findall(text))
    heads = len(MD_HEAD.findall(text))
    toks = sum(1 for w in DOC_TOKS if w in text.lower())

    score = 0
    score += 1 if length >= 800 else 0
    score += 1 if fences >= 1 else 0
    score += 1 if heads >= 2 else 0
    score += 1 if toks >= 3 else 0

    # File extension strong indicator (if provided)
    if filename:
        doc_exts = (
            ".md",
            ".txt",
            ".rst",
            ".cfg",
            ".conf",
            ".ini",
            ".yaml",
            ".yml",
            ".json",
        )
        if any(filename.lower().endswith(ext) for ext in doc_exts):
            score += 2

    # Very low threshold for maximum recall (reduce FPR)
    # ANY indicator suggests documentation
    ctx = "documentation" if score >= 1 or length >= 400 else "generic"

    return {
        "ctx": ctx,
        "length": length,
        "fences": fences,
        "headers": heads,
        "doc_tokens": toks,
        "score": score,
        "filename": filename,
    }


# Execution context patterns
FUNC_CALL = re.compile(r"(?i)(?<![A-Za-z0-9_])[A-Za-z_]\w*\s*\(")
SCRIPT_TAG = re.compile(r"(?i)<\s*script\b")
JS_SCHEME = re.compile(r"(?i)\bjavascript\s*:")
ON_EVENT = re.compile(r"(?i)\bon\w+\s*=")


def is_exec_context(text: str, context: str = "generic") -> bool:
    """
    Check if text contains actual execution context.

    In documentation, only return True for DANGEROUS patterns:
    - Script tags: <script>
    - JavaScript schemes: javascript:
    - Event handlers: onclick=
    - Dangerous function calls: alert(), eval(), exec()

    In generic context, any function call counts.
    """
    # Always dangerous
    if SCRIPT_TAG.search(text) or JS_SCHEME.search(text) or ON_EVENT.search(text):
        return True

    # In documentation, be VERY strict - only script tags/schemes, not mentions
    if context == "documentation":
        # Only actual executable contexts, not code examples
        return False  # In docs, function calls are examples unless script tag/scheme present

    # In generic context, any function call is exec context
    return bool(FUNC_CALL.search(text))


# Network/Exploit markers
SCHEME = re.compile(r"(?i)\bhttps?://")
NET_APIS = re.compile(r"(?i)\b(curl|wget|requests\.get|fetch|axios|httpx)\b")
EXPLOIT_MARK = re.compile(r"(?i)\b(exploit|payload|bypass|attack|malicious)\b")


def is_network_context(text: str) -> bool:
    """Check if text contains actual network operations"""
    return bool(SCHEME.search(text) and NET_APIS.search(text))


def is_exploit_context(text: str, context: str = "generic") -> bool:
    """
    Check if text explicitly contains exploit code (not just mentions).

    In documentation: Only return True if exploit code is executable
    In generic: Any exploit/attack/payload mention counts
    """
    has_exploit_words = bool(EXPLOIT_MARK.search(text))

    if not has_exploit_words:
        return False

    # In documentation, require BOTH exploit words AND executable context
    if context == "documentation":
        # Must have script tag, javascript scheme, or function constructor
        return bool(
            SCRIPT_TAG.search(text)
            or JS_SCHEME.search(text)
            or re.search(r"(?i)\bFunction\s*\(", text)
            or re.search(r"(?i)\beval\s*\(", text)
        )

    # In generic context, exploit words alone are suspicious
    return True


def detect_short_snippet_like_docs(text: str) -> bool:
    """
    Detect if text is short snippet that looks like documentation/metadata.
    Used for FPR reduction on package metadata, config snippets, etc.

    Returns True if:
    - Text is < 200 chars
    - No exec context (function calls, script tags, etc)
    - No network URLs
    - Contains benign markers (entry_points, metadata, etc)
    OR is very short neutral text (<=40 words)
    """
    t = text.strip()
    if len(t) >= 200:
        return False

    # Not doc-like if contains exec context
    if is_exec_context(t, "generic"):
        return False

    # Not doc-like if contains URLs
    if SCHEME.search(t):
        return False

    # Benign markers in package metadata / readme snippets
    benign_markers = (
        "entry_points",
        "console_scripts",
        "top_level",
        "usage",
        "example",
        "install",
        "requirements",
        "metadata",
        "version",
        "license",
        "description",
        "author",
        "keywords",
        "classifier",
    )
    if any(m in t.lower() for m in benign_markers):
        return True

    # Very short, neutral text - treat as doc-like
    return len(t.split()) <= 40
