#!/usr/bin/env python3
"""
Attack Pattern Detector - RC3 Critical Fix
Detects plaintext attack patterns (SQL, XSS, Path, RCE)
"""
import re
import urllib.parse
from typing import List


def normalize_for_detection(text: str) -> str:
    """Normalize text for better pattern matching"""
    # Decode hex escapes
    try:
        text = text.encode('utf-8').decode('unicode_escape')
    except:
        pass

    # URL decode
    try:
        text = urllib.parse.unquote(text)
    except:
        pass

    # Remove comments (preserving content)
    text = re.sub(r'//.*?(\n|$)', ' ', text)
    text = re.sub(r'/\*.*?\*/', ' ', text, flags=re.DOTALL)

    # Collapse whitespace
    text = ' '.join(text.split())

    # Remove null bytes
    text = text.replace('\x00', '')

    return text

# SQL Injection Patterns
SQL_KEYWORDS = re.compile(
    r'\b(DROP|DELETE|TRUNCATE|ALTER|CREATE|INSERT|UPDATE|EXEC|EXECUTE|UNION|SELECT)\s+(TABLE|DATABASE|INTO|FROM)\b',
    re.IGNORECASE
)
SQL_INJECTION = re.compile(
    r"('|\")\s*(OR|AND)\s*('|\")?\s*[0-9='\"]+\s*(--|#|;)",
    re.IGNORECASE
)
SQL_COMMENT = re.compile(r"('|--).*?(DROP|TABLE|admin|root)", re.IGNORECASE)

# XSS Patterns
XSS_SCHEMES = re.compile(
    r'\b(javascript|data|vbscript|file|about):\s*',
    re.IGNORECASE
)
XSS_TAGS = re.compile(
    r'<\s*(script|iframe|object|embed|img|svg|video|audio)\b',
    re.IGNORECASE
)
XSS_EVENTS = re.compile(
    r'\bon(load|error|click|mouse|focus|blur|change|submit)\s*=',
    re.IGNORECASE
)

# Path Traversal
PATH_TRAVERSAL = re.compile(r'\.\.[/\\]')
SYSTEM_PATHS = re.compile(
    r'(etc/passwd|etc/shadow|windows/system32|proc/self|\.\.)',  # Removed leading / to catch fragments
    re.IGNORECASE
)

# RCE Patterns
LOG4J_JNDI = re.compile(
    r'\$\{\s*(jndi|lower|upper|env|sys|java|ctx)\s*:',
    re.IGNORECASE
)
COMMAND_INJECTION = re.compile(
    r'[;|&`$]\s*(cat|ls|dir|whoami|id|curl|wget|nc|bash|sh|cmd|powershell)\b',
    re.IGNORECASE
)
TEMPLATE_INJECTION = re.compile(
    r'(\{\{.*?\}\}|<%.*?%>|#\{.*?\}|\$\{.*?\}|@\{.*?\}|\{%.*?%\})',
    re.DOTALL
)

# LDAP/SSRF
LDAP_INJECTION = re.compile(r'ldap://|ldaps://', re.IGNORECASE)
SSRF_INTERNAL = re.compile(
    r'(169\.254\.169\.254|127\.0\.0\.\d+|localhost|0\.0\.0\.0|\[::1?\])',
    re.IGNORECASE
)

def scan_attack_patterns(text: str) -> List[str]:
    """
    Scan for plaintext attack patterns
    Returns list of detected attack signals (STRONG)
    """
    signals = []

    # Normalize for better detection
    text_normalized = normalize_for_detection(text)

    # Scan BOTH original and normalized
    texts_to_scan = [text, text_normalized]

    # Check for encoding fragments with attack keywords
    # e.g., "Dr" + base64("OP") + " TABLE" → partial "DROP TABLE"
    if any(kw in text.upper() for kw in ['DROP', 'TABLE', 'DELETE', 'EXEC']):
        # Check for Base64 fragments near keywords
        if re.search(r'[A-Za-z0-9+/=]{4,}', text):
            signals.append('attack_keyword_with_encoding')

    # Check for dangerous schemes (even if obfuscated)
    # Look for partial matches + suspicious patterns
    if re.search(r'j[a\u0430\u0251]v[a\u0430\u0251]script', text, re.IGNORECASE):
        signals.append('xss_scheme_obfuscated')
    if re.search(r'vbscript|data:text/html', text, re.IGNORECASE):
        signals.append('dangerous_scheme_detected')

    # Detect Base64 near suspicious keywords
    if re.search(r'(DR|TA|EX|javascript|alert|script).{0,10}[A-Za-z0-9+/=]{8,}', text, re.IGNORECASE):
        signals.append('encoding_near_attack_keyword')

    # Detect fragmented keywords with interference (/**/,  \u200b, etc)
    # Remove all interference chars first
    text_defragged = re.sub(r'/\*\*/|\u200b|\u200c|\u200d|\ufeff| +', '', text)
    if re.search(r'\b(DROP|DELETE|TRUNCATE|ALTER)\s*TABLE\b', text_defragged, re.IGNORECASE):
        signals.append('sql_defragmented_keyword')
    if re.search(r'javascript.*alert', text_defragged, re.IGNORECASE):
        signals.append('xss_defragmented_attack')

    for txt in texts_to_scan:
        # SQL Injection
        if SQL_KEYWORDS.search(txt):
            signals.append('sql_keywords_destructive')
        if SQL_INJECTION.search(txt):
            signals.append('sql_injection_pattern')
        if SQL_COMMENT.search(txt):
            signals.append('sql_comment_injection')

        # XSS
        if XSS_SCHEMES.search(txt):
            signals.append('xss_dangerous_scheme')
        if XSS_TAGS.search(txt):
            signals.append('xss_script_tag')
        if XSS_EVENTS.search(txt):
            signals.append('xss_event_handler')

        # Path Traversal
        if PATH_TRAVERSAL.search(txt):
            signals.append('path_traversal_dotdot')
        if SYSTEM_PATHS.search(txt):
            signals.append('path_system_file_access')

        # RCE
        if LOG4J_JNDI.search(txt):
            signals.append('rce_log4j_jndi')
        if COMMAND_INJECTION.search(txt):
            signals.append('rce_command_injection')
        if TEMPLATE_INJECTION.search(txt):
            signals.append('rce_template_injection')

        # LDAP/SSRF
        if LDAP_INJECTION.search(txt):
            signals.append('ldap_injection')
        if SSRF_INTERNAL.search(txt):
            signals.append('ssrf_internal_target')

    # Deduplicate
    signals = list(set(signals))

    return signals

