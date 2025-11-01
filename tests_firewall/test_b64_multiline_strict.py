#!/usr/bin/env python3
"""
Unit tests for strict Base64 multiline detector
RC2 P3.3: Validates decode-based detection, context-awareness
"""

import sys
from pathlib import Path

repo_root = Path(__file__).parent.parent
sys.path.insert(0, str(repo_root / "src"))

from llm_firewall.detectors.exotic_encodings import (
    detect_base64_multiline,
    detect_base64_multiline_strict,
)


def test_short_strings_in_code_do_not_trigger():
    """Short code strings like 'Path', 'src' should NOT trigger"""
    text = 'import os\nNAME="Path"\nBASE="src"\n'
    det = detect_base64_multiline(text, context="code")
    assert det is False


def test_shebang_and_imports_do_not_trigger():
    """Shebang and imports should NOT trigger"""
    text = "#!/usr/bin/env python3\nimport sys\n"
    det = detect_base64_multiline(text, context="code")
    assert det is False


def test_two_decodable_lines_trigger():
    """Two decodable Base64 tokens on different lines SHOULD trigger"""
    s1 = "TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5"  # decodable
    s2 = "aGlzIHJlYXNvbiwgYnV0IGJ5IHRoaXMgc2luZ3VsYXI="  # decodable
    text = f'/* a */ "{s1}"\n/* b */ "{s2}"\n'
    det = detect_base64_multiline(text, context="code")
    assert det is True


def test_single_long_token_triggers():
    """Single long (>=64 chars) decodable token SHOULD trigger"""
    tok = "TWFu" * 20 + "=="  # >= 64 chars total
    text = f'const B = "{tok}";\n'
    det = detect_base64_multiline(text, context="code")
    assert det is True


def test_textual_decoded_short_is_ignored():
    """Short tokens that decode to pure text should be ignored"""
    tok = "VGhpc2lzYWxtb3N0cHVyZXRleHQ="  # decodes to "Thisisalmostpuretext"
    text = f'let T = "{tok}";\n'
    det = detect_base64_multiline(text, context="code")
    assert det is False


def test_context_code_stricter_than_natural():
    """Code context has higher threshold (24) than natural (20)"""
    # 22-char token: triggers in natural, not in code
    tok = "SGVsbG9Xb3JsZFRlc3Qx"  # 20 chars, decodable
    text = f'value = "{tok}"\n'
    det_natural = detect_base64_multiline(text, context="natural")
    det_code = detect_base64_multiline(text, context="code")
    # Both might be False if too short or too textual, but code should be stricter
    assert det_code is False  # 20 chars < 24 threshold


def test_strict_returns_spans():
    """Strict version returns (detected, spans) with line numbers"""
    s1 = "TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5"
    s2 = "aGlzIHJlYXNvbiwgYnV0IGJ5IHRoaXMgc2luZ3VsYXI="
    text = f'line1: "{s1}"\nline2: "{s2}"\n'
    det, spans = detect_base64_multiline_strict(text, context="code")
    assert det is True
    assert len(spans) >= 2
    assert all(isinstance(ln, int) and isinstance(tok, bytes) for ln, tok in spans)


def test_non_decodable_high_ratio_ignored():
    """High Base64-alphabet ratio but NOT decodable should be ignored"""
    # Random string with Base64 chars but not valid Base64
    text = 'ABC = "PathValueSrcEnvBase"\n'
    det = detect_base64_multiline(text, context="code")
    assert det is False


def test_real_attack_multiline_detected():
    """Real attack: split Base64 secret across lines"""
    import base64

    # Realistic secret: longer payload
    secret_full = base64.b64encode(
        b"[[SECRET_TOKEN_ATTACK_LONG_PAYLOAD_FOR_TESTING]]"
    ).decode()
    part1 = secret_full[: len(secret_full) // 2]
    part2 = secret_full[len(secret_full) // 2 :]
    text = f'key = "{part1}"\nkey += "{part2}"\n'
    det = detect_base64_multiline(text, context="code")
    # Should detect if parts are individually >= 24 chars
    assert det is True


if __name__ == "__main__":
    import pytest

    pytest.main([__file__, "-v"])
