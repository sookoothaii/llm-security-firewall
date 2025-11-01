#!/usr/bin/env python3
"""
Unit tests for AST-Gating (RC2 P4.3)
Ensures detectors only scan string literals/comments, not identifiers
"""
import sys
from pathlib import Path

repo_root = Path(__file__).parent.parent
sys.path.insert(0, str(repo_root / "src"))

from llm_firewall.preprocess.extract_literals import extract_py_literals_and_comments, extract_scannable_parts


def test_extracts_string_literals():
    """Should extract string literals"""
    src = '''
x = "TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5"
y = 'aGlzIHJlYXNvbiwgYnV0IGJ5IHRoaXMgc2luZ3VsYXI='
'''
    literals = extract_py_literals_and_comments(src)
    assert len(literals) >= 2
    contents = [c for c, _ in literals]
    assert any('TWFu' in c for c in contents)
    assert any('aGlz' in c for c in contents)


def test_ignores_identifiers():
    """Should NOT extract identifiers like detect_base64_multiline_strict"""
    src = 'def detect_base64_multiline_strict(text): pass'
    literals = extract_py_literals_and_comments(src)
    # Function name should NOT be in literals
    assert not any('detect_base64' in c for c, _ in literals)


def test_extracts_comments():
    """Should extract comments"""
    src = '# Comment with TWFuIGlz\nx = 1'
    literals = extract_py_literals_and_comments(src)
    assert len(literals) >= 1
    assert any('TWFu' in c for c, _ in literals)


def test_fallback_on_malformed():
    """Should fallback to full text on tokenize error"""
    src = 'def broken( x = "'  # Unclosed string
    literals = extract_py_literals_and_comments(src)
    # Fallback returns full text
    assert len(literals) == 1
    assert literals[0][0] == src


def test_scannable_parts_code_context():
    """In code context, should return only literals"""
    src = '''
# Comment
x = "base64data"
def function_name_with_base64_in_it():
    pass
'''
    parts = extract_scannable_parts(src, context="code")
    # Should have comment and string, NOT function name
    combined = ' '.join(parts)
    assert 'base64data' in combined
    assert 'Comment' in combined
    assert 'function_name_with_base64_in_it' not in combined


def test_scannable_parts_natural_context():
    """In natural context, should return full text"""
    text = "Some natural language text with keywords"
    parts = extract_scannable_parts(text, context="natural")
    assert len(parts) == 1
    assert parts[0] == text


if __name__ == '__main__':
    import pytest
    pytest.main([__file__, '-v'])

