"""Tests for OWASP sink guards."""

import pytest
import yaml
from pathlib import Path

from src.layer15.owasp_sinks import OWASPSinkGuards


@pytest.fixture
def cfg():
    """Load Layer 15 config."""
    cfg_path = Path(__file__).parent.parent.parent / "config" / "layer15.yaml"
    return yaml.safe_load(cfg_path.read_text(encoding='utf-8'))


def test_sql_blocks_comment_sequence(cfg):
    """Test SQL guard blocks comment-based injection."""
    g = OWASPSinkGuards(cfg["owasp_sinks"])
    
    result = g.check_sql("SELECT * FROM t WHERE x=1;-- drop table t;")
    assert result == "BLOCK"


def test_sql_blocks_or_injection(cfg):
    """Test SQL guard blocks OR-based injection."""
    g = OWASPSinkGuards(cfg["owasp_sinks"])
    
    result = g.check_sql("SELECT * FROM users WHERE name='admin' or 1=1")
    assert result == "BLOCK"


def test_sql_allows_clean_query(cfg):
    """Test SQL guard allows clean parametrized query."""
    g = OWASPSinkGuards(cfg["owasp_sinks"])
    
    result = g.check_sql("SELECT * FROM users WHERE id = ?")
    assert result == "ALLOW"


def test_shell_blocks_pipe(cfg):
    """Test shell guard blocks pipe metacharacter."""
    g = OWASPSinkGuards(cfg["owasp_sinks"])
    
    result = g.check_shell("cat input | grep foo")
    assert result == "BLOCK"


def test_shell_blocks_command_substitution(cfg):
    """Test shell guard blocks command substitution."""
    g = OWASPSinkGuards(cfg["owasp_sinks"])
    
    result = g.check_shell("echo $(whoami)")
    assert result == "BLOCK"


def test_shell_blocks_semicolon(cfg):
    """Test shell guard blocks semicolon chaining."""
    g = OWASPSinkGuards(cfg["owasp_sinks"])
    
    result = g.check_shell("ls; rm -rf /")
    assert result == "BLOCK"


def test_shell_allows_clean_command(cfg):
    """Test shell guard allows clean command."""
    g = OWASPSinkGuards(cfg["owasp_sinks"])
    
    result = g.check_shell("ls -la /tmp")
    assert result == "ALLOW"


def test_html_sanitization_script(cfg):
    """Test HTML sanitizer escapes script tags."""
    g = OWASPSinkGuards(cfg["owasp_sinks"])
    
    html = g.sanitize_html_md("<script>alert(1)</script><p>OK</p>")
    
    assert "<script" not in html
    assert "&lt;script" in html
    assert "<p>OK</p>" in html


def test_html_sanitization_iframe(cfg):
    """Test HTML sanitizer escapes iframe tags."""
    g = OWASPSinkGuards(cfg["owasp_sinks"])
    
    html = g.sanitize_html_md("<iframe src='evil.com'></iframe>")
    
    assert "<iframe" not in html
    assert "&lt;iframe" in html


def test_html_sanitization_multiple_tags(cfg):
    """Test HTML sanitizer handles multiple dangerous tags."""
    g = OWASPSinkGuards(cfg["owasp_sinks"])
    
    html = g.sanitize_html_md(
        "<script>x()</script><div>safe</div><iframe src='x'></iframe>"
    )
    
    assert "<script" not in html
    assert "<iframe" not in html
    assert "&lt;script" in html
    assert "&lt;iframe" in html
    assert "<div>safe</div>" in html
