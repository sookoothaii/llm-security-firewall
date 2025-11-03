"""OWASP sink guards for dangerous output destinations.

Validates generated outputs sent to:
- SQL databases (injection prevention)
- Shell commands (command injection prevention)
- HTML/Markdown (XSS prevention)

Credit: GPT-5 collaboration 2025-11-04
"""

from typing import Dict, Any


class OWASPSinkGuards:
    """Guards for dangerous output sinks."""
    
    def __init__(self, cfg: Dict[str, Any]):
        """Initialize with configuration from layer15.yaml.
        
        Args:
            cfg: Configuration dict from owasp_sinks section
        """
        self.cfg = cfg

    def check_sql(self, query: str) -> str:
        """Check SQL query for dangerous patterns.
        
        Args:
            query: SQL query string
            
        Returns:
            'BLOCK' if dangerous patterns detected, 'ALLOW' otherwise
        """
        s = self.cfg["sinks"]["sql"]
        
        # Check for SQL injection patterns
        if any(tok in query.lower() for tok in s["block_keywords"]):
            return "BLOCK"
        
        # Stub: assume parametrized upstream
        return "ALLOW"

    def check_shell(self, cmd: str) -> str:
        """Check shell command for dangerous meta-characters.
        
        Args:
            cmd: Shell command string
            
        Returns:
            'BLOCK' if dangerous tokens detected, 'ALLOW' otherwise
        """
        s = self.cfg["sinks"]["shell"]
        
        # Check for shell meta-characters
        if any(tok in cmd for tok in s["block_tokens"]):
            return "BLOCK"
        
        return "ALLOW"

    def sanitize_html_md(self, html: str) -> str:
        """Sanitize HTML/Markdown output.
        
        Args:
            html: HTML/Markdown string
            
        Returns:
            Sanitized string with dangerous tags escaped
        """
        pol = self.cfg["sinks"]["html_md"]
        
        # Escape script tags
        if pol.get("allow_script", False) is False:
            html = html.replace("<script", "&lt;script")
            html = html.replace("</script>", "&lt;/script&gt;")
        
        # Escape iframe tags
        if pol.get("allow_iframe", False) is False:
            html = html.replace("<iframe", "&lt;iframe")
            html = html.replace("</iframe>", "&lt;/iframe&gt;")
        
        return html

