"""OWASP sink hardening for SQL, Shell, and HTML/MD outputs."""

from typing import Dict, Any


class OWASPSinkGuards:
    """Validate generated outputs before dangerous sinks."""

    def __init__(self, cfg: Dict[str, Any]):
        self.cfg = cfg

    def check_sql(self, query: str) -> str:
        """Check SQL query for injection patterns.

        Returns:
            'BLOCK' or 'ALLOW'
        """
        s = self.cfg["sinks"]["sql"]
        if any(tok in query.lower() for tok in s["block_keywords"]):
            return "BLOCK"
        # Stub: assume parametrized upstream
        return "ALLOW"

    def check_shell(self, cmd: str) -> str:
        """Check shell command for metacharacters.

        Returns:
            'BLOCK' or 'ALLOW'
        """
        s = self.cfg["sinks"]["shell"]
        if any(tok in cmd for tok in s["block_tokens"]):
            return "BLOCK"
        return "ALLOW"

    def sanitize_html_md(self, html: str) -> str:
        """Sanitize HTML/Markdown output.

        Returns:
            Sanitized string
        """
        pol = self.cfg["sinks"]["html_md"]

        # Escape dangerous tags
        if pol.get("allow_script", False) is False:
            html = html.replace("<script", "&lt;script")
        if pol.get("allow_iframe", False) is False:
            html = html.replace("<iframe", "&lt;iframe")

        return html
