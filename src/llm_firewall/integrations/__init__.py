"""
LLM Security Firewall - Third-Party Integrations

Provides integrations with popular LLM frameworks and libraries.

Available Integrations:
- LangChain: Callback handler for automatic input/output validation
- OpenAI: (Coming soon) Direct wrapper with built-in firewall

Creator: Developer Adoption Initiative (Path 2)
Date: 2025-12-01
License: MIT
"""

__all__ = []

# LangChain integration (optional dependency)
try:
    from llm_firewall.integrations.langchain import (
        FirewallCallbackHandler,
        LLMFirewallCallback,  # Alias for convenience
    )

    __all__.extend(["FirewallCallbackHandler", "LLMFirewallCallback"])
    HAS_LANGCHAIN = True
except ImportError:
    HAS_LANGCHAIN = False
    FirewallCallbackHandler = None  # type: ignore
    LLMFirewallCallback = None  # type: ignore
