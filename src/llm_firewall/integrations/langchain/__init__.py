"""
LangChain Integration for LLM Security Firewall

Provides callback handler for automatic input/output validation in LangChain chains.

Usage:
    from llm_firewall.integrations.langchain import FirewallCallbackHandler

    callback = FirewallCallbackHandler()
    chain = LLMChain(llm=llm, callbacks=[callback])

Creator: Developer Adoption Initiative (Path 2)
Date: 2025-12-01
License: MIT
"""

from llm_firewall.integrations.langchain.callbacks import FirewallCallbackHandler

# Convenience alias
LLMFirewallCallback = FirewallCallbackHandler

__all__ = ["FirewallCallbackHandler", "LLMFirewallCallback"]
