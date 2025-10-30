"""
Spatial CAPTCHA Module
======================

Spatial reasoning challenges for human/bot differentiation.

Based on: "Spatial CAPTCHA: Generatively Benchmarking Spatial Reasoning"

Components:
- Generator: Procedural challenge generation
- Renderer: PNG visualization
- Adapter: Hexagonal architecture integration

Creator: Joerg Bollwahn
Date: 2025-10-30
License: MIT
"""

from llm_firewall.spatial.generator import SpatialCaptchaGenerator, verify_response
from llm_firewall.spatial.renderer import SpatialCaptchaRenderer

__all__ = [
    "SpatialCaptchaGenerator",
    "SpatialCaptchaRenderer",
    "verify_response"
]

