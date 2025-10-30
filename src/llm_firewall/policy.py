"""Policy configuration for firewall modes (permissive vs strict)."""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Sequence


@dataclass(frozen=True)
class Policy:
    """Firewall policy configuration."""

    mode: str = "permissive"  # permissive | strict
    default_allow_structurals: bool = True
    base64_len_allow_threshold: int = 200
    suspicious_terms: tuple[str, ...] = ()


def _cfg_get(d: Any, path: Sequence[str], default: Any) -> Any:
    """Navigate nested config dict/object."""
    cur = d
    try:
        for k in path:
            cur = getattr(cur, k) if hasattr(cur, k) else cur[k]
        return cur
    except Exception:
        return default


def from_hydra(cfg: Any | None) -> Policy:
    """
    Load policy from Hydra config.

    Args:
        cfg: Hydra config object (or None for defaults)

    Returns:
        Policy instance with configured mode and thresholds
    """
    mode = "permissive"
    default_allow = True
    thr = 200
    terms: tuple[str, ...] = ()

    if cfg:
        mode = _cfg_get(cfg, ("llm_firewall", "policy", "mode"), mode)
        default_allow = bool(
            _cfg_get(
                cfg,
                ("llm_firewall", "policy", "hex_uuid_base64_default_allow"),
                mode != "strict",
            )
        )
        thr = int(
            _cfg_get(cfg, ("llm_firewall", "policy", "base64_len_allow_threshold"), thr)
        )
        lst = _cfg_get(cfg, ("llm_firewall", "policy", "suspicious_terms"), [])
        terms = tuple(str(x).lower() for x in (lst or []))

    # env override (emergency switch)
    if _cfg_get(cfg, ("llm_firewall", "env_override"), True):
        env_mode = os.getenv("FIREWALL_POLICY_MODE")
        if env_mode in ("permissive", "strict"):
            mode = env_mode
            default_allow = env_mode != "strict"

    return Policy(
        mode=mode,
        default_allow_structurals=default_allow,
        base64_len_allow_threshold=thr,
        suspicious_terms=terms,
    )

