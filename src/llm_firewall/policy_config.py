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

    # Decode budgets (DoS protection)
    max_inflate_bytes: int = 65536
    max_zip_files: int = 5
    max_zip_read_bytes: int = 32768
    max_png_chunks: int = 8

    # Auto-strict guard
    auto_strict_enabled: bool = True
    auto_strict_alarm_threshold: int = 3
    auto_strict_window_seconds: int = 300
    auto_strict_duration_seconds: int = 300


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

    # Decode budgets
    max_inflate = 65536
    max_zip_files = 5
    max_zip_read = 32768
    max_png_chunks = 8

    # Auto-strict
    auto_strict_on = True
    auto_strict_alarms = 3
    auto_strict_window = 300
    auto_strict_duration = 300

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

        # Budgets
        max_inflate = int(
            _cfg_get(cfg, ("llm_firewall", "policy", "max_inflate_bytes"), max_inflate)
        )
        max_zip_files = int(
            _cfg_get(cfg, ("llm_firewall", "policy", "max_zip_files"), max_zip_files)
        )
        max_zip_read = int(
            _cfg_get(
                cfg, ("llm_firewall", "policy", "max_zip_read_bytes"), max_zip_read
            )  # noqa: E501
        )
        max_png_chunks = int(
            _cfg_get(cfg, ("llm_firewall", "policy", "max_png_chunks"), max_png_chunks)
        )

        # Auto-strict
        auto_strict_on = bool(
            _cfg_get(
                cfg, ("llm_firewall", "policy", "auto_strict_enabled"), auto_strict_on
            )  # noqa: E501
        )
        auto_strict_alarms = int(
            _cfg_get(
                cfg,
                ("llm_firewall", "policy", "auto_strict_alarm_threshold"),
                auto_strict_alarms,
            )
        )
        auto_strict_window = int(
            _cfg_get(
                cfg,
                ("llm_firewall", "policy", "auto_strict_window_seconds"),
                auto_strict_window,
            )
        )
        auto_strict_duration = int(
            _cfg_get(
                cfg,
                ("llm_firewall", "policy", "auto_strict_duration_seconds"),
                auto_strict_duration,
            )
        )

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
        max_inflate_bytes=max_inflate,
        max_zip_files=max_zip_files,
        max_zip_read_bytes=max_zip_read,
        max_png_chunks=max_png_chunks,
        auto_strict_enabled=auto_strict_on,
        auto_strict_alarm_threshold=auto_strict_alarms,
        auto_strict_window_seconds=auto_strict_window,
        auto_strict_duration_seconds=auto_strict_duration,
    )
