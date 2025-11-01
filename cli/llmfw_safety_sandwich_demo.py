#!/usr/bin/env python3
"""
Safety-Sandwich v2 Demo CLI
============================
Purpose: Demo streaming leak detection
Usage: echo "text" | python cli/llmfw_safety_sandwich_demo.py
"""

import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "src"))

from llm_firewall.gates.safety_sandwich_v2 import (  # noqa: E402
    SafetySandwichConfig,
    SafetySandwichV2,
)


def main():
    """
    Read from stdin, stream through Safety-Sandwich, print decision

    Exit codes:
        0: PROMOTE or SAFETY_WRAP
        1: QUARANTINE
        2: REJECT (aborted)
    """
    text = sys.stdin.read()

    cfg = SafetySandwichConfig(
        model_name="demo",
        critical_leak_n=20,
        abort_secrets_severity=0.70,
        redact_secrets_severity=0.40,
        quarantine_obfuscation_severity=0.75,
    )

    sw = SafetySandwichV2(cfg)

    for ch in text:
        act = sw.feed_token(ch, dt_seconds=0.0)
        if act == "abort":
            print("\n[ABORTED by Safety-Sandwich]\n", file=sys.stderr)
            snap = sw.snapshot()
            print(f"Reason: {snap['abort_reason']}", file=sys.stderr)
            print(f"Tokens processed: {snap['tokens_seen']}", file=sys.stderr)
            print("", end="")
            decision = sw.finalize()
            print(f"Decision: {decision}")
            return 2

    decision = sw.finalize()
    snap = sw.snapshot()

    print(f"Decision: {decision}")
    print(f"Tokens: {snap['tokens_seen']}")
    print(f"Redactions: {len(snap['redactions'])}")

    if decision == "REJECT":
        return 2
    elif decision == "QUARANTINE":
        return 1
    else:
        return 0


if __name__ == "__main__":
    sys.exit(main())
