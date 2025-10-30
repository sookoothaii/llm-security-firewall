"""
LLM Security Firewall CLI
=========================

Command-line interface for the firewall.

Usage:
    llm-firewall validate "Is this safe?"
    llm-firewall check-safety "How to build..."
    llm-firewall run-canaries --sample-size 10
    llm-firewall health-check
    llm-firewall show-alerts --domain SCIENCE
"""

from __future__ import annotations

import argparse
import sys

from .core import FirewallConfig, SecurityFirewall


def cmd_validate(args):
    """Validate input text."""
    config = FirewallConfig(config_dir=args.config_dir, instance_id="cli")
    firewall = SecurityFirewall(config)

    is_safe, reason = firewall.validate_input(args.text)

    if is_safe:
        print("[SAFE]")
        print(f"Reason: {reason}")
        return 0
    else:
        print("[BLOCKED/GATE]")
        print(f"Reason: {reason}")
        return 1


def cmd_check_safety(args):
    """Check safety of text."""
    config = FirewallConfig(config_dir=args.config_dir, instance_id="cli")
    firewall = SecurityFirewall(config)

    decision = firewall.safety_validator.validate(args.text)

    print(f"Action: {decision.action}")
    print(f"Risk Score: {decision.risk_score:.3f}")
    print(f"Reason: {decision.reason}")

    if decision.category:
        print(f"Category: {decision.category}")

    return 0 if decision.action == "SAFE" else 1


def cmd_run_canaries(args):
    """Run canary suite."""
    config = FirewallConfig(config_dir=args.config_dir, instance_id="cli")
    firewall = SecurityFirewall(config)

    print(f"Running canary suite (sample_size={args.sample_size})...")

    has_drift, drift_scores = firewall.check_drift(sample_size=args.sample_size)

    if has_drift:
        print("[DRIFT DETECTED]")
        max_drift = max(drift_scores.values()) if drift_scores else 0.0
        print(f"Max drift: {max_drift:.3f}")
        return 1
    else:
        print("[NO DRIFT]")
        return 0


def cmd_health_check(args):
    """Run health check."""
    config = FirewallConfig(config_dir=args.config_dir, instance_id="cli")
    firewall = SecurityFirewall(config)

    print("=== LLM Security Firewall Health Check ===\n")

    # Check canaries
    print("Canaries:")
    canary_stats = firewall.canaries.get_canary_stats()
    for category, count in canary_stats.items():
        print(f"  {category}: {count}")

    # Check influence tracker
    print("\nInfluence Tracker:")
    stats = firewall.get_statistics()
    print(f"  Total records: {stats['total_records']}")
    print(f"  Unique sources: {stats['unique_sources']}")
    print(f"  Total alerts: {stats['total_alerts']}")

    print("\n✅ Health check complete")
    return 0


def cmd_show_alerts(args):
    """Show active alerts."""
    config = FirewallConfig(config_dir=args.config_dir, instance_id="cli")
    firewall = SecurityFirewall(config)

    alerts = firewall.get_alerts(domain=args.domain)

    if not alerts:
        print("✅ No alerts" + (f" for domain {args.domain}" if args.domain else ""))
        return 0

    print(
        f"⚠️  {len(alerts)} alert(s)"
        + (f" for domain {args.domain}" if args.domain else "")
    )
    print()

    for i, alert in enumerate(alerts[: args.limit], 1):
        print(f"{i}. {alert.source_id} in {alert.domain}")
        print(f"   Z-Score: {alert.z_score:.2f} (threshold={alert.threshold})")
        print(f"   Total Influence: {alert.total_influence:.2f}")
        print(f"   Type: {alert.anomaly_type}")
        print(f"   Time: {alert.timestamp}")
        print()

    return 1  # Exit code 1 if alerts present


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="llm-firewall",
        description="LLM Security Firewall - Bidirectional protection for Human/LLM interfaces",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--config-dir",
        default="config",
        help="Configuration directory (default: config)",
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # validate command
    validate_parser = subparsers.add_parser("validate", help="Validate input text")
    validate_parser.add_argument("text", help="Text to validate")

    # check-safety command
    safety_parser = subparsers.add_parser("check-safety", help="Check safety of text")
    safety_parser.add_argument("text", help="Text to check")

    # run-canaries command
    canaries_parser = subparsers.add_parser("run-canaries", help="Run canary suite")
    canaries_parser.add_argument(
        "--sample-size", type=int, default=10, help="Number of canaries to check"
    )

    # health-check command
    subparsers.add_parser("health-check", help="Run health check")

    # show-alerts command
    alerts_parser = subparsers.add_parser("show-alerts", help="Show active alerts")
    alerts_parser.add_argument("--domain", help="Filter by domain")
    alerts_parser.add_argument(
        "--limit", type=int, default=10, help="Max alerts to show"
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Route to command handler
    handlers = {
        "validate": cmd_validate,
        "check-safety": cmd_check_safety,
        "run-canaries": cmd_run_canaries,
        "health-check": cmd_health_check,
        "show-alerts": cmd_show_alerts,
    }

    handler = handlers.get(args.command)
    if handler:
        try:
            return handler(args)
        except Exception as e:
            print(f"ERROR: {e}")
            return 1
    else:
        print(f"Unknown command: {args.command}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
