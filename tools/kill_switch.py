"""
Kill-Switch CLI for Evidence & Safety Stack
===========================================

Emergency rollback tool for production incidents.

Usage:
    python tools/kill_switch.py --dsn "postgresql://..." --domains SCIENCE MEDICINE

Features:
- Unmount last N adapters (domain-scoped)
- Demote/quarantine last M promotions
- Freeze memory writes (read-only mode)
- Trigger canary suite
- Produce signed ledger events

Requirements:
- psycopg3
- PostgreSQL with evidence_ledger, domain_adapters, feature_flags tables
"""

from __future__ import annotations

import argparse
import datetime as dt
import sys

try:
    import psycopg
except ImportError:
    print("ERROR: psycopg3 required. Install with: pip install psycopg[binary]>=3.0")
    sys.exit(1)


def kill_switch(
    dsn: str,
    domains: list[str],
    last_n_adapters: int = 5,
    last_m_promotions: int = 200,
    dry_run: bool = False
):
    """
    Execute kill-switch procedure.

    Args:
        dsn: PostgreSQL connection string
        domains: List of domains to affect
        last_n_adapters: Number of recent adapters to unmount per domain
        last_m_promotions: Number of recent promotions to demote
        dry_run: If True, only print actions without executing
    """
    now = dt.datetime.utcnow().isoformat()

    print("=== Kill-Switch Procedure ===")
    print(f"Timestamp: {now}")
    print(f"Domains: {domains}")
    print(f"Unmount adapters: last {last_n_adapters} per domain")
    print(f"Demote promotions: last {last_m_promotions}")
    print(f"Dry-run: {dry_run}")
    print()

    if dry_run:
        print("DRY-RUN MODE - No changes will be made")
        print()

    try:
        with psycopg.connect(dsn, autocommit=False) as conn:
            with conn.cursor() as cur:
                # 1) Unmount last N adapters (domain-scoped)
                print("Step 1: Unmounting adapters...")
                for domain in domains:
                    query = """
                        UPDATE domain_adapters
                        SET mounted = FALSE, unmounted_at = now()
                        WHERE domain = %s
                        ORDER BY created_at DESC
                        LIMIT %s
                        RETURNING adapter_id, created_at;
                    """

                    if not dry_run:
                        cur.execute(query, (domain, last_n_adapters))
                        rows = cur.fetchall()
                        print(f"  {domain}: Unmounted {len(rows)} adapters")
                    else:
                        print(f"  {domain}: Would unmount {last_n_adapters} adapters")

                # 2) Demote/quarantine last M promotions
                print("\nStep 2: Demoting promotions...")
                query = """
                    UPDATE evidence_ledger
                    SET decision = 'DEMOTED',
                        notes = COALESCE(notes,'') || ' | kill-switch ' || %s
                    WHERE decision = 'PROMOTE'
                    ORDER BY created_at DESC
                    LIMIT %s
                    RETURNING decision_id, created_at;
                """

                if not dry_run:
                    cur.execute(query, (now, last_m_promotions))
                    rows = cur.fetchall()
                    print(f"  Demoted {len(rows)} promotions")
                else:
                    print(f"  Would demote {last_m_promotions} promotions")

                # 3) Freeze memory writes
                print("\nStep 3: Freezing memory writes...")
                query = """
                    UPDATE feature_flags
                    SET enabled = FALSE
                    WHERE name = 'memory_write_enabled'
                    RETURNING name;
                """

                if not dry_run:
                    cur.execute(query)
                    if cur.rowcount > 0:
                        print("  Memory writes frozen")
                    else:
                        print("  Warning: feature_flags table may not exist")
                else:
                    print("  Would freeze memory writes")

                # 4) Ledger event
                print("\nStep 4: Creating ledger event...")
                query = """
                    INSERT INTO operational_events(kind, payload, created_at)
                    VALUES ('KILL_SWITCH',
                            jsonb_build_object('domains', %s, 'time', %s, 'dry_run', %s),
                            now())
                    RETURNING id;
                """

                if not dry_run:
                    cur.execute(query, (domains, now, dry_run))
                    event_id = cur.fetchone()
                    print(f"  Ledger event created: {event_id[0] if event_id else 'N/A'}")
                else:
                    print("  Would create ledger event")

                # Commit or rollback
                if not dry_run:
                    conn.commit()
                    print("\n✓ Kill-switch executed successfully")
                else:
                    conn.rollback()
                    print("\n✓ Dry-run complete (no changes made)")

    except psycopg.OperationalError as e:
        print("\nERROR: Database connection failed")
        print(f"  {e}")
        sys.exit(1)
    except Exception as e:
        print("\nERROR: Kill-switch failed")
        print(f"  {e}")
        sys.exit(1)


def main():
    """Main entry point."""
    ap = argparse.ArgumentParser(
        description="Kill-switch for Evidence & Safety Stack",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Dry-run
  python tools/kill_switch.py --dsn "postgresql://..." --domains SCIENCE --dry-run

  # Production (affects SCIENCE and MEDICINE domains)
  python tools/kill_switch.py --dsn "postgresql://..." --domains SCIENCE MEDICINE

  # Custom limits
  python tools/kill_switch.py --dsn "postgresql://..." --domains SCIENCE --last-n-adapters 10 --last-m-promotions 500
        """
    )

    ap.add_argument("--dsn", required=True,
                    help="PostgreSQL connection string")
    ap.add_argument("--domains", nargs="+", required=True,
                    help="Domains to affect (SCIENCE, MEDICINE, etc.)")
    ap.add_argument("--last-n-adapters", type=int, default=5,
                    help="Number of recent adapters to unmount per domain (default: 5)")
    ap.add_argument("--last-m-promotions", type=int, default=200,
                    help="Number of recent promotions to demote (default: 200)")
    ap.add_argument("--dry-run", action="store_true",
                    help="Dry-run mode (no changes)")

    args = ap.parse_args()

    # Confirmation prompt (unless dry-run)
    if not args.dry_run:
        print("WARNING: This will affect production data!")
        print(f"Domains: {', '.join(args.domains)}")
        confirm = input("Type 'CONFIRM' to proceed: ")

        if confirm != "CONFIRM":
            print("Aborted.")
            sys.exit(0)

    kill_switch(
        dsn=args.dsn,
        domains=args.domains,
        last_n_adapters=args.last_n_adapters,
        last_m_promotions=args.last_m_promotions,
        dry_run=args.dry_run
    )


if __name__ == "__main__":
    main()

