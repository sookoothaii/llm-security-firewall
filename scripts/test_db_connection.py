"""
Test PostgreSQL database connection via SQLAlchemy.

Connects to local PostgreSQL instance to verify connectivity.
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

try:
    from sqlalchemy import create_engine, text
    from sqlalchemy.exc import OperationalError

    print("[OK] SQLAlchemy imported successfully")
except ImportError as e:
    print(f"[FAIL] SQLAlchemy not available: {e}")
    sys.exit(1)


def test_connection(
    host="127.0.0.1", port=5432, database="postgres", user="postgres", password=""
):
    """Test PostgreSQL connection."""
    print(f"\n{'=' * 80}")
    print("Testing PostgreSQL Connection")
    print(f"{'=' * 80}\n")

    # Build connection string
    if password:
        conn_string = f"postgresql://{user}:{password}@{host}:{port}/{database}"
        display_string = f"postgresql://{user}:****@{host}:{port}/{database}"
    else:
        conn_string = f"postgresql://{user}@{host}:{port}/{database}"
        display_string = conn_string

    print(f"Connection String: {display_string}")
    print()

    try:
        # Create engine
        engine = create_engine(conn_string, echo=False)
        print("[OK] SQLAlchemy engine created")

        # Test connection
        with engine.connect() as conn:
            print("[OK] Connection established")

            # Query PostgreSQL version
            result = conn.execute(text("SELECT version()"))
            version = result.scalar()
            print(f"[OK] PostgreSQL Version: {version[:80]}...")
            print()

            # List databases
            result = conn.execute(
                text(
                    "SELECT datname FROM pg_database WHERE datistemplate = false ORDER BY datname"
                )
            )
            databases = [row[0] for row in result]
            print(f"Available Databases ({len(databases)}):")
            for db in databases:
                print(f"  - {db}")
            print()

            # Check for HAK_GAL related tables
            result = conn.execute(
                text("""
                SELECT schemaname, tablename
                FROM pg_tables
                WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
                ORDER BY schemaname, tablename
            """)
            )
            tables = list(result)

            if tables:
                print(f"User Tables ({len(tables)}):")
                for schema, table in tables[:20]:  # Limit to 20
                    print(f"  - {schema}.{table}")
                if len(tables) > 20:
                    print(f"  ... and {len(tables) - 20} more")
            else:
                print("No user tables found (empty database)")
            print()

        print("[OK] Connection test successful!")
        return True

    except OperationalError as e:
        print(f"[FAIL] Connection failed: {e}")
        print()
        print("Troubleshooting:")
        print("1. Check PostgreSQL is running: services.msc (Windows)")
        print("2. Verify port: Default is 5432, not 5172")
        print("3. Check credentials: Default user is 'postgres'")
        print("4. Check pg_hba.conf: Allow local connections")
        return False

    except Exception as e:
        print(f"[FAIL] Unexpected error: {e}")
        import traceback

        traceback.print_exc()
        return False


def main():
    """Run connection test."""
    print("\n")
    print("+" + "=" * 78 + "+")
    print("|" + " " * 20 + "PostgreSQL Connection Test" + " " * 32 + "|")
    print("+" + "=" * 78 + "+")

    # Try different connection configurations
    configs = [
        {
            "host": "127.0.0.1",
            "port": 5432,
            "database": "postgres",
            "user": "postgres",
            "password": "",
        },
        {
            "host": "localhost",
            "port": 5432,
            "database": "postgres",
            "user": "postgres",
            "password": "",
        },
        {
            "host": "127.0.0.1",
            "port": 5172,
            "database": "postgres",
            "user": "postgres",
            "password": "",
        },
    ]

    for i, config in enumerate(configs, 1):
        print(f"\nAttempt {i}/{len(configs)}: {config['host']}:{config['port']}")
        if test_connection(**config):
            print(f"\n[SUCCESS] Connected via {config['host']}:{config['port']}")
            break
    else:
        print("\n[FAIL] All connection attempts failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
