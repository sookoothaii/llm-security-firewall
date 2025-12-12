"""
Generate secure Redis password and update .env file
"""
import secrets
import string
from pathlib import Path

def generate_secure_password(length=32):
    """Generate a secure random password."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    password = ''.join(secrets.choice(alphabet) for i in range(length))
    return password

def update_redis_password_in_env(new_password):
    """Update Redis password in .env file."""
    env_file = Path(".env")
    
    if not env_file.exists():
        print("ERROR: .env file not found. Run create_env.py first.")
        return False
    
    content = env_file.read_text(encoding="utf-8", errors="ignore")
    lines = content.split("\n")
    updated = False
    
    for i, line in enumerate(lines):
        if line.startswith("REDIS_CLOUD_PASSWORD="):
            lines[i] = f"REDIS_CLOUD_PASSWORD={new_password}"
            updated = True
            break
    
    if not updated:
        # Add if not found
        lines.append(f"REDIS_CLOUD_PASSWORD={new_password}")
    
    env_file.write_text("\n".join(lines), encoding="utf-8")
    return True

if __name__ == "__main__":
    print("=" * 70)
    print("Redis Password Generator")
    print("=" * 70)
    print()
    
    # Generate password
    password = generate_secure_password(32)
    
    print(f"Generated secure password: {password}")
    print(f"Length: {len(password)} characters")
    print()
    
    # Update .env file
    if update_redis_password_in_env(password):
        print("✅ Updated .env file with new password")
    else:
        print("⚠️  Could not update .env file")
    
    print()
    print("=" * 70)
    print("NEXT STEPS:")
    print("=" * 70)
    print("1. Go to Redis Cloud Dashboard")
    print("2. Select your database (database-MIK9R3GG)")
    print("3. Go to Configuration -> Default User")
    print("4. Change password to the generated password above")
    print("5. Test connection: python test_redis_final.py")
    print("=" * 70)

