#!/usr/bin/env python3
"""
CyberSentinel WAF - Password Reset Utility
Securely generates bcrypt password hashes for admin/analyst accounts
"""
import sys
import sqlite3
import getpass
from pathlib import Path

try:
    import bcrypt
except ImportError:
    print("Error: bcrypt library not found.")
    print("Install it with: pip3 install bcrypt")
    sys.exit(1)


def generate_password_hash(password: str) -> str:
    """Generate bcrypt hash for password"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def validate_password_strength(password: str) -> tuple[bool, str]:
    """Validate password meets security requirements"""
    if len(password) < 12:
        return False, "Password must be at least 12 characters long"
    
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
    
    if not (has_upper and has_lower and has_digit and has_special):
        return False, "Password must contain uppercase, lowercase, digit, and special character"
    
    return True, "Password meets requirements"


def list_users(db_path: Path) -> list[tuple[int, str, str]]:
    """Returns (id, username, role) for every account, or [] if the DB
    doesn't exist yet (first-run — 'admin'/'analyst' get seeded lazily by
    the backend on next startup, not by this script)."""
    if not db_path.exists():
        return []
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, username, role FROM users ORDER BY id ASC")
        return cur.fetchall()
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()


def update_users_db(db_path: Path, username: str, password_hash: str) -> bool:
    """Reset the given account's password hash directly in users.db — the
    source of truth for login since the Admin > Users panel was introduced.
    Also bumps session_version so any existing session for this account is
    invalidated immediately (see backend/app/services/auth.py:decode_token),
    matching what an admin-issued reset via the API does."""
    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET password_hash = ?, enabled = 1, "
            "session_version = session_version + 1, updated_at = CURRENT_TIMESTAMP "
            "WHERE username = ?",
            (password_hash, username),
        )
        conn.commit()
        updated = cur.rowcount > 0
        conn.close()
        return updated
    except Exception as e:
        print(f"Error updating users database: {e}")
        return False


def main():
    print("=" * 70)
    print("CyberSentinel WAF - Password Reset Utility")
    print("=" * 70)
    print()
    
    # Locate users.db (created automatically the first time the backend starts)
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    db_path = project_root / "backend" / "app" / "data" / "users.db"

    print(f"Users database: {db_path}")
    print()

    users = list_users(db_path)
    if not users:
        print("No users.db found yet (or it has no accounts). Start the backend once")
        print("first — it seeds the legacy 'admin'/'analyst' accounts on first run —")
        print("then re-run this script.")
        sys.exit(1)

    # Select account — usernames are no longer just 'admin'/'analyst';
    # the Admin > Users panel supports arbitrary accounts and multiple admins.
    print("Accounts:")
    for user_id, username, role in users:
        print(f"  {user_id}. {username} ({role})")
    print()

    choice = input("Enter the number of the account to reset: ").strip()
    selected = next((u for u in users if str(u[0]) == choice), None)
    if selected is None:
        print("Invalid choice. Exiting.")
        sys.exit(1)
    _, username, role = selected
    role_name = role.capitalize()

    print()
    print(f"Resetting password for: {username} ({role_name})")
    print()
    print("Password Requirements:")
    print("  • Minimum 12 characters")
    print("  • Contains uppercase letter")
    print("  • Contains lowercase letter")
    print("  • Contains digit")
    print("  • Contains special character (!@#$%^&*...)")
    print()
    
    # Get password with validation
    while True:
        password = getpass.getpass(f"Enter new {role_name} password: ")
        password_confirm = getpass.getpass("Confirm password: ")
        
        if password != password_confirm:
            print("❌ Passwords do not match. Try again.")
            print()
            continue
        
        is_valid, message = validate_password_strength(password)
        if not is_valid:
            print(f"❌ {message}")
            print()
            continue
        
        break
    
    # Generate hash
    print()
    print("Generating bcrypt hash...")
    password_hash = generate_password_hash(password)
    
    # Update users database
    print(f"Updating {db_path}...")
    if update_users_db(db_path, username, password_hash):
        print()
        print("=" * 70)
        print(f"✅ SUCCESS: password for '{username}' has been reset!")
        print("=" * 70)
        print()
        print("No backend restart needed — log in with the new password now.")
        print()
    else:
        print()
        print("❌ Failed to update users database")
        sys.exit(1)


if __name__ == "__main__":
    main()
