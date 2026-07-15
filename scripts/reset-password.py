#!/usr/bin/env python3
"""
CyberSentinel WAF - Password Reset Utility
Securely generates bcrypt password hashes for admin/analyst accounts
"""
import sys
import json
import os
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


def update_settings_file(settings_path: Path, role: str, password_hash: str):
    """Update settings.json with new password hash"""
    try:
        with open(settings_path, 'r') as f:
            settings = json.load(f)
        
        if role == 'admin':
            settings['auth']['password_hash'] = password_hash
        elif role == 'analyst':
            settings['auth']['analyst_password_hash'] = password_hash
        
        with open(settings_path, 'w') as f:
            json.dump(settings, f, indent=2)
        
        return True
    except Exception as e:
        print(f"Error updating settings file: {e}")
        return False


def main():
    print("=" * 70)
    print("CyberSentinel WAF - Password Reset Utility")
    print("=" * 70)
    print()
    
    # Locate settings.json
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    settings_path = project_root / "backend" / "app" / "config" / "settings.json"
    
    if not settings_path.exists():
        print(f"Error: settings.json not found at {settings_path}")
        print("Please ensure you're running this from the project scripts directory.")
        sys.exit(1)
    
    print(f"Settings file: {settings_path}")
    print()
    
    # Select role
    print("Select role to reset:")
    print("  1. Admin (full system access)")
    print("  2. Analyst (read-only access)")
    print()
    
    choice = input("Enter choice (1 or 2): ").strip()
    
    if choice == '1':
        role = 'admin'
        role_name = 'Admin'
    elif choice == '2':
        role = 'analyst'
        role_name = 'Analyst'
    else:
        print("Invalid choice. Exiting.")
        sys.exit(1)
    
    print()
    print(f"Resetting password for: {role_name}")
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
    
    # Update settings file
    print(f"Updating {settings_path}...")
    if update_settings_file(settings_path, role, password_hash):
        print()
        print("=" * 70)
        print(f"✅ SUCCESS: {role_name} password has been reset!")
        print("=" * 70)
        print()
        print("Next steps:")
        print("  1. Restart the backend container: docker compose restart backend")
        print("  2. Log in with the new password via the dashboard")
        print()
    else:
        print()
        print("❌ Failed to update settings file")
        sys.exit(1)


if __name__ == "__main__":
    main()
