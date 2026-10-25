"""Security standards, password policy enforcement, and authentication utilities.

Adheres to NIST SP 800-63B Digital Identity Guidelines and OWASP Authentication Standards.
"""

from __future__ import annotations

import re

# Banned common / easily guessable passwords
COMMON_WEAK_PASSWORDS = {
    "password",
    "password123",
    "12345678",
    "123456789",
    "1234567890",
    "qwerty123",
    "admin123",
    "letmein123",
    "welcome123",
    "iloveyou",
    "bantaynet",
    "changeme",
    "operator123",
    "pass1234",
}


def validate_password_standards(password: str, username: str = "") -> list[str]:
    """Validate a password against modern NIST SP 800-63B & OWASP security standards.

    Returns a list of human-readable error messages. An empty list signifies
    compliance with all standards.
    """
    errors: list[str] = []

    if not password:
        return ["Password cannot be empty."]

    # 1. Length requirements
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long.")
    elif len(password) > 128:
        errors.append("Password cannot exceed 128 characters.")

    # 2. Character diversity
    if not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter (A-Z).")
    if not any(c.islower() for c in password):
        errors.append("Password must contain at least one lowercase letter (a-z).")
    if not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one number (0-9).")
    if not any(not c.isalnum() for c in password):
        errors.append("Password must contain at least one special character (!@#$%^&* etc.).")

    # 3. Contextual checks: disallow username inclusion
    clean_user = (username or "").strip().lower()
    if clean_user and len(clean_user) >= 3 and clean_user in password.lower():
        errors.append("Password cannot contain your username.")

    # 4. Common weak passwords check
    if password.lower() in COMMON_WEAK_PASSWORDS:
        errors.append("Password is too common or easily guessable. Please choose a more complex passphrase.")

    # 5. Trivial repetitive patterns (e.g., 'aaaaaa', '111111')
    if re.search(r"(.)\1{4,}", password):
        errors.append("Password contains excessive repeated characters.")

    return errors


def validate_username_standards(username: str) -> list[str]:
    """Validate username against naming standards."""
    errors: list[str] = []
    clean = (username or "").strip()
    if not clean:
        return ["Username cannot be empty."]
    if len(clean) < 3 or len(clean) > 32:
        errors.append("Username must be between 3 and 32 characters long.")
    if not re.match(r"^[a-zA-Z0-9_\-\.]+$", clean):
        errors.append("Username may only contain letters, numbers, underscores, hyphens, and periods.")
    return errors
