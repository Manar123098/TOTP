"""
users.py
────────
In-memory user store for the TOTP simulation.

Each record stores:
  salt            – random bytes used in PBKDF2 password hashing
  password_hash   – PBKDF2-HMAC-SHA256 digest (never the raw password)
  shared_secret   – AES-256-CBC encrypted TOTP secret (never plaintext)
  last_used_step  – last accepted TOTP time-step (replay prevention)
  failed_attempts – consecutive failed login attempts (lockout counter)
  lock_until      – Unix timestamp when account lock expires (or None)

Security notes:
  - Passwords are never stored in plaintext.
  - Shared secrets are never stored in plaintext.
  - Replay prevention state is kept per-user, not per-code.
"""

# Key  : username (str)
# Value: dict with the fields described above
users_db: dict = {}
