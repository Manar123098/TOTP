"""
auth.py
───────
Server-side authentication logic.

Covers:
  - User registration (password hashing + secret generation + encryption)
  - Password verification (PBKDF2 + constant-time compare)
  - TOTP verification (tolerance window + replay prevention)
  - Account lockout after repeated failures (brute-force mitigation)
  - Re-enrollment (revoke old secret, issue new encrypted secret)
"""

import time
import hmac as _hmac

from users import users_db
from security import (
    generate_salt,
    hash_password,
    verify_password as _verify_pw,
    store_secret,
    load_secret,
)
from totp_utils import generate_shared_secret, verify_totp_code


# ── Registration ──────────────────────────────

def register_user(username: str, password: str):
    """
    Register a new user.

    Steps:
      1. Validate inputs.
      2. Hash the password with PBKDF2 + random salt.
      3. Generate a unique TOTP shared secret.
      4. Encrypt the secret with AES-256 before storing.
      5. Persist the record in users_db.

    Returns (True, plaintext_secret) so the caller can display or QR-encode
    the secret exactly once during enrollment.

    SECURITY NOTE — one-time disclosure:
      The plaintext secret is returned here and ONLY here.  It is never
      stored; only the AES-256 encrypted form is written to users_db.
      After this function returns, the plaintext secret is gone from the
      server.  The user must scan the QR code (or record the secret) at
      this moment — there is no way to retrieve it again later.
      If the user loses access, re-enrollment generates a brand-new secret.
    """
    if not username or not password:
        return False, "Username and password are required"
    if len(password) < 8:
        return False, "Password must be at least 8 characters"

    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"

    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"

    if username in users_db:
        return False, "User already exists"

    salt          = generate_salt()
    password_hash = hash_password(password, salt)
    raw_secret    = generate_shared_secret()
    enc_secret    = store_secret(raw_secret)          # AES-256 encrypted

    users_db[username] = {
        "salt":            salt,
        "password_hash":   password_hash,
        "shared_secret":   enc_secret,                # stored encrypted
        "last_used_step":  None,
        "failed_attempts": 0,
        "lock_until":      None,
    }

    return True, raw_secret   # plaintext returned once for QR provisioning


# ── Password Verification ─────────────────────

def verify_password(username: str, password: str) -> bool:
    """
    Verify a password using constant-time PBKDF2 comparison.
    Returns False silently if the user does not exist (avoids enumeration).
    """
    user = users_db.get(username)
    if not user:
        return False
    return _verify_pw(user["password_hash"], user["salt"], password)


# ── TOTP Verification ─────────────────────────

def verify_totp(username: str, otp: str):
    """
    Verify a submitted TOTP code.

    Security measures:
      - Decrypt the stored secret before use.
      - Accept codes within ±1 time-step (clock-drift tolerance).
      - Constant-time comparison inside verify_totp_code().
      - Reject any OTP whose time-step was already accepted (replay prevention).
      - Increment failed_attempts on every rejection.

    Returns (True, message) or (False, reason).
    """
    user = users_db.get(username)
    if not user:
        return False, "User not found"
    if not otp:
        return False, "OTP is required"

    # Decrypt the secret for this verification only
    raw_secret = load_secret(user["shared_secret"])

    matched_step = verify_totp_code(raw_secret, otp, tolerance=1)

    if matched_step is None:
        user["failed_attempts"] += 1
        return False, "Invalid or expired OTP"

    # Replay prevention: reject if this time-step was already used.
    # failed_attempts is incremented so that repeated replay attempts
    # trigger the same account-lockout policy as other failures.
    if user["last_used_step"] == matched_step:
        user["failed_attempts"] += 1
        return False, "Replay attack detected: OTP already used"

    # Accept — record the step and reset failure counter
    user["last_used_step"]  = matched_step
    user["failed_attempts"] = 0
    return True, "OTP verified successfully"


# ── Full Login (password + OTP) ───────────────

def login(username: str, password: str, otp: str):
    """
    Two-factor login: password first, then TOTP.

    Lockout policy:
      - 3 consecutive failures (wrong password or wrong OTP) lock the
        account for 30 seconds.
      - The lock expires automatically; no manual intervention required.
    """
    user = users_db.get(username)
    if not user:
        return False, "User not found"

    # Check whether account is currently locked
    if user["lock_until"] is not None:
        if time.time() < user["lock_until"]:
            remaining = int(user["lock_until"] - time.time())
            return False, f"Account locked. Try again in {remaining} second(s)."
        # Lock has expired — clear it
        user["lock_until"]      = None
        user["failed_attempts"] = 0

    # Factor 1: password
    if not verify_password(username, password):
        user["failed_attempts"] += 1
        if user["failed_attempts"] >= 3:
            user["lock_until"] = time.time() + 30
            return False, "Too many failed attempts. Account locked for 30 seconds."
        return False, "Incorrect password"

    # Factor 2: TOTP
    success, message = verify_totp(username, otp)

    if not success:
        if user["failed_attempts"] >= 3:
            user["lock_until"] = time.time() + 30
            return False, "Too many failed attempts. Account locked for 30 seconds."

    return success, message


# ── Re-enrollment ─────────────────────────────

def re_enroll_user(username: str, password: str):
    """
    Revoke the current shared secret and issue a new one.

    Re-enrollment requires password confirmation to prevent an attacker
    with physical access to an unlocked device from silently replacing
    the secret.

    Steps:
      1. Verify the user's password (constant-time).
      2. Generate a new random secret.
      3. Encrypt the new secret and overwrite the stored value.
      4. Reset replay-prevention and lockout state.

    Returns (True, plaintext_new_secret) on success.
    """
    user = users_db.get(username)
    if not user:
        return False, "User not found"

    # Require password confirmation before revoking the old secret
    if not verify_password(username, password):
        return False, "Incorrect password"

    new_raw_secret = generate_shared_secret()
    new_enc_secret = store_secret(new_raw_secret)

    user["shared_secret"]   = new_enc_secret   # old secret is overwritten
    user["last_used_step"]  = None
    user["failed_attempts"] = 0
    user["lock_until"]      = None

    return True, new_raw_secret
