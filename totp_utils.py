"""
totp_utils.py
─────────────
Responsible for:
  - Shared secret generation
  - TOTP code generation (HMAC-SHA1 based, RFC 6238)
  - Manual HMAC-SHA1 + dynamic truncation implementation
  - Time-step calculation (30-second window)

All TOTP logic follows RFC 6238 (TOTP) and RFC 4226 (HOTP).
"""

import hmac
import hashlib
import struct
import time
import base64
import secrets


# ── Constants ─────────────────────────────────
TOTP_INTERVAL = 30        # seconds per time-step (RFC 6238 default)
TOTP_DIGITS   = 6         # output length
T0            = 0         # Unix epoch as reference point


# ── Secret Generation ─────────────────────────

def generate_shared_secret() -> str:
    """
    Generate a cryptographically random 20-byte secret and encode it
    as Base32.  Base32 is the standard encoding for TOTP secrets because
    it is case-insensitive and avoids ambiguous characters.
    20 bytes = 160 bits, matching the output size of SHA-1.
    """
    raw = secrets.token_bytes(20)
    return base64.b32encode(raw).decode("utf-8")


# ── Time-Step ─────────────────────────────────

def get_current_timestep() -> int:
    """
    Compute T = floor((current_time - T0) / X)
    where T0 = 0 (Unix epoch) and X = 30 seconds.
    This value increments every 30 seconds and is the counter
    fed into HOTP to produce a TOTP code.
    """
    return int(time.time() - T0) // TOTP_INTERVAL


# ── HMAC-SHA1 Core (manual implementation) ────

def _hotp(secret_b32: str, counter: int) -> str:
    """
    Compute one HOTP value for the given Base32 secret and counter.
    Implements the algorithm defined in RFC 4226, Section 5:

      Step 1 – HS = HMAC-SHA1(K, C)
               K = secret key (decoded from Base32)
               C = 8-byte big-endian counter

      Step 2 – Dynamic Truncation
               offset  = HS[19] & 0x0F
               P       = HS[offset : offset+4]
               code    = (P as 31-bit integer) mod 10^Digit

    Returns a zero-padded string of length TOTP_DIGITS.
    """
    # Decode the Base32 secret to raw bytes
    key = base64.b32decode(secret_b32.upper())

    # Encode the counter as an 8-byte big-endian value
    counter_bytes = struct.pack(">Q", counter)

    # Step 1: HMAC-SHA1
    hs = hmac.new(key, counter_bytes, hashlib.sha1).digest()   # 20 bytes

    # Step 2: Dynamic truncation
    offset = hs[19] & 0x0F                        # last nibble of digest
    p = struct.unpack(">I", hs[offset:offset + 4])[0]
    code = (p & 0x7FFFFFFF) % (10 ** TOTP_DIGITS) # 31-bit integer mod 10^6

    return str(code).zfill(TOTP_DIGITS)


def generate_totp(secret_b32: str) -> str:
    """
    Generate the current TOTP code.
    TOTP(K, T) = HOTP(K, T)  where T = current time-step.
    """
    return _hotp(secret_b32, get_current_timestep())


def verify_totp_code(secret_b32: str, submitted_otp: str,
                     tolerance: int = 1) -> int | None:
    """
    Verify a submitted OTP against the current time-step ± tolerance.
    A tolerance of 1 accepts codes from the previous and next window,
    compensating for up to 30 seconds of clock drift (RFC 6238 §5.2).

    Returns the matched time-step (int) so the caller can store it for
    replay prevention, or None if no window matched.

    Uses hmac.compare_digest for constant-time comparison to prevent
    timing side-channel attacks.
    """
    current = get_current_timestep()
    for delta in range(-tolerance, tolerance + 1):
        step = current + delta
        expected = _hotp(secret_b32, step)
        # Constant-time comparison — prevents timing oracle attacks
        if hmac.compare_digest(expected, submitted_otp):
            return step
    return None

