"""
attack_simulation.py
────────────────────

Demonstrates four attack scenarios against the TOTP system and shows
that each one is blocked by the implemented countermeasures.

  Scenario 1 – Brute-Force Attack
      Tries every 6-digit OTP (000000–999999).
      Blocked by: account lockout after 3 failures.

  Scenario 2 – Replay Attack (same time-step)
      Reuses a valid OTP within the same 30-second window.
      Blocked by: last_used_step tracking per user.

  Scenario 3 – Expired OTP Replay
      Uses an OTP generated for a past time-step (outside tolerance).
      Blocked by: tolerance window only accepts current ±1 step.

  Scenario 4 – Re-enrollment invalidates old secret
      After re-enrollment the original OTP is no longer valid.
      Blocked by: secret revocation on re-enroll.
"""

import sys, os, time
sys.path.insert(0, os.path.dirname(__file__))

from auth import register_user, login, re_enroll_user, verify_totp
from totp_utils import _hotp, get_current_timestep, generate_totp
from security import load_secret
from users import users_db

SEP  = "─" * 56
SEP2 = "═" * 56


def hdr(title):
    print(f"\n{SEP}\n  {title}\n{SEP}")


def reset(username):
    if username in users_db:
        users_db[username]["failed_attempts"] = 0
        users_db[username]["lock_until"]      = None
        users_db[username]["last_used_step"]  = None


def setup(username="victim", password="SecurePass99!"):
    """Register the test account (or reset if it already exists)."""
    if username not in users_db:
        ok, secret = register_user(username, password)
        print(f"  [Setup] Account '{username}' created.")
        print(f"  [Setup] Plaintext secret (for reference): {secret}")
    else:
        reset(username)
        print(f"  [Setup] Using existing account '{username}' (state reset).")
    return username, password


# ──────────────────────────────────────────────
# Scenario 1 — Brute-Force
# ──────────────────────────────────────────────

def scenario_brute_force(username, password):
    hdr("SCENARIO 1 — Brute-Force Attack")
    print(f"  Method  : try every OTP from 000000 to 999999")
    print(f"  Defense : lockout after 3 consecutive wrong attempts\n")
    reset(username)

    attempts = 0
    for guess in range(1_000_000):
        otp = f"{guess:06d}"
        attempts += 1
        ok, msg = login(username, password, otp)
        print(f"  Attempt {attempts:>3}  OTP={otp}  → {msg}")

        if ok:
            print("\n    Attack SUCCEEDED — check lockout logic!")
            return

        if "locked" in msg.lower():
            print(f"\n   Locked after {attempts} attempt(s).")
            print( "   Brute-force BLOCKED.")
            print( "     Each lock = 30 s wait → full search ≈ years.")
            return

    print("  ✅ All guesses exhausted without success.")


# ──────────────────────────────────────────────
# Scenario 2 — Replay (same window)
# ──────────────────────────────────────────────

def scenario_replay(username, password):
    hdr("SCENARIO 2 — Replay Attack (same time-step)")
    print(f"  Method  : capture a valid OTP and submit it twice")
    print(f"  Defense : last_used_step stored per user\n")
    reset(username)

    enc = users_db[username]["shared_secret"]
    raw = load_secret(enc)
    otp = generate_totp(raw)
    print(f"  [Attacker intercepts OTP]: {otp}")

    ok1, msg1 = login(username, password, otp)
    print(f"\n  1st submission → {'✅' if ok1 else '❌'} {msg1}")

    ok2, msg2 = login(username, password, otp)
    print(f"  2nd submission → {'✅' if ok2 else '❌'} {msg2}")

    print()
    if not ok2 and "replay" in msg2.lower():
        print("   Replay BLOCKED.")
    elif ok2:
        print("   Replay SUCCEEDED — fix replay prevention!")
    else:
        print(f"   Rejected ({msg2}).")


# ──────────────────────────────────────────────
# Scenario 3 — Expired OTP
# ──────────────────────────────────────────────

def scenario_expired_otp(username, password):
    hdr("SCENARIO 3 — Expired OTP Replay")
    print(f"  Method  : submit an OTP from 5 time-steps ago (2.5 min old)")
    print(f"  Defense : tolerance window is ±1 step only\n")
    reset(username)

    enc        = users_db[username]["shared_secret"]
    raw        = load_secret(enc)
    old_step   = get_current_timestep() - 5          # 5 steps = 150 s ago
    old_otp    = _hotp(raw, old_step)

    print(f"  Current time-step : {get_current_timestep()}")
    print(f"  OTP time-step     : {old_step}  (150 seconds ago)")
    print(f"  Expired OTP       : {old_otp}")

    ok, msg = login(username, password, old_otp)
    print(f"\n  Submission → {'' if ok else '❌'} {msg}")

    print()
    if not ok:
        print("   Expired OTP REJECTED.")
    else:
        print("    Expired OTP ACCEPTED — check tolerance window!")


# ──────────────────────────────────────────────
# Scenario 4 — Re-enrollment invalidates old secret
# ──────────────────────────────────────────────

def scenario_reenrollment(username, password):
    hdr("SCENARIO 4 — Re-enrollment Invalidates Old Secret")
    print(f"  Method  : capture OTP before re-enrollment, replay after")
    print(f"  Defense : old secret is revoked and replaced\n")
    reset(username)

    # Capture current OTP with the OLD secret
    enc_old = users_db[username]["shared_secret"]
    raw_old = load_secret(enc_old)
    otp_old = generate_totp(raw_old)
    print(f"  OTP captured with OLD secret : {otp_old}")

    # Re-enroll — generates a new secret
    ok_re, new_secret = re_enroll_user(username, password)
    if ok_re:
        print(f"  Re-enrollment successful.  New secret: {new_secret}")
    else:
        print(f"  Re-enrollment failed: {new_secret}")
        return

    # Try the old OTP after re-enrollment
    reset(username)
    ok, msg = login(username, password, otp_old)
    print(f"\n  Old OTP after re-enrollment → {'✅' if ok else '❌'} {msg}")

    print()
    if not ok:
        print("   Old OTP correctly REJECTED after re-enrollment.")
    else:
        print("    Old OTP still works — re-enrollment is broken!")


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────

def main():
    print(f"\n{SEP2}")
    print("   TOTP Security — Attack Simulation")

    print(f"{SEP2}")

    username, password = setup()

    scenario_brute_force(username, password)
    time.sleep(0.5)

    scenario_replay(username, password)
    time.sleep(0.5)

    scenario_expired_otp(username, password)
    time.sleep(0.5)

    scenario_reenrollment(username, password)

    print(f"\n{SEP2}")
    print("  All scenarios complete.")
    print(f"{SEP2}\n")


if __name__ == "__main__":
    main()
