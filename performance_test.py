import sys, os, time, statistics
sys.path.insert(0, '/mnt/user-data/uploads')
 
from auth import register_user, login, re_enroll_user
from totp_utils import generate_totp, generate_shared_secret
from security import load_secret, hash_password, generate_salt, encrypt_secret, decrypt_secret
from users import users_db
 
RUNS = 50  # number of repetitions per operation
SEP  = "─" * 52
 
def measure(label, fn, runs=RUNS):
    times = []
    for _ in range(runs):
        start = time.perf_counter()
        fn()
        times.append((time.perf_counter() - start) * 1000)
    avg  = statistics.mean(times)
    minn = min(times)
    maxx = max(times)
    print(f"  {label}")
    print(f"    avg={avg:.2f} ms  min={minn:.2f} ms  max={maxx:.2f} ms  (n={runs})")
    return avg
 
print(f"\n{'═'*52}")
print("  TOTP System — Performance test")
print(f"{'═'*52}\n")
 
# ── Setup a test user ──────────────────────────
register_user("bench_user", "BenchPass99!")
enc = users_db["bench_user"]["shared_secret"]
raw = load_secret(enc)
salt = users_db["bench_user"]["salt"]
 
print(f"{SEP}")
print("  1. REGISTRATION")
print(f"{SEP}")
# Each run registers a fresh username
reg_times = []
for i in range(RUNS):
    uname = f"reg_test_{i}"
    start = time.perf_counter()
    register_user(uname, "BenchPass99!")
    reg_times.append((time.perf_counter() - start) * 1000)
avg_reg = statistics.mean(reg_times)
print(f"  register_user()")
print(f"    avg={avg_reg:.2f} ms  min={min(reg_times):.2f} ms  max={max(reg_times):.2f} ms  (n={RUNS})")
 
print(f"\n{SEP}")
print("  2. PASSWORD HASHING  (PBKDF2)")
print(f"{SEP}")
avg_hash = measure("hash_password()", lambda: hash_password("BenchPass99!", salt))
 
print(f"\n{SEP}")
print("  3. OTP GENERATION")
print(f"{SEP}")
avg_otp_gen = measure("generate_totp(secret)", lambda: generate_totp(raw), runs=500)
 
print(f"\n{SEP}")
print("  4. SECRET ENCRYPTION / DECRYPTION  (AES-256)")
print(f"{SEP}")
test_secret = generate_shared_secret()
avg_enc = measure("encrypt_secret()", lambda: encrypt_secret(test_secret), runs=500)
enc_val  = encrypt_secret(test_secret)
avg_dec = measure("decrypt_secret()", lambda: decrypt_secret(enc_val), runs=500)
 
print(f"\n{SEP}")
print("  5. FULL LOGIN  (password + OTP)")
print(f"{SEP}")
# Successful login
login_times = []
for _ in range(RUNS):
    users_db["bench_user"]["failed_attempts"] = 0
    users_db["bench_user"]["lock_until"]      = None
    users_db["bench_user"]["last_used_step"]  = None
    otp = generate_totp(raw)
    start = time.perf_counter()
    login("bench_user", "BenchPass99!", otp)
    login_times.append((time.perf_counter() - start) * 1000)
avg_login = statistics.mean(login_times)
print(f"  login() — correct password + valid OTP")
print(f"    avg={avg_login:.2f} ms  min={min(login_times):.2f} ms  max={max(login_times):.2f} ms  (n={RUNS})")
 
# Failed login — wrong password
fail_times = []
for _ in range(RUNS):
    users_db["bench_user"]["failed_attempts"] = 0
    users_db["bench_user"]["lock_until"]      = None
    start = time.perf_counter()
    login("bench_user", "WrongPass99!", "000000")
    fail_times.append((time.perf_counter() - start) * 1000)
avg_fail = statistics.mean(fail_times)
print(f"  login() — wrong password")
print(f"    avg={avg_fail:.2f} ms  min={min(fail_times):.2f} ms  max={max(fail_times):.2f} ms  (n={RUNS})")
 
print(f"\n{SEP}")
print("  6. RE-ENROLLMENT")
print(f"{SEP}")
re_times = []
for i in range(RUNS):
    uname = f"re_test_{i}"
    register_user(uname, "BenchPass99!")
    start = time.perf_counter()
    re_enroll_user(uname, "BenchPass99!")
    re_times.append((time.perf_counter() - start) * 1000)
avg_re = statistics.mean(re_times)
print(f"  re_enroll_user()")
print(f"    avg={avg_re:.2f} ms  min={min(re_times):.2f} ms  max={max(re_times):.2f} ms  (n={RUNS})")
 
print(f"\n{'═'*52}")
print("  SUMMARY")
print(f"{'═'*52}")
print(f"  Registration          : {avg_reg:.0f} ms")
print(f"  Password hashing      : {avg_hash:.0f} ms")
print(f"  OTP generation        : {avg_otp_gen:.3f} ms")
print(f"  AES encrypt           : {avg_enc:.3f} ms")
print(f"  AES decrypt           : {avg_dec:.3f} ms")
print(f"  Full login (success)  : {avg_login:.0f} ms")
print(f"  Full login (failure)  : {avg_fail:.0f} ms")
print(f"  Re-enrollment         : {avg_re:.0f} ms")
print(f"{'═'*52}\n")
 