import hashlib
import hmac
import secrets
import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# PBKDF2 settings
# 260,000 iterations based on NIST SP 800-132 recommendations
_PBKDF2_ITERATIONS = 260_000
_PBKDF2_HASH = "sha256"
_SALT_BYTES = 32


def generate_salt() -> str:
    # each user gets a unique random salt
    return secrets.token_hex(_SALT_BYTES)


def hash_password(password: str, salt: str) -> str:
    # PBKDF2-HMAC-SHA256 makes brute-force expensive
    dk = hashlib.pbkdf2_hmac(
        _PBKDF2_HASH,
        password.encode("utf-8"),
        salt.encode("utf-8"),
        _PBKDF2_ITERATIONS,
        dklen=32
    )
    return dk.hex()


def verify_password(stored_hash: str, stored_salt: str, provided_password: str) -> bool:
    # constant-time compare to prevent timing attacks
    computed = hash_password(provided_password, stored_salt)
    return hmac.compare_digest(computed, stored_hash)


# AES master key - in production load from environment variable
# never hard-code this in a real system
_AES_MASTER_KEY_STR = os.environ.get("TOTP_AES_MASTER_KEY", "totp-demo-aes-master-key-32byte!")
_AES_MASTER_KEY = _AES_MASTER_KEY_STR.encode("utf-8")[:32].ljust(32, b"0")


def _derive_aes_key() -> bytes:
    # SHA-256 gives us a clean 32-byte key for AES-256
    return hashlib.sha256(_AES_MASTER_KEY).digest()


def encrypt_secret(plaintext: str) -> str:
    # AES-256-CBC with a fresh random IV each time
    # format: Base64(IV + ciphertext)
    key = _derive_aes_key()
    iv = secrets.token_bytes(16)

    # PKCS#7 padding
    raw = plaintext.encode("utf-8")
    pad_len = 16 - (len(raw) % 16)
    padded = raw + bytes([pad_len] * pad_len)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return base64.b64encode(iv + ciphertext).decode("utf-8")


def decrypt_secret(encrypted: str) -> str:
    # extract IV from first 16 bytes then decrypt
    key = _derive_aes_key()
    raw = base64.b64decode(encrypted)
    iv = raw[:16]
    ct = raw[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()

    # remove PKCS#7 padding
    pad_len = padded[-1]
    return padded[:-pad_len].decode("utf-8")


def store_secret(secret: str) -> str:
    return encrypt_secret(secret)


def load_secret(encrypted: str) -> str:
    return decrypt_secret(encrypted)
