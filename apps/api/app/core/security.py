"""Security utilities: HMAC, encryption, OTP, tokens, constant-time compare."""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import struct
import time
from base64 import urlsafe_b64decode, urlsafe_b64encode
from typing import Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ── HMAC helpers ─────────────────────────────────────────────────

def hmac_sha256(data: str, key: str) -> str:
    """HMAC-SHA256 of *data* keyed by *key*. Returns hex digest."""
    return hmac.new(
        key.encode("utf-8"),
        data.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def hash_sha256(data: str) -> str:
    """Plain SHA-256 hex digest."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def hash_ip(ip: str) -> str:
    """Hash an IP for storage — never store raw."""
    return hashlib.sha256(ip.encode("utf-8")).hexdigest()[:16]


def constant_time_compare(a: str, b: str) -> bool:
    """Constant-time string comparison."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


# ── OTP ──────────────────────────────────────────────────────────

def generate_otp() -> str:
    """Generate a 6-digit OTP using CSPRNG."""
    return f"{secrets.randbelow(1_000_000):06d}"


def hash_otp(otp: str, pepper: str) -> str:
    """HMAC-hash an OTP for storage."""
    return hmac_sha256(otp, pepper)


# ── Magic link token ─────────────────────────────────────────────

def generate_magic_token() -> str:
    """Generate a 256-bit URL-safe token."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """SHA-256 hash a token for storage."""
    return hash_sha256(token)


# ── Session ──────────────────────────────────────────────────────

def create_session_token(scan_id: str, secret: str) -> str:
    """Create a signed session token binding to a scan ID."""
    payload = f"{scan_id}:{int(time.time())}"
    sig = hmac_sha256(payload, secret)
    raw = f"{payload}:{sig}"
    return urlsafe_b64encode(raw.encode()).decode()


def verify_session_token(token: str, secret: str) -> Optional[str]:
    """Verify and extract scan_id from session token. Returns None on failure."""
    try:
        raw = urlsafe_b64decode(token.encode()).decode()
        parts = raw.split(":")
        if len(parts) != 3:
            return None
        scan_id, ts_str, sig = parts
        expected = hmac_sha256(f"{scan_id}:{ts_str}", secret)
        if not constant_time_compare(sig, expected):
            return None
        # 24-hour max lifetime
        if time.time() - int(ts_str) > 86400:
            return None
        return scan_id
    except Exception:
        return None


# ── AES-256-GCM envelope encryption ─────────────────────────────

def _derive_key(master_hex: str) -> bytes:
    """Derive a 32-byte key from hex-encoded master key."""
    raw = bytes.fromhex(master_hex)
    if len(raw) != 32:
        raise ValueError("MASTER_KEY must be 32 bytes (64 hex chars)")
    return raw


def encrypt_payload(plaintext: bytes, master_key_hex: str, key_id: str = "v1") -> Tuple[bytes, str]:
    """
    Envelope-encrypt *plaintext*.

    Returns (ciphertext_blob, key_id).
    Blob format: 12-byte nonce ‖ 32-byte wrapped-DEK ‖ 12-byte DEK-nonce ‖ ciphertext
    """
    master = _derive_key(master_key_hex)

    # Per-scan data key
    dek = AESGCM(os.urandom(32))
    dek_raw = os.urandom(32)
    dek = AESGCM(dek_raw)

    # Encrypt plaintext with DEK
    dek_nonce = os.urandom(12)
    ct = dek.encrypt(dek_nonce, plaintext, None)

    # Wrap DEK with master key
    master_aesgcm = AESGCM(master)
    wrap_nonce = os.urandom(12)
    wrapped_dek = master_aesgcm.encrypt(wrap_nonce, dek_raw, None)

    # Blob: wrap_nonce(12) + wrapped_dek(32+16) + dek_nonce(12) + ct
    blob = wrap_nonce + wrapped_dek + dek_nonce + ct
    return blob, key_id


def decrypt_payload(blob: bytes, master_key_hex: str) -> bytes:
    """Decrypt an envelope-encrypted blob."""
    master = _derive_key(master_key_hex)
    master_aesgcm = AESGCM(master)

    wrap_nonce = blob[:12]
    wrapped_dek = blob[12:60]  # 32 bytes + 16 bytes GCM tag
    dek_nonce = blob[60:72]
    ct = blob[72:]

    dek_raw = master_aesgcm.decrypt(wrap_nonce, wrapped_dek, None)
    dek = AESGCM(dek_raw)
    return dek.decrypt(dek_nonce, ct, None)


# ── Queue payload encryption (simpler, symmetric) ───────────────

def encrypt_queue_payload(plaintext: bytes, key_hex: str) -> bytes:
    """Encrypt a queue payload with AES-256-GCM. Returns nonce + ciphertext."""
    key = bytes.fromhex(key_hex)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct


def decrypt_queue_payload(blob: bytes, key_hex: str) -> bytes:
    """Decrypt a queue payload."""
    key = bytes.fromhex(key_hex)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(blob[:12], blob[12:], None)
