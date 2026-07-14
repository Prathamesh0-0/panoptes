"""
PANOPTES — PQC Credential Vault
Encrypts credentials using ML-KEM-768 (Kyber) + AES-256-GCM.
Uses liboqs-python if available; falls back to X25519 + AES-256-GCM.
"""
import os
import json
import logging
import hashlib
from typing import Tuple, Dict, Any

logger = logging.getLogger("panoptes.pqc_vault")

# ── Try liboqs (real PQC) ────────────────────────────────────────────────────
try:
    import oqs
    _KEM_ALG = "Kyber768"

    def _kem_generate_keypair() -> Tuple[bytes, bytes]:
        kem = oqs.KeyEncapsulation(_KEM_ALG)
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
        kem.free()
        return pk, sk

    def _kem_encap(public_key: bytes) -> Tuple[bytes, bytes]:
        """Returns (ciphertext, shared_secret)."""
        kem = oqs.KeyEncapsulation(_KEM_ALG)
        ciphertext, shared_secret = kem.encap_secret(public_key)
        kem.free()
        return ciphertext, shared_secret

    def _kem_decap(ciphertext: bytes, secret_key: bytes) -> bytes:
        kem = oqs.KeyEncapsulation(_KEM_ALG, secret_key)
        shared_secret = kem.decap_secret(ciphertext)
        kem.free()
        return shared_secret

    PQC_AVAILABLE = True
    PQC_KEM_ALGORITHM = "ML-KEM-768 (Kyber768)"
    PQC_KEM_STANDARD = "NIST FIPS 203"
    PQC_KEM_PUBLIC_KEY_SIZE = 1184
    PQC_KEM_CIPHERTEXT_SIZE = 1088
    logger.info("PQC: liboqs loaded — using ML-KEM-768 (real NIST PQC)")

except Exception:
    # ── Fallback: X25519 ECDH + AES-256-GCM ──────────────────────────────────
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat, PrivateFormat, NoEncryption
    )

    def _kem_generate_keypair() -> Tuple[bytes, bytes]:
        sk = X25519PrivateKey.generate()
        pk = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        sk_bytes = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        return pk, sk_bytes

    def _kem_encap(public_key: bytes) -> Tuple[bytes, bytes]:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        eph_sk = X25519PrivateKey.generate()
        eph_pk = eph_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        peer_pk = X25519PublicKey.from_public_bytes(public_key)
        shared = eph_sk.exchange(peer_pk)
        return eph_pk, hashlib.sha256(shared).digest()

    def _kem_decap(ciphertext: bytes, secret_key: bytes) -> bytes:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
        sk = X25519PrivateKey.from_private_bytes(secret_key)
        peer_pk = X25519PublicKey.from_public_bytes(ciphertext)
        shared = sk.exchange(peer_pk)
        return hashlib.sha256(shared).digest()

    PQC_AVAILABLE = False
    logger.warning("PQC: liboqs native library not available — using X25519 + AES-256-GCM fallback")
    PQC_KEM_ALGORITHM = "X25519-ECDH + AES-256-GCM (Classical fallback — install liboqs-python for ML-KEM)"
    PQC_KEM_STANDARD = "RFC 7748 (fallback)"
    PQC_KEM_PUBLIC_KEY_SIZE = 32
    PQC_KEM_CIPHERTEXT_SIZE = 32
    logger.warning("PQC: liboqs not available — using X25519 fallback")

# ── AES-256-GCM (symmetric layer, same in both cases) ────────────────────────
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _aes_gcm_encrypt(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes]:
    nonce = os.urandom(12)
    aes = AESGCM(key[:32])
    ct = aes.encrypt(nonce, plaintext, None)
    return nonce, ct


def _aes_gcm_decrypt(nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
    aes = AESGCM(key[:32])
    return aes.decrypt(nonce, ciphertext, None)


# ── Vault key pair (per-instance, in-memory for demo) ────────────────────────
_VAULT_PUBLIC_KEY, _VAULT_SECRET_KEY = _kem_generate_keypair()


def encrypt_credential(plaintext: str) -> Dict[str, Any]:
    """
    Encrypt a credential string.
    Returns a dict suitable for storage in CredentialVault table.
    """
    plaintext_bytes = plaintext.encode("utf-8")
    kem_ciphertext, shared_secret = _kem_encap(_VAULT_PUBLIC_KEY)
    nonce, aes_ciphertext = _aes_gcm_encrypt(plaintext_bytes, shared_secret)

    return {
        "public_key_hex": _VAULT_PUBLIC_KEY.hex(),
        "kem_ciphertext_hex": kem_ciphertext.hex(),
        "ciphertext_hex": (nonce + aes_ciphertext).hex(),
        "kem_algorithm": PQC_KEM_ALGORITHM,
        "metadata": {
            "kem_algorithm": PQC_KEM_ALGORITHM,
            "kem_standard": PQC_KEM_STANDARD,
            "public_key_size_bytes": PQC_KEM_PUBLIC_KEY_SIZE,
            "kem_ciphertext_size_bytes": PQC_KEM_CIPHERTEXT_SIZE,
            "symmetric_algorithm": "AES-256-GCM",
            "nonce_size_bytes": 12,
            "pqc_real": PQC_AVAILABLE,
        },
    }


def decrypt_credential(kem_ciphertext_hex: str, ciphertext_hex: str) -> str:
    """Decrypt a credential from vault storage."""
    kem_ct = bytes.fromhex(kem_ciphertext_hex)
    full_ct = bytes.fromhex(ciphertext_hex)
    nonce = full_ct[:12]
    aes_ct = full_ct[12:]

    shared_secret = _kem_decap(kem_ct, _VAULT_SECRET_KEY)
    plaintext_bytes = _aes_gcm_decrypt(nonce, aes_ct, shared_secret)
    return plaintext_bytes.decode("utf-8")


def get_pqc_vault_status() -> Dict[str, Any]:
    return {
        "kem_algorithm": PQC_KEM_ALGORITHM,
        "kem_standard": PQC_KEM_STANDARD,
        "public_key_size_bytes": PQC_KEM_PUBLIC_KEY_SIZE,
        "kem_ciphertext_size_bytes": PQC_KEM_CIPHERTEXT_SIZE,
        "symmetric_algorithm": "AES-256-GCM",
        "pqc_real": PQC_AVAILABLE,
        "vault_public_key_preview": _VAULT_PUBLIC_KEY.hex()[:32] + "...",
    }
