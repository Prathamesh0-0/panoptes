"""
PANOPTES — Hybrid PQC Credential Vault
Architecture: HPKE (Hybrid Public Key Encryption)
  KEM layer  : X25519 ECDH (ephemeral per-message key agreement)
  Symmetric  : AES-256-GCM (NIST FIPS 197 + SP 800-38D)
  KDF        : HKDF-SHA256 (RFC 5869)

When liboqs native library is compiled and placed in PATH, this module
automatically upgrades to ML-KEM-768 (NIST FIPS 203 / Kyber768).

The architecture is PQC-ready: swapping X25519→ML-KEM only changes
the KEM layer; all AES-GCM ciphertext format stays identical.
"""
import os
import json
import struct
import hmac
import hashlib
import logging
from typing import Tuple, Dict, Any

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger("panoptes.pqc_vault")

# ─── Try real liboqs (ML-KEM-768) ────────────────────────────────────────────
_USE_PQC = False
try:
    import ctypes, ctypes.util
    _lib_name = ctypes.util.find_library("oqs") or ctypes.util.find_library("liboqs")
    if _lib_name:
        import oqs as _oqs_mod
        # Quick smoke-test
        _t = _oqs_mod.KeyEncapsulation("Kyber768")
        _t.free()
        _USE_PQC = True
        logger.info("PQC: liboqs native found — ML-KEM-768 ACTIVE")
except Exception:
    pass

if _USE_PQC:
    import oqs as _oqs_mod

    def _kem_generate_keypair() -> Tuple[bytes, bytes]:
        kem = _oqs_mod.KeyEncapsulation("Kyber768")
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
        kem.free()
        return pk, sk

    def _kem_encap(pk: bytes) -> Tuple[bytes, bytes]:
        kem = _oqs_mod.KeyEncapsulation("Kyber768")
        ct, ss = kem.encap_secret(pk)
        kem.free()
        return ct, ss

    def _kem_decap(ct: bytes, sk: bytes) -> bytes:
        kem = _oqs_mod.KeyEncapsulation("Kyber768", sk)
        ss = kem.decap_secret(ct)
        kem.free()
        return ss

    PQC_AVAILABLE    = True
    KEM_ALGORITHM    = "ML-KEM-768 (Kyber768)"
    KEM_STANDARD     = "NIST FIPS 203"
    KEM_PK_BYTES     = 1184
    KEM_CT_BYTES     = 1088

else:
    # ── X25519 ECDH KEM (HPKE-like, PQC-ready architecture) ─────────────────
    def _kem_generate_keypair() -> Tuple[bytes, bytes]:
        sk = X25519PrivateKey.generate()
        pk = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        sk_b = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        return pk, sk_b

    def _kem_encap(pk: bytes) -> Tuple[bytes, bytes]:
        """Ephemeral sender key → DH → HKDF → shared secret."""
        eph_sk = X25519PrivateKey.generate()
        eph_pk = eph_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        peer_pk = X25519PublicKey.from_public_bytes(pk)
        dh = eph_sk.exchange(peer_pk)
        ss = _hkdf(dh, info=b"PANOPTES-KEM-v1")
        return eph_pk, ss

    def _kem_decap(ct: bytes, sk_b: bytes) -> bytes:
        """Receiver decapsulates shared secret from ephemeral public key."""
        sk = X25519PrivateKey.from_private_bytes(sk_b)
        eph_pk = X25519PublicKey.from_public_bytes(ct)
        dh = sk.exchange(eph_pk)
        return _hkdf(dh, info=b"PANOPTES-KEM-v1")

    PQC_AVAILABLE    = False
    KEM_ALGORITHM    = "X25519-ECDH-HPKE + AES-256-GCM"
    KEM_STANDARD     = "RFC 9180 (HPKE) / PQC-ready architecture"
    KEM_PK_BYTES     = 32
    KEM_CT_BYTES     = 32

    logger.info("PQC: Using X25519 HPKE (PQC-ready — upgrade to ML-KEM-768 by installing liboqs)")


# ─── KDF helper ──────────────────────────────────────────────────────────────
def _hkdf(ikm: bytes, info: bytes = b"", length: int = 32) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    ).derive(ikm)


# ─── AES-256-GCM symmetric layer ─────────────────────────────────────────────
def _aes_encrypt(pt: bytes, key: bytes) -> bytes:
    """Returns nonce || ciphertext."""
    nonce = os.urandom(12)
    return nonce + AESGCM(key[:32]).encrypt(nonce, pt, None)


def _aes_decrypt(data: bytes, key: bytes) -> bytes:
    return AESGCM(key[:32]).decrypt(data[:12], data[12:], None)


# ─── Per-instance vault key pair ─────────────────────────────────────────────
_VAULT_PK, _VAULT_SK = _kem_generate_keypair()


# ─── Public API ──────────────────────────────────────────────────────────────
def encrypt_credential(plaintext: str) -> Dict[str, Any]:
    """Encrypt a credential. Returns storage-ready dict."""
    kem_ct, ss = _kem_encap(_VAULT_PK)
    aes_ct = _aes_encrypt(plaintext.encode(), ss)
    return {
        "public_key_hex":    _VAULT_PK.hex(),
        "kem_ciphertext_hex": kem_ct.hex(),
        "ciphertext_hex":    aes_ct.hex(),
        "kem_algorithm":     KEM_ALGORITHM,
        "metadata": {
            "kem_algorithm":           KEM_ALGORITHM,
            "kem_standard":            KEM_STANDARD,
            "public_key_size_bytes":   KEM_PK_BYTES,
            "kem_ciphertext_size_bytes": KEM_CT_BYTES,
            "symmetric_algorithm":     "AES-256-GCM (NIST FIPS 197)",
            "nonce_size_bytes":        12,
            "pqc_real":                PQC_AVAILABLE,
        },
    }


def decrypt_credential(kem_ct_hex: str, ct_hex: str) -> str:
    """Decrypt a stored credential."""
    ss = _kem_decap(bytes.fromhex(kem_ct_hex), _VAULT_SK)
    return _aes_decrypt(bytes.fromhex(ct_hex), ss).decode()


def get_pqc_vault_status() -> Dict[str, Any]:
    return {
        "kem_algorithm":             KEM_ALGORITHM,
        "kem_standard":              KEM_STANDARD,
        "public_key_size_bytes":     KEM_PK_BYTES,
        "kem_ciphertext_size_bytes": KEM_CT_BYTES,
        "symmetric_algorithm":       "AES-256-GCM",
        "pqc_real":                  PQC_AVAILABLE,
        "vault_public_key_preview":  _VAULT_PK.hex()[:32] + "...",
    }
