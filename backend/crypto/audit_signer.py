"""
PANOPTES — Quantum-Safe Audit Log Signer
Signs audit log entries with ML-DSA-65 (Dilithium3) so logs are tamper-evident.
Uses liboqs-python if available; falls back to Ed25519.
"""
import json
import hashlib
import logging
from typing import Dict, Any, Tuple

logger = logging.getLogger("panoptes.audit_signer")

# ── Try liboqs (real PQC signatures) ─────────────────────────────────────────
try:
    import oqs
    _SIG_ALG = "Dilithium3"

    _sig_keygen = oqs.Signature(_SIG_ALG)
    _SIG_PUBLIC_KEY = _sig_keygen.generate_keypair()
    _SIG_SECRET_KEY = _sig_keygen.export_secret_key()
    _sig_keygen.free()

    def _sign(message: bytes) -> bytes:
        sig = oqs.Signature(_SIG_ALG, _SIG_SECRET_KEY)
        signature = sig.sign(message)
        sig.free()
        return signature

    def _verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
        try:
            verifier = oqs.Signature(_SIG_ALG)
            result = verifier.verify(message, signature, public_key)
            verifier.free()
            return result
        except Exception:
            return False

    PQC_SIG_AVAILABLE = True
    PQC_SIG_ALGORITHM = "ML-DSA-65 (Dilithium3)"
    PQC_SIG_STANDARD = "NIST FIPS 204"
    PQC_SIG_PUBLIC_KEY_SIZE = 1952
    PQC_SIG_SIZE = 3293
    logger.info("PQC: liboqs loaded — using ML-DSA-65 for audit signing")

except Exception:
    # ── Fallback: Ed25519 ──────────────────────────────────────────────────────
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat, PrivateFormat, NoEncryption
    )

    _ed_private_key = Ed25519PrivateKey.generate()
    _ed_public_key = _ed_private_key.public_key()
    _SIG_PUBLIC_KEY = _ed_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    _SIG_SECRET_KEY = _ed_private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    def _sign(message: bytes) -> bytes:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        sk = Ed25519PrivateKey.from_private_bytes(_SIG_SECRET_KEY)
        return sk.sign(message)

    def _verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            pk = Ed25519PublicKey.from_public_bytes(public_key)
            pk.verify(signature, message)
            return True
        except Exception:
            return False

    PQC_SIG_AVAILABLE = False
    PQC_SIG_ALGORITHM = "Ed25519 (Classical fallback — install liboqs-python for ML-DSA)"
    PQC_SIG_STANDARD = "RFC 8032 (fallback)"
    PQC_SIG_PUBLIC_KEY_SIZE = 32
    PQC_SIG_SIZE = 64
    logger.warning("PQC: liboqs not available — using Ed25519 fallback for signatures")


def _canonicalize(entry: Dict) -> bytes:
    """Stable JSON serialization for signing."""
    return json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_entry(entry: Dict) -> Dict[str, Any]:
    """
    Sign an audit log entry.
    Returns the entry augmented with 'signature' and 'public_key' fields.
    """
    canonical = _canonicalize(entry)
    content_hash = hashlib.sha256(canonical).hexdigest()
    signature = _sign(canonical)

    return {
        **entry,
        "content_hash": content_hash,
        "signature": signature.hex(),
        "public_key": _SIG_PUBLIC_KEY.hex(),
        "sig_algorithm": PQC_SIG_ALGORITHM,
    }


def verify_entry(signed_entry: Dict) -> Dict[str, Any]:
    """
    Verify an audit log entry's signature.
    Returns {valid: bool, reason: str}
    """
    # Extract signing fields
    entry = {k: v for k, v in signed_entry.items()
             if k not in ("signature", "public_key", "content_hash", "sig_algorithm")}

    canonical = _canonicalize(entry)

    try:
        signature = bytes.fromhex(signed_entry["signature"])
        public_key = bytes.fromhex(signed_entry["public_key"])
    except (KeyError, ValueError) as e:
        return {"valid": False, "reason": f"Malformed signature data: {e}"}

    # Also verify hash
    expected_hash = hashlib.sha256(canonical).hexdigest()
    stored_hash = signed_entry.get("content_hash", "")

    valid_sig = _verify(canonical, signature, public_key)
    valid_hash = expected_hash == stored_hash

    if valid_sig and valid_hash:
        return {
            "valid": True,
            "reason": "Signature and hash verified successfully.",
            "algorithm": PQC_SIG_ALGORITHM,
        }
    elif not valid_hash:
        return {
            "valid": False,
            "reason": "TAMPER DETECTED: Content hash mismatch. Log entry has been modified.",
            "algorithm": PQC_SIG_ALGORITHM,
        }
    else:
        return {
            "valid": False,
            "reason": "TAMPER DETECTED: Signature verification failed. Log entry integrity compromised.",
            "algorithm": PQC_SIG_ALGORITHM,
        }


def get_pqc_sig_status() -> Dict[str, Any]:
    return {
        "sig_algorithm": PQC_SIG_ALGORITHM,
        "sig_standard": PQC_SIG_STANDARD,
        "public_key_size_bytes": PQC_SIG_PUBLIC_KEY_SIZE,
        "signature_size_bytes": PQC_SIG_SIZE,
        "pqc_real": PQC_SIG_AVAILABLE,
        "public_key_preview": _SIG_PUBLIC_KEY.hex()[:32] + "...",
    }
