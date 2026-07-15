"""
PANOPTES — PQC Demo router
Interactive encrypt/decrypt and sign/verify endpoints.
"""
import uuid
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from backend.database import get_db
from backend.db_models import CredentialVault
from backend.crypto.pqc_vault import (
    encrypt_credential, decrypt_credential,
    get_pqc_vault_status, PQC_AVAILABLE, KEM_ALGORITHM,
)
from backend.crypto.audit_signer import (
    sign_entry, verify_entry, get_pqc_sig_status, PQC_SIG_AVAILABLE,
)
from backend.policy.engine import is_opa_running

router = APIRouter(prefix="/api/pqc", tags=["pqc"])


class EncryptRequest(BaseModel):
    label: str
    plaintext: str
    owner_id: str = "demo_user"


class DecryptRequest(BaseModel):
    vault_id: str


class SignRequest(BaseModel):
    message: str
    event_type: str = "MANUAL_TEST"


class VerifyRequest(BaseModel):
    entry: dict


@router.get("/status")
async def pqc_status():
    vault  = get_pqc_vault_status()
    signing = get_pqc_sig_status()
    return {
        "opa_running":     is_opa_running(),
        "opa_mode":        "Real OPA (Rego)" if is_opa_running() else "Inline Python policy",
        "vault":           vault,
        "signing":         signing,
        "overall_pqc_real": vault["pqc_real"] and signing["pqc_real"],
    }


@router.post("/vault/encrypt")
async def vault_encrypt(req: EncryptRequest, db: AsyncSession = Depends(get_db)):
    result   = encrypt_credential(req.plaintext)
    vault_id = f"vault_{uuid.uuid4().hex[:12]}"
    entry = CredentialVault(
        vault_id=vault_id,
        label=req.label,
        owner_id=req.owner_id,
        ciphertext_hex=result["ciphertext_hex"],
        kem_ciphertext_hex=result["kem_ciphertext_hex"],
        public_key_hex=result["public_key_hex"],
        kem_algorithm=result["kem_algorithm"],
    )
    db.add(entry)
    await db.commit()
    return {
        "vault_id":             vault_id,
        "label":                req.label,
        "kem_algorithm":        result["kem_algorithm"],
        "ciphertext_preview":   result["ciphertext_hex"][:64] + "...",
        "kem_ciphertext_preview": result["kem_ciphertext_hex"][:64] + "...",
        "metadata":             result["metadata"],
        "message":              "Credential encrypted and stored in vault.",
    }


@router.post("/vault/decrypt")
async def vault_decrypt(req: DecryptRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(CredentialVault).where(CredentialVault.vault_id == req.vault_id)
    )
    entry = result.scalar_one_or_none()
    if not entry:
        raise HTTPException(status_code=404, detail="Vault entry not found")
    plaintext = decrypt_credential(entry.kem_ciphertext_hex, entry.ciphertext_hex)
    return {
        "vault_id":      req.vault_id,
        "label":         entry.label,
        "plaintext":     plaintext,
        "kem_algorithm": entry.kem_algorithm,
        "message":       "Credential successfully decrypted.",
    }


@router.post("/sign")
async def sign_message(req: SignRequest):
    import datetime
    entry = {
        "event_type": req.event_type,
        "message":    req.message,
        "timestamp":  datetime.datetime.utcnow().isoformat(),
    }
    signed = sign_entry(entry)
    return {
        "signed_entry":      signed,
        "signature_preview": signed["signature"][:64] + "...",
        "public_key_preview": signed["public_key"][:64] + "...",
        "algorithm":         signed["sig_algorithm"],
        "message":           "Entry signed with post-quantum-ready digital signature.",
    }


@router.post("/verify")
async def verify_message(req: VerifyRequest):
    return verify_entry(req.entry)


@router.get("/vault")
async def list_vault(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(CredentialVault).limit(50))
    entries = result.scalars().all()
    return {
        "entries": [
            {
                "vault_id":      e.vault_id,
                "label":         e.label,
                "owner_id":      e.owner_id,
                "kem_algorithm": e.kem_algorithm,
                "created_at":    e.created_at.isoformat() if e.created_at else None,
            }
            for e in entries
        ]
    }
