import os
from pathlib import Path
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import httpx
import logging

router = APIRouter(prefix="/api/policy", tags=["policy_editor"])
logger = logging.getLogger("panoptes.policy_editor")

REGO_PATH = Path(__file__).parent.parent.parent / "opa" / "panoptes.rego"
OPA_URL = os.getenv("OPA_URL", "http://localhost:8181")

class PolicyUpdate(BaseModel):
    rego_content: str

@router.get("")
async def get_policy():
    """Read the current OPA Rego policy."""
    try:
        if not REGO_PATH.exists():
            return {"content": "# Policy file not found"}
        return {"content": REGO_PATH.read_text(encoding="utf-8")}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.put("")
async def update_policy(payload: PolicyUpdate):
    """Save the OPA Rego policy to disk and hot-reload it into the running OPA server."""
    try:
        # 1. Save to disk
        REGO_PATH.write_text(payload.rego_content, encoding="utf-8")
        
        # 2. Push to running OPA server via REST API
        # The endpoint is /v1/policies/<policy-id>
        async with httpx.AsyncClient() as client:
            resp = await client.put(
                f"{OPA_URL}/v1/policies/panoptes",
                content=payload.rego_content,
                headers={"Content-Type": "text/plain"},
                timeout=5.0
            )
            
            if resp.status_code != 200:
                logger.error(f"OPA Reload Failed: {resp.text}")
                raise HTTPException(status_code=400, detail=f"Syntax Error in Rego Policy: {resp.text}")
                
        return {"status": "ok", "message": "Policy deployed successfully"}
    except httpx.RequestError as e:
        logger.warning(f"Could not connect to OPA server for reload: {e}")
        return {"status": "partial", "message": "Saved to disk, but OPA server is not reachable for live reload."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
