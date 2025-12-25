import os
import uvicorn
import base64
import secrets
from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel
from typing import Optional
from supabase import create_client
from engine import UniversalEngine
from models import TransactionRequest

app = FastAPI(title="AgentPay Universal API", version="3.1.0 (Fixed)")
engine = UniversalEngine()

# Conexión DB
db_url = os.environ.get("SUPABASE_URL")
db_key = os.environ.get("SUPABASE_KEY")
supabase = create_client(db_url, db_key)

# --- MODELOS ---
class PaymentPayload(BaseModel):
    vendor: str
    amount: float
    description: str

class RegisterPayload(BaseModel):
    client_name: str

# --- SEGURIDAD ---
async def get_current_agent(x_api_key: str = Header(..., description="Tu API Key")):
    response = supabase.table("api_keys").select("agent_id, is_active").eq("key", x_api_key).execute()
    if not response.data: raise HTTPException(status_code=403, detail="API Key inválida.")
    key_data = response.data[0]
    if not key_data['is_active']: raise HTTPException(status_code=403, detail="API Key desactivada.")
    return key_data['agent_id']

# --- ENDPOINT NUEVO: REGISTRO ---
@app.post("/v1/register")
def register_new_client(payload: RegisterPayload):
    print(f"📝 Creando cuenta para: {payload.client_name}")
    agent_id = f"agent_{secrets.token_hex(4)}"
    new_api_key = f"sk_live_{secrets.token_urlsafe(24)}"
    
    try:
        # Whitelist por defecto
        default_whitelist = ["openai.com", "anthropic.com"]
        
        # 1. Crear Billetera
        supabase.table("wallets").insert({
            "agent_id": agent_id, "balance": 0.00, 
            "max_transaction_limit": 50.00, "allowed_vendors": default_whitelist
        }).execute()

        # 2. Guardar API Key
        supabase.table("api_keys").insert({
            "key": new_api_key, "agent_id": agent_id, "is_active": True
        }).execute()

        return {
            "status": "created",
            "message": "Cuenta creada. Guarda tu API Key.",
            "data": {
                "client_name": payload.client_name,
                "agent_id": agent_id,
                "api_key": new_api_key
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error DB: {str(e)}")

# --- ENDPOINT PAGO ---
@app.post("/v1/pay")
def process_payment(payload: PaymentPayload, agent_id: str = Depends(get_current_agent)):
    req = TransactionRequest(agent_id=agent_id, vendor=payload.vendor, amount=payload.amount, description=payload.description)
    try:
        result = engine.evaluate(req)
        return {"success": result.authorized, "status": result.status, "message": result.reason, "data": {"approval_link": result.approval_link}}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --- ENDPOINT ADMIN ---
@app.get("/admin/approve")
def approve_endpoint(token: str):
    try:
        decoded = base64.b64decode(token).decode()
        agent_id, new_vendor = decoded.split(":")
        res = supabase.table("wallets").select("allowed_vendors").eq("agent_id", agent_id).execute()
        if not res.data: return {"error": "Wallet no encontrada"}
        current = res.data[0]['allowed_vendors'] or []
        msg = "Ya estaba aprobado."
        if new_vendor not in current:
            current.append(new_vendor)
            supabase.table("wallets").update({"allowed_vendors": current}).eq("agent_id", agent_id).execute()
            msg = f"✅ '{new_vendor}' ha sido APROBADO."
        return {"status": "success", "message": msg}
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)