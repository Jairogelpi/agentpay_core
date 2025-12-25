# main.py - AGENTPAY UNIVERSAL API
import os
import uvicorn
import base64
from fastapi import FastAPI, HTTPException, Header, Request
from pydantic import BaseModel
from typing import Optional

# Importamos tu motor existente (¡Reciclamos la lógica que ya funciona!)
from engine import UniversalEngine
from models import TransactionRequest
from supabase import create_client

# --- CONFIGURACIÓN ---
app = FastAPI(title="AgentPay API", version="1.0.0")
engine = UniversalEngine()

# Cliente DB para Admin
db_url = os.environ.get("SUPABASE_URL")
db_key = os.environ.get("SUPABASE_KEY")
supabase = create_client(db_url, db_key)

# --- MODELOS DE ENTRADA ---
class PaymentPayload(BaseModel):
    agent_id: str
    vendor: str
    amount: float
    description: str

# --- SEGURIDAD SIMPLIFICADA (API KEY) ---
# En un SaaS real, esto vendría de una base de datos de clientes.
# Aquí usamos una variable de entorno para proteger tu API.
MASTER_API_KEY = os.environ.get("AGENTPAY_API_KEY", "sk_agentpay_dev_12345")

async def verify_api_key(x_api_key: str = Header(None)):
    if x_api_key != MASTER_API_KEY:
        raise HTTPException(status_code=403, detail="API Key inválida")

# --- ENDPOINT 1: LA API DE PAGO (UNIVERSAL) ---
# Esto es lo que usan las IAs, LangChain, Zapier, etc.
@app.post("/v1/pay")
def process_payment(payload: PaymentPayload, x_api_key: str = Header(None)):
    # 1. Seguridad
    if x_api_key != MASTER_API_KEY:
        raise HTTPException(status_code=403, detail="Acceso denegado. Verifica tu API Key.")

    # 2. Convertir payload a formato interno
    req = TransactionRequest(
        agent_id=payload.agent_id,
        vendor=payload.vendor,
        amount=payload.amount,
        description=payload.description
    )

    # 3. Ejecutar Motor (Tu lógica de Stripe/Supabase)
    try:
        result = engine.evaluate(req)
        
        # 4. Devolver JSON estandarizado
        return {
            "success": result.authorized,
            "status": result.status, # APPROVED, PENDING_APPROVAL, REJECTED
            "message": result.reason,
            "data": {
                "transaction_id": result.transaction_id,
                "new_balance": result.new_remaining_balance,
                "approval_link": result.approval_link # Si es necesario
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --- ENDPOINT 2: EL APROBADOR HUMANO (MAGIC LINKS) ---
@app.get("/admin/approve")
def approve_endpoint(token: str):
    try:
        decoded = base64.b64decode(token).decode()
        agent_id, new_vendor = decoded.split(":")
        
        # Lógica de aprobación directa en DB
        res = supabase.table("wallets").select("allowed_vendors").eq("agent_id", agent_id).execute()
        if not res.data: return {"error": "Wallet no encontrada"}
        
        current = res.data[0]['allowed_vendors'] or []
        
        msg = "Ya estaba aprobado."
        if new_vendor not in current:
            current.append(new_vendor)
            supabase.table("wallets").update({"allowed_vendors": current}).eq("agent_id", agent_id).execute()
            msg = f"✅ '{new_vendor}' ha sido APROBADO exitosamente."
            
        return {
            "status": "success",
            "message": msg,
            "instruction": "El Agente ya puede reintentar el pago."
        }
    except Exception as e:
        return {"error": str(e)}

# --- ENDPOINT 3: HEALTH CHECK ---
@app.get("/")
def home():
    return {"status": "AgentPay Universal API is Running", "docs": "/docs"}

# Arranque
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)