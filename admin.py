from fastapi import FastAPI
from supabase import create_client
from dotenv import load_dotenv
import base64
import os
import jwt # <--- Security

load_dotenv()
app = FastAPI()
db = create_client(os.environ.get("SUPABASE_URL"), os.environ.get("SUPABASE_KEY"))

@app.get("/")
def home():
    return {"status": "AgentPay Admin API Online"}

@app.get("/admin/approve")
def approve_vendor(token: str):
    try:
        # 1. Validar JWT
        secret = os.environ.get("JWT_SECRET", "super-secret-fix-in-prod")
        payload = jwt.decode(token, secret, algorithms=["HS256"])
        tx_id = payload.get("tx_id")
        
        # 2. Recuperar Transacción
        res = db.table("transaction_logs").select("*").eq("id", tx_id).single().execute()
        if not res.data: return {"error": "Transacción no encontrada"}
        
        tx_data = res.data
        agent_id = tx_data.get("agent_id")
        vendor = tx_data.get("vendor")
        
        # 3. Aprobar Transacción
        db.table("transaction_logs").update({
             "status": "APPROVED",
             "reason": "Aprobado manualmente desde Admin API."
        }).eq("id", tx_id).execute()
        
        # 4. Whitelist Vendor
        wallet_res = db.table("wallets").select("allowed_vendors").eq("agent_id", agent_id).execute()
        if wallet_res.data:
            current_vendors = wallet_res.data[0].get('allowed_vendors') or []
            if vendor and vendor not in current_vendors:
                current_vendors.append(vendor)
                db.table("wallets").update({"allowed_vendors": current_vendors}).eq("agent_id", agent_id).execute()

        return {
            "result": "success",
            "message": f"✅ APROBADO: {vendor} añadido a confianza para {agent_id}.",
            "instruction": "El agente puede reintentar la operación."
        }
    except jwt.ExpiredSignatureError:
        return {"error": "Token expirado"}
    except jwt.InvalidTokenError:
        return {"error": "Token inválido"}
    except Exception as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": str(e)}