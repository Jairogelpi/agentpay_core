from fastapi import FastAPI
from supabase import create_client
from dotenv import load_dotenv
import base64
import os

load_dotenv()
app = FastAPI()
db = create_client(os.environ.get("SUPABASE_URL"), os.environ.get("SUPABASE_KEY"))

@app.get("/")
def home():
    return {"status": "AgentPay Admin API Online"}

@app.get("/admin/approve")
def approve_vendor(token: str):
    try:
        # Decodificar token
        decoded = base64.b64decode(token).decode()
        agent_id, new_vendor = decoded.split(":")
        
        # Obtener whitelist actual
        res = db.table("wallets").select("allowed_vendors").eq("agent_id", agent_id).execute()
        if not res.data: return {"error": "Agente no encontrado"}
        
        current_vendors = res.data[0]['allowed_vendors'] or []
        
        # Idempotencia (No duplicar)
        if new_vendor not in current_vendors:
            current_vendors.append(new_vendor)
            db.table("wallets").update({"allowed_vendors": current_vendors}).eq("agent_id", agent_id).execute()
            msg = f"✅ APROBADO: '{new_vendor}' añadido a la whitelist."
        else:
            msg = f"ℹ️ INFO: '{new_vendor}' ya estaba aprobado."
            
        return {
            "result": "success",
            "message": msg,
            "instruction": "Dile a tu Agente que intente el pago de nuevo."
        }
    except Exception as e:
        return {"error": str(e)}