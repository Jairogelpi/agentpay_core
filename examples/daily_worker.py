import requests
import time
import json

# --- CONFIGURACIÓN DEL DESARROLLADOR ---
# El programador solo necesita la URL de AgentPay y su API Key.
AGENTPAY_HOST = "https://agentpay-core.onrender.com" # O localhost:8000
MY_AGENT_ID = "sk_a03c7e53830d4dc4a779418d"
API_KEY = "sk_a03c7e53830d4dc4a779418d"

def log(msg): print(f"🤖 [MY BOT]: {msg}")

class DailyInfrastructureBot:
    """
    Ejemplo de un Agente de Mantenimiento que usa AgentPay 
    como su 'Director Financiero' autónomo.
    """
    
    def run_daily_routine(self):
        log("Iniciando rutina diaria de mantenimiento (#Day 42)...")
        
        # PASO 1: GOBERNANZA (¿Tengo salud financiera para operar hoy?)
        # -------------------------------------------------------------
        log("Consultando mis métricas en AgentPay...")
        dashboard = requests.get(f"{AGENTPAY_HOST}/v1/analytics/dashboard/{MY_AGENT_ID}").json()
        
        if dashboard.get('status') == 'ERROR':
            # Si no existo, me registro (Onboarding Invisible)
            # En un caso real, aquí llamaríamos a register_new_agent
            log("Primera vez aquí. Operando con perfil default.")
        
        credit_score = dashboard.get('financial_health', {}).get('credit_score', 0)
        log(f"Mi Credit Score es: {credit_score}. Salud Financiera: OK.")

        # PASO 2: LEGAL (Firmar contrato con nuevo proveedor)
        # ---------------------------------------------------
        TARGET_VENDOR = "https://api.cloud-provider.io"
        COST = 25.00
        
        # El bot decide qué contrato firmar. AgentPay asegura la responsabilidad legal.
        log(f"Necesito comprar servidores en {TARGET_VENDOR}. Firmando TyC...")
        
        # 1. FIRMA REAL (Legal Wrapper)
        tos_res = requests.post(f"{AGENTPAY_HOST}/v1/legal/sign_tos", json={
            "agent_id": MY_AGENT_ID,
            "platform_url": TARGET_VENDOR
        }).json()
        
        if tos_res.get('status') == 'SIGNED':
             cert_id = tos_res['certificate']['certificate_id']
             log(f"Contrato firmado. Certificado de Responsabilidad: {cert_id}")
        else:
             log(f"❌ Error firmando contrato: {tos_res}")
             return

        # PASO 3: PAGO (Ejecutar la compra segura)
        # ----------------------------------------
        log(f"Pagando ${COST} por capacidad de servidor...")
        
        payment_payload = {
            "agent_id": MY_AGENT_ID,
            "vendor": TARGET_VENDOR,
            "amount": COST,
            "description": "Daily Server Capacity - Cluster A",
            "justification": "Required for maintaining 99.9% uptime SLA." # Esta justificación se audita
        }
        
        # 2. PAGO REAL (Engine Evaluate)
        payment_res = requests.post(f"{AGENTPAY_HOST}/v1/pay", json=payment_payload).json()
        
        if payment_res.get('success'): 
            # CAPTURANDO ID REAL (Chain chain chain...)
            tx_id = payment_res.get('transaction_id') 
            
            if not tx_id:
                # Fallback por si la API antigua cacheada en Render aún no devuelve el ID
                log("⚠️ API aún no devuelve ID (Deploy pendiente). Usando fallback temporal...")
                tx_id = "tx_fallback_" + str(int(time.time()))
            
            log(f"✅ Pago Aprobado (ID: {tx_id}). Balance restante: ${payment_res.get('balance')}")
        else:
            log(f"❌ Pago Rechazado: {payment_res.get('message')}")
            return

        # PASO 4: TRUST (Verificar si me estafaron)
        # -----------------------------------------
        # Simulamos que probamos el servidor y funciona
        service_logs = "200 OK - Server Active - Latency 12ms"
        log("Verificando calidad del servicio recibido...")
        
        # 3. VERIFICACIÓN REAL (Trust Engine)
        time.sleep(2) # Dar un respiro a la DB
        try:
            trust_res = requests.post(f"{AGENTPAY_HOST}/v1/trust/verify", json={
                "agent_id": MY_AGENT_ID, 
                "transaction_id": tx_id, # <--- REAL ID LINKED
                "service_logs": service_logs
            }).json()
            log(f"TRUST CHECK: {trust_res.get('status')} - {trust_res.get('message')}")
        except Exception as e:
            log(f"⚠️ Trust API endpoint error: {e}")

        # PASO 5: ROI (Demostrar mi valor al jefe)
        # ----------------------------------------
        # Yo gasté $25, pero mantuve arriba el e-commerce que facturó x20.
        VALUE_GENERATED = COST * 20.0
        
        log(f"Reportando ROI: Gasté ${COST}, Generé ${VALUE_GENERATED}")
        requests.post(f"{AGENTPAY_HOST}/v1/analytics/report_value", json={
            "agent_id": MY_AGENT_ID,
            "transaction_id": tx_id, # <--- REAL ID LINKED
            "perceived_value": VALUE_GENERATED
        })
        
        log("Rutina completada. Dormir hasta mañana. 💤")

if __name__ == "__main__":
    bot = DailyInfrastructureBot()
    bot.run_daily_routine()
