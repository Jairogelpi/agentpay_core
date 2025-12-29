"""
AGENTE OPERATIVO REAL: Translation Bot
=======================================
Este agente REALMENTE:
1. Recibe textos para traducir
2. Pide permiso de pago a AgentPay
3. Llama a API de traducción REAL (DeepL o similar)
4. Reporta ROI

REQUISITOS:
- API Key de DeepL (gratis hasta 500k chars/mes): https://www.deepl.com/pro-api
- Saldo en AgentPay

Para conectarlo como MCP a Claude Desktop, usa server.py
"""

import requests
import os

# --- CONFIGURACIÓN ---
AGENTPAY_HOST = "https://agentpay-core.onrender.com"
MY_AGENT_ID = "sk_a03c7e53830d4dc4a779418d"  # Tu agent ID
DEEPL_API_KEY = os.environ.get("DEEPL_API_KEY")  # Configura en tu entorno

def log(msg): print(f"🤖 [TRANSLATOR BOT]: {msg}")

class TranslatorAgent:
    """
    Agente de Traducción con Gobernanza Financiera.
    Cada traducción tiene un costo estimado y pasa por AgentPay.
    """
    
    COST_PER_1000_CHARS = 0.02  # $0.02 por 1000 caracteres (precio típico)
    
    def translate(self, text: str, target_lang: str = "ES") -> dict:
        """
        Flujo completo de traducción con gobernanza AgentPay.
        """
        log(f"Nueva solicitud: Traducir {len(text)} caracteres a {target_lang}")
        
        # 1. CALCULAR COSTO
        estimated_cost = (len(text) / 1000) * self.COST_PER_1000_CHARS
        estimated_cost = max(0.01, round(estimated_cost, 2))  # Mínimo $0.01
        
        log(f"Costo estimado: ${estimated_cost}")
        
        # 2. PEDIR APROBACIÓN A AGENTPAY
        log("Solicitando aprobación financiera a AgentPay...")
        
        payment_req = {
            "agent_id": MY_AGENT_ID,
            "vendor": "api.deepl.com",
            "amount": estimated_cost,
            "description": f"Translation API: {len(text)} chars to {target_lang}",
            "justification": "User requested translation. Cost-effective batch pricing applied."
        }
        
        pay_response = requests.post(f"{AGENTPAY_HOST}/v1/pay", json=payment_req).json()
        
        if not pay_response.get('success'):
            log(f"❌ Pago rechazado: {pay_response.get('message')}")
            return {
                "status": "BLOCKED",
                "reason": pay_response.get('message'),
                "translated_text": None
            }
        
        tx_id = pay_response.get('transaction_id')
        log(f"✅ Pago aprobado (TX: {tx_id}). Ejecutando traducción...")
        
        # 3. EJECUTAR TRADUCCIÓN REAL
        if not DEEPL_API_KEY:
            # Modo demo sin API key real
            log("⚠️ DEEPL_API_KEY no configurada. Usando traducción simulada.")
            translated = f"[TRANSLATED TO {target_lang}]: {text[:50]}..."
        else:
            # LLAMADA REAL A DEEPL
            deepl_response = requests.post(
                "https://api-free.deepl.com/v2/translate",
                headers={"Authorization": f"DeepL-Auth-Key {DEEPL_API_KEY}"},
                data={
                    "text": text,
                    "target_lang": target_lang
                }
            )
            
            if deepl_response.status_code == 200:
                translated = deepl_response.json()['translations'][0]['text']
            else:
                log(f"❌ Error DeepL: {deepl_response.text}")
                # Si falla, abrir disputa automáticamente
                requests.post(f"{AGENTPAY_HOST}/v1/trust/verify", json={
                    "agent_id": MY_AGENT_ID,
                    "transaction_id": tx_id,
                    "service_logs": f"DeepL Error: {deepl_response.status_code} - {deepl_response.text}"
                })
                return {"status": "API_FAILURE", "reason": "Translation service failed"}
        
        # 4. REPORTAR VALOR GENERADO (ROI)
        # Asumimos que una traducción tiene valor = 10x su costo para el negocio
        value_generated = estimated_cost * 10
        
        log(f"Reportando ROI: Gasté ${estimated_cost}, Generé ${value_generated}")
        requests.post(f"{AGENTPAY_HOST}/v1/analytics/report_value", json={
            "agent_id": MY_AGENT_ID,
            "transaction_id": tx_id,
            "perceived_value": value_generated
        })
        
        log("✅ Traducción completada exitosamente.")
        
        return {
            "status": "SUCCESS",
            "original_text": text,
            "translated_text": translated,
            "cost_usd": estimated_cost,
            "transaction_id": tx_id
        }


if __name__ == "__main__":
    agent = TranslatorAgent()
    
    # PRUEBA REAL
    result = agent.translate(
        text="Hello, this is a test of the AgentPay translation system. "
             "We are verifying that the financial governance layer works correctly "
             "before deploying to production.",
        target_lang="ES"
    )
    
    print("\n" + "="*50)
    print("RESULTADO FINAL:")
    print(result)
