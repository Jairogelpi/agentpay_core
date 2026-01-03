import requests
import time
from loguru import logger

# Configuración
BASE_URL = "https://agentpay-core.onrender.com"
AGENT_ID = "ag_1583476b1a31"  # Tu agente activo
HEADERS = {"Content-Type": "application/json"}

def run_advanced_tests():
    logger.info("🏛️ INICIANDO TEST DE GOBERNANZA Y SEGURIDAD AVANZADA")

    # ---------------------------------------------------------
    # 1. TEST DE ESCROW (Garantía de Fondos)
    # ---------------------------------------------------------
    logger.info("\n1️⃣ ESCROW: Creando contrato con retención de fondos...")
    escrow_payload = {
        "agent_id": AGENT_ID,
        "vendor": "ai-developer-service.com",
        "amount": 150.0,
        "description": "Desarrollo de módulo de cifrado cuántico"
    }
    escrow_res = requests.post(f"{BASE_URL}/v1/escrow/create", json=escrow_payload).json()
    
    if escrow_res.get("status") == "ESCROW_ACTIVE":
        tx_id = escrow_res['transaction_id']
        logger.success(f"✅ Fondos bloqueados en Escrow. ID: {tx_id}")
    else:
        logger.error(f"❌ Fallo en Escrow: {escrow_res}")
        return

    # ---------------------------------------------------------
    # 2. TEST DE DISPUTA Y JUEZ IA (Arbitraje)
    # ---------------------------------------------------------
    logger.info("\n2️⃣ DISPUTA: Simulando fallo del proveedor y arbitraje...")
    dispute_payload = {
        "agent_id": AGENT_ID,
        "transaction_id": tx_id,
        "issue_description": "El código entregado no compila y el proveedor no responde.",
        "technical_evidence": "Logs: Error 500 at build time. Signature mismatch in delivery."
    }
    dispute_res = requests.post(f"{BASE_URL}/v1/escrow/dispute", json=dispute_payload).json()
    logger.info(f"⚖️ Veredicto del Juez IA: {dispute_res.get('status')}")
    logger.info(f"Opinion Judicial: {dispute_res.get('verdict', {}).get('judicial_opinion')}")

    # ---------------------------------------------------------
    # 3. TEST DE HIVE MIND (Mente Colmena / Blacklist)
    # ---------------------------------------------------------
    logger.info("\n3️⃣ HIVE MIND: Reportando fraude y verificando bloqueo global...")
    fraud_domain = "malicious-api-scam.net"
    
    # Reportamos el fraude
    requests.post(f"{BASE_URL}/v1/fraud/report", json={
        "agent_id": AGENT_ID,
        "vendor": fraud_domain,
        "reason": "Phishing detectado en el endpoint de pago."
    })
    logger.warning(f"🚨 Dominio {fraud_domain} reportado a la red.")

    # Intentamos pagar al mismo dominio (debería ser bloqueado por la reputación global)
    pay_attempt = requests.post(f"{BASE_URL}/v1/pay", json={
        "agent_id": AGENT_ID,
        "vendor": fraud_domain,
        "amount": 10.0,
        "description": "Test de bloqueo"
    }).json()
    
    if pay_attempt.get("status") == "REJECTED":
        logger.success("✅ MENTE COLMENA OK: El pago fue bloqueado por reputación global.")
    else:
        logger.error("⚠️ FALLO: La mente colmena no propagó el bloqueo.")

    # ---------------------------------------------------------
    # 4. TEST DE LÍMITES DIARIOS (Circuit Breaker)
    # ---------------------------------------------------------
    logger.info("\n4️⃣ LÍMITES: Verificando protección de gasto diario...")
    # Intentamos un pago que exceda el límite (asumiendo límite de $1000 y saldo restante)
    limit_payload = {
        "agent_id": AGENT_ID,
        "vendor": "expensive-service.com",
        "amount": 5000.0,
        "description": "Compra excesiva"
    }
    limit_res = requests.post(f"{BASE_URL}/v1/pay", json=limit_payload).json()
    
    if limit_res.get("status") == "REJECTED" and "límite" in limit_res.get("reason", "").lower():
        logger.success("✅ FUSIBLE OK: El sistema impidió el gasto excesivo.")
    else:
        logger.info(f"Resultado límites: {limit_res.get('reason')}")

    # ---------------------------------------------------------
    # 5. TEST LEGAL (Liability Certificate)
    # ---------------------------------------------------------
    logger.info("\n5️⃣ LEGAL: Generando Certificado de Responsabilidad Civil...")
    legal_payload = {
        "agent_id": AGENT_ID,
        "email": f"{AGENT_ID}@agentpay.ai",
        "platform_url": "https://service-provider.com",
        "forensic_hash": "SHA256-PROOF-OF-INTENT-99"
    }
    legal_res = requests.post(f"{BASE_URL}/v1/legal/issue-certificate", json=legal_payload).json()
    
    if legal_res.get("status") == "ACTIVE":
        logger.success(f"✅ Certificado Legal Emitido: {legal_res['certificate_id']}")
        logger.info(f"Firma Criptográfica: {legal_res['signature'][:20]}...")
    else:
        logger.error("❌ Fallo al emitir certificado legal.")

if __name__ == "__main__":
    run_advanced_tests()