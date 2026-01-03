import requests
import time
from loguru import logger

BASE_URL = "https://agentpay-core.onrender.com"

def test_full_compliance_cycle():
    logger.info("🌍 INICIANDO PRUEBA DE CONTABILIDAD Y POLÍTICAS EU/US")

    # 1. Registro y Configuración de Políticas
    reg_res = requests.post(f"{BASE_URL}/v1/agent/register", json={"client_name": "Consensus_Tech_SL", "country": "ES"}).json()
    agent_id = reg_res['agent_id']
    headers = {"Authorization": f"Bearer {reg_res['api_key']}", "Content-Type": "application/json"}
    
    logger.success(f"✅ Agente Registrado: {agent_id}")

    # Necesitamos saldo
    requests.post(f"{BASE_URL}/v1/topup/auto", json={"agent_id": agent_id, "amount": 2000.0})

    # Aplicar Políticas de Rol y Límites
    requests.post(f"{BASE_URL}/v1/agent/settings", headers=headers, json={
        "agent_id": agent_id,
        "agent_role": "Senior Cloud Infrastructure Engineer", # Rol Profesional
        "owner_email": "accounting@consensus.tech"
    })
    
    requests.post(f"{BASE_URL}/v1/agent/limits", headers=headers, json={
        "agent_id": agent_id,
        "max_tx": 500.0, # Política de límite por transacción
        "daily_limit": 1000.0
    })
    logger.info("✅ Políticas de Rol y Límites aplicadas.")

    # 2. Ejecución de Pago
    logger.info("💸 Ejecutando pago bajo política...")
    pay_res = requests.post(f"{BASE_URL}/v1/pay", headers=headers, json={
        "vendor": "cloud.google.com",
        "amount": 250.75,
        "description": "Compute Engine instances",
        "justification": "Scaling production DB"
    }).json()
    
    tx_id = pay_res.get('db_log_id') or pay_res.get('transaction_id')
    logger.info(f"⏳ Pago iniciado ({tx_id}). Esperando clasificación IA...")
    time.sleep(10) # Tiempo para que la IA clasifique y genere el PDF

    # 3. Verificación Contable
    status = requests.post(f"{BASE_URL}/v1/transactions/status", headers=headers, json={"transaction_id": tx_id}).json()
    logger.info(f"📊 Clasificación Contable: {status.get('accounting_tag')} | Deducible: {status.get('tax_deductible')}")
    logger.info(f"💱 FX Rate: {status.get('fx_rate')} | Moneda: {status.get('settlement_currency')}")
    
    invoice = requests.post(f"{BASE_URL}/v1/invoices/download", headers=headers, json={"transaction_id": tx_id}).json()
    logger.success(f"📄 Factura Legal (EU VAT Compliant) generada en: {invoice.get('invoice_url')}")

if __name__ == "__main__":
    test_full_compliance_cycle()