import requests
import time
import uuid
from loguru import logger

# Configuración del entorno
BASE_URL = "https://agentpay-core.onrender.com"
logger.add("compliance_audit.log", rotation="10 MB")

def run_global_compliance_test():
    logger.info("🌍 INICIANDO AUDITORÍA INTEGRAL DE CUMPLIMIENTO (EU/US)")

    # 1. REGISTRO LEGAL (KYC/KYB Automático)
    # ---------------------------------------------------------
    logger.info("\n1️⃣ REGISTRO: Creando agente con parámetros de cumplimiento...")
    reg_payload = {
        "client_name": "Autonomous_Consensus_LLC",
        "country": "ES" # Probamos con España (Europa) para validar 3DS y VAT
    }
    reg_res = requests.post(f"{BASE_URL}/v1/agent/register", json=reg_payload).json()
    
    agent_id = reg_res['agent_id']
    api_key = reg_res['api_key']
    headers = {"Authorization": f"Bearer {api_key}"}
    
    logger.success(f"✅ Agente Registrado legalmente: {agent_id}")

    # 2. CONFIGURACIÓN FISCAL (Tax IDs y Contacto)
    # ---------------------------------------------------------
    logger.info("\n2️⃣ FISCAL: Configurando datos de facturación para la UE...")
    requests.post(f"{BASE_URL}/v1/agent/settings", headers=headers, json={
        "agent_id": agent_id,
        "owner_email": "accounting@consensus_llc.ai",
        "agent_role": "AI Infrastructure Manager"
    })
    
    # Recarga de saldo inicial para operar
    requests.post(f"{BASE_URL}/v1/topup/auto", json={"agent_id": agent_id, "amount": 1000.0})
    logger.info("💰 Saldo fondeado: $1000.0")

    # 3. EJECUCIÓN DE GASTO CON CLASIFICACIÓN IA
    # ---------------------------------------------------------
    logger.info("\n3️⃣ PAGO: Ejecutando gasto B2B (Google Cloud)...")
    payment_payload = {
        "vendor": "cloud.google.com",
        "amount": 250.75,
        "description": "Compute Engine instances for LLM fine-tuning",
        "justification": "Necessary server infrastructure for client delivery."
    }
    
    pay_res = requests.post(f"{BASE_URL}/v1/pay", headers=headers, json=payment_payload).json()
    tx_id = pay_res.get("db_log_id") or pay_res.get("transaction_id")
    
    logger.success(f"✅ Pago aprobado. Esperando firma forense y contable...")
    time.sleep(12) # Tiempo para que el Oracle v4 procese la contabilidad

    # 4. AUDITORÍA DE DOCUMENTACIÓN (Factura + Ledger)
    # ---------------------------------------------------------
    logger.info("\n4️⃣ CONTABILIDAD: Verificando la 'Huella Digital' del gasto...")
    
    # Consultar estado en el Ledger
    tx_status = requests.post(f"{BASE_URL}/v1/transactions/status", headers=headers, json={"transaction_id": tx_id}).json()
    
    logger.info(f"📊 Código GL (Libro Mayor): {tx_status.get('accounting_tag')}")
    logger.info(f"⚖️ Deducibilidad Fiscal: {'SÍ' if tx_status.get('tax_deductible') else 'NO'}")
    
    # Descargar Factura PDF Legal (con desglose de impuestos)
    invoice_res = requests.post(f"{BASE_URL}/v1/invoices/download", headers=headers, json={"transaction_id": tx_id}).json()
    logger.success(f"📄 Factura Legal Generada: {invoice_res.get('invoice_url')}")

    # 5. EMISIÓN DE CERTIFICADO DE RESPONSABILIDAD (Legal Wrapper)
    # ---------------------------------------------------------
    logger.info("\n5️⃣ LEGAL: Generando aval de responsabilidad civil...")
    legal_res = requests.post(f"{BASE_URL}/v1/legal/issue-certificate", headers=headers, json={
        "agent_id": agent_id,
        "email": "accounting@consensus_llc.ai",
        "platform_url": "https://console.cloud.google.com",
        "forensic_hash": tx_status.get("forensic_hash")
    }).json()
    
    logger.success(f"⚖️ Certificado de Cumplimiento emitido: {legal_res['certificate_id']}")

    # 6. EXPORTACIÓN PARA EL CONTADOR (CSV)
    # ---------------------------------------------------------
    logger.info("\n6️⃣ EXPORTACIÓN: Generando reporte para QuickBooks/Xero...")
    export_url = f"{BASE_URL}/v1/accounting/export-csv?month=1&year=2026"
    logger.info(f"📥 Link de exportación contable: {export_url}")

if __name__ == "__main__":
    run_global_compliance_test()