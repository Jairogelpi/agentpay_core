"""
========================================
POLICY BREAKER TEST SCRIPT
Tests the Corporate Expense Policy Engine
========================================
"""
import requests
import time
from loguru import logger
BASE_URL = "https://agentpay-core.onrender.com"
def setup_agent_with_strict_policies():
    """Crea un agente con políticas estrictas para testear."""
    # 1. Registrar agente
    reg_res = requests.post(f"{BASE_URL}/v1/agent/register", json={
        "client_name": f"PolicyTest_{int(time.time())}",
        "country": "ES"
    }).json()
    
    agent_id = reg_res.get('agent_id')
    api_key = reg_res.get('api_key')
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    
    logger.success(f"✅ Agente creado: {agent_id}")
    
    # 2. Configurar políticas estrictas (simula que un admin las definió)
    # NOTA: En producción esto se haría desde el dashboard
    strict_policies = {
        "spending_limits": {
            "max_per_item": 50.00,       # Máximo $50 por compra
            "daily_budget": 200.00,
            "soft_limit_slack": 25.00    # >$25 requiere aprobación Slack
        },
        "restricted_vendors": ["amazon.com", "ebay.com", "aliexpress.com"],
        "working_hours": {
            "start": "09:00",
            "end": "18:00",
            "timezone": "Europe/Madrid"
        },
        "enforce_justification": True,
        "allowed_categories": ["cloud_services", "saas_tools"]  # Solo IT
    }
    
    # Actualizar settings con rol Y políticas corporativas
    settings_res = requests.post(f"{BASE_URL}/v1/agent/settings", headers=headers, json={
        "agent_id": agent_id,
        "agent_role": "DevOps",
        "corporate_policies": strict_policies  # ← ENVIAR POLÍTICAS A SUPABASE
    })
    if settings_res.status_code != 200:
        logger.warning(f"⚠️ Settings response: {settings_res.text}")
    
    # Fondear
    topup_res = requests.post(f"{BASE_URL}/v1/topup/auto", headers=headers, json={"agent_id": agent_id, "amount": 500.0})
    if topup_res.status_code != 200:
        logger.error(f"❌ Topup falló: {topup_res.status_code} - {topup_res.text}")
    else:
        logger.info("💰 Saldo fondeado: $500.00")
    
    logger.info("📋 Políticas estrictas configuradas y enviadas a Supabase.")
    return agent_id, api_key, headers
def test_restricted_vendor(headers):
    """TEST 1: Intenta comprar en Amazon (restringido)"""
    logger.info("\n🧪 TEST 1: Proveedor Restringido (Amazon)")
    res = requests.post(f"{BASE_URL}/v1/pay", headers=headers, json={
        "vendor": "amazon.com",
        "amount": 10.0,
        "description": "Libro de Python",
        "justification": "Necesito aprender para el proyecto de migración cloud."
    })
    result = res.json()
    
    if "restringido" in str(result.get('reason', '')).lower() or result.get('status') == 'REJECTED':
        logger.success(f"✅ TEST 1 PASSED: Bloqueado correctamente. Razón: {result.get('reason')}")
    else:
        logger.error(f"❌ TEST 1 FAILED: Debería haber bloqueado. Respuesta: {result}")
def test_over_limit(headers):
    """TEST 2: Intenta comprar más del límite por item ($50)"""
    logger.info("\n🧪 TEST 2: Exceso de Límite por Item ($75 > $50)")
    res = requests.post(f"{BASE_URL}/v1/pay", headers=headers, json={
        "vendor": "cloud.google.com",
        "amount": 75.0,
        "description": "Créditos GCP",
        "justification": "Necesito más capacidad de cómputo para el proyecto de IA."
    })
    result = res.json()
    
    if "excede" in str(result.get('reason', '')).lower() or result.get('status') == 'REJECTED':
        logger.success(f"✅ TEST 2 PASSED: Bloqueado por límite. Razón: {result.get('reason')}")
    else:
        logger.error(f"❌ TEST 2 FAILED: Debería haber bloqueado. Respuesta: {result}")
def test_no_justification(headers):
    """TEST 3: Intenta comprar sin justificación (requerida)"""
    logger.info("\n🧪 TEST 3: Sin Justificación")
    res = requests.post(f"{BASE_URL}/v1/pay", headers=headers, json={
        "vendor": "render.com",
        "amount": 15.0,
        "description": "Hosting",
        "justification": ""  # Vacía
    })
    result = res.json()
    
    if "justificación" in str(result.get('reason', '')).lower() or result.get('status') == 'REJECTED':
        logger.success(f"✅ TEST 3 PASSED: Bloqueado por falta de justificación. Razón: {result.get('reason')}")
    else:
        logger.error(f"❌ TEST 3 FAILED: Debería haber bloqueado. Respuesta: {result}")
def test_valid_purchase(headers):
    """TEST 4: Compra válida (cumple todas las políticas)"""
    logger.info("\n🧪 TEST 4: Compra Válida (Dentro de Políticas)")
    res = requests.post(f"{BASE_URL}/v1/pay", headers=headers, json={
        "vendor": "cloud.google.com",
        "amount": 20.0,
        "description": "Créditos GCP pequeños",
        "justification": "Necesito capacidad de cómputo para el proyecto de monitoreo de servidores."
    })
    result = res.json()
    
    if result.get('status') in ['APPROVED', 'APPROVED_PENDING_AUDIT']:
        logger.success(f"✅ TEST 4 PASSED: Compra aprobada. ID: {result.get('db_log_id') or result.get('transaction_id')}")
    else:
        logger.error(f"❌ TEST 4 FAILED: Debería haber aprobado. Respuesta: {result}")
def run_policy_tests():
    """Ejecuta todos los tests de políticas."""
    logger.info("🏛️ INICIANDO SUITE DE TESTS DE POLÍTICAS CORPORATIVAS\n")
    
    try:
        agent_id, api_key, headers = setup_agent_with_strict_policies()
        
        test_restricted_vendor(headers)
        test_over_limit(headers)
        test_no_justification(headers)
        test_valid_purchase(headers)
        
        logger.info("\n" + "="*50)
        logger.info("📊 SUITE DE TESTS COMPLETADA")
        logger.info("="*50)
        
    except Exception as e:
        logger.error(f"Error en test suite: {e}")
if __name__ == "__main__":
    run_policy_tests()
