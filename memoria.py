import sys
import os
import json
from unittest.mock import MagicMock, patch

# Colores para la terminal
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"

def print_pass(msg):
    print(f"{GREEN}[PASS] {msg}{RESET}")

def print_fail(msg):
    print(f"{RED}[FAIL] {msg}{RESET}")

print("🔍 INICIANDO AUDITORÍA DE INTEGRACIÓN SENTRY...\n")

# --- PASO 1: Verificación de Dependencias ---
try:
    import sentry_sdk
    from sentry_sdk import Hub
    print_pass("Librería 'sentry-sdk' instalada correctamente.")
except ImportError:
    print_fail("Falta 'sentry-sdk'. Ejecuta: pip install sentry-sdk")
    sys.exit(1)

# --- PASO 2: Verificación de Variables de Entorno ---
dsn = os.environ.get("SENTRY_DSN")
if dsn:
    print_pass(f"SENTRY_DSN detectado: {dsn[:10]}...******")
else:
    print_fail("SENTRY_DSN no encontrado en variables de entorno.")
    print("      >> Configúralo con: export SENTRY_DSN='tu_url_aqui'")
    # Continuamos para probar la lógica, aunque el envío real fallaría

# --- PASO 3: Verificación de Inicialización en Main (FastAPI) ---
print("\n--- Probando Inicialización en main.py ---")
try:
    # Intentamos importar app para ver si dispara sentry_sdk.init()
    from agentpay_core.main import app
    
    if Hub.current.client:
        print_pass("Sentry inicializado correctamente en main.py (Client activo).")
    else:
        print_fail("Sentry NO está activo. ¿Llamaste a sentry_sdk.init() antes de 'app = FastAPI'?")
except Exception as e:
    print_fail(f"Error importando main.py: {e}")

# --- PASO 4: Verificación de Captura Manual en Server (MCP Tools) ---
print("\n--- Probando Captura de Errores en server.py (MCP) ---")
try:
    from agentpay_core import server
    
    # Mockeamos (simulamos) el engine para que falle a propósito
    original_engine = server.engine
    mock_engine = MagicMock()
    mock_engine.evaluate.side_effect = Exception("🔥 ERROR DE PRUEBA SIMULADO POR EL TEST 🔥")
    server.engine = mock_engine

    # Mockeamos Sentry para ver si intenta capturar el error
    with patch('sentry_sdk.capture_exception') as mock_capture:
        print("   >> Ejecutando tool 'request_payment' con fallo simulado...")
        
        # Ejecutamos la función que debería fallar
        response_json = server.request_payment("VendorTest", 100.0, "Test Desc", "agent_test")
        response = json.loads(response_json)

        # Verificaciones
        if response.get("status") == "ERROR":
            print_pass("El servidor manejó la excepción y devolvió JSON válido al agente.")
        else:
            print_fail("El servidor no devolvió el JSON de error esperado.")

        if mock_capture.called:
            print_pass("¡ÉXITO! sentry_sdk.capture_exception() fue llamado dentro del bloque except.")
            print(f"      (Excepción capturada: {mock_capture.call_args[0][0]})")
        else:
            print_fail("Sentry NO capturó el error. Verifica que añadiste 'sentry_sdk.capture_exception(e)' en el bloque except.")

    # Restauramos el engine original
    server.engine = original_engine

except ImportError:
    print_fail("No se pudo importar agentpay_core.server.")
except Exception as e:
    print_fail(f"Error inesperado durante el test: {e}")

# --- PASO 5: Verificación de Loguru (Breadcrumbs) ---
print("\n--- Probando Integración Loguru -> Sentry ---")
try:
    from loguru import logger
    
    # Verificamos si hay algún handler que parezca de Sentry
    # Esto es difícil de inspeccionar, así que probaremos interceptando capture_message
    with patch('sentry_sdk.capture_message') as mock_msg:
        logger.error("TEST DE LOGURU: Esto debería ir a Sentry")
        
        # Damos un pequeño margen o verificamos llamadas
        if mock_msg.called:
            print_pass("Loguru envió el error a Sentry (capture_message llamado).")
        else:
            print("⚠️ [WARNING] No se detectó llamada automática de Loguru a Sentry.")
            print("      (Esto es normal si no configuraste el 'SentryHandler' personalizado, pero idealmente deberías tenerlo).")

except ImportError:
    print("Saltando test de Loguru (librería no instalada).")

print("\n" + "="*40)
print("🏁 RESULTADO FINAL")
print("Si viste todos los [PASS] en verde, tu integración es sólida.")
print("Ahora, fuerza un error real en producción y revisa tu panel de Sentry.")