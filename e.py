import requests
import time
import stripe # Necesitas: pip install stripe

import os

# --- CONFIGURACIÓN ---
API_URL = "https://agentpay-core.onrender.com"
# Recuperamos la clave del entorno para no subir secretos a GitHub
STRIPE_KEY_PARA_PRUEBAS = os.getenv("STRIPE_SECRET_KEY") 

if not STRIPE_KEY_PARA_PRUEBAS:
    # Fallback solo si el usuario lo define localmente, pero NO lo escribas en el código
    print("⚠️ ADVERTENCIA: No se encontró STRIPE_SECRET_KEY en las variables de entorno.")
    print("   El paso final de cobro real (Test Helpers) fallará si no configuras la variable.")

stripe.api_key = STRIPE_KEY_PARA_PRUEBAS

def flow_realidad_total():
    print("\n🌍 --- INICIANDO ECOSISTEMA FINANCIERO REAL (Full Loop) ---")
    
    # -------------------------------------------------------------------------
    # ACTO 1: REGISTRO
    # -------------------------------------------------------------------------
    print("\n👤 [CLIENTE] Registrándose...")
    try:
        reg = requests.post(f"{API_URL}/v1/agent/register", json={
            "client_name": "Usuario Tester",
            "country_code": "ES"
        }).json()
    except Exception as e:
        print(f"❌ Error conectando a {API_URL}: {e}")
        return

    if reg.get("status") == "ERROR":
        print(f"❌ Error registro: {reg}")
        return

    agent_id = reg['agent_id']
    api_key = reg['api_key'] 
    print(f"   ✅ Agente: {agent_id}")

    # FIX LÍMITES
    requests.post(f"{API_URL}/v1/agent/limits", json={"agent_id": agent_id, "max_tx": 2000.0})

    # -------------------------------------------------------------------------
    # ACTO 2: RECARGA REAL
    # -------------------------------------------------------------------------
    print("\n💳 [CLIENTE] Ingresando $100.00...")
    topup = requests.post(f"{API_URL}/v1/topup/direct_charge", json={
        "agent_id": agent_id,
        "amount": 100.00,
        "payment_method_id": "pm_card_visa"
    }).json()

    if topup.get("status") != "SUCCESS":
        print(f"❌ Fallo recarga: {topup}")
        return
    print(f"   💰 Saldo: ${topup['new_balance']}")

    # -------------------------------------------------------------------------
    # ACTO 3: EMISIÓN DE TARJETA
    # -------------------------------------------------------------------------
    print(f"\n🤖 [AGENTE] Creando tarjeta para suscripción ($20/mes)...")
    
    headers = {"Authorization": f"Bearer {api_key}"}
    pago_req = {
        "vendor": "Netflix Inc",
        "amount": 20.00,
        "description": "Suscripción Video",
        "justification": "Ocio del equipo"
    }

    resp = requests.post(f"{API_URL}/v1/pay", json=pago_req, headers=headers).json()

    if not resp.get("success"):
        print(f"❌ Error emitiendo tarjeta: {resp}")
        return

    card = resp['card']
    print(f"   ✅ TARJETA OBTENIDA: {card['number']} (Exp: {card['exp_month']}/{card['exp_year']})")

    # -------------------------------------------------------------------------
    # ACTO 4: EL COBRO REAL (PRUEBA DE FUEGO)
    # -------------------------------------------------------------------------
    print(f"\n🛒 [VENDEDOR] Netflix intenta cobrar $20.00 a la tarjeta REALMENTE...")
    
    if "sk_" not in STRIPE_KEY_PARA_PRUEBAS:
        print("⚠️  AVISO: No has puesto la STRIPE_KEY en el script. El cobro real se saltará.")
        print("    (Edita e.py y pon tu sk_test_... al principio para probar esto)")
        return

    try:
        # 1. Simular una autorización desde la RED (Visa/Mastercard)
        # Esto salta la restricción de PCI porque emulamos ser la red, no el comerciante.
        print(f"   📡 Simulando transacción de red para la tarjeta {card.get('id', 'N/A')}...")
        
        if not card.get('id'):
             print("   ⚠️  [ERROR] La API no devolvió el ID de la tarjeta. Asegúrate de que models.py y engine.py estén actualizados.")
             return

        auth = stripe.test_helpers.issuing.Authorization.create(
            amount=2000, 
            currency="usd",
            card=card['id'], 
            merchant_data={
                "name": "Netflix Inc",
                "category": "digital_goods_large_digital_goods_merchant" 
            }
        )
        print(f"   ✅ [STRIPE] Autorización Creada: {auth.id}")

        # 2. Capturar el dinero (Cobro definitivo)
        capture = stripe.test_helpers.issuing.Authorization.capture(auth.id)
        
        print(f"   ✅ [STRIPE] ¡COBRO APROBADO Y CAPTURADO!")
        print(f"   📄 Estado: {capture.status.upper()}")
        print(f"   💸 El dinero se ha descontado correctamente del balance.")

    except stripe.error.StripeError as e:
        print(f"   ❌ [STRIPE] Error: {e.user_message}")
    except Exception as e:
        print(f"   ❌ [ERROR] Fallo al cobrar: {e}")

    print("\n✨ --- TEST FINALIZADO --- ✨")

if __name__ == "__main__":
    flow_realidad_total()