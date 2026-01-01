import requests
import time

API_URL = "https://agentpay-core.onrender.com"

def flow_realidad_total():
    print("\n🌍 --- INICIANDO ECOSISTEMA FINANCIERO REAL ---")
    
    # -------------------------------------------------------------------------
    # ACTO 1: EL CLIENTE ENTRA (Registro)
    # -------------------------------------------------------------------------
    print("\n👤 [CLIENTE] Registrándose en la plataforma...")
    try:
        reg = requests.post(f"{API_URL}/v1/agent/register", json={
            "client_name": "Usuario VIP",
            "country_code": "ES"
        }).json()
    except Exception as e:
        print(f"❌ Error de conexión: {e}")
        return
    
    if reg.get("status") == "ERROR":
        print(f"❌ Error en registro: {reg}")
        return

    agent_id = reg['agent_id']
    api_key = reg['api_key'] 
    print(f"   ✅ Cuenta Creada: {agent_id}")

    # -------------------------------------------------------------------------
    # ACTO 1.5: SUBIR LÍMITES (EL FIX)
    # -------------------------------------------------------------------------
    # Por defecto el límite es $50. Lo subimos a $1000 para poder pagar Adobe.
    print(f"   ⚙️ [CONFIG] Aumentando límite de transacción a $1000...")
    requests.post(f"{API_URL}/v1/agent/limits", json={
        "agent_id": agent_id,
        "max_tx": 1000.0,
        "daily_limit": 5000.0
    })

    # -------------------------------------------------------------------------
    # ACTO 2: EL CLIENTE METE DINERO (Top-Up Real)
    # -------------------------------------------------------------------------
    monto_recarga = 150.00
    print(f"\n💳 [CLIENTE] Recargando ${monto_recarga} con su tarjeta personal (VISA)...")
    
    recarga = requests.post(f"{API_URL}/v1/topup/direct_charge", json={
        "agent_id": agent_id,
        "amount": monto_recarga,
        "payment_method_id": "pm_card_visa" 
    }).json()

    if recarga.get("status") == "SUCCESS":
        print(f"   🏦 [BANCO] ¡Pago Aceptado! ID Transacción: {recarga['tx_id']}")
        print(f"   💰 Saldo Disponible: ${recarga['new_balance']}")
    else:
        print(f"   ❌ Error Recarga: {recarga}")
        return

    # -------------------------------------------------------------------------
    # ACTO 3: EL AGENTE EMITE UNA TARJETA VIRTUAL (Issuing)
    # -------------------------------------------------------------------------
    print(f"\n🤖 [AGENTE] Solicitando Tarjeta Virtual para comprar Software...")
    
    headers = {"Authorization": f"Bearer {api_key}"}
    pago_req = {
        "vendor": "Adobe Creative Cloud",
        "amount": 59.99, # Ahora sí pasará porque 59.99 < 1000
        "description": "Licencia Mensual Photoshop",
        "justification": "Herramienta de trabajo necesaria"
    }

    respuesta_pago = requests.post(f"{API_URL}/v1/pay", json=pago_req, headers=headers).json()

    if not respuesta_pago.get("success"):
        print(f"   ❌ Denegado: {respuesta_pago.get('message')}")
        if respuesta_pago.get('approval_link'):
             print(f"   🔗 Link Aprobación: {respuesta_pago.get('approval_link')}")
        return

    card = respuesta_pago.get('card', {})
    print(f"   ✅ [ISSUING] ¡TARJETA EMITIDA EXITOSAMENTE!")
    print(f"      🔹 Numero: {card.get('number')}  (Real de Test)")
    print(f"      🔹 CVC:    {card.get('cvv')}")
    print(f"      🔹 Exp:    {card.get('exp_month')}/{card.get('exp_year')}")
    print(f"      🔹 Saldo Restante: ${respuesta_pago.get('balance')}")

    # -------------------------------------------------------------------------
    # ACTO 4: EL VENDEDOR COBRA (Simulación de Compra)
    # -------------------------------------------------------------------------
    print(f"\n🛒 [VENDEDOR - ADOBE] Procesando compra con la tarjeta {card.get('number', '')[-4:]}...")
    time.sleep(1.5)
    
    if card.get('status') == 'active':
        print(f"   ✅ [ADOBE] ¡Pago de ${pago_req['amount']} APROBADO!")
        print(f"   📄 Factura enviada al correo del agente.")
    else:
        print(f"   ❌ [ADOBE] Tarjeta rechazada.")

    print("\n✨ --- FLUJO COMPLETADO --- ✨")

if __name__ == "__main__":
    flow_realidad_total()