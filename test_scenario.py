import time
import webbrowser
from models import TransactionRequest
from engine import UniversalEngine

# Instanciamos el motor (el mismo que usa el servidor)
engine = UniversalEngine()

def simular_intento(vendor, amount):
    print(f"\n🤖 [AGENTE] Intentando pagar a: {vendor} (${amount})...")
    
    # Creamos la petición como la haría la IA
    req = TransactionRequest(
        agent_id="production_agent",
        vendor=vendor,
        amount=amount,
        description="Prueba de concepto"
    )
    
    # El motor evalúa
    result = engine.evaluate(req)
    
    if result.status == "APPROVED":
        print(f"✅ ÉXITO: Pago realizado. Saldo restante: ${result.new_remaining_balance}")
        return True
    elif result.status == "PENDING_APPROVAL":
        print(f"✋ PAUSA: Proveedor desconocido.")
        print(f"🔗 MAGIC LINK: {result.approval_link}")
        
        # Truco pro: Abrimos el navegador automáticamente por ti
        print("   -> Abriendo navegador para aprobación humana...")
        webbrowser.open(result.approval_link)
        return False
    else:
        print(f"⛔ ERROR: {result.reason}")
        return False

def correr_demo():
    print("=== INICIANDO DEMOSTRACIÓN DE AGENTPAY ===")

    # CASO 1: Proveedor Conocido (Debería pasar directo)
    print("\n--- CASO 1: PAGO ESTÁNDAR (OpenAI) ---")
    simular_intento("api.openai.com", 15.50)

    # CASO 2: El Desconocido (Debería pausarse)
    print("\n--- CASO 2: EL DESCUBRIMIENTO ---")
    proveedor_nuevo = "herramienta-super-nueva.com"
    exito = simular_intento(proveedor_nuevo, 50.00)

    if not exito:
        print("\n⏳ Esperando a que el humano (tú) haga clic en 'Aprobar' en el navegador...")
        # Hacemos un bucle simple esperando a que apruebes
        input("👉 Haz clic en el link que se abrió, espera al mensaje de 'ÉXITO' y luego PRESIONA ENTER aquí para reintentar...")

        # CASO 3: El Reintento (Debería pasar ahora)
        print("\n--- CASO 3: EL REINTENTO (Aprendizaje) ---")
        simular_intento(proveedor_nuevo, 50.00)

if __name__ == "__main__":
    correr_demo()