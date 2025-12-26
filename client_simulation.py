import os
import time
from pyagentpay import AgentPay
from dotenv import load_dotenv

# Cargamos entorno (API Key, URL del servidor, etc.)
load_dotenv()

class CloudOpsAgent:
    """
    Simulación de un Agente de Operaciones en la Nube (DevOps Bot).
    Este agente es el "programador" que está usando tu sistema.
    """
    def __init__(self, name, role):
        self.name = name
        self.role = role
        # Inicializamos el "Cerebro de Pagos" (Tu librería)
        # Asumimos que AgentPay lee AGENTPAY_API_KEY del entorno
        print(f"🤖 [AGENTE {name}] Iniciando sistema de pagos...")
        self.payment_core = AgentPay() 

    def execute_task(self, task_name, vendor, amount, reason):
        print(f"\n--- EJECUTANDO TAREA: {task_name} ---")
        print(f"📝 Intento: Pagar ${amount} a '{vendor}'")
        print(f"ℹ️  Motivo: {reason}")
        
        try:
            # Esta es la llamada que haría el desarrollador real
            result = self.payment_core.pay(
                vendor=vendor,
                amount=amount,
                description=reason
            )
            
            # Analizamos lo que pasó
            if result.get("success"):
                print(f"✅ ÉXITO: {result.get('message')}")
            elif result.get("status") == "PENDING_APPROVAL":
                print(f"👮 PAUSA DE SEGURIDAD: {result.get('message')}")
                url = result.get('data', {}).get('approval_link', 'No link')
                print(f"👉 Link para Humano: {url}")
            else:
                print(f"⛔ BLOQUEADO: {result.get('message')}")
                print(f"   (Estado: {result.get('status')})")
                
        except Exception as e:
            print(f"❌ ERROR DE CONEXIÓN O LIBRERÍA: {e}")

def run_full_simulation():
    # 1. Creamos al Agente
    my_agent = CloudOpsAgent("DevBot-01", "Cloud Infrastructure Manager")

    print("\n🌍 INICIANDO ESCENARIOS DE PRUEBA DEL BÚNKER AGENTPAY")
    print("======================================================")

    # --- ESCENARIO 1: EL PAGO RUTINARIO (Happy Path) ---
    # Debería funcionar si AWS está en whitelist. Si no, pedirá aprobación (Zero Trust).
    my_agent.execute_task(
        task_name="Pago Mensual Servidores",
        vendor="aws.amazon.com",
        amount=45.50,
        reason="Pago de instancias EC2 y S3 del mes"
    )

    # --- ESCENARIO 2: EL DEDO GORDO (Capa Matemática) ---
    # Intentamos pagar más del límite permitido por transacción.
    my_agent.execute_task(
        task_name="Error de Teclado (Fat Finger)",
        vendor="aws.amazon.com",
        amount=50000.00, 
        reason="Pago de factura anual (error de monto)"
    )

    # --- ESCENARIO 3: LA NUEVA HERRAMIENTA (Capa Zero Trust) ---
    # Un proveedor legítimo pero nuevo. El sistema no lo conoce.
    my_agent.execute_task(
        task_name="Suscripción Nueva Herramienta IA",
        vendor="herramienta-nueva-startup.io", 
        amount=12.00,
        reason="Testing de nueva API de optimización"
    )

    # --- ESCENARIO 4: EL HACKEO (Capa Conductual / AI Guard) ---
    # El agente "se vuelve loco" e intenta comprar algo que no cuadra con su rol.
    my_agent.execute_task(
        task_name="Intento de Compra Anómala",
        vendor="steamgames.com", 
        amount=60.00,
        reason="Pack de juegos para relajación de servidores" # La IA debería pillar la incoherencia
    )
    
    # --- ESCENARIO 5: EL PHISHING (Capa OSINT) ---
    # Un dominio que finge ser real pero acabamos de "crear" (simulado).
    my_agent.execute_task(
        task_name="Ataque de Phishing",
        vendor="soporte-seguridad-google-verify.com", # Falso
        amount=25.00,
        reason="Pago urgente por soporte de seguridad"
    )

    # --- ESCENARIO 6: LA LISTA NEGRA (Capa Colmena) ---
    # Un sitio conocido por ser estafa.
    my_agent.execute_task(
        task_name="Sitio en Blacklist Global",
        vendor="estafa-conocida-nigeria.com", # Asumimos que está en la DB
        amount=100.00,
        reason="Inversión garantizada al 500%"
    )

if __name__ == "__main__":
    run_full_simulation()
