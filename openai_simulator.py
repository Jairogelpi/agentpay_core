import time
from agentpay import AgentPay

def simulate_openai_signup():
    """
    Simulación detallada de un agente IA registrándose en OpenAI.
    """
    print("\n" + "="*50)
    print("🤖 AGENTPAY: OPENAI SIGNUP SIMULATOR")
    print("="*50)

    # 1. Preparación del Agente
    print("\n[STEP 1] Inicializando Agente Autónomo...")
    agent = AgentPay.from_env()
    
    # 2. Generación de Identidad Profesional
    # OpenAI bloquea emails temporales (10minmail, etc), 
    # pero acepta nuestro dominio corporativo agentpay.it.com.
    print(f"\n[STEP 2] Generando identidad corporativa...")
    email = agent.get_email()
    print(f"💎 Identidad asignada: {email}")
    
    # 3. Simulación de Interacción con OpenAI
    print(f"\n[STEP 3] Iniciando flujo en 'auth.openai.com'...")
    print(f"  > Introduciendo email: {email}")
    print("  > Saltando protecciones de bot (resuelto internamente)...")
    time.sleep(2)
    print("  > Formulario enviado correctamente.")
    
    # 4. Espera del Código de Verificación (OTP)
    print(f"\n[STEP 4] Esperando correo de verificación de OpenAI...")
    print("📢 ACCIÓN REQUERIDA: Envía un email ahora a:")
    print(f"👉 {email}")
    print("💡 El asunto puede ser 'OpenAI Verification' y el cuerpo 'Your code is 123456'.")
    print("-" * 30)
    
    # wait_for_otp hace el polling por nosotros y usa IA para extraer el código 
    # de un párrafo complejo si es necesario.
    otp_data = agent.wait_for_otp(timeout=180) # Damos 3 minutos
    
    if otp_data:
        code = otp_data.get('otp_code')
        sender = otp_data.get('sender')
        print(f"\n✅ [EMAIL RECIBIDO]")
        print(f"📧 De: {sender}")
        print(f"🔑 CÓDIGO EXTRAÍDO POR IA: {code}")
        
        # 5. Finalización del Registro
        print(f"\n[STEP 5] Completando registro en OpenAI...")
        print(f"  > Introduciendo código {code}...")
        time.sleep(1)
        print("🎉 [SUCCESS] ¡Agente registrado exitosamente en OpenAI!")
        print("🚀 El agente ya puede empezar a usar la API de ChatGPT.")
    else:
        print("\n❌ Error: No se detectó ningún correo de verificación en el tiempo límite.")

if __name__ == "__main__":
    # Asegúrate de tener tu AGENTPAY_API_KEY en el entorno
    simulate_openai_signup()
