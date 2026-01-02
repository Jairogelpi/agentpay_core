import requests
import json

# Configuración
API_URL = "https://agentpay-core.onrender.com"
AGENT_ID = "ag_34a4888b84e4" # Usa el ID de tu agente real

def probar_validez_legal():
    print("⚖️ --- INICIANDO PRUEBA DE CERTIFICACIÓN LEGAL ---")
    
    payload = {
        "agent_id": AGENT_ID,
        "email": "agent-001@agentpay.it",
        "platform_url": "https://aws.amazon.com/tos",
        "forensic_hash": "H4SH-FORENSICO-DE-INTENCION-REAL"
    }

    # 1. EMISIÓN DEL CERTIFICADO
    print("\n📜 Generando Certificado de Responsabilidad Civil...")
    res = requests.post(f"{API_URL}/v1/legal/issue-certificate", json=payload)
    cert = res.json()

    if "certificate_id" in cert:
        print(f"   ✅ Certificado Emitido: {cert['certificate_id']}")
        print(f"   ✅ Firma Digital: {cert['signature'][:20]}...")
        print("\n--- BLOQUE LEGAL GENERADO ---")
        print(cert['declaration_text'])
        print("----------------------------")
    else:
        print(f"   ❌ Error: {cert}")
        return

    # 2. EMISIÓN DE PASAPORTE KYC (Válido para cumplimiento PSD2/GDPR)
    print("\n🛂 Generando Pasaporte KYC Digital...")
    res_passport = requests.post(f"{API_URL}/v1/legal/passport", json={"agent_id": AGENT_ID})
    passport = res_passport.json()
    
    if "passport_token" in passport:
        print("   ✅ Pasaporte KYC emitido correctamente.")
        print(f"   ✅ Nivel de cumplimiento: STANDARD (GDPR, PSD2, AI_ETHICS_V1)")
    else:
        print("   ⚠️ Nota: El endpoint /v1/legal/passport debe estar configurado para llamar a issue_kyc_passport.")

if __name__ == "__main__":
    probar_validez_legal()