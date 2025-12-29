import os
import json
from openai import OpenAI
import datetime

class AutoLawyer:
    """
    Abogado Automatizado para Agentes de IA.
    Analiza logs técnicos y redacta disputas de pago formales (Stripe/PayPal formatted).
    """
    
    def __init__(self):
        try:
            self.client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
            self.ai_enabled = True
        except:
            self.ai_enabled = False

    def analyze_case(self, agent_id, vendor, amount, claim_reason, proof_logs):
        """
        Analiza la viabilidad de una disputa y genera el dossier de evidencia.
        """
        if not self.ai_enabled:
            return {
                "decision": "UNABLE_TO_JUDGE", 
                "dossier": "AI not available. Manual review required."
            }
            
        print(f"⚖️ ABOGADO IA: Analizando caso contra {vendor} por ${amount}...")

        prompt = f"""
        ACTÚA COMO UN ABOGADO EXPERTO EN DISPUTAS DE PAGOS DIGITALES (STRIPE/VISA).
        
        CASO:
        - Cliente (Agente IA): {agent_id}
        - Proveedor Acusado: {vendor}
        - Monto en Disputa: ${amount}
        - Reclamación del Cliente: "{claim_reason}"
        
        EVIDENCIA TÉCNICA (LOGS DEL AGENTE):
        {proof_logs}
        
        TAREA:
        1. Analiza los logs. ¿Demuestran que el proveedor falló (ej: error 500, 403, timeout, key invalida)?
        2. Determina si el caso es GANABLE ("WINNABLE") o DÉBIL ("WEAK").
        3. REDACTA EL DOSSIER PARA STRIPE (En Inglés Formal Legal):
           - "Evidence Summary": Resumen de los hechos.
           - "Technical Proof": Explicación de los logs.
           - "Conclusion": Por qué se debe devolver el dinero.
           
        SALIDA JSON:
        {{
            "viability": "WINNABLE" | "WEAK",
            "confidence_score": 0-100,
            "dossier_text": " Texto completo del reclamo formal... "
        }}
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "Eres un abogado experto en disputas fintech."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"},
                temperature=0.0
            )
            
            return json.loads(response.choices[0].message.content)
            
        except Exception as e:
            return {"decision": "ERROR", "error": str(e)}

    def file_stripe_dispute(self, transaction_id, dossier):
        """
        Simula la presentación formal de la evidencia ante la API de Stripe.
        """
        # En producción: stripe.Dispute.update(dispute_id, evidence=...)
        dispute_ref = f"DSP-{datetime.datetime.now().strftime('%Y%m%d')}-{transaction_id[:4]}"
        
        return {
            "status": "FILED",
            "reference": dispute_ref,
            "filed_at": datetime.datetime.now().isoformat(),
            "note": "Evidence dossier submitted successfully via API."
        }
