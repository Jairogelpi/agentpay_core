import os
import json
import datetime
from openai import OpenAI

# Configuración: The High Court (Supreme Judicial Tier)
COURT_MODEL = "gpt-4o"

class AutoLawyer:
    """
    EL TRIBUNAL SUPREMO: Infraestructura judicial de alta precisión para Agentes.
    Resuelve conflictos de Escrow y redacta documentos legales con rigor de Corte Suprema.
    """
    
    def __init__(self):
        try:
            self.client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
            self.ai_enabled = True
        except:
            self.ai_enabled = False

    def _court_call(self, system_prompt, user_prompt, temperature=0.0):
        response = self.client.chat.completions.create(
            model=COURT_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            response_format={"type": "json_object"},
            temperature=temperature
        )
        return json.loads(response.choices[0].message.content)

    def analyze_case(self, agent_id, vendor, amount, claim_reason, proof_logs, transaction_context={}):
        """
        EL PROCESO JUDICIAL: 3 Etapas de Arbitraje de Élite.
        """
        if not self.ai_enabled:
            return {"decision": "UNABLE_TO_JUDGE", "judicial_opinion": "Court System Offline."}
            
        print(f"⚖️ [HIGH COURT] Iniciando Arbitraje Multi-Etapa contra {vendor}...")

        # --- ETAPA 1: DESCUBRIMIENTO DE EVIDENCIA ---
        discovery_prompt = f"""
        ACTÚA COMO UN PERITO INFORMÁTICO FORENSE.
        Analiza estos logs técnicos del agente {agent_role if 'agent_role' in locals() else 'IA'}:
        {proof_logs}
        
        TAREA: Identifica fallos objetivos (Timeouts, 4xx, 5xx, payloads vacíos, inconsistencias de API).
        
        OUTPUT JSON:
        {{
            "technical_failures": ["list of facts"],
            "evidence_weight": 0-100,
            "fact_summary": "resumen técnico"
        }}
        """
        discovery = self._court_call("Elite Forensic Discovery Agent.", discovery_prompt)

        # --- ETAPA 2: INTERROGATORIO ADVERSARIAL (CROSS-EXAMINATION) ---
        adversary_prompt = f"""
        EVIDENCIA RECOGIDA: {json.dumps(discovery)}
        RECLAMO DEL AGENTE: "{claim_reason}"
        VENDOR: {vendor} (${amount})
        
        TAREA: Actúa como el Defensor del Vendedor. Cuestiona el reclamo del agente. 
        ¿Es posible que el fallo sea culpa del agente? ¿El servicio se entregó pero el agente no supo leerlo?
        Busca EXCEPCIONES en los TyC estándar de APIs.
        
        OUTPUT JSON:
        {{
            "counter_arguments": ["logic 1", "logic 2"],
            "doubt_level": 0-100,
            "defender_verdict": "string"
        }}
        """
        cross_exam = self._court_call("Aggressive Defense Attorney.", adversary_prompt, temperature=0.2)

        # --- ETAPA 3: VEREDICTO DEL TRIBUNAL ---
        tribunal_prompt = f"""
        EVIDENCIA FORENSE: {json.dumps(discovery)}
        DEFENSA ADVERSARIAL: {json.dumps(cross_exam)}
        CASO: {claim_reason} (${amount})
        
        TAREA: Como Tribunal de Arbitraje, dicta sentencia. 
        Aplica justicia ciega basada en el desempeño técnico.
        
        OUTPUT JSON:
        {{
            "viability": "WINNABLE" | "WEAK" | "DISMISSED",
            "judicial_opinion": "Análisis profundo reconciliando evidencia y defensa",
            "suggested_action": "REFUND" | "NEGOTIATE" | "REJECT_CLAIM",
            "legal_dossier": "Texto formal para Stripe/Bancos en inglés técnico",
            "confidence_score": 0-100
        }}
        """
        verdict = self._court_call("The High Court Tribunal.", tribunal_prompt)
        
        return verdict

    def file_stripe_dispute(self, transaction_id, dossier):
        """
        Ejecución Financiera: Fuerza el reembolso en Stripe basado en el expediente judicial.
        """
        import stripe
        stripe.api_key = os.environ.get("STRIPE_SECRET_KEY")
        
        try:
            refund = stripe.Refund.create(
                payment_intent=transaction_id,
                reason="requested_by_customer",
                metadata={"court_ruling_ref": f"JUD-{datetime.datetime.now().strftime('%Y%m%d')}"}
            )
            return {"status": "JUDICIAL_REFUND_EXECUTED", "refund_id": refund.id}
        except Exception as e:
            return {"status": "EXECUTION_FAILED", "error": str(e)}
