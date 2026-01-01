import os
import json
import datetime
from openai import OpenAI

# Configuración
COURT_MODEL = "gpt-4o"

class AutoLawyer:
    """
    TRIBUNAL SUPREMO: Infraestructura judicial robusta.
    Nunca devuelve 'None'. Siempre devuelve un veredicto estructural.
    """
    
    def __init__(self):
        self.api_key = os.environ.get("OPENAI_API_KEY")
        self.ai_enabled = bool(self.api_key)
        if self.ai_enabled:
            try:
                self.client = OpenAI(api_key=self.api_key)
            except:
                self.ai_enabled = False

    def _court_call(self, system_prompt, user_prompt, temperature=0.0):
        if not self.ai_enabled:
            raise Exception("AI Offline")
            
        try:
            response = self.client.chat.completions.create(
                model=COURT_MODEL,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                response_format={"type": "json_object"},
                temperature=temperature
            )
            content = response.choices[0].message.content
            if not content:
                raise ValueError("Empty response from OpenAI")
            return json.loads(content)
            
        except Exception as e:
            print(f"⚖️ [COURT ERROR] {str(e)}")
            return {}

    def analyze_case(self, agent_id, vendor, amount, claim_reason, proof_logs, transaction_context={}):
        """
        EL PROCESO JUDICIAL: Blindado.
        """
        print(f"⚖️ [HIGH COURT] Iniciando Arbitraje contra {vendor}...")
        
        # Fallback si no hay IA configurada
        if not self.ai_enabled:
            return {
                "viability": "DISMISSED",
                "judicial_opinion": "Court System Offline (No API Key).",
                "suggested_action": "REJECT_CLAIM",
                "confidence_score": 0
            }

        try:
            # ETAPA 1: DESCUBRIMIENTO
            discovery_prompt = f"""
            ACTÚA COMO PERITO FORENSE. Analiza logs: {proof_logs}.
            OUTPUT JSON: {{ "technical_failures": [], "evidence_weight": 0-100 }}
            """
            discovery = self._court_call("Forensic Agent", discovery_prompt)

            # ETAPA 2: DEFENSA
            adversary_prompt = f"""
            EVIDENCIA: {json.dumps(discovery)}. RECLAMO: "{claim_reason}".
            OUTPUT JSON: {{ "counter_arguments": [], "doubt_level": 0-100 }}
            """
            cross_exam = self._court_call("Defense Attorney", adversary_prompt, temperature=0.3)

            # ETAPA 3: VEREDICTO FINAL
            tribunal_prompt = f"""
            EVIDENCIA: {json.dumps(discovery)}
            DEFENSA: {json.dumps(cross_exam)}
            CASO: {claim_reason} (${amount})
            
            TAREA: Dicta sentencia final.
            OUTPUT JSON (Strict):
            {{
                "viability": "WINNABLE" | "DISMISSED",
                "judicial_opinion": "Breve explicación",
                "suggested_action": "REFUND" | "REJECT_CLAIM",
                "confidence_score": 0-100
            }}
            """
            verdict = self._court_call("Supreme Court", tribunal_prompt)
            
            # 🛡️ DEFENSA FINAL: Si el JSON vino vacío, forzar rechazo
            if not verdict.get("suggested_action"):
                return {
                    "viability": "ERROR",
                    "judicial_opinion": "Mistrial: AI generated invalid verdict.",
                    "suggested_action": "REJECT_CLAIM",
                    "confidence_score": 0
                }
            
            return verdict

        except Exception as e:
            print(f"🔥 CRITICAL COURT FAILURE: {e}")
            return {
                "viability": "ERROR",
                "judicial_opinion": f"System Error: {str(e)}",
                "suggested_action": "REJECT_CLAIM",
                "confidence_score": 0
            }
