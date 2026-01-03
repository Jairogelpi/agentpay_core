import os
import json
import datetime
from loguru import logger
from openai import OpenAI

# Configuración
COURT_MODEL = "gpt-4o"

class AutoLawyer:
    """
    TRIBUNAL SUPREMO: Infraestructura judicial robusta.
    Garantiza que siempre se devuelva un veredicto JSON, incluso si la IA falla.
    """
    
    def __init__(self):
        self.api_key = os.environ.get("OPENAI_API_KEY")
        self.ai_enabled = bool(self.api_key)
        self.client = None
        if self.ai_enabled:
            try:
                self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
            except Exception as e:
                logger.error(f"⚠️ OpenAI Client Init Error: {e}")
                self.ai_enabled = False

    def _court_call(self, system_prompt, user_prompt, temperature=0.0):
        if not self.ai_enabled or not self.client:
            # Retornamos dict vacío en vez de lanzar excepción
            return {}
            
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
                return {}
            return json.loads(content)
            
        except Exception as e:
            logger.error(f"⚖️ [COURT ERROR] {str(e)}")
            return None

    def analyze_case(self, agent_id, vendor, amount, claim_reason, proof_logs, transaction_context=None):
        """
        JUEZ SUPREMO: Decide quién tiene la razón en un conflicto.
        Acepta contexto de transacción opcional para mayor precisión.
        """
        logger.info(f"⚖️ [HIGH COURT] Iniciando Arbitraje para Agente {agent_id} contra {vendor}...")
        
        # 1. Fallback si no hay IA
        if not self.ai_enabled:
            return {
                "viability": "DISMISSED",
                "judicial_opinion": "Court System Offline (No API Key).",
                "suggested_action": "REJECT_CLAIM",
                "confidence_score": 0
            }
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
            
            # 🛡️ DEFENSA FINAL: Si el JSON vino vacío o inválido
            if not verdict or not verdict.get("suggested_action"):
                return {
                    "viability": "ERROR",
                    "judicial_opinion": "Mistrial: AI generated invalid verdict.",
                    "suggested_action": "REJECT_CLAIM",
                    "confidence_score": 0
                }
            
            return verdict

        except Exception as e:
            logger.critical(f"🔥 CRITICAL COURT FAILURE: {e}")
            # RETORNO DE EMERGENCIA (¡Esto es lo que faltaba!)
            return {
                "viability": "ERROR",
                "judicial_opinion": f"System Error: {str(e)}",
                "suggested_action": "REJECT_CLAIM",
                "confidence_score": 0
            }

    # --- PILLAR 4: AUTO-DISPUTES ---
    def raise_escrow_dispute(self, forensic_hash, evidence_bundle):
        """
        Genera un paquete de disputa formal para Stripe/PayPal.
        Usa el expediente forense del ForensicAuditor.
        """
        dispute_id = f"DSP-{datetime.datetime.now().strftime('%Y%m%d')}-{json.dumps(evidence_bundle).__hash__()}"
        
        # 1. Redactar Carta Legal Automática
        legal_letter_prompt = f"""
        ACT AS LEGAL COUNSEL. Write a formal dispute letter for transaction {forensic_hash}.
        EVIDENCE: {json.dumps(evidence_bundle)}
        
        CLAIM: "Fraudulent transaction detected by AI Sentinel System."
        REQUEST: "Immediate chargeback and freeze of vendor funds."
        """
        
        letter = self._court_call("Legal Clerk", legal_letter_prompt, temperature=0.2)
        
        return {
            "dispute_id": dispute_id,
            "status": "FILED_AUTOMATICALLY",
            "legal_brief": letter,
            "attached_evidence_hash": forensic_hash
        }
