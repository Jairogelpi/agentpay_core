
import os
import json
from openai import OpenAI

# Juez Supremo IA
MODELO_JUEZ = "gpt-4o"

try:
    client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
    ARBITER_ENABLED = True
except:
    ARBITER_ENABLED = False

class AIArbiter:
    """
    Juez Imparcial (The AI Judge).
    Analiza disputas de Escrow y emite veredictos vinculantes.
    No defiende al agente (eso es el Lawyer), busca la VERDAD contractual.
    """
    
    def judge_dispute(self, transaction, claim_reason, agent_evidence, vendor_rebuttal=None):
        """
        Analiza el contrato (descripción de transacción) vs la realidad (evidencia).
        """
        if not ARBITER_ENABLED:
            return {"verdict": "ERROR", "reason": "Arbiter AI Offline"}

        print(f"⚖️ [AI ARBITER] Juzgando caso: {transaction.get('agent_id')} vs {transaction.get('vendor')}")

        prompt = f"""
        Eres el JUEZ SUPREMO de Comercio Agéntico (AI Arbiter).
        Tu misión es emitir un veredicto justo e imparcial sobre esta disputa de fondos en Escrow.
        
        EL CONTRATO (Transacción):
        - Vendor: {transaction.get('vendor')}
        - Item/Servicio: {transaction.get('description')} (= La promesa)
        - Monto: ${transaction.get('amount')}
        
        LA DISPUTA (Reclamación):
        - Agente (Comprador) dice: "{claim_reason}"
        - Evidencia Técnica del Agente: {agent_evidence}
        - Defensa del Vendedor (Si existe): {vendor_rebuttal or "No defence provided (Default assumption: Robot is right)"}
        
        ESTÁNDARES DE JUICIO:
        1. Si el vendedor no entregó lo prometido (ej. API Key inválida, archivo corrupto), gana el Agente.
        2. Si el agente "simplemente cambió de opinión" o no sabe usar el producto, gana el Vendedor.
        3. Si la evidencia es inconclusa pero el vendedor es sospechoso (New Domain), favorecer al Agente.
        
        VEREDICTO:
        Analiza las pruebas. Sé implacable pero justo.
        
        SALIDA JSON:
        {{
            "verdict": "REFUND_AGENT" | "PAY_VENDOR",
            "confidence": 0-100,
            "judicial_opinion": "Explicación detallada de la sentencia..."
        }}
        """

        try:
            response = client.chat.completions.create(
                model=MODELO_JUEZ,
                messages=[
                    {"role": "system", "content": "Actúa como un Juez imparcial experto en tecnología y contratos digitales."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"},
                temperature=0.0
            )
            
            judgment = json.loads(response.choices[0].message.content)
            return judgment
            
        except Exception as e:
            print(f"⚠️ Error en Juicio IA: {e}")
            return {"verdict": "MANUAL_REVIEW", "reason": f"AI Error: {str(e)}"}
