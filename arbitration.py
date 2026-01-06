import os
import json
import uuid
from openai import OpenAI
from loguru import logger
from datetime import datetime

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
    Ahora con PODER EJECUTIVO (Execute Verdict).
    """
    
    def __init__(self, engine_instance=None):
        self.engine = engine_instance # Inyección de dependencia para mover fondos
    
    def judge_dispute(self, transaction, claim_reason, agent_evidence, vendor_rebuttal=None):
        """
        Analiza el contrato y EJECUTA la sentencia.
        """
        if not ARBITER_ENABLED:
            return {"verdict": "ERROR", "reason": "Arbiter AI Offline"}

        logger.info(f"⚖️ [AI ARBITER] Juzgando caso: {transaction.get('agent_id')} vs {transaction.get('vendor')}")

        prompt = f"""
        Eres el JUEZ SUPREMO de Comercio Agéntico (AI Arbiter).
        Tu misión es emitir un veredicto justo e imparcial sobre esta disputa de fondos en Escrow.
        
        EL CONTRATO (Transacción):
        - ID: {transaction.get('id')}
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
            
            # --- FASE DE EJECUCIÓN (REAL MONEY MOVEMENT) ---
            execution_report = self.execute_verdict(transaction.get('id'), transaction.get('agent_id'), transaction.get('amount'), judgment)
            judgment["execution"] = execution_report
            
            return judgment
            
        except Exception as e:
            logger.error(f"⚠️ Error en Juicio IA: {e}")
            return {"verdict": "MANUAL_REVIEW", "reason": f"AI Error: {str(e)}"}

    def execute_verdict(self, transaction_id, agent_id, amount, verdict_json):
        """
        Ejecuta la sentencia final en la base de datos y pasarelas de pago.
        """
        decision = verdict_json.get("verdict")
        logger.info(f"🔨 [ARBITER EXECUTION] Veredicto: {decision} para TX {transaction_id}")
        
        if not self.engine:
            return {"status": "FAILED", "reason": "No Execution Engine linked."}
            
        result = {"status": "PENDING", "action": decision}

        try:
            if decision == "REFUND_AGENT":
                # 1. Llamar al Engine para reembolsar (Redis + DB)
                # OJO: Asumimos que _reverse_transaction maneja la lógica de reembolso
                # Necesitamos pasar el agent_id y el monto
                self.engine._reverse_transaction(agent_id, float(amount))
                
                # 2. Actualizar estado de disputa en DB
                self.engine.db.table("disputes").upsert({
                    "transaction_id": transaction_id,
                    "status": "RESOLVED_REFUNDED",
                    "verdict_json": verdict_json,
                    "resolved_at": datetime.now().isoformat()
                }).execute()
                
                result["status"] = "EXECUTED_REFUND"
                logger.success(f"   ✅ [JUSTICE] Reembolso de ${amount} ejecutado para {agent_id}")

            elif decision == "PAY_VENDOR":
                # Liberar fondos al vendedor (En nuestro caso, simplemente marcamos como resuelto y 'Lost' para el agente)
                # Si tuviéramos Hold en Stripe, aquí haríamos capture. Por ahora el dinero ya salió del wallet.
                
                self.engine.db.table("disputes").upsert({
                    "transaction_id": transaction_id,
                    "status": "RESOLVED_PAID",
                    "verdict_json": verdict_json,
                    "resolved_at": datetime.now().isoformat()
                }).execute()
                
                result["status"] = "EXECUTED_PAYMENT"
                logger.info(f"   ✅ [JUSTICE] Pago confirmado al vendedor. Reclamo cerrado.")

            else: 
                result["status"] = "UNKNOWN_VERDICT"
        
        except Exception as e:
            logger.error(f"🔥 Error ejecutando sentencia: {e}")
            result["status"] = "EXECUTION_ERROR"
            result["error"] = str(e)
            
        return result
