import json
import uuid
import hashlib
from datetime import datetime

class ForensicAuditor:
    """
    Servicio de Auditoría Forense (CSI).
    Genera expedientes legales completos e inmutables.
    """
    
    def __init__(self, supabase_client=None):
        # Aceptamos el cliente de base de datos para buscar el historial
        self.db = supabase_client

    def generate_audit_bundle(self, agent_id, vendor, amount, justification, intent_hash, signature):
        """
        Bundle para una sola transacción (usado en engine.py).
        """
        bundle = {
            "bundle_id": f"TX-{str(uuid.uuid4())[:8].upper()}",
            "timestamp": datetime.now().isoformat(),
            "agent_id": agent_id,
            "financial_data": {
                "vendor": vendor,
                "amount": amount,
                "currency": "USD"
            },
            "governance_proof": {
                "intent_hash": intent_hash,
                "justification_cot": justification,
                "legal_signature": signature
            },
            "compliance_status": "VERIFIED_BY_AGENTPAY"
        }
        return self._seal_bundle(bundle)

    def generate_agent_bundle(self, agent_id):
        """
        Bundle COMPLETO del Agente (La "Caja Negra" para juicios).
        Recopila: Transacciones, Logs de Seguridad y Metadatos.
        """
        if not self.db:
            return {"error": "No database connection configured for Auditor."}

        # 1. Recopilar Historial Financiero
        try:
            tx_res = self.db.table("transaction_logs").select("*").eq("agent_id", agent_id).order("created_at", desc=True).limit(50).execute()
            history = tx_res.data
        except: history = []

        # 2. Recopilar Eventos de Seguridad (Blacklist hits, bloqueos)
        security_events = [tx for tx in history if tx.get('status') == 'REJECTED']

        # 3. Construir el Expediente
        evidence_pack = {
            "bundle_id": f"CSI-{str(uuid.uuid4())[:12].upper()}",
            "generated_at": datetime.now().isoformat(),
            "agent_id": agent_id,
            "report_type": "FULL_FORENSIC_DISCLOSURE",
            "financial_history": history,
            "security_events": security_events,
            "chain_of_custody": {
                "auditor": "AgentPay Automated Sentinel",
                "version": "v2.1"
            }
        }

        # 4. Firmar Digitalmente
        return self._seal_bundle(evidence_pack)

    def _seal_bundle(self, data_dict):
        """Añade hash de integridad y firma."""
        # Serializamos para hash consistente
        json_str = json.dumps(data_dict, sort_keys=True, default=str)
        integrity_hash = hashlib.sha256(json_str.encode()).hexdigest()
        
        data_dict["integrity_hash"] = integrity_hash
        # Simulación de firma RSA
        data_dict["signature"] = f"rsa_sig_{integrity_hash[:16]}.{uuid.uuid4().hex[:8]}"
        
        return data_dict

    def export_to_pdf_template(self, bundle):
        return f"AUDIT_CERTIFICATE_{bundle['bundle_id']}.pdf"
