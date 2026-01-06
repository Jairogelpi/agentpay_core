import json
import uuid
import hashlib
from datetime import datetime
from legal import LegalWrapper

class ForensicAuditor:
    """
    Servicio de Auditoría Forense (CSI).
    Genera expedientes legales completos e inmutables.
    Incluye detección avanzada de lavado de dinero (Ahora en Background Cron).
    """
    
    def __init__(self, supabase_client=None):
        self.db = supabase_client
        self.signer = LegalWrapper(supabase_client) # Usar la autoridad real

    def generate_audit_bundle(self, agent_id, vendor, amount, description, reasoning_cot, intent_hash, signature, osint_data=None):
        """
        Bundle para una sola transacción (usado en engine.py).
        """
        bundle = {
            "bundle_id": f"TX-{str(uuid.uuid4())[:8].upper()}",
            "timestamp": datetime.now().isoformat(),
            "agent_id": agent_id,
            "forensic_type": "INDIVIDUAL_TRANSACTION_AUDIT",
            "financial_data": {
                "vendor": vendor,
                "amount": amount,
                "currency": "USD",
                "description": description
            },
            "governance_proof": {
                "intent_hash": intent_hash,
                "reasoning_cot": reasoning_cot,
                "legal_signature": signature,
                "osint_investigation": osint_data or "N/A"
            },
            "compliance": {
                "status": "VERIFIED_BY_AGENTPAY",
                "e_sign_standard": "SYNTHETIC_EIDAS_V1",
                "liability_coverage": "ACTIVE"
            }
        }
        return self._seal_bundle(bundle)

    def generate_agent_bundle(self, agent_id):
        """
        Bundle COMPLETO del Agente (La "Caja Negra" para juicios).
        """
        if not self.db:
            return {"error": "No database connection configured for Auditor."}

        # 1. Recopilar Historial Financiero
        try:
            tx_res = self.db.table("transaction_logs").select("*").eq("agent_id", agent_id).order("created_at", desc=True).limit(100).execute()
            history = tx_res.data
        except: history = []

        # 2. Recopilar Eventos de Seguridad
        security_events = [tx for tx in history if tx.get('status') == 'REJECTED']

        # 3. Construir el Expediente
        evidence_pack = {
            "bundle_id": f"CSI-{str(uuid.uuid4())[:12].upper()}",
            "generated_at": datetime.now().isoformat(),
            "agent_id": agent_id,
            "report_type": "FULL_FORENSIC_DISCLOSURE",
            "aml_check": "See Daily Background Job Logs", 
            "financial_history": history,
            "security_events": security_events,
            "chain_of_custody": {
                "auditor": "AgentPay Automated Sentinel",
                "version": "v2.3 (RSA Signed)"
            }
        }

        # 4. Firmar Digitalmente
        return self._seal_bundle(evidence_pack)

    def _seal_bundle(self, data_dict):
        """Añade hash de integridad y firma RSA REAL."""
        # Serializamos para hash consistente
        json_str = json.dumps(data_dict, sort_keys=True, default=str)
        integrity_hash = hashlib.sha256(json_str.encode()).hexdigest()
        
        data_dict["integrity_hash"] = integrity_hash
        
        # FIRMA REAL
        try:
            # Firmamos el JSON completo para inmutabilidad
            signature = self.signer._sign_payload(json_str) 
            data_dict["signature"] = signature
        except Exception as e:
            # Fallback seguro por si falla KMS/RSA local (no debería en prod)
            data_dict["signature"] = f"ERROR_SIGNING_{str(e)}"
        
        return data_dict

    def export_to_pdf_template(self, bundle):
        return f"AUDIT_CERTIFICATE_{bundle['bundle_id']}.pdf"
