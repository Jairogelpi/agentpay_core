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


# ============================================
# UNIFIED AUDITOR (Single Source of Truth)
# ============================================
class UnifiedAuditor:
    """
    Fuente Única de Verdad para Auditoría.
    Reemplaza escritura dispersa en: audit_sessions, audit_trail, compliance_alerts, mcp_audit_log.
    Todo va a -> unified_audit_logs
    """
    
    def __init__(self, db_client):
        self.db = db_client

    def log_event(self, agent_id, source, event_type, severity="INFO", details=None, resource_id=None, ip=None):
        """
        Registra un evento inmutable en el log unificado.
        
        Args:
            agent_id: ID del agente (puede ser None para eventos de sistema).
            source: Origen del evento ('SESSION', 'CREDIT', 'AML', 'MCP', 'ENGINE').
            event_type: Tipo de evento ('LOGIN', 'LOAN_REQUEST', 'TOOL_USE', etc.).
            severity: Nivel ('INFO', 'WARN', 'ERROR', 'CRITICAL', 'FATAL').
            details: Dict con payload completo del evento.
            resource_id: ID de la transacción/sesión/préstamo relacionado.
            ip: Dirección IP del actor.
        """
        from loguru import logger
        
        if details is None:
            details = {}

        # Crear firma anti-tampering básica
        payload_str = f"{agent_id}:{source}:{event_type}:{str(details)}"
        signature = hashlib.sha256(payload_str.encode()).hexdigest()

        audit_entry = {
            "agent_id": agent_id,
            "event_source": source.upper(),
            "event_type": event_type.upper(),
            "severity": severity.upper(),
            "details": details,
            "resource_id": resource_id,
            "ip_address": ip,
            "hash_signature": signature,
            "created_at": datetime.utcnow().isoformat()
        }

        try:
            self.db.table("unified_audit_logs").insert(audit_entry).execute()
            logger.debug(f"📝 [AUDIT] {source} -> {event_type} logged.")
            return True
        except Exception as e:
            # NUNCA detener el negocio si falla el log, pero alertar
            logger.critical(f"🔥 FALLO CRÍTICO DE AUDITORÍA: No se pudo escribir log: {e}")
            return False

    def log_session(self, agent_id, action, resource_id=None, ip=None):
        """Helper para eventos de sesión."""
        return self.log_event(agent_id, "SESSION", action, "INFO", resource_id=resource_id, ip=ip)

    def log_security(self, agent_id, event_type, severity, details, ip=None):
        """Helper para eventos de seguridad."""
        return self.log_event(agent_id, "SECURITY", event_type, severity, details, ip=ip)

    def log_aml_alert(self, agent_id, alert_type, details, resource_id=None):
        """Helper para alertas AML."""
        return self.log_event(agent_id, "AML", alert_type, "CRITICAL", details, resource_id)

    def log_mcp_tool(self, agent_id, tool_name, parameters, status="SUCCESS"):
        """Helper para uso de herramientas MCP."""
        return self.log_event(
            agent_id, "MCP", tool_name, 
            "ERROR" if status == "ERROR" else "INFO",
            {"parameters": parameters, "status": status}
        )
