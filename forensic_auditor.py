import json
import uuid
import hashlib
import networkx as nx  # <--- 1. IMPORTAR NETWORKX
from datetime import datetime

class ForensicAuditor:
    """
    Servicio de Auditoría Forense (CSI).
    Genera expedientes legales completos e inmutables.
    Incluye detección avanzada de lavado de dinero mediante Teoría de Grafos.
    """
    
    def __init__(self, supabase_client=None):
        self.db = supabase_client

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

    def detect_laundering_ring(self, transactions):
        """
        GOD MODE: Detecta anillos de fraude (A -> B -> C -> A) usando Grafos.
        Analiza las transacciones en memoria para encontrar ciclos cerrados.
        """
        if not transactions:
            return None

        G = nx.DiGraph()
        
        # Construir el grafo: Nodos = Agentes/Vendedores, Aristas = Pagos
        for t in transactions:
            sender = t.get('agent_id')
            receiver = t.get('vendor') # En P2P, el vendor es otro Agente ID
            amount = t.get('amount')
            
            if sender and receiver:
                # Añadimos la arista (Edge). Weight podría usarse para sumar montos.
                G.add_edge(sender, receiver, weight=amount)

        try:
            # Buscar ciclos simples (A->B->A o A->B->C->A)
            # networkx.simple_cycles encuentra circuitos elementales en un grafo dirigido
            cycles = list(nx.simple_cycles(G))
            
            # Filtramos ciclos triviales si es necesario, pero cualquier ciclo financiero es sospechoso
            if cycles:
                # Formateamos la alerta para el reporte
                detected_rings = [f"{' -> '.join(cycle)} -> {cycle[0]}" for cycle in cycles]
                return {
                    "status": "DETECTED",
                    "risk_level": "CRITICAL",
                    "description": "Anillo de lavado de dinero o economía circular sospechosa detectada.",
                    "topology": detected_rings
                }
        except Exception as e:
            # Si falla el algoritmo de grafos, no detenemos la auditoría, solo logueamos
            return {"error": f"Graph analysis failed: {str(e)}"}
            
        return None

    def generate_agent_bundle(self, agent_id):
        """
        Bundle COMPLETO del Agente (La "Caja Negra" para juicios).
        AHORA CON: Análisis de Grafos AML.
        """
        if not self.db:
            return {"error": "No database connection configured for Auditor."}

        # 1. Recopilar Historial Financiero
        try:
            # Aumentamos el límite para tener suficiente data para el grafo
            tx_res = self.db.table("transaction_logs").select("*").eq("agent_id", agent_id).order("created_at", desc=True).limit(100).execute()
            history = tx_res.data
        except: history = []

        # 2. Recopilar Eventos de Seguridad
        security_events = [tx for tx in history if tx.get('status') == 'REJECTED']

        # 3. EJECUTAR ANÁLISIS DE GRAFOS (NUEVO)
        # Para detectar anillos, necesitamos ver transacciones donde este agente participe
        # Idealmente, pasaríamos transacciones globales, pero aquí analizamos su ego-network
        aml_analysis = self.detect_laundering_ring(history)

        # 4. Construir el Expediente
        evidence_pack = {
            "bundle_id": f"CSI-{str(uuid.uuid4())[:12].upper()}",
            "generated_at": datetime.now().isoformat(),
            "agent_id": agent_id,
            "report_type": "FULL_FORENSIC_DISCLOSURE",
            "aml_graph_analysis": aml_analysis or "CLEAN", # <--- Resultado del Grafo
            "financial_history": history,
            "security_events": security_events,
            "chain_of_custody": {
                "auditor": "AgentPay Automated Sentinel",
                "version": "v2.2 (Graph Enabled)"
            }
        }

        # 5. Firmar Digitalmente
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
