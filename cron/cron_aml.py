import os
import networkx as nx
from dotenv import load_dotenv
from supabase import create_client, Client
from loguru import logger
from datetime import datetime, timedelta
from observability import setup_observability

# Cargar variables de entorno
load_dotenv()

# Configurar Observabilidad Centralizada (Logtail/BetterStack + Sentry)
setup_observability()

class AMLSentinel:
    """
    Vigilante Nocturno Anti-Lavado de Dinero.
    Ejecuta algoritmos de Grafos pesados que no pueden correr en tiempo real.
    """
    
    def __init__(self):
        url = os.environ.get("SUPABASE_URL")
        key = os.environ.get("SUPABASE_KEY")
        if not url or not key:
            logger.error("❌ Credenciales Supabase faltantes.")
            raise ValueError("Missing Supabase Credentials")
            
        self.db: Client = create_client(url, key)

    def fetch_global_transactions(self, days=30):
        """Descarga transacciones recientes para construir el grafo global."""
        start_date = (datetime.utcnow() - timedelta(days=days)).isoformat()
        
        logger.info(f"📡 Descargando transacciones desde {start_date}...")
        
        all_txs = []
        page = 0
        page_size = 1000
        
        while True:
            # Paginación para no reventar memoria
            res = self.db.table("transaction_logs")\
                .select("agent_id, vendor, amount, id, created_at")\
                .gte("created_at", start_date)\
                .range(page * page_size, (page + 1) * page_size - 1)\
                .execute()
                
            data = res.data
            if not data:
                break
                
            all_txs.extend(data)
            page += 1
            logger.info(f"   ...Pagina {page} cargada ({len(data)} items)")
            
        logger.info(f"✅ Total transacciones para análisis: {len(all_txs)}")
        return all_txs

    def build_and_analyze_graph(self, transactions):
        """Construye grafo dirigido y busca ciclos."""
        G = nx.DiGraph()
        
        for t in transactions:
            u = t['agent_id'] # Origen
            v = t['vendor']   # Destino
            
            # Normalizar nodos (Vendor puede ser URL o ID de otro agente)
            if not u or not v: continue
            
            # Añadimos arista. Podemos acumular peso (monto total)
            if G.has_edge(u, v):
                G[u][v]['weight'] += float(t['amount'])
                G[u][v]['count'] += 1
            else:
                G.add_edge(u, v, weight=float(t['amount']), count=1)

        logger.info(f"🕸️ Grafo construido: {G.number_of_nodes()} nodos, {G.number_of_edges()} conexiones.")

        # ALGORITMO: Simple Cycles (DFS)
        # Ojo: NP-Hard en grafos muy densos, pero manageable en financieros ralos con límite de profundidad implícito
        try:
            logger.info("🕵️ Buscando anillos de fraude (Cycles)...")
            cycles = list(nx.simple_cycles(G))
            
            suspicious_rings = []
            for cycle in cycles:
                if len(cycle) < 2: continue # Auto-ciclos triviales (A->A) a veces permitidos o ignorados
                
                # Criterio: ¿Es un ciclo financiero relevante?
                # Ej: A -> B -> C -> A (Triangulación clásica)
                
                # Calcular volumen total del ciclo (opcional)
                ring_vol = 0
                for i in range(len(cycle)):
                    u, v = cycle[i], cycle[(i + 1) % len(cycle)]
                    ring_vol += G[u][v]['weight']
                
                suspicious_rings.append({
                    "nodes": cycle,
                    "length": len(cycle),
                    "estimated_volume": ring_vol
                })
                
            return suspicious_rings
            
        except Exception as e:
            logger.error(f"❌ Error analizando grafo: {e}")
            return []

    def flag_fraud_ring(self, ring):
        """Marca a los usuarios involucrados y genera alerta."""
        nodes = ring['nodes']
        logger.critical(f"🚨 FRAUDE DETECTADO: Anillo de {len(nodes)} nodos. Vol: ${ring['estimated_volume']:.2f}")
        logger.critical(f"   Participantes: {nodes}")

        # 1. Registrar Alerta en DB (Tabla de Compliance/Alerts)
        for agent_id in nodes:
            # Solo si parece ser un ID de agente (UUID) y no un vendor externo (google.com)
            # Simplificación: Asumimos que si está en 'agent_id' es agente. 
            # Si está en 'vendor' y es parte del ciclo, investigamos.
            
            alert = {
                "agent_id": agent_id,
                "type": "AML_FRAUD_RING",
                "severity": "CRITICAL",
                "description": f"Participación en esquema circular detectado: {' -> '.join(nodes)}",
                "metadata": ring
            }
            try:
                self.db.table("compliance_alerts").insert(alert).execute()
            except Exception as e:
                # Si la tabla no existe, loguear
                logger.error(f"No se pudo guardar alerta en DB: {e}")

    def run_nightly_job(self):
        logger.info("🌙 Iniciando AML Sentinel (Nightly Job)...")
        txs = self.fetch_global_transactions(days=30)
        
        if not txs:
            logger.info("💤 No hay transacciones para analizar.")
            return

        rings = self.build_and_analyze_graph(txs)
        
        if rings:
            logger.warning(f"⚠️ Se detectaron {len(rings)} posibles anillos de lavado.")
            for ring in rings:
                self.flag_fraud_ring(ring)
        else:
            logger.success("✨ No se detectaron anillos de fraude. Red limpia.")

if __name__ == "__main__":
    sentinel = AMLSentinel()
    sentinel.run_nightly_job()
