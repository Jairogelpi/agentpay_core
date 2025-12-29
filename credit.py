import random
import datetime

class CreditBureau:
    """
    Agencia de Calificación Crediticia para IAs.
    Calcula el 'FICO Score' de un agente basándose en su historial.
    """
    
    def __init__(self, db_client):
        self.db = db_client

    def calculate_org_score(self, owner_name):
        """
        Calcula la reputación promedio de toda la organización (Mente Colmena Corporativa).
        """
        try:
             # Buscar todos los agentes de esta empresa
             response = self.db.table("wallets").select("agent_id").eq("owner_name", owner_name).execute()
             agents = response.data
             
             if not agents: return 300
             
             total_score = 0
             count = 0
             for a in agents:
                 s = self.calculate_score(a['agent_id'])
                 if s > 300: # Solo contamos agentes activos con historia
                     total_score += s
                     count += 1
            
             if count == 0: return 300
             
             return int(total_score / count)
        except Exception as e:
            print(f"Error calculando Org Score: {e}")
            return 300

    def calculate_score(self, agent_id):
        """
        Analiza el historial de transacciones y devuelve un Score (0-850).
        """
        # En producción real, esto sería una consulta SQL agregada compleja
        # Simulamos lógica básica:
        # +10 puntos por cada pago APPROVED
        # -50 puntos por cada REJECTED
        # -200 puntos por cada FLAGGED
        
        try:
            # Recuperamos ultimas 50 transacciones
            response = self.db.table("transaction_logs").select("status").eq("agent_id", agent_id).limit(50).execute()
            history = response.data
            
            base_score = 600 # Score inicial neutro
            
            for tx in history:
                if tx['status'] == 'APPROVED':
                    base_score += 10
                elif tx['status'] == 'REJECTED':
                    base_score -= 50
                elif tx['status'] == 'FLAGGED':
                    base_score -= 100
            
            # Normalizar entre 300 y 850
            final_score = max(300, min(850, base_score))
            return final_score
            
        except Exception as e:
            print(f"Error calculando score: {e}")
            return 300 # Score mínimo por defecto ante error

    def check_credit_eligibility(self, agent_id):
        """
        Determina si el agente merece crédito y cuánto.
        Incluye 'Aval Corporativo': Si la organización es buena, sube el score.
        """
        score = self.calculate_score(agent_id)
        boost_reason = ""
        
        try:
             # Buscar owner de este agente
             w_resp = self.db.table("wallets").select("owner_name").eq("agent_id", agent_id).execute()
             if w_resp.data:
                 owner = w_resp.data[0]['owner_name']
                 org_score = self.calculate_org_score(owner)
                 
                 # Si la empresa es muy fiable (>700), avalamos al agente
                 if org_score > 700:
                     boost = 50
                     score = min(850, score + boost)
                     boost_reason = f" (+{boost} Aval Corporativo '{owner}')"
        except Exception as e:
            print(f"Error checking owner logic: {e}")

        
        if score >= 750:
            return {
                "eligible": True,
                "score": score,
                "tier": "PLATINUM",
                "credit_limit": 5000.00,
                "interest_rate": 0.05, # 5% anual
                "message": f"FICO Score: {score}{boost_reason}"
            }
        elif score >= 650:
            return {
                "eligible": True,
                "score": score,
                "tier": "GOLD",
                "credit_limit": 1000.00,
                "interest_rate": 0.10
            }
        else:
            return {
                "eligible": False,
                "score": score,
                "tier": "STANDARD",
                "credit_limit": 0.00,
                "reason": f"Score insuficiente ({score}). Sigue operando con prepago.",
                "message": f"FICO Score: {score}{boost_reason}"
            }
