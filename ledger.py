import uuid
from decimal import Decimal
from loguru import logger

class LedgerManager:
    def __init__(self, db_client):
        self.db = db_client

    def get_or_create_account(self, agent_id, name=None, acc_type="LIABILITY"):
        """
        Helper para obtener la cuenta contable de un agente.
        Si no existe, la crea on-the-fly.
        """
        try:
            # 1. Buscar existente
            res = self.db.table("accounts").select("id").eq("agent_id", agent_id).execute()
            if res.data:
                return res.data[0]['id']
            
            # 2. Crear si no existe
            logger.info(f"🆕 Creando cuenta contable para {agent_id}...")
            new_acc = {
                "name": name or f"Wallet: {agent_id}",
                "type": acc_type,
                "agent_id": agent_id,
                "balance": 0.00
            }
            res_create = self.db.table("accounts").insert(new_acc).execute()
            return res_create.data[0]['id']
        except Exception as e:
            logger.error(f"❌ Error Ledger Account Lookup: {e}")
            return None

    def record_entry(self, transaction_id, movements):
        """
        Registra un movimiento de doble entrada atómico.
        movements = [
            {"account_id": "uuid-juan", "amount": 10.00, "type": "DEBIT"},
            {"account_id": "uuid-sistema", "amount": 10.00, "type": "CREDIT"}
        ]
        """
        # 1. VERIFICACIÓN DE SUMA CERO (La Regla de Oro)
        # Convertimos a string primero para evitar float precision issues con Decimal
        total_debits = sum(Decimal(str(m['amount'])) for m in movements if m['type'] == 'DEBIT')
        total_credits = sum(Decimal(str(m['amount'])) for m in movements if m['type'] == 'CREDIT')

        # Tolerancia mínima para floats si vienen del exterior, pero idealmente usamos Decimal estricto
        if abs(total_debits - total_credits) > Decimal("0.0001"):
             raise ValueError(f"🚨 ERROR CONTABLE: Asiento desbalanceado. Debits: {total_debits}, Credits: {total_credits}")

        # 2. Generar ID de grupo (Ledger Group ID) si no se pasa uno externo
        # En este caso usamos el transaction_id que venía del Engine
        
        entry_list = []
        for m in movements:
            entry_list.append({
                "transaction_id": transaction_id,
                "account_id": m['account_id'],
                "direction": m['type'],
                "amount": float(m['amount']) # Supabase require float/numeric
            })

        # 3. Ejecutar escritura atómica
        try:
            self.db.table("ledger_entries").insert(entry_list).execute()
            
            # TODO: Aquí podríamos disparar un RPC o Trigger para actualizar balances cacheados en 'accounts'
            logger.info(f"📒 [LEDGER] Asiento registrado para TX {transaction_id}")
            return {"status": "RECORDED"}
        except Exception as e:
            logger.error(f"❌ Fallo crítico en Ledger Write: {e}")
            # No lanzamos excepción para no romper el flujo principal (Shadow Mode), pero logueamos CRITICAL
            return {"status": "ERROR", "message": str(e)}
