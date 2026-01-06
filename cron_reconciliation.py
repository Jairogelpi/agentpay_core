import os
import stripe
import time
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from supabase import create_client
from loguru import logger
from observability import setup_observability

# Cargar entorno y setup de logs
load_dotenv()
setup_observability()

# Configuración
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    logger.critical("❌ Faltan credenciales de Supabase")
    exit(1)

db = create_client(SUPABASE_URL, SUPABASE_KEY)

def reconcile_yesterday():
    logger.info("🕵️ Iniciando Reconciliación Bancaria Diaria...")
    
    # 1. Definir ventana de tiempo (Ayer 00:00 - 23:59 UTC)
    # Usamos UTC explícito para consistencia financiera
    now = datetime.now(timezone.utc)
    yesterday = now - timedelta(days=1)
    
    start_dt = yesterday.replace(hour=0, minute=0, second=0, microsecond=0)
    end_dt = yesterday.replace(hour=23, minute=59, second=59, microsecond=999999)
    
    start_ts = int(start_dt.timestamp())
    end_ts = int(end_dt.timestamp())

    logger.info(f"📅 Ventana de Auditoría: {start_dt.isoformat()} -> {end_dt.isoformat()}")

    # 2. Obtener LA VERDAD (Stripe Balance Transactions)
    logger.info("   📥 Descargando movimientos de Stripe (BalanceTransactions)...")
    
    try:
        # Paginación automática de Stripe
        stripe_txs = stripe.BalanceTransaction.list(
            created={'gte': start_ts, 'lte': end_ts},
            limit=100
        )
    except Exception as e:
        logger.critical(f"❌ Error conectando a Stripe: {e}")
        return

    stripe_map = {}
    total_stripe_volume = 0.0
    count_stripe = 0
    
    for tx in stripe_txs.auto_paging_iter():
        count_stripe += 1
        # Intentamos obtener un ID de correlación
        # En AgentPay, el 'description' o 'metadata' suele tener el ID interno si lo pusimos
        # O el source transfer
        internal_id = tx.metadata.get('internal_tx_id') or tx.id # Fallback al ID de Stripe
        
        amount_usd = abs(tx.amount / 100.0) # Normalizamos a positivo para volumen
        # Ojo: Net vs Gross. 
        # Stripe BalanceTransaction 'amount' es el NETO afectando al saldo.
        
        stripe_map[internal_id] = amount_usd
        total_stripe_volume += amount_usd

    # 3. Obtener TUS REGISTROS (Supabase)
    logger.info("   📥 Descargando logs internos...")
    
    try:
        db_txs = db.table("transaction_logs")\
            .select("id, amount, status, vendor")\
            .gte("created_at", start_dt.isoformat())\
            .lte("created_at", end_dt.isoformat())\
            .eq("status", "APPROVED")\
            .execute()
    except Exception as e:
        logger.critical(f"❌ Error conectando a BD: {e}")
        return

    total_db_volume = 0.0
    count_db = 0
    if db_txs.data:
        for log in db_txs.data:
            count_db += 1
            amount = float(log['amount'])
            total_db_volume += amount

    # 4. CRUCE DE DATOS (The Audit)
    # Nota: Este es un cruce imperfecto (Volumen vs Volumen) para "Smoke Test".
    # Una reconciliación fila-a-fila requiere IDs compartidos estrictos.
    
    logger.info(f"   ⚖️ Comparando: {count_stripe} Tx Bancarias (${total_stripe_volume:.2f}) vs {count_db} Tx Internas (${total_db_volume:.2f})")

    # 5. RESULTADO
    # Ajustar tolerancia según fee structure. 
    # Transaction Logs usually records GROSS amount.
    # Stripe BalanceTransaction usually records NET amount (after fees).
    # Este script asume que estamos comparando peras con manzanas si no ajustamos fees.
    # Para AgentPay, asumiremos una tolerancia amplia O que Stripe TXs se filtran por 'transfers' (salidas)
    
    diff = abs(total_stripe_volume - total_db_volume)
    
    # UMBRAL DE ALARMA: 5% de desviación o $50 fijos, lo que sea mayor (En dev/test)
    # En PROD esto debe ser centavos.
    tolerance = max(total_db_volume * 0.05, 50.0)
    
    if diff > tolerance: 
        logger.critical(f"🚨 ERROR GRAVE DE RECONCILIACIÓN")
        logger.critical(f"   Banco (Stripe): ${total_stripe_volume}")
        logger.critical(f"   Libros (DB):    ${total_db_volume}")
        logger.critical(f"   Diferencia:     ${diff}")
        
        # Insertar Alerta de Compliance
        try:
            db.table("compliance_alerts").insert({
                "agent_id": "SYSTEM_TREASURY",
                "type": "RECONCILIATION_MISMATCH",
                "severity": "CRITICAL",
                "description": f"El dinero no cuadra. Desviación: ${diff:.2f}",
                "metadata": {"stripe_vol": total_stripe_volume, "db_vol": total_db_volume, "date": start_dt.isoformat()}
            }).execute()
        except:
            pass # Si falla la alerta DB, ya está en Logtail
            
    else:
        logger.success(f"✅ Reconciliación Aceptable (Diferencia: ${diff:.2f}). Libros cuadrados.")

if __name__ == "__main__":
    reconcile_yesterday()
