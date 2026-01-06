import os
import redis
import asyncio
import json
import time
import sys
import signal
from datetime import datetime
from loguru import logger
from engine import UniversalEngine

# Configure Redis
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
STREAM_KEY = "payment_events"
GROUP_NAME = "payment_processors"
CONSUMER_NAME = f"worker-{os.getpid()}"

engine = UniversalEngine()

def process_stream():
    r = redis.from_url(REDIS_URL)
    
    # Create Consumer Group if not exists
    try:
        r.xgroup_create(STREAM_KEY, GROUP_NAME, id="0", mkstream=True)
    except redis.exceptions.ResponseError as e:
        if "BUSYGROUP" not in str(e):
            raise
    except Exception as e:
        logger.error(f"Redis Error creating group: {e}")

    logger.info(f"👷 Worker Blindado iniciado PID: {os.getpid()}")

    # 1. RECUPERACIÓN DE PAGOS ZOMBIES (Lo primero al arrancar)
    # Si el worker anterior murió, recuperamos sus tareas pendientes.
    try:
        pending_entries = r.xreadgroup(GROUP_NAME, CONSUMER_NAME, {STREAM_KEY: "0"}, count=10)
        if pending_entries:
            logger.warning(f"🧟 Recuperando {len(pending_entries[0][1])} transacciones zombies de un crash anterior...")
            for stream, messages in pending_entries:
                for message_id, data in messages:
                    process_single_message(r, message_id, data)
    except Exception as e:
        logger.error(f"⚠️ Error recuperando zombies: {e}")

    while True:
        try:
            # Leemos solo NUEVOS mensajes (">")
            entries = r.xreadgroup(GROUP_NAME, CONSUMER_NAME, {STREAM_KEY: ">"}, count=1, block=2000)
            
            if not entries:
                continue

            for stream, messages in entries:
                for message_id, data in messages:
                    process_single_message(r, message_id, data)
                        
        except MemoryError:
            logger.critical("💀 RAM LLENA. Reiniciando worker ordenadamente...")
            sys.exit(1) # El orquestador (Docker/Heroku) lo reiniciará limpio
        except Exception as e:
            logger.error(f"Error loop: {e}")
            time.sleep(1)

def process_single_message(r, message_id, data):
    # Decode data (Redis returns bytes)
    try:
        payload = {k.decode('utf-8'): v.decode('utf-8') for k, v in data.items()}
    except AttributeError:
         # Handle case where it might already be str (unlikely with standard redis client but possible in mocks)
         payload = data

    try:
        # Procesamos
        # Nota: fee_locked puede venir como string del payload
        asyncio.run(engine._process_async_transaction(
            payload, 
            payload['tx_id'], 
            float(payload.get('fee_locked', 0.0)), 
            0.0
        ))
        # CONFIRMAMOS ÉXITO (Solo si no hubo error)
        r.xack(STREAM_KEY, GROUP_NAME, message_id)
        
    except Exception as e:
        logger.error(f"❌ Fallo en TX {payload.get('tx_id', 'UNKNOWN')}: {e}")
        # AQUÍ ESTÁ LA CLAVE 2026:
        # Si falla por código (bug), lo mandamos a una 'Dead Letter Queue' en Redis
        # para no bloquear el stream, pero NO lo perdemos.
        try:
            r.xadd("failed_transactions_dlq", {
                "original_id": message_id, 
                "error": str(e), 
                "payload": json.dumps(payload)
            })
            r.xack(STREAM_KEY, GROUP_NAME, message_id) # Lo sacamos del stream principal
            logger.info(f"🗑️ Enviado a DLQ: {message_id}")
        except Exception as dlq_error:
            logger.critical(f"FATAL: No se pudo enviar a DLQ: {dlq_error}")

if __name__ == "__main__":
    process_stream()
