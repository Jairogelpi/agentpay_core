import os
import redis
import asyncio
import json
import time
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

    logger.info(f"👷 Worker iniciado. Escuchando '{STREAM_KEY}'...")

    while True:
        try:
            # Read new messages
            entries = r.xreadgroup(GROUP_NAME, CONSUMER_NAME, {STREAM_KEY: ">"}, count=1, block=2000)
            
            if not entries:
                continue

            for stream, messages in entries:
                for message_id, data in messages:
                    # Decode data (Redis returns bytes)
                    payload = {k.decode('utf-8'): v.decode('utf-8') for k, v in data.items()}
                    
                    try:
                        # Ejecutar la lógica pesada (IA + Stripe)
                        asyncio.run(engine._process_async_transaction(
                            payload, 
                            payload['tx_id'], 
                            float(payload['fee_locked']), 
                            0.0 # Balance not needed for async log usually
                        ))
                        
                        # Acknowledge (Remove from pending)
                        r.xack(STREAM_KEY, GROUP_NAME, message_id)
                        
                    except Exception as e:
                        logger.error(f"⚠️ Error procesando evento {message_id}: {e}")
                        # Implement DLQ (Dead Letter Queue) logic here if needed
                        
        except Exception as e:
            logger.error(f"🔥 Error en loop del worker: {e}")
            time.sleep(1)

if __name__ == "__main__":
    process_stream()
