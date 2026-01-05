import asyncio
import time
from models import TransactionRequest
from engine import UniversalEngine
from loguru import logger
import sys

# Configure logger to stderr
logger.remove()
logger.add(sys.stderr, level="INFO")

async def verify():
    logger.info("🔧 Initializing Engine...")
    engine = UniversalEngine()
    
    if not engine.redis_enabled:
        logger.warning("⚠️ Redis NOT enabled. Test will run in Sync Fallback mode (High Latency).")
    else:
        logger.info("✅ Redis Enabled. Testing Fast Path.")

    # Create a dummy request
    # Use a safe vendor to avoid blocks
    req = TransactionRequest(
        agent_id="test_agent_123",
        vendor="openai.com",
        amount=10.0,
        description="Event Driven Test",
        justification="Testing architecture"
    )

    # Measure Latency
    start = time.time()
    logger.info(f"🚀 Sending Request: {req.vendor} (${req.amount})")
    
    try:
        result = await engine.evaluate(req)
        duration = (time.time() - start) * 1000
        
        logger.info(f"⏱️ Latency: {duration:.2f}ms")
        logger.info(f"📋 Result Status: {result.status}")
        logger.info(f"📜 Reason: {result.reason}")
        
        if result.status == "PROCESSING":
            logger.success("✅ SUCCESS: Fast Path returned PROCESSING immediately.")
        elif result.status == "APPROVED" and not engine.redis_enabled:
             logger.success("✅ SUCCESS: Sync Fallback returned APPROVED (Expected without Redis).")
        else:
            logger.warning(f"⚠️ Unexpected Status: {result.status}")

    except Exception as e:
        logger.error(f"❌ Error during evaluation: {e}")

if __name__ == "__main__":
    asyncio.run(verify())
