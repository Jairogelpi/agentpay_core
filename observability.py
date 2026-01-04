import os
import sentry_sdk
from loguru import logger
from logtail import LogtailHandler

# Helper para conectar Loguru -> Sentry
class SentrySink:
    def write(self, message):
        record = message.record
        level = record["level"].name
        if level in ["ERROR", "CRITICAL"]:
            # Captura el mensaje estructurado en Sentry
            sentry_sdk.capture_message(record["message"], level=level.lower())
    """
    Configura el pipeline de logs 'Grado Bancario'.
    Conecta Loguru con Better Stack (Logtail).
    """
    if not LOGTAIL_TOKEN:
        logger.warning("⚠️ LOGTAIL_TOKEN no encontrado. Los logs no se enviarán a Better Stack.")
        return logger

    # 1. Limpiar handlers por defecto para evitar duplicados
    logger.remove()

    # 2. Handler de Consola (Para ver logs en Render/Terminal)
    logger.add(
        sys.stderr,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level> | {extra}",
        level="INFO"
    )

    # 3. Handler de Better Stack (La Nube)
    try:
        # Host de ingesta explícito (Global/EU compatible)
        # Default: Cluster EU-NBG-2 que sabemos que funciona
        default_host = "https://s1661963.eu-nbg-2.betterstackdata.com"
        LOGTAIL_HOST = os.getenv("LOGTAIL_HOST", default_host)
        
        # Instanciamos el handler con host explícito
        handler = LogtailHandler(source_token=LOGTAIL_TOKEN, host=LOGTAIL_HOST)
        
        # Conectamos Loguru al handler de Logtail (Info +)
        logger.add(
            handler,
            format="{message}", 
            level="INFO",
            backtrace=True, # Capturar trazas de error completas (Stack Traces)
            diagnose=True,  # Mostrar variables en errores
            serialize=False # LogtailHandler ya serializa el JSON internamente
        )
        
        # Conectamos Loguru a Sentry (Error +)
        logger.add(SentrySink(), level="ERROR") # <--- AHORA SÍ: Logs de error van a Sentry
        
        logger.success(f"✅ Better Stack & Sentry Pipes Conectados")
        
    except Exception as e:
        logger.error(f"❌ Error conectando a Better Stack: {e}")

    return logger
