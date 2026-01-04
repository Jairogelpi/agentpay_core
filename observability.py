import sys
from loguru import logger
from logtail import LogtailHandler

# TUS CREDENCIALES REALES (No las compartas públicamente)
# TUS CREDENCIALES REALES
LOGTAIL_TOKEN = "U9uJndRo8hPrgj1grS5yCRci"
# LOGTAIL_HOST eliminado para usar el endpoint de ingestión por defecto (in.logs.betterstack.com)

def setup_observability():
    """
    Configura el pipeline de logs 'Grado Bancario'.
    Conecta Loguru con Better Stack (Logtail).
    """
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
        # Instanciamos el handler usando el endpoint default de Better Stack
        handler = LogtailHandler(source_token=LOGTAIL_TOKEN)
        
        # Conectamos Loguru al handler de Logtail
        logger.add(
            handler,
            format="{message}", 
            level="INFO",
            backtrace=True, # Capturar trazas de error completas (Stack Traces)
            diagnose=True,  # Mostrar variables en errores
            serialize=False # LogtailHandler ya serializa el JSON internamente
        )
        
        logger.success(f"✅ Better Stack Conectado")
        
    except Exception as e:
        logger.error(f"❌ Error conectando a Better Stack: {e}")

    return logger
