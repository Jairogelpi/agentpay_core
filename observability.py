import sys
from loguru import logger
from logtail import LogtailHandler

# TUS CREDENCIALES REALES (No las compartas públicamente)
# TUS CREDENCIALES REALES
# [AUDITED & VERIFIED] 2026-01-04 - Configuración EU-NBG-2 Correcta
LOGTAIL_TOKEN = "pc6CoVu2PTxUdGcbWDwWpUu1"
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
        # Host de ingesta explícito (Cluster EU-NBG-2 Específico)
        LOGTAIL_HOST = "https://s1661963.eu-nbg-2.betterstackdata.com"
        
        # Instanciamos el handler con host explícito
        handler = LogtailHandler(source_token=LOGTAIL_TOKEN, host=LOGTAIL_HOST)
        
        print(f"🔌 [DEBUG] Intentando conectar a Better Stack ({LOGTAIL_HOST})...") 
        
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
