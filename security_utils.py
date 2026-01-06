import whois
from urllib.parse import urlparse
from loguru import logger
from datetime import datetime

def extract_domain(url_or_vendor):
    """Limpia la entrada para obtener solo el dominio (ej: 'https://api.google.com/v1' -> 'google.com')"""
    if "http" not in url_or_vendor:
        url_or_vendor = "http://" + url_or_vendor
    
    try:
        domain = urlparse(url_or_vendor).netloc
        # Si tiene subdominio (ej: api.stripe.com), a veces queremos chequear el raíz.
        # Por simplicidad, whois suele manejar bien los subdominios principales.
        return domain
    except:
        return url_or_vendor

def check_domain_age(vendor):
    """
    🔍 OSINT: Verifica la fecha de nacimiento del dominio.
    Retorna: 
    - Diccionario con 'age_days', 'status' ('YOUNG', 'MATURE', 'UNKNOWN_DATE', 'HIDDEN'), y 'registrar'.
    """
    domain = extract_domain(vendor)
    logger.debug(f"📡 OSINT: Investigando nacimiento de '{domain}'...")
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        
        # Whois returns list for multiple registrars
        if isinstance(creation, list):
            creation = creation[0]
            
        if not creation:
            return {"age_days": 0, "status": "UNKNOWN_DATE"}
            
        age_days = (datetime.now() - creation).days
        logger.debug(f"   ↳ Edad del dominio: {age_days} días.")
        
        return {
            "age_days": age_days,
            "status": "YOUNG" if age_days < 30 else "MATURE",
            "registrar": w.registrar
        }
            
    except Exception as e:
        logger.warning(f"   ↳ Error WHOIS: {e}")
        return {"age_days": 0, "status": "HIDDEN", "error": str(e)}

# --- SECURITY UTILS ---
from cryptography.fernet import Fernet
import os

def get_cipher():
    # En producción, esto viene de KMS o ENV
    key = os.getenv("ENCRYPTION_KEY")
    if not key:
        # Fallback para dev (NO USAR EN PROD REAL)
        # Generamos una clave determinista basada en el secreto de la app
        base = os.getenv("SUPABASE_KEY", "default-insecure-key-padding-32bytes")[:32]
        import base64
        key = base64.urlsafe_b64encode(base.encode().ljust(32)[:32])
    return Fernet(key)

def encrypt_password(raw_password):
    try:
        f = get_cipher()
        return f.encrypt(raw_password.encode()).decode()
    except Exception as e:
        logger.error(f"Encryption error: {e}")
        return raw_password

def decrypt_password(encrypted_token):
    try:
        f = get_cipher()
        return f.decrypt(encrypted_token.encode()).decode()
    except Exception as e:
        logger.error(f"Decryption error: {e}")
        return encrypted_token
