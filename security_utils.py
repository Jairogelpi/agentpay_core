import whois
from urllib.parse import urlparse
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
    - "SAFE": Dominio antiguo (> 30 días).
    - "DANGEROUS_NEW": Dominio recién nacido (< 30 días).
    - "UNKNOWN": No se pudo verificar (fallo de red/privacidad).
    """
    domain = extract_domain(vendor)
    print(f"📡 OSINT: Investigando nacimiento de '{domain}'...")

    try:
        # Consultamos la base de datos global
        w = whois.whois(domain)
        
        # WHOIS es un caos, a veces devuelve listas, a veces strings. Normalizamos:
        creation_date = w.creation_date
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0] # Cogemos la primera fecha
            
        if not creation_date:
            return "UNKNOWN" # El dominio oculta su fecha

        # Cálculo de días de vida
        now = datetime.now()
        age_days = (now - creation_date).days
        
        print(f"   ↳ Edad del dominio: {age_days} días.")

        if age_days < 30:
            return "DANGEROUS_NEW"
        
        return "SAFE"

    except Exception as e:
        print(f"   ↳ Error WHOIS: {e}")
        return "UNKNOWN"
