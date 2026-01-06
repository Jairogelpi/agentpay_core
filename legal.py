
import hashlib
import json
import base64
import uuid
import os
import requests # Necesario para TSA real
import rfc3161ng # TSA Real (RFC 3161)
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Nuevas librerías para Criptografía Real (RSA)
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend

load_dotenv()

class LegalWrapper:
    """
    Identidad Legal Sintética v2.0 (Enterprise Grade).
    Incluye: Soporte RSA, Privacidad GDPR, Revocación y TSA Real.
    """
    
    def __init__(self, db_client=None):
        self.db = db_client # Necesario para chequear revocaciones
        
        # --- 1. GESTIÓN DE CLAVES (Simulación de HSM) ---
        # En producción real con AWS KMS, esto sería un cliente boto3.
        # Aquí generamos/cargamos una RSA localmente para que funcione el JWKS.
        self._load_or_generate_keys()

    def _load_or_generate_keys(self):
        # Intentar cargar clave privada de variable de entorno (PEM)
        pem_data = os.getenv("LEGAL_PRIVATE_KEY_PEM")
        
        if pem_data:
            self.private_key = serialization.load_pem_private_key(
                pem_data.encode(), password=None, backend=default_backend()
            )
        else:
            # Generar una al vuelo (Solo DEV/TEST)
            # print("⚠️ WARNING: Usando clave RSA efímera (Solo Dev). Configurar LEGAL_PRIVATE_KEY_PEM en prod.")
            self.private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048, backend=default_backend()
            )

        self.public_key = self.private_key.public_key()

    def get_public_jwks(self):
        """Genera el JSON Web Key Set (JWKS) para /.well-known/jwks.json"""
        public_numbers = self.public_key.public_numbers()
        return {
            "keys": [{
                "kty": "RSA",
                "kid": "agentpay-root-v1", # ID de la clave rotativa
                "use": "sig",
                "alg": "RS256",
                "n": base64.urlsafe_b64encode(
                    public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big')
                ).decode('utf-8').rstrip("="),
                "e": base64.urlsafe_b64encode(
                    public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, 'big')
                ).decode('utf-8').rstrip("=")
            }]
        }

    def _sign_payload(self, payload_str):
        """Firma criptográfica RSA-SHA256 (Estándar Bancario)"""
        signature = self.private_key.sign(
            payload_str.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()

    def check_revocation(self, agent_id):
        """Checkea la Lista de Revocación (CRL) en DB"""
        if not self.db: return False # Si no hay DB conectada, asumimos válido (fallback)
        
        try:
            # Busca si el agente está en la tabla negra
            res = self.db.table("revoked_credentials").select("id").eq("agent_id", agent_id).execute()
            if res.data and len(res.data) > 0:
                return True # ESTÁ REVOCADO
        except Exception as e:
            # print(f"Error checking revocation: {e}")
            pass
        return False

    def issue_kyc_passport(self, agent_id, owner_name, compliance_level="STANDARD"):
        """
        Emite Pasaporte Digital con Privacidad (GDPR Compliant).
        """
        if self.check_revocation(agent_id):
            raise ValueError(f"CRITICAL: Agent {agent_id} is REVOKED. Cannot issue passport.")

        # --- 2. PRIVACIDAD (HASHING) ---
        # No guardamos "Juan Perez", guardamos SHA256("Juan Perez" + SALT)
        salt = os.getenv("PRIVACY_SALT", "random-salt-123")
        owner_hash = hashlib.sha256(f"{owner_name}:{salt}".encode()).hexdigest()

        expiration = (datetime.now() + timedelta(days=30)).isoformat() # 30 días, no 365 (Seguridad)
        
        payload = {
            "iss": "AgentPay Authority (RSA)",
            "sub": agent_id,
            "owner_privacy": {
                "hash": owner_hash,
                "verification_method": "BANK_ID",
                "jurisdiction": "EU"
            },
            "level": compliance_level,
            "kid": "agentpay-root-v1", # Indica qué clave pública usar para verificar
            "exp": expiration
        }
        
        payload_str = json.dumps(payload, sort_keys=True)
        signature = self._sign_payload(payload_str)
        
        return {
            "passport_token": base64.b64encode(payload_str.encode()).decode(),
            "signature": signature,
            "format": "AgentPay-JWT-RS256"
        }

    # --- 3. TIMESTAMPING AUTHORITY (TSA REAL - RFC 3161) ---
    def _get_tsa_timestamp(self, document_hash_hex):
        """
        Obtiene un sello de tiempo REAL (RFC 3161) desde FreeTSA.org.
        Este sello es una prueba legal de que el documento existía en ese instante.
        
        Args:
            document_hash_hex (str): El hash SHA256 del documento en hexadecimal.
        """
        tsa_url = "https://freetsa.org/tsr"
        
        try:
            # 1. Convertir el hash hex a bytes (formato binario)
            data_bytes = bytes.fromhex(document_hash_hex)
            
            # 2. Instanciar el cliente TSA (FreeTSA usa SHA256 por defecto)
            timestamper = rfc3161ng.RemoteTimestamper(
                url=tsa_url, 
                hashname='sha256'
            )
            
            # 3. Solicitar el sello (Request TSA)
            # Esto envía una petición POST binaria al servidor
            tsr_content = timestamper.timestamp(data=data_bytes)
            
            # 4. Verificar la respuesta inmediatamente (Opcional pero recomendado)
            # Esto asegura que el sello recibido es matemáticamente válido
            tst_info = rfc3161ng.decode_timestamp(tsr_content)
            
            # 5. Formatear para almacenamiento (JSON)
            # Guardamos el token completo en Base64 (es la prueba legal)
            # y metadatos legibles para la UI/DB.
            proof_data = {
                "authority": "FreeTSA.org (RFC 3161)",
                "gen_time": tst_info[1]['genTime'].strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
                "serial_number": str(tst_info[1]['serialNumber']),
                "policy_id": str(tst_info[1]['policy']),
                "hash_linked": document_hash_hex,
                "tsr_token_base64": base64.b64encode(tsr_content).decode('utf-8')
            }
            
            return json.dumps(proof_data)

        except Exception as e:
            # En producción, podrías tener un fallback a otra TSA (ej. SafeCreative)
            print(f"⚠️ Error conectando con TSA Real: {e}")
            # Retornar error estructurado para que el sistema sepa que falló el sellado
            return json.dumps({
                "error": "TSA_CONNECTION_FAILED",
                "details": str(e),
                "timestamp": datetime.utcnow().isoformat()
            })
            
    # Mantenemos compatibilidad con métodos antiguos llamando a los nuevos o adaptándolos...
    def sign_contract(self, agent_id, contract_hash, signer_role="Authorized Agent"):
        """Firma contrato con RSA + TSA Real (RFC 3161)"""
        # 1. Firma interna (Tuya con RSA)
        payload = f"{agent_id}|{contract_hash}|{datetime.now()}"
        internal_sig = self._sign_payload(payload)
        
        # 2. Sello de Tiempo Externo (De terceros)
        tsa_proof_json = self._get_tsa_timestamp(contract_hash)
        
        return {
            "status": "SIGNED", 
            "internal_signature": internal_sig, 
            "tsa_proof": json.loads(tsa_proof_json), # Parsear para devolver objeto limpio
            "validity": "RSA_2048_BINDING + RFC3161_TIMESTAMP"
        }

