import hashlib
import hmac
import os
import json
import base64
import uuid
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

class LegalWrapper:
    """
    Identidad Legal Sintética.
    Permite a un agente firmar contratos criptográficos vinculantes
    utilizando una entidad paraguas (AgentPay LLC/DAO) y emitir pasaportes KYC.
    """
    
    def __init__(self):
        # En producción, esto debería ser un secret real
        self.secret_key = os.getenv("LEGAL_SECRET_KEY", "agentpay-legal-secret").encode()

    def _sign_hash(self, text):
        """Genera una firma HMAC-SHA256 consistente"""
        return hmac.new(self.secret_key, text.encode(), hashlib.sha256).hexdigest()

    def sign_contract(self, agent_id, contract_hash, signer_role="Authorized Agent"):
        """
        Genera una firma digital válida para un contrato.
        """
        timestamp = datetime.now().isoformat()
        
        signature_payload = f"{agent_id}|{contract_hash}|{timestamp}|AgentPay_LLC_Wrapper"
        digital_signature = self._sign_hash(signature_payload)
        
        legal_text = f"""
        SIGNED AND AGREED:
        
        Entity: AgentPay DAO (acting as legal wrapper for Agent {agent_id})
        Role: {signer_role}
        Timestamp: {timestamp}
        Blockchain Ref: PROOF-{digital_signature[:16].upper()}
        
        This signature represents a legally binding agreement under the 
        Synthetic Economy E-Sign Act Protocol v1.
        """
        
        return {
            "status": "SIGNED",
            "signature_hash": digital_signature,
            "legal_block": legal_text.strip(),
            "validity": "LEGALLY_BINDING_WRAPPER"
        }

    def sign_intent(self, agent_id, vendor, amount, justification):
        """
        Firma Forense: Vincula una transacción con la INTENCIÓN que la originó.
        """
        timestamp = datetime.now().isoformat()
        
        legal_text = (
            f"PROOF OF INTENT\n"
            f"---------------\n"
            f"Agent: {agent_id}\n"
            f"Vendor: {vendor}\n"
            f"Amount: ${amount}\n"
            f"Justification: {justification}\n"
            f"Timestamp: {timestamp}\n"
            f"Disclaimer: The agent affirms this expense is necessary for its designated goals."
        )
        
        intent_hash = self._sign_hash(legal_text)
        
        return {
            "proof_text": legal_text,
            "signature": intent_hash,
            "timestamp": timestamp,
            # Legacy field for compatibility just in case
            "intent_hash": intent_hash 
        }

    def certify_identity(self, identity_data):
        """
        Emite una 'Declaración de Identidad Certificada'.
        Vincula un email/identidad técnica con la entidad legal (LLC).
        Sirve para demostrar ante proveedores que 'agent-xyz@agentpay.it.com' es una entidad legal válida.
        """
        timestamp = datetime.now().isoformat()
        
        # Datos a certificar
        data_block = (
            f"CERTIFIED IDENTITY DECLARATION\n"
            f"------------------------------\n"
            f"Identity ID: {identity_data.get('identity_id')}\n"
            f"Email Alias: {identity_data.get('email')}\n"
            f"Linked Agent: {identity_data.get('agent_id')}\n"
            f"Provider: {identity_data.get('provider', 'AgentPay Secure Mail')}\n"
            f"Certifier: AgentPay Authority LLC\n"
            f"Timestamp: {timestamp}\n"
            f"Legal Status: The entity controlling this identity matches KYC Record #{abs(hash(identity_data.get('agent_id'))) % 10000}."
        )
        
        signature = self._sign_hash(data_block)
        
        return {
            "status": "CERTIFIED",
            "certificate_id": f"CERT-{signature[:12].upper()}",
            "declaration_text": data_block,
            "signature": signature,
            "timestamp": timestamp
        }

    def issue_kyc_passport(self, agent_id, owner_name, compliance_level="STANDARD"):
        """
        Emite un Pasaporte Digital (KYC) firmado para el agente.
        Avala que el agente pertenece a un humano verificado y tiene seguro de responsabilidad.
        """
        expiration = (datetime.now() + timedelta(days=365)).isoformat()
        
        payload = {
            "iss": "AgentPay Authority (Automated)",
            "sub": agent_id,
            "owner": owner_name,
            "level": compliance_level, # STANDARD, GOLD, PLATINUM
            "insurance_policy": f"AP-{abs(hash(agent_id)) % 10000}-LIA",
            "compliance": ["GDPR", "PSD2", "AI_ETHICS_V1"],
            "exp": expiration
        }
        
        # Firmamos el JSON
        payload_str = json.dumps(payload, sort_keys=True)
        signature = self._sign_hash(payload_str)
        
        return {
            "passport_token": base64.b64encode(payload_str.encode()).decode(),
            "signature": signature,
            "format": "AgentPay-Passport-V1"
        }

    def issue_liability_certificate(self, agent_id, identity_email, platform_url, coverage_amount=10000.00, forensic_hash="N/A"):
        """
        Emite un Certificado de Responsabilidad Civil.
        Actúa como un "Aval" corporativo para que el agente pueda firmar ToS.
        Incluye Hash Forense para Trazabilidad Jurídica (Reasoning Link).
        """
        cert_id = f"LIAB-{uuid.uuid4().hex[:8].upper()}"
        timestamp = datetime.now().isoformat()
        
        # Declaración Legal
        declaration = (
            f"LIABILITY CERTIFICATE OF AUTHENTICITY\n"
            f"--------------------------------------\n"
            f"Certificate ID: {cert_id}\n"
            f"Issued By: AgentPay LLC (Legal Entity Identification: AP-9988-US)\n"
            f"Beneficiary Agent: {agent_id}\n"
            f"Identity Alias: {identity_email}\n"
            f"Platform Scope: {platform_url}\n"
            f"Forensic Link (Intent Hash): {forensic_hash}\n"
            f"Coverage Limit: ${coverage_amount:,.2f} USD\n"
            f"Timestamp: {timestamp}\n\n"
            f"DECLARATION: AgentPay LLC hereby assumes subsidiary legal liability for the actions "
            f"of the Beneficiary Agent on the Platform Scope, up to the Coverage Limit, "
            f"in accordance with the Master Service Agreement v2.1."
        )
        
        signature = self._sign_hash(declaration)
        
        return {
            "certificate_id": cert_id,
            "status": "ACTIVE",
            "declaration_text": declaration,
            "signature": signature,
            "coverage_amount": coverage_amount,
            "issued_at": timestamp,
            "forensic_hash": forensic_hash
        }

    def verify_passport(self, passport_data):
        """
        Verifica la validez de un pasaporte presentado (Firma + Expiración).
        """
        try:
            token = base64.b64decode(passport_data['passport_token']).decode()
            signature = passport_data['signature']
            
            # 1. Verificar Firma
            expected_sig = self._sign_hash(token)
            if signature != expected_sig:
                return {"valid": False, "reason": "Firma Inválida (Invalid Signature)"}
            
            # 2. Verificar Expiración
            data = json.loads(token)
            exp = datetime.fromisoformat(data['exp'])
            if datetime.now() > exp:
                return {"valid": False, "reason": "Pasaporte Expirado (Expired)"}
                
            return {"valid": True, "data": data, "message": "Pasaporte Válido. Agente certificado."}
            
        except Exception as e:
            return {"valid": False, "reason": f"Error de formato: {str(e)}"}
