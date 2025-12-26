import requests
import time

class AgentPay:
    """
    SDK Universal 'Irrompible' de AgentPay.
    Capa de abstracción total para la Economía Sintética.
    """
    
    def __init__(self, api_key=None, base_url="http://localhost:8000"):
        # api_key es opcional si solo se va a registrar un nuevo agente
        self.api_key = api_key
        self.base_url = base_url
        self.headers = {"X-API-KEY": self.api_key, "Content-Type": "application/json"}

    def _post(self, endpoint, data, timeout=10):
        """Wrapper robusto con manejo de errores y timeout."""
        try:
            if self.api_key and "agent_id" not in data:
                data["agent_id"] = self.api_key
                
            response = requests.post(f"{self.base_url}{endpoint}", json=data, headers=self.headers, timeout=timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"status": "ERROR", "message": f"Connection failed: {str(e)}"}

    # --- 0. ONBOARDING & CONFIG ---

    @staticmethod
    def register(client_name, base_url="http://localhost:8000"):
        """Crea un nuevo agente programáticamente y devuelve sus credenciales."""
        try:
            res = requests.post(f"{base_url}/v1/agent/register", json={"client_name": client_name}, timeout=10).json()
            return res # {agent_id, api_key, dashboard_url}
        except Exception as e:
            return {"error": str(e)}

    def configure(self, webhook_url=None, owner_email=None):
        """Inicializa alertas y callbacks."""
        return self._post("/v1/agent/settings", {"webhook_url": webhook_url, "owner_email": owner_email})

    def limits(self, max_tx=None, daily_limit=None):
        """Control de Presupuesto Dinámico (Budget Control)."""
        return self._post("/v1/agent/limits", {"max_tx": max_tx, "daily_limit": daily_limit})

    # --- 1. DINERO (Engine) ---

    def pay(self, vendor, amount, description):
        """Pago seguro con IA Guard y OSINT."""
        return self._post("/v1/pay", {"vendor": vendor, "amount": amount, "description": description})

    def check_payment_status(self, transaction_id):
        """Human-in-the-loop: Verifica si un pago pendiente fue aprobado."""
        return self._post("/v1/transactions/status", {"transaction_id": transaction_id})

    def download_invoice(self, transaction_id):
        """Contabilidad: Obtiene URL del PDF."""
        return self._post("/v1/invoices/download", {"transaction_id": transaction_id})

    def stream_pay(self, vendor, amount):
        """Micropagos de alta frecuencia (<$0.01)."""
        return self._post("/v1/streaming/pack", {"vendor": vendor, "amount": amount})
        
    def top_up(self, amount):
        """Recarga de saldo real (Stripe)."""
        return self._post("/v1/topup/create", {"amount": amount})

    # --- 2. IDENTIDAD (Protocolo Ghost) ---

    def create_identity(self, needs_phone=False):
        """Crea Email + Proxy (+ SMS simulado)."""
        # needs_phone simulado en main si se pasa
        return self._post("/v1/identity/create", {"needs_phone": needs_phone})

    def check_otp(self, identity_id):
        """Consulta puntual del buzón."""
        # Check OTP via GET usually, but here mapped to wrapper logic if needed. 
        # But server uses GET /v1/identity/{id}/check. 
        # Let's implement robust GET wrapper or just use requests directly here for simplicity.
        try:
            res = requests.get(f"{self.base_url}/v1/identity/{identity_id}/check", headers=self.headers, timeout=10)
            return res.json()
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}

    def wait_for_otp(self, identity_id, timeout=60, interval=5):
        """Smart Polling: Espera activamente al código."""
        start = time.time()
        while time.time() - start < timeout:
            res = self.check_otp(identity_id)
            if res.get("status") == "RECEIVED":
                return res.get("latest_message", {}).get("otp_code")
            time.sleep(interval)
        return None # Timeout

    def get_proxy(self, region="US"):
        """Obtiene IP residencial."""
        return self._post("/v1/identity/proxy", {"region": region})

    def solve_captcha(self, image_url):
        """Visión Artificial vs Captchas."""
        return self._post("/v1/identity/captcha", {"image_url": image_url})

    # --- 3. LEGAL Y DEFENSA ---

    def sign_contract(self, contract_hash):
        """Firma Legal con Wrapper (DAO/LLC)."""
        return self._post("/v1/legal/sign", {"contract_hash": contract_hash})

    def get_status(self):
        """Panel de Salud: Balance, Score y Config."""
        return self._post("/v1/agent/status", {})

    def send_alert(self, message):
        """Notificación Directa al Dueño (Push/Email)."""
        return self._post("/v1/agent/notify", {"message": message})

    def report_issue(self, transaction_id, reason):
        """Disputa / Chargeback / Reporte de Fraude."""
        return self._post("/v1/transactions/dispute", {"transaction_id": transaction_id, "reason": reason})
    
    def report_fraud(self, vendor, reason):
        """Mente Colmena: Reportar vendedor malicioso."""
        return self._post("/v1/fraud/report", {"vendor": vendor, "reason": reason})
