
import requests
import sys

# URL del Servidor (ajustar si es local o producción)
AGENTPAY_HOST = "https://agentpay-core.onrender.com"
# AGENTPAY_HOST = "http://localhost:8000"

def create_agent():
    print(f"\n🔐 --- AgentPay Registration CLI ---")
    print(f"Connecting to: {AGENTPAY_HOST}\n")
    
    # 1. Solicitar Nombre
    client_name = input("Enter Agent/Client Name (e.g. 'Marketing Bot V2'): ").strip()
    if not client_name:
        print("Error: Name cannot be empty.")
        return

    # 2. Llamar API
    try:
        url = f"{AGENTPAY_HOST}/v1/agent/register"
        print(f"DTO -> POST {url} ...")
        
        response = requests.post(url, json={"client_name": client_name})
        
        if response.status_code == 200:
            data = response.json()
            api_key = data.get("api_key") or data.get("agent_id") # SDK MVP usa ID como Key sometimes
            dash_url = data.get("dashboard_url")
            
            print(f"\n✅ SUCCESS! Agent Created.")
            print(f"------------------------------------------------")
            print(f"🆔 AGENT ID (API KEY): {api_key}")
            print(f"📊 Dashboard URL:      {dash_url}")
            print(f"------------------------------------------------")
            print(f"\n👉 SAVE THIS KEY! You will need it to run the daily_worker.py example.")
            
        else:
            print(f"❌ Error {response.status_code}: {response.text}")

    except Exception as e:
        print(f"❌ Connection Error: {e}")
        print("Tip: Ensure the server is running and accessible.")

if __name__ == "__main__":
    create_agent()
