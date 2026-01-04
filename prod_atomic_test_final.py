
# Script de Prueba Atomic Final (Production Simulation)
# Usa un dominio real (aws.amazon.com) para verificar la validación OSINT correcta.

import requests
import json
import uuid

# URL del backend (Local o Render - ajustable)
BASE_URL = "http://localhost:8000" # Ajusta si pruebas contra Render

def intentar_pago(i, agent_id, api_key):
    print(f"\n--- Intento de Pago #{i} ---")
    payload = {
        "agent_id": agent_id,
        "vendor": "aws.amazon.com",  # <--- CAMBIO: Usamos el dominio real
        "vendor_url": "https://aws.amazon.com", # <--- NUEVO: Ayuda al OSINT
        "amount": 10.00,
        "description": f"Serverless Node #{i}", 
        "justification": "Approved Infrastructure" 
    }
    
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    
    try:
        response = requests.post(f"{BASE_URL}/v1/payments/process", json=payload, headers=headers)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text}")
    except Exception as e:
        print(f"Error en request: {e}")

if __name__ == "__main__":
    # Nota: Este script asume que ya tienes un agent_id y api_key.
    # Si no, deberías usar register_new_agent primero, pero para este snippet
    # solo definimos la función como pidió el usuario.
    print("Este script define la función intentar_pago para pruebas.")
