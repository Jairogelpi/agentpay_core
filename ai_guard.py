import os
import json
from openai import OpenAI

# Configuración: Usar GPT-4o es OBLIGATORIO para este nivel de inteligencia.
# gpt-4o-mini es bueno, pero gpt-4o es un genio forense.
MODELO_IA = "gpt-4o" 

try:
    client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
    AI_ENABLED = True
except:
    AI_ENABLED = False

def audit_transaction(vendor, amount, description, agent_id, agent_role, history=[]):
    """
    NIVEL DIOS: Analiza no solo el gasto actual, sino la desviación del patrón histórico.
    Recibe 'history': Una lista de las últimas 5 transacciones de este agente.
    """
    if not AI_ENABLED:
        return {"decision": "FLAGGED", "reason": "IA Off"}

    # Calculamos el promedio de gasto histórico para dar contexto matemático a la IA
    avg_spend = sum([float(h['amount']) for h in history]) / len(history) if history else 0
    
    # Formateamos el historial para que la IA lo lea. Asumimos que 'created_at' es la fecha
    # Ajustamos para leer 'reason' o 'description' del historial si existe
    history_text = "\n".join([f"- {h.get('created_at', 'N/A')}: ${h['amount']} a {h['vendor']} ({h.get('reason', 'N/A')})" for h in history])

    print(f"🕵️‍♂️ AI GUARD (Behavioral): Auditando {vendor} (${amount})... Promedio Histórico: ${avg_spend:.2f}")

    prompt = f"""
    Eres el Auditor de Comportamiento de AgentPay.
    Tu objetivo es detectar ANOMALÍAS en el patrón de gasto.
    
    PERFIL:
    - Agente: {agent_role} (ID: {agent_id})
    - Gasto Promedio Histórico: ${avg_spend:.2f}

    HISTORIAL RECIENTE (El comportamiento normal de este agente):
    {history_text}
    
    TRANSACCIÓN A EVALUAR (¿Encaja en el patrón?):
    - Proveedor: "{vendor}"
    - Monto: ${amount}
    - Motivo: "{description}"
    
    ANÁLISIS DE ANOMALÍAS (Piensa paso a paso):
    1. **Salto de Monto:** ¿El monto actual es drásticamente superior al promedio histórico o a compras similares recientes?
    2. **Cambio de Proveedor:** ¿Es un proveedor nuevo en una categoría totalmente distinta a lo que suele comprar?
    3. **Frecuencia:** ¿Está comprando demasiado rápido lo mismo?
    4. **Coherencia de Rol:** (Igual que antes, ¿tiene sentido para su rol?).

    SI detectas un cambio brusco de comportamiento (ej: gastaba $10 y ahora $500, o compraba software y ahora comida), marca como FLAGGED.
    
    SALIDA JSON:
    {{
        "decision": "APPROVED" | "REJECTED" | "FLAGGED",
        "risk_score": 0-100,
        "anomaly_detected": true/false,
        "reason": "Explica la desviación del patrón histórico o la razón del rechazo."
    }}
    """

    try:
        response = client.chat.completions.create(
            model=MODELO_IA,
            messages=[
                {"role": "system", "content": "Eres un sistema de seguridad conductual. Detectas patrones anómalos."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"},
            temperature=0.0 
        )
        
        content = json.loads(response.choices[0].message.content)
        
        # Mapping para compatibilidad con engine.py si retorna reason en vez de reasoning
        if 'reason' in content and 'reasoning' not in content:
            content['reasoning'] = content['reason']

        # CAPA DE SEGURIDAD EXTRA
        if content['decision'] == 'APPROVED' and content.get('risk_score', 0) > 20:
             content['decision'] = 'FLAGGED'
             content['reasoning'] += " (Riesgo conductual > 20%)"

        return content

    except Exception as e:
        print(f"❌ Error Crítico IA: {e}")
        return {"decision": "REJECTED", "reason": "Fallo en sistema de seguridad. Bloqueo preventivo."}