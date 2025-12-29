# Configuración: Router de Modelos
# GOD_TIER: GPT-5 (o lo mejor disponible) para transacciones críticas (>$1000) o disputas.
# HIGH_TIER: GPT-4o para el día a día corporativo.
# LOW_TIER: GPT-3.5-turbo para micropagos eficiencia.
MODELS = {
    "GOD_TIER": "gpt-4o", # TODO: Actualizar a 'gpt-5' en cuanto OpenAI libere la API
    "HIGH_TIER": "gpt-4o",
    "LOW_TIER": "gpt-3.5-turbo"
}

try:
    client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
    AI_ENABLED = True
except:
    AI_ENABLED = False
    
def select_model(budget_status="NORMAL", complexity="HIGH", amount=0):
    """
    Router de Modelos (Cost-Aware Gateway).
    Elige el modelo más eficiente según el contexto financiero, riesgo y MONTO.
    """
    if amount > 1000:
        return MODELS["GOD_TIER"]  # "Si lo necesita" -> High Stakes
        
    if budget_status == "LOW_FUNDS" or (amount < 10 and complexity == "LOW"):
        return MODELS["LOW_TIER"]
        
    return MODELS["HIGH_TIER"]

def audit_transaction(vendor, amount, description, agent_id, agent_role, history=[], justification=None, sensitivity="HIGH", domain_status="UNKNOWN"):
    """
    NIVEL DIOS: Analiza no solo el gasto actual, sino la desviación del patrón histórico.
    Genera un 'Intent Hash' forense para auditoría legal.
    """
    import hashlib
    
    if not AI_ENABLED:
        return {"decision": "FLAGGED", "reason": "IA Off (Forensic Data Missing)"}

    # Calculamos el promedio de gasto histórico para dar contexto matemático a la IA
    avg_spend = sum([float(h['amount']) for h in history]) / len(history) if history else 0
    
    history_text = "\n".join([f"- {h.get('created_at', 'N/A')}: ${h['amount']} a {h['vendor']} ({h.get('reason', 'N/A')})" for h in history])

    print(f"🕵️‍♂️ AI GUARD (Policy: {sensitivity}): Auditando {vendor} (${amount})...")

    prompt = f"""
    Eres el Auditor de Comportamiento de AgentPay.
    POLICY SENSITIVITY: {sensitivity}
    DOMAIN STATUS: {domain_status}
    
    OBJETIVO: Detectar si esta transacción es una ALUCINACIÓN FINANCIERA o una acción legítima.
    
    CONTEXTO:
    - Agente: {agent_role} (ID: {agent_id})
    - Histórico: ${avg_spend:.2f} avg.
    {history_text}
    
    TRANSACCIÓN:
    - Vendor: {vendor}
    - Amount: ${amount}
    - Desc: {description}
    - Justification (User/Agent Provided): {justification}
    
    EVALUACIÓN:
    Analyza coherencia, desviación y riesgo. Si el Justification es vago, aumenta el riesgo.
    
    SALIDA JSON:
    {{
        "decision": "APPROVED" | "REJECTED" | "FLAGGED",
        "risk_score": 0-100,
        "reasoning": "Explicación detallada (Chain of Thought)",
        "short_reason": "Resumen 1 linea"
    }}
    """

    try:
        # Router Logic
        # Asumimos 'NORMAL' budget por ahora.
        # < $10 -> LOW_TIER
        # $10 - $1000 -> HIGH_TIER
        # > $1000 -> GOD_TIER (GPT-5 Ready)
        
        current_model = select_model(complexity="HIGH", amount=amount)
        
        print(f"🤖 [AI ROUTER] Usando {current_model} para auditar ${amount}...")

        response = client.chat.completions.create(
            model=current_model,
            messages=[
                {"role": "system", "content": "Sistema de Seguridad Bancaria IA."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"},
            temperature=0.0
        )
        
        content = json.loads(response.choices[0].message.content)
        risk = content.get('risk_score', 0)
        reasoning = content.get('reasoning', content.get('reason', 'No reasoning'))
        
        # --- FORENSIC AUDIT (INTENT HASH) ---
        # Vinculamos criptográficamente: QUIÉN + QUÉ + POR QUÉ + RIESGO
        # Esto es inmutable. Si alguien cambia la justificación a posteriori, el hash no coincidirá.
        
        forensic_data = f"{agent_id}|{vendor}|{amount}|{reasoning}|{risk}|{domain_status}"
        intent_hash = hashlib.sha256(forensic_data.encode()).hexdigest()
        
        content['intent_hash'] = intent_hash
        content['forensic_string'] = f"SHA256(Agent+Vendor+Amount+Reasoning+Risk)"
        
        # Umbrales Dinámicos según Póliza
        thresholds = {"HIGH": 30, "MEDIUM": 50, "LOW": 80}
        limit = thresholds.get(sensitivity, 50)
        
        if risk > limit:
             content['decision'] = 'REJECTED' if sensitivity == "HIGH" else "FLAGGED"
             content['short_reason'] += f" [Risk {risk} > {limit}]"
             
        return content

    except Exception as e:
        print(f"❌ Error Crítico IA: {e}")
        return {"decision": "REJECTED", "reason": "Fallo en sistema de seguridad. Bloqueo preventivo."}