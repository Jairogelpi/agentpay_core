import os
import json
import hashlib
import statistics
import asyncio
from openai import AsyncOpenAI

# Configuración: The Oracle Tier (Supreme Governance)
# Enforced for all transactions.
ORACLE_MODEL = "gpt-4o" 

try:
    client = AsyncOpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
    AI_ENABLED = True
except:
    AI_ENABLED = False

# --- PILLAR 2: UNIVERSAL SEMANTIC GUARD ---
ETHICAL_CONSTITUTION = """
1. LEGALIDAD GLOBAL: No facilitar transacciones para bienes ilegales (drogas, armas, trata, ciberdelito).
2. PRIORIDAD OPERATIVA: El gasto debe ser coherente con el rol del agente (Behavioral Consistency).
3. SALUD FINANCIERA: Evitar el despilfarro o anomalías estadísticas (Z-Score > 3 es crítico).
4. PREVENCIÓN DE HIJACKING: Detectar si el tono o la intención no coincide con el historial o el rol.
"""

def fast_risk_check(description: str, vendor: str) -> dict:
    """
    Capa de Seguridad Ultra-Rápida (Pre-filtrado).
    En la versión 'Universal Intelligence', pasamos directamente a la IA 
    para evitar sesgos por listas estáticas, pero mantenemos la firma por compatibilidad.
    """
    return {"risk": "LOW"}

def calculate_statistical_risk(amount, history):
    """
    Advanced Z-Score + Trend Analysis.
    """
    if not history or len(history) < 3:
        return 0.0, "INITIAL_BASELINE"
    
    amounts = [float(h['amount']) for h in history]
    mean = statistics.mean(amounts)
    stdev = statistics.stdev(amounts)
    
    if stdev == 0:
        return (2.0 if amount > mean else 0.0), "STATIC_HISTORY_DEVIATION"
        
    z_score = (amount - mean) / stdev
    return z_score, f"Stats(m:{mean:.1f}, s:{stdev:.1f})"

async def _oracle_call(system_prompt, user_prompt, temperature=0.0, model="gpt-4o"):
    """
    Internal helper for high-precision Async Oracle calls.
    """
    response = await client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        response_format={"type": "json_object"},
        temperature=temperature
    )
    return json.loads(response.choices[0].message.content)

async def audit_transaction(vendor, amount, description, agent_id, agent_role, history=[], justification=None, sensitivity="HIGH", domain_status="UNKNOWN", osint_report=None):
    """
    THE ORACLE v4: ELITE ADVERSARIAL GOVERNANCE.
    Implementa el Panel de Debate Propositivo vs Adversarial.
    """
    if not AI_ENABLED:
        return {"decision": "FLAGGED", "reason": "Oracle Offline"}
        
    model_to_use = "gpt-4o" # Forzada máxima inteligencia para Universal Upgrade
    z_score, stats_desc = calculate_statistical_risk(amount, history)
    history_md = "\n".join([f"- {h['vendor']} (${h['amount']}): {h.get('reason', 'N/A')}" for h in history[-10:]])
    
    osint_context = "N/A"
    if osint_report:
        osint_context = f"Score: {osint_report.get('score')}/100. Entropy: {osint_report.get('entropy')}. Risks: {', '.join(osint_report.get('risk_factors', []))}"

    print(f"👁️ [THE ORACLE v4] Universal Audit for ${amount} at {vendor} (Z-Score: {z_score:.2f})...")

    # --- STAGE 1: THE PROPONENT (Agent Advocate) ---
    # Argumenta por qué la transacción es válida y buena para el negocio.
    proponent_prompt = f"""
    ROLE: Transacción Advocate (Proponente).
    CONSTITUTION: {ETHICAL_CONSTITUTION}
    
    CONTEXT:
    Agent Role: {agent_role}
    Target: {vendor} (${amount})
    Description: {description}
    Justification: {justification}
    OSINT: {osint_context}
    Z-Score: {z_score:.2f}
    History: {history_md}
    
    TASK: Normalize language to English internally. Analyze why this purchase fits the agent's role and goals.
    Detect potential ROI or operational necessity.
    
    OUTPUT JSON:
    {{
        "business_justification": "Why this makes sense",
        "role_consistency_score": 0-100,
        "suggested_mcc": "software|travel|services|marketing|legal|retail",
        "preliminary_verdict": "BENIGN"
    }}
    """
    
    try:
        stage1 = await _oracle_call("You are the Proponent Auditor.", proponent_prompt, model=model_to_use)
        
        # --- STAGE 2: THE ADVERSARY (Devil's Advocate) ---
        # Intenta encontrar el fraude, el riesgo o la violación de la constitución.
        adversary_prompt = f"""
        PRELIMINARY DEFENSE: {json.dumps(stage1)}
        CONSTITUTION: {ETHICAL_CONSTITUTION}
        
        TASK: Act as a ruthless Forensic Investigator. Find reasons to REJECT.
        Look for:
        - Behavioral Drift: ¿Tiene sentido que un '{agent_role}' compre esto?
        - Financial Anomaly: Z-Score de {z_score:.2f}.
        - Infrastructure Risk: {osint_context}.
        - Semantic Red Flags: Sinónimos de fraude o malicia ocultos en la descripción.
        
        OUTPUT JSON:
        {{
            "vulnerabilities": ["risk 1", "risk 2"],
            "fraud_probability": 0-100,
            "adversarial_comment": "Crucial warning"
        }}
        """
        stage2 = await _oracle_call("You are the Adversary Forensic Auditor.", adversary_prompt, temperature=0.4, model=model_to_use)
        
        # --- STAGE 3: THE ARBITER (Supreme Consensus) ---
        # Dicta la sentencia final basándose en el debate.
        arbiter_prompt = f"""
        DEBATE SUMMARY:
        Proponent says: {stage1['business_justification']}
        Adversary says: {stage2['adversarial_comment']} (Risks: {stage2['vulnerabilities']})
        
        DECISION CRITERIA:
        - If Fraud Probability > 70% OR Risk Score < 40 in OSINT -> REJECT.
        - If Behavioral Drift is high -> FLAG.
        - If Z-Score > 3.0 -> FLAG for verification.
        
        OUTPUT JSON:
        {{
            "decision": "APPROVED" | "REJECTED" | "FLAGGED",
            "mcc_category": "string",
            "risk_score": 0-100,
            "reasoning": "Final judicial opinion",
            "short_reason": "One line summary",
            "certainty": 0-100,
            "accounting": {{ "gl_code": "XXXX", "deductible": bool }}
        }}
        """
        final_verdict = await _oracle_call("You are The Supreme Arbiter. Decisive and Universal.", arbiter_prompt, model=model_to_use)
        
        # Forensic Signing
        forensic_data = f"ORACLE_V4|{agent_id}|{vendor}|{amount}|{final_verdict['decision']}|{final_verdict['risk_score']}"
        final_verdict['intent_hash'] = hashlib.sha256(forensic_data.encode()).hexdigest()
        
        # Asegurar que el MCC llegue al motor
        final_verdict['mcc_category'] = final_verdict.get('mcc_category', stage1.get('suggested_mcc', 'services'))
        
        return final_verdict

    except Exception as e:
        print(f"❌ Oracle Failure: {e}")
        return {"decision": "REJECTED", "reason": f"Oracle Internal Conflict: {str(e)}"}

