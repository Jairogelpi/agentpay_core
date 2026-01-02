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

async def audit_transaction(vendor, amount, description, agent_id, agent_role, history=[], justification=None, sensitivity="HIGH", domain_status="UNKNOWN", osint_report=None, trusted_context=None):
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

    # --- STAGE 1: THE PROPONENT (Strategic Business Consultant) ---
    proponent_prompt = f"""
    YOU ARE: A Strategic Business Consultant.
    EVALUATING AGENT ROLE: {agent_role} (This is the buyer's professional identity).
    
    TRANSACTION: {vendor} (${amount})
    DESCRIPTION: {description}
    JUSTIFICATION: {justification}
    OSINT: {osint_context}
    Z-Score: {z_score:.2f}
    History: {history_md}
    
    TASK: Argue why this purchase is a REASONABLE and NECESSARY business expense for a professional '{agent_role}'. 
    Focus on operational utility and potential ROI.
    
    OBLIGATORY JSON STRUCTURE:
    {{
        "business_justification": "Detailed business-centric explanation",
        "role_consistency_score": 0-100,
        "suggested_mcc": "software|marketing|services|travel|retail",
        "preliminary_verdict": "BENIGN"
    }}
    """
    
    try:
        # Llamada a la Etapa 1
        stage1_raw = await _oracle_call("You are the Proponent Auditor.", proponent_prompt, model=model_to_use)
        
        # VALIDACIÓN DE SEGURIDAD: Asegurar que el campo existe aunque la IA falle
        stage1 = {
            "business_justification": stage1_raw.get("business_justification", "No explicit justification provided by AI"),
            "role_consistency_score": stage1_raw.get("role_consistency_score", 50),
            "suggested_mcc": stage1_raw.get("suggested_mcc", "services"),
            "preliminary_verdict": stage1_raw.get("preliminary_verdict", "UNCERTAIN")
        }

        # --- STAGE 2: THE ADVERSARY (Ruthless Forensic Psychologist) ---
        adversary_prompt = f"""
        YOU ARE: A Ruthless Forensic Auditor.
        SUBJECT UNDER REVIEW: An autonomous agent acting as a '{agent_role}'.
        
        PRELIMINARY DEFENSE: {json.dumps(stage1)}
        
        TASK: Find reasons to REJECT. Is the justification a 'semantic smoke screen' for fraud?
        Check for Behavioral Drift: Why would a '{agent_role}' need this specifically?
        - Z-Score actual: {z_score:.2f}.
        
        OBLIGATORY JSON STRUCTURE:
        {{
            "vulnerabilities": ["List specific risks"],
            "fraud_probability": 0-100,
            "adversarial_comment": "Direct warning about the transaction"
        }}
        """
        stage2_raw = await _oracle_call("You are the Adversary Forensic Auditor.", adversary_prompt, temperature=0.4, model=model_to_use)
        
        # VALIDACIÓN DE SEGURIDAD
        stage2 = {
            "vulnerabilities": stage2_raw.get("vulnerabilities", ["General risk"]),
            "fraud_probability": stage2_raw.get("fraud_probability", 50),
            "adversarial_comment": stage2_raw.get("adversarial_comment", "Review required")
        }
        
        # --- STAGE 3: THE ARBITER (Supreme Court) ---
        arbiter_prompt = f"""
        DEBATE:
        Proponent: {stage1['business_justification']}
        Adversary: {stage2['adversarial_comment']}
        
        DECISION CRITERIA: Reject if Fraud > 70% or OSINT < 40.
        
        OBLIGATORY JSON STRUCTURE:
        {{
            "decision": "APPROVED" | "REJECTED" | "FLAGGED",
            "risk_score": 0-100,
            "reasoning": "Full opinion",
            "short_reason": "Summary",
            "accounting": {{ "gl_code": "XXXX", "deductible": false }}
        }}
        """
        final_verdict = await _oracle_call("You are The Supreme Arbiter.", arbiter_prompt, model=model_to_use)
        
        # Valores por defecto para el veredicto final
        final_verdict["decision"] = final_verdict.get("decision", "FLAGGED")
        final_verdict["reasoning"] = final_verdict.get("reasoning", "Incomplete analysis - flagging for safety")
        final_verdict["short_reason"] = final_verdict.get("short_reason", "Safety Check")
        final_verdict["risk_score"] = final_verdict.get("risk_score", 100)
        final_verdict["accounting"] = final_verdict.get("accounting", {"gl_code": "Suspense", "deductible": False})
        
        # Firma forense
        forensic_data = f"ORACLE_V4|{agent_id}|{vendor}|{amount}|{final_verdict['decision']}"
        final_verdict['intent_hash'] = hashlib.sha256(forensic_data.encode()).hexdigest()
        
        # Asegurar que el MCC llegue al motor
        final_verdict['mcc_category'] = stage1.get('suggested_mcc', 'services')
        
        return final_verdict

    except Exception as e:
        print(f"❌ Oracle Failure: {e}")
        return {"decision": "REJECTED", "reason": f"Oracle Internal Conflict: {str(e)}"}
