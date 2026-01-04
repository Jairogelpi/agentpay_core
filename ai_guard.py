import os
import json
import time
from loguru import logger
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

async def audit_transaction(vendor, amount, description, agent_id, agent_role, history=[], justification=None, sensitivity="HIGH", domain_status="UNKNOWN", osint_report=None, trusted_context=None, corporate_policies=None):
    """
    THE ORACLE v4: ELITE ADVERSARIAL GOVERNANCE.
    Implementa el Panel de Debate Propositivo vs Adversarial.
    Ahora incluye CORPORATE POLICIES para decisiones más inteligentes.
    """
    if not AI_ENABLED:
        return {"decision": "FLAGGED", "reason": "Oracle Offline"}
        
    model_to_use = "gpt-4o" # Forzada máxima inteligencia para Universal Upgrade
    z_score, stats_desc = calculate_statistical_risk(amount, history)
    history_md = "\n".join([f"- {h['vendor']} (${h['amount']}): {h.get('reason', 'N/A')}" for h in history[-10:]])
    
    osint_context = "N/A"
    if osint_report:
        osint_context = f"Score: {osint_report.get('score')}/100. Entropy: {osint_report.get('entropy')}. Risks: {', '.join(osint_report.get('risk_factors', []))}"

    # Format corporate policies for the AI
    policy_context = "No specific corporate policies defined."
    if corporate_policies:
        spending = corporate_policies.get('spending_limits', {})
        policy_context = f"""
CORPORATE EXPENSE POLICIES (OFFICIAL COMPANY RULES):
- Max Per Item: ${spending.get('max_per_item', 'Unlimited')}
- Daily Budget: ${spending.get('daily_budget', 'Unlimited')}  
- Slack Approval Threshold: ${spending.get('soft_limit_slack', 'N/A')} (amounts above require human approval)
- Restricted Vendors: {', '.join(corporate_policies.get('restricted_vendors', []) or ['None'])}
- Allowed Categories: {', '.join(corporate_policies.get('allowed_categories', ['all']))}
- Working Hours: {corporate_policies.get('working_hours', {}).get('start', 'Any')} - {corporate_policies.get('working_hours', {}).get('end', 'Any')} ({corporate_policies.get('working_hours', {}).get('timezone', 'UTC')})
- Justification Required: {corporate_policies.get('enforce_justification', False)}
"""

    logger.info(f"👁️ [THE ORACLE v4] Universal Audit for ${amount} at {vendor} (Z-Score: {z_score:.2f})...")

    # --- STAGE 1: THE PROPONENT (Strategic Business Consultant) ---
    proponent_prompt = f"""
    YOU ARE: A Strategic Business Consultant.
    EVALUATING AGENT ROLE: {agent_role} (This is the buyer's professional identity).
    
    {policy_context}
    
    TRANSACTION: {vendor} (${amount})
    DESCRIPTION: {description}
    JUSTIFICATION: {justification}
    OSINT: {osint_context}
    Z-Score: {z_score:.2f}
    History: {history_md}
    
    TASK: Argue why this purchase is a REASONABLE and NECESSARY business expense for a professional '{agent_role}'. 
    Consider the company's official policies above when evaluating.
    If the vendor is in the restricted list, acknowledge it but still provide business justification.
    
    OBLIGATORY JSON STRUCTURE:
    {{
        "business_justification": "Detailed business-centric explanation",
        "role_consistency_score": 0-100,
        "policy_compliance_score": 0-100,
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

        # --- STAGE 2: THE ADVERSARY (Ruthless Fraud Investigator & Cynical Tech Auditor) ---
        adversary_prompt = f"""
        YOU ARE: A Ruthless Fraud Investigator & Cynical Tech Auditor.
        SUBJECT: A '{agent_role}' buying from '{vendor}'.
        JUSTIFICATION GIVEN: "{justification}"
        
        {policy_context}
        
        INSTRUCTIONS:
        1. DETECT 'TECHNOBABBLE': Is the user using complex technical words to hide a consumer purchase? (e.g. calling a PlayStation a "GPU Cluster" -> FRAUD). But if a DevOps Engineer buys AWS/Serverless, that is NORMAL.
        2. ANALYZE VENDOR MATCH: A Backend Dev buys from AWS/Azure/DigitalOcean = VALID. A Lawyer buys LexisNexis = VALID.
        3. ALTERNATIVES: If they are buying Consumer Hardware/Goods for a Professional Role -> HIGH PROBABILITY OF FRAUD.
        4. POLICY VIOLATION: Check if the vendor is in the RESTRICTED VENDORS list. If so, this is a CRITICAL violation.
        5. CATEGORY MISMATCH: Check if the purchase category matches the ALLOWED CATEGORIES in the policy.
        
        TASK: Scrutinize the Proponent's argument.
        - If the Role + Vendor match is logical (e.g. Tech Role + Cloud Vendor), do NOT flag as high risk just because policies are generic.
        - Focus on detecting REAL consumer fraud (Gaming, Gambling, Luxury), not blocking business tools.
        
        OBLIGATORY JSON STRUCTURE:
        {
            "vulnerabilities": ["List specific doubts"],
            "policy_violations": ["List any policy violations detected"],
            "fraud_probability": 0-100,
            "adversarial_comment": "Direct accusation if applicable"
        }
        """
        stage2_raw = await _oracle_call("You are the Adversary Forensic Auditor.", adversary_prompt, temperature=0.4, model=model_to_use)
        
        # VALIDACIÓN DE SEGURIDAD
        stage2 = {
            "vulnerabilities": stage2_raw.get("vulnerabilities", ["Possible semantic obfuscation"]),
            "fraud_probability": stage2_raw.get("fraud_probability", 50),
            "adversarial_comment": stage2_raw.get("adversarial_comment", "Review required for role consistency.")
        }
        
        # --- STAGE 3: THE ARBITER (Supreme Judge) ---
        arbiter_prompt = f"""
        YOU ARE: The Supreme Arbiter of Financial Logic.
        
        {policy_context}
        
        DEBATE:
        Proponent: {stage1['business_justification']}
        Proponent Policy Compliance Score: {stage1.get('policy_compliance_score', 50)}/100
        Adversary: {stage2['adversarial_comment']} (Fraud Prob: {stage2['fraud_probability']}%)
        Policy Violations Detected: {stage2.get('policy_violations', ['None'])}
        
        CRITICAL RULES (IN ORDER OF PRIORITY):
        1. If vendor is in RESTRICTED VENDORS list -> AUTOMATIC REJECT (Policy Override)
        2. If amount exceeds Max Per Item in policy -> REJECT
        3. If Fraud Probability > 95% -> REJECT (Extreme threshold: Only blocking certain fraud)
        4. "IN DUBIO PRO REO": If there is doubt, or the Fraud Probability is < 95%, you MUST APPROVE (or FLAG if 80-94%).
        5. DO NOT BLOCK valid work. Unless you have PROOF of fraud (Gaming/Luxury/Illegal), the verdict must be APPROVED.
        
        OBLIGATORY JSON STRUCTURE:
        {{
            "decision": "APPROVED" | "REJECTED" | "FLAGGED",
            "risk_score": 0-100,
            "policy_violation": true | false,
            "reasoning": "Final verdict explaining why, including policy considerations",
            "short_reason": "Summary for logs",
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
        logger.error(f"❌ Oracle Failure: {e}")
        return {"decision": "REJECTED", "reason": f"Oracle Internal Conflict: {str(e)}"}
