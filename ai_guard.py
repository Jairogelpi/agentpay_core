import os
import json
import hashlib
import statistics
from openai import OpenAI

# Configuración: The Oracle Tier (Supreme Governance)
# Enforced for all transactions.
ORACLE_MODEL = "gpt-4o" 

try:
    client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
    AI_ENABLED = True
except:
    AI_ENABLED = False

def calculate_statistical_risk(amount, history):
    """
    Advanced Z-Score + Trend Analysis.
    """
    if not history or len(history) < 2:
        return 0.0, "INITIAL_BASELINE"
    
    amounts = [float(h['amount']) for h in history]
    mean = statistics.mean(amounts)
    stdev = statistics.stdev(amounts)
    
    if stdev == 0:
        return (50.0 if amount > mean else 0.0), "STATIC_HISTORY_DEVIATION"
        
    z_score = (amount - mean) / stdev
    return z_score, f"Stats(m:{mean:.1f}, s:{stdev:.1f})"

def _oracle_call(system_prompt, user_prompt, temperature=0.0):
    """
    Internal helper for high-precision Oracle calls.
    """
    response = client.chat.completions.create(
        model=ORACLE_MODEL,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        response_format={"type": "json_object"},
        temperature=temperature
    )
    return json.loads(response.choices[0].message.content)

def audit_transaction(vendor, amount, description, agent_id, agent_role, history=[], justification=None, sensitivity="HIGH", domain_status="UNKNOWN"):
    """
    THE ORACLE v3: Multi-Stage Adversarial Governance.
    The highest security standard for AI-driven financial operations.
    """
    if not AI_ENABLED:
        return {"decision": "FLAGGED", "reason": "Oracle Offline (Forensic Warning)"}

    z_score, stats_desc = calculate_statistical_risk(amount, history)
    history_md = "\n".join([f"- {h['vendor']} (${h['amount']}): {h.get('reason', 'N/A')}" for h in history[-5:]])

    print(f"👁️ [THE ORACLE] Commencing 3-Stage Elite Audit for ${amount} at {vendor}...")

    # --- STAGE 1: THE EXPERT PANEL ---
    panel_prompt = f"""
    PERSPECTIVES:
    1. THE DETECTIVE: Domain reputation ({domain_status}), carding risk, fraud patterns.
    2. THE PSYCHOLOGIST: Agent Drift. Does this intent match role '{agent_role}'?
    3. THE CFO: ROI, Z-Score ({z_score:.2f}), budget health, business sense.
    
    CONTEXT:
    Agent: {agent_role} (ID: {agent_id})
    Target: {vendor} (${amount})
    Justification: {justification}
    Recent History: {history_md}
    
    TAREA ADICIONAL: Determina el Merchant Category Code (MCC) más apropiado.
    Categorías disponibles en Stripe: 'software', 'cloud_computing', 'advertising', 'travel', 'food_and_beverage', 'retail', 'services', 'entertainment', 'utilities'.
    
    OUTPUT JSON:
    {{
        "detective_audit": "detailed analysis",
        "psychologist_audit": "behavioral drift check",
        "cfo_audit": "financial viability check",
        "suggested_mcc_category": "string (one of the valid categories)",
        "preliminary_risk": 0-100,
        "preliminary_decision": "APPROVE" | "REJECT" | "FLAG"
    }}
    """
    
    try:
        # Step 1: Experts weigh in
        stage1 = _oracle_call("You are the Elite Panel of AgentPay Experts.", panel_prompt)
        
        # --- STAGE 2: ADVERSARIAL REVIEW (DEVIL'S ADVOCATE) ---
        adversary_prompt = f"""
        PRELIMINARY ANALYSIS: {json.dumps(stage1)}
        
        TASK: Act as a Devil's Advocate. Your job is to find reasons to REJECT this transaction. 
        Detect if the experts were too lenient or missed a subtle fraud signal (Agent Hijacking).
        
        OUTPUT JSON:
        {{
            "weaknesses_found": ["signal 1", "signal 2"],
            "adversarial_risk_multiplier": 1.0-2.0,
            "final_warning": "string"
        }}
        """
        stage2 = _oracle_call("Act as a ruthless Adversarial Security Auditor.", adversary_prompt, temperature=0.3)
        
        # --- STAGE 3: THE ARBITER CONSENSUS ---
        final_risk = min(100, stage1['preliminary_risk'] * stage2['adversarial_risk_multiplier'])
        
        arbiter_prompt = f"""
        PANEL DECISION: {stage1['preliminary_decision']}
        MCC CATEGORY: {stage1.get('suggested_mcc_category', 'services')}
        RISK: {final_risk}
        ADVERSARY FINDINGS: {stage2['final_warning']}
        
        TASK: Consolidate the verdict. If Risk > {sensitivity == "HIGH" and 30 or 50}, REJECT or FLAG.
        
        OUTPUT JSON:
        {{
            "decision": "APPROVED" | "REJECTED" | "FLAGGED",
            "mcc_category": "string (confirm the MCC from the panel)",
            "risk_score": {final_risk},
            "short_reason": "Veredicto final",
            "reasoning": "Chain of Thought consolidation",
            "metadata": {{ "z_score": {z_score}, "adversary_active": true }}
        }}
        """
        final_verdict = _oracle_call("You are The Arbiter. Your decision is final and legally binding.", arbiter_prompt)
        
        # --- FORENSIC SIGNING ---
        forensic_data = f"ORACLE|{agent_id}|{vendor}|{amount}|{final_verdict['reasoning']}|{final_risk}"
        final_verdict['intent_hash'] = hashlib.sha256(forensic_data.encode()).hexdigest()
        
        # Asegurar que el MCC llegue al motor
        final_verdict['mcc_category'] = final_verdict.get('mcc_category', stage1.get('suggested_mcc_category', 'services'))
        
        return final_verdict

    except Exception as e:
        print(f"❌ Oracle Failure: {e}")
        return {"decision": "REJECTED", "reason": f"Oracle Internal Conflict: {str(e)}"}