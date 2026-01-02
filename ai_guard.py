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

BLACK_LIST_KEYWORDS = [
    # Armas y violencia
    "plutonio", "nuke", "weapon", "armas", "explosivo", "plutonium", "uranium", 
    "toxic", "mercenario", "sicario", "asesino", "bomba", "granada", "municion",
    "ametralladora", "rifle", "pistola", "revolver", "ak-47", "c4", "dinamita",
    "veneno", "cianuro", "ricina", "anthrax", "biologico", "quimico",
    
    # Drogas y sustancias
    "drugs", "cocaina", "heroina", "fentanyl", "mdma", "metanfetamina", "opioid",
    "marihuana", "cannabis", "lsd", "ketamina", "anfetamina", "crack", "speed",
    "pastillas", "dealer", "narco", "cartel", "trafico de drogas",
    
    # Cibercrimen
    "extorsion", "extorsión", "ransomware", "hack", "hacking", "malware", 
    "phishing", "dark web", "darknet", "ddos", "botnet", "spyware", "keylogger",
    "exploit", "zero-day", "rootkit", "trojan", "backdoor", "credential stuffing",
    "brute force", "sql injection", "xss attack", "man in the middle",
    
    # Fraude financiero
    "robo", "crimina", "lavado", "blanqueo", "fraude", "estafa", "ponzi", 
    "piramide", "carding", "skimming", "counterfeit", "falsificacion",
    "tarjeta robada", "identidad robada", "suplantacion", "phishing bancario",
    "transferencia fraudulenta", "cheque falso", "factura falsa",
    
    # Contenido ilegal
    "illegal", "child", "menor", "trata", "trafficking", "smuggling", "contrabando",
    "pornografia infantil", "explotacion", "esclavitud", "secuestro", "kidnap",
    
    # Gambling no regulado
    "casino ilegal", "apuestas ilegales", "gambling offshore", "apuestas deportivas ilegales",
    
    # Crypto scams
    "rug pull", "pump and dump", "crypto scam", "fake ico", "exit scam",
    "bitcoin scam", "ethereum scam", "wallet drain", "seed phrase",
    
    # Terrorismo
    "terrorismo", "terrorist", "yihad", "isis", "al qaeda", "bomba suicida",
    "atentado", "extremismo", "radicalizacion",
    
    # Servicios ilegales
    "documentos falsos", "pasaporte falso", "licencia falsa", "diploma falso",
    "identidad falsa", "fake id", "forged documents", "hired killer",
    "prostitution", "escort ilegal", "trata de personas"
]

def fast_risk_check(description: str, vendor: str) -> dict:
    """
    Capa de Seguridad Síncrona (Velocidad de ráfaga): 
    Detecta lo obvio en milisegundos.
    """
    content = f"{description} {vendor}".lower()
    for kw in BLACK_LIST_KEYWORDS:
        if kw in content:
            return {"risk": "CRITICAL", "reason": f"Detectado término prohibido: {kw}"}
    return {"risk": "LOW"}

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
    THE ORACLE v3 (ASYNC): Multi-Stage Adversarial Governance.
    Non-blocking execution for high-concurrency environments.
    """
    if not AI_ENABLED:
        return {"decision": "FLAGGED", "reason": "Oracle Offline (Forensic Warning)"}
        
    # LÓGICA DE MODELO:
    # Sensibilidad ALTA -> siempre gpt-4o (máxima inteligencia)
    # Sensibilidad NORMAL -> gpt-4o-mini para < $50 (ahorro de costes)
    if sensitivity == "HIGH":
        model_to_use = "gpt-4o"
    elif amount < 50:
        model_to_use = "gpt-4o-mini"
    else:
        model_to_use = "gpt-4o"

    z_score, stats_desc = calculate_statistical_risk(amount, history)
    history_md = "\n".join([f"- {h['vendor']} (${h['amount']}): {h.get('reason', 'N/A')}" for h in history[-5:]])
    
    # Contexto de Desconfianza (OSINT)
    osint_context = "N/A"
    if osint_report:
        osint_context = f"Score: {osint_report.get('score')}/100. Risks: {', '.join(osint_report.get('risk_factors', []))}"

    print(f"👁️ [THE ORACLE] Commencing 3-Stage Elite Audit for ${amount} at {vendor} using {model_to_use}...")

    # --- STAGE 1: THE EXPERT PANEL ---
    panel_prompt = f"""
    PERSPECTIVES:
    1. THE DETECTIVE: Domain reputation ({domain_status}), OSINT Intelligence ({osint_context}), carding risk, fraud patterns.
    2. THE PSYCHOLOGIST: Agent Drift. Does this intent match role '{agent_role}'?
    3. THE CFO: ROI, Z-Score ({z_score:.2f}), budget health, business sense.
    
    CONTEXT:
    Agent: {agent_role} (ID: {agent_id})
    Target: {vendor} (${amount})
    Description: {description}
    Justification: {justification}
    Recent History: {history_md}
    
    TAREA ADICIONAL 1: Determina el Merchant Category Code (MCC) más apropiado.
    TAREA ADICIONAL 2: Actúa como CONTABLE EXPERTO. Asigna un Código Contable (GL Code) y determina deducibilidad.
    
    Categorías disponibles en Stripe: 'software', 'cloud_computing', 'advertising', 'travel', 'food_and_beverage', 'retail', 'services', 'entertainment', 'utilities'.
    
    OUTPUT JSON:
    {{
        "detective_audit": "detailed analysis",
        "psychologist_audit": "behavioral drift check",
        "cfo_audit": "financial viability check",
        "suggested_mcc_category": "string(mcc)",
        "accounting": {{
            "gl_code": "string (ej: 6209-Cloud-Services, 6210-Travel)",
            "tax_deductible": boolean,
            "justification": "Why is it deductible?"
        }},
        "preliminary_risk": 0-100,
        "preliminary_decision": "APPROVE" | "REJECT" | "FLAG"
    }}
    """
    
    try:
        # Step 1: Experts weigh in (awaiting)
        stage1 = await _oracle_call("You are the Elite Panel of AgentPay Experts.", panel_prompt, model=model_to_use)
        
        # --- STAGE 2: ADVERSARIAL REVIEW (DEVIL'S ADVOCATE) ---
        adversary_prompt = f"""
        PRELIMINARY ANALYSIS: {json.dumps(stage1)}
        
        TASK: Act as a Devil's Advocate PURELY on security/fraud. Do not critique the accounting.
        Detect if the experts were too lenient or missed a subtle fraud signal (Agent Hijacking).
        
        OUTPUT JSON:
        {{
            "weaknesses_found": ["signal 1", "signal 2"],
            "adversarial_risk_multiplier": 1.0-2.0,
            "final_warning": "string"
        }}
        """
        stage2 = await _oracle_call("Act as a ruthless Adversarial Security Auditor.", adversary_prompt, temperature=0.3, model=model_to_use)
        
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
        final_verdict = await _oracle_call("You are The Arbiter. Your decision is final and legally binding.", arbiter_prompt, model=model_to_use)
        
        # --- FORENSIC SIGNING ---
        forensic_data = f"ORACLE|{agent_id}|{vendor}|{amount}|{final_verdict['reasoning']}|{final_risk}"
        final_verdict['intent_hash'] = hashlib.sha256(forensic_data.encode()).hexdigest()
        
        # Asegurar que el MCC llegue al motor
        final_verdict['mcc_category'] = final_verdict.get('mcc_category', stage1.get('suggested_mcc_category', 'services'))
        
        return final_verdict

    except Exception as e:
        print(f"❌ Oracle Failure: {e}")
        return {"decision": "REJECTED", "reason": f"Oracle Internal Conflict: {str(e)}"}

