import os
import json
import hashlib
import statistics
import time
from loguru import logger
from openai import AsyncOpenAI

# Configuración
try:
    client = AsyncOpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
    AI_ENABLED = True
except:
    AI_ENABLED = False

EMBEDDING_MODEL = "text-embedding-3-small"
ORACLE_MODEL = "gpt-4o"

# ==========================================
# CAPA 1: MATEMÁTICA (EXISTENTE - NO TOCAR)
# ==========================================
def calculate_statistical_risk(amount, history):
    """
    Mantiene la compatibilidad con engine.py.
    Detecta anomalías numéricas puras (Z-Score).
    """
    if not history or len(history) < 3:
        return 0.0, "INITIAL_BASELINE"
    
    try:
        amounts = [float(h['amount']) for h in history]
        mean = statistics.mean(amounts)
        stdev = statistics.stdev(amounts)
        
        if stdev == 0:
            return (2.0 if amount > mean else 0.0), "STATIC_HISTORY_DEVIATION"
            
        z_score = (amount - mean) / stdev
        return z_score, f"Stats(m:{mean:.1f}, s:{stdev:.1f})"
    except Exception as e:
        logger.error(f"Stats Error: {e}")
        return 0.0, "ERROR"

# ==========================================
# CAPA 2: FAST-WALL (EXISTENTE - NO TOCAR)
# ==========================================
async def fast_risk_check(description: str, vendor: str) -> dict:
    """
    Filtro rápido de criminalidad. Se mantiene igual.
    """
    if not AI_ENABLED:
        return {"risk": "LOW", "reason": "AI Offline"}

    prompt = f"""
    CHECK FOR SEVERE CRIME (Drugs, Weapons, Human Trafficking, Explosives).
    Vendor: {vendor} | Desc: {description}
    Return JSON: {{ "is_criminal": true/false, "confidence": 0-100, "reason": "..." }}
    """
    
    try:
        response = await client.chat.completions.create(
            model="gpt-4o-mini", # Rápido y barato
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
            temperature=0.0
        )
        res = json.loads(response.choices[0].message.content)
        
        if res.get("is_criminal", False) and res.get("confidence", 0) > 95:
            return {"risk": "CRITICAL", "reason": f"FAST-WALL: {res.get('reason')}"}
            
    except Exception as e:
        logger.warning(f"Fast-Wall Skipped: {e}")
        
    return {"risk": "LOW", "reason": "Clean"}

# ==========================================
# CAPA 3: MEMORIA RAG (NUEVA CAPA)
# ==========================================
async def get_embedding(text: str):
    """Genera vector de memoria para guardar/buscar."""
    try:
        text = text.replace("\n", " ")
        res = await client.embeddings.create(input=[text], model=EMBEDDING_MODEL)
        return res.data[0].embedding
    except Exception as e:
        logger.error(f"⚠️ Embedding Error: {e}")
        return None

async def search_memory(db_client, description, vendor):
    """Busca en el pasado si ya aprobamos algo igual."""
    if not db_client: return []
    try:
        query_text = f"{vendor} {description}"
        vector = await get_embedding(query_text)
        if not vector: return []

        # Llama a la función SQL que creamos en el Paso 1
        res = db_client.rpc("match_transactions", {
            "query_embedding": vector,
            "match_threshold": 0.85, # 85% de similitud requerida
            "match_count": 5
        }).execute()
        return res.data if res.data else []
    except Exception as e:
        return []

# ==========================================
# CAPA 4: THE ORACLE v5 (INTEGRACIÓN TOTAL)
# ==========================================
async def audit_transaction(vendor, amount, description, agent_id, agent_role, history=[], justification=None, sensitivity="HIGH", osint_report=None, corporate_policies=None, db_client=None, screenshot_base64=None, domain_status=None, trusted_context=None):
    """
    Versión HÍBRIDA: Usa todo (Stats + Policies + RAG + Visión).
    """
    if not AI_ENABLED:
        return {"decision": "FLAGGED", "reasoning": "AI Offline", "risk_score": 50}

    # 1. RECUPERAR MEMORIA (RAG)
    memory_txt = "No history."
    past_approvals = 0
    if db_client:
        similar_txs = await search_memory(db_client, description, vendor)
        if similar_txs:
            past_approvals = sum(1 for tx in similar_txs if tx['status'] == 'APPROVED')
            memory_txt = f"FOUND {len(similar_txs)} SIMILAR PAST CASES. Approved: {past_approvals}. Examples: {[t['description'] for t in similar_txs[:2]]}"

    # 2. CALIBRAR PARANOIA
    # Si ya lo aprobamos 3 veces, la IA debe relajarse.
    suspicion_level = "NEUTRAL"
    if past_approvals >= 3:
        suspicion_level = "VERY LOW (TRUSTED PATTERN)"
    elif sensitivity == "CRITICAL":
        suspicion_level = "HIGH (PARANOID MODE)"

    # 3. POLÍTICAS
    policy_txt = "Standard Logic."
    if corporate_policies:
        limits = corporate_policies.get('spending_limits', {})
        policy_txt = f"Max Item: ${limits.get('max_per_item', 'Unlimited')}. Restricted: {corporate_policies.get('restricted_vendors', [])}"

    # 4. PROMPT MAESTRO
    system_prompt = f"""
    YOU ARE 'THE ORACLE', an elite AI Financial Auditor.
    
    INPUTS:
    - ROLE: {agent_role}
    - MEMORY (RAG): {memory_txt}
    - POLICIES: {policy_txt}
    - SUSPICION LEVEL: {suspicion_level}
    - OSINT: {osint_report.get('score', 'N/A') if osint_report else 'N/A'}
    
    CORE DIRECTIVE:
    1. CHECK MEMORY: If we approved this before -> APPROVE again (unless policies changed).
    2. CHECK ROLE: Is this tool logical for a {agent_role}? (e.g. Dev -> AWS = OK).
    3. CHECK VISION: If image provided, does the site look like a scam?
    
    VERDICT:
    Be fair. Do not block valid business tools. Block only fraud, illegal items, or clear policy violations.
    """

    user_content = [
        {"type": "text", "text": f"""
        TRANSACTION:
        Vendor: {vendor}
        Amount: ${amount}
        Desc: {description}
        Justification: {justification}
        
        Return JSON:
        {{
            "decision": "APPROVED" | "FLAGGED" | "REJECTED",
            "reasoning": "Concise explanation.",
            "risk_score": 0-100,
            "category_mcc": "services"
        }}
        """}
    ]

    # Inyección de Visión (Si el Engine nos pasa la captura)
    if screenshot_base64:
        user_content.append({
            "type": "image_url",
            "image_url": {"url": f"data:image/jpeg;base64,{screenshot_base64}"}
        })
        user_content[0]["text"] += "\n[EVIDENCE]: See attached screenshot of vendor site."

    try:
        response = await client.chat.completions.create(
            model=ORACLE_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content}
            ],
            response_format={"type": "json_object"},
            temperature=0.1
        )
        
        result = json.loads(response.choices[0].message.content)
        
        # Override de Memoria (Red de Seguridad Final)
        # Si la IA duda pero el historial dice que es seguro, forzamos aprobación.
        if result['decision'] != 'APPROVED' and past_approvals >= 3:
            result['decision'] = 'APPROVED'
            result['reasoning'] = f"Auto-Approved based on {past_approvals} past precedents (RAG Override)."
            result['risk_score'] = 10

        # Generar hash forense
        forensic_str = f"{agent_id}|{vendor}|{amount}|{result['decision']}"
        result['intent_hash'] = hashlib.sha256(forensic_str.encode()).hexdigest()
        result['mcc_category'] = result.get('category_mcc', 'services')
        result['short_reason'] = result['reasoning'] # Compatibilidad
        
        return result

    except Exception as e:
        logger.error(f"Oracle Error: {e}")
        return {"decision": "FLAGGED", "reasoning": "AI Error", "risk_score": 50, "intent_hash": "ERR"}
