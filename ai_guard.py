import os
import json
import hashlib
import statistics
import time
from loguru import logger
from openai import AsyncOpenAI
from groq import Groq

# Configuración OpenAI (Nivel 2 - El Cerebro)
try:
    client = AsyncOpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
    AI_ENABLED = True
except:
    AI_ENABLED = False

# Configuración Groq (Nivel 1 - El Portero Rápido)
try:
    groq_client = Groq(api_key=os.environ.get("GROQ_API_KEY"))
    GROQ_ENABLED = True
except:
    GROQ_ENABLED = False
    logger.warning("⚠️ Groq API Key faltante. El sistema funcionará solo con OpenAI (más lento).")

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
# NUEVA FUNCIÓN: NIVEL 1 (GROQ / LLAMA 3)
# ==========================================
def _tier1_fast_audit(vendor, amount, description):
    """
    Inferencia ultrarrápida (~200ms) usando LPU de Groq.
    Solo aprueba lo OBVIO. Ante la duda, delega.
    """
    if not GROQ_ENABLED:
        return None
        
    # REGLA DE ORO: El dinero grande va al cerebro grande.
    # Si es > $50, nos saltamos a Groq por seguridad.
    if amount > 50.0:
        return None

    system_prompt = """
    You are a Tier-1 Risk Filter. Analyze this transaction for FRAUD or PERSONAL CONSUMPTION disguised as business.
    CRITERIA FOR 'SAFE':
    1. Known SaaS/Business tool (AWS, Google, Slack, Notion, etc.).
    2. Description matches the vendor nature.
    3. Low value (<$50).
    
    OUTPUT JSON ONLY:
    {
        "risk": "LOW" | "HIGH" | "UNCERTAIN",
        "reason": "short explanation"
    }
    """
    
    try:
        completion = groq_client.chat.completions.create(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Vendor: {vendor} | Amount: ${amount} | Desc: {description}"}
            ],
            model="llama-3.3-70b-versatile", # Modelo ultrarrápido y potente (Actualizado 2026)
            temperature=0.0,
            response_format={"type": "json_object"}
        )
        return json.loads(completion.choices[0].message.content)
    except Exception as e:
        logger.warning(f"⚠️ Tier 1 (Groq) Error: {e}")
        return None

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
# CAPA 3: MEMORIA RAG (EXISTENTE)
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
        logger.error(f"❌ RAG Memory Search Failed (RPC Error): {e}")
        if hasattr(e, 'response') and hasattr(e.response, 'text'):
             logger.error(f"   RPC Response Body: {e.response.text}")
        return []

# ==========================================
# CAPA 4: THE ORACLE (MODIFICADA - HIBRIDA)
# ==========================================
async def audit_transaction(vendor, amount, description, agent_id, agent_role, history=[], justification=None, sensitivity="HIGH", osint_report=None, corporate_policies=None, db_client=None, screenshot_base64=None, domain_status=None, trusted_context=None, structured_data=None):
    """
    Versión HÍBRIDA TIERED: Intenta aprobar rápido con Groq, si no, escala a OpenAI.
    Si recibe `structured_data` (ACP Intent), aplica lógica determinista (Nivel 0).
    """
    if not AI_ENABLED:
        return {"decision": "FLAGGED", "reasoning": "AI Offline", "risk_score": 50}

    # ---------------------------------------------------------
    # PASO 0: NIVEL 0 - DETERMINISTA (ACP PROTOCOL) [NUEVO]
    # ---------------------------------------------------------
    if structured_data:
        # El Intent Object viene firmado criptográficamente por el vendedor.
        # No necesitamos "adivinar" con IA si es un fraude. Son datos duros.
        logger.info(f"🛡️ [AI GUARD] Auditando datos estructurados ACP: {structured_data.get('intent_id')}")
        
        items = structured_data.get('items', [])
        total_intent_amount = float(structured_data.get('total_amount', 0))
        
        # 1. Validar coherencia de monto
        if abs(total_intent_amount - amount) > 0.05: # Margen pequeño por redondeo
             return {"decision": "REJECTED", "reasoning": "Amount mismatch between Mandate vs Intent", "risk_score": 100}

        # 2. Validar Categorías Prohibidas (Hardfast Rule)
        forbidden_categories = ["gambling", "adult", "weapons"]
        detected_forbidden = [i['name'] for i in items if i.get('category') in forbidden_categories]
        
        if detected_forbidden:
             return {"decision": "REJECTED", "reasoning": f"ACP Detected Forbidden Categories: {detected_forbidden}", "risk_score": 100}

        # 3. Aprobación Determinista
        # Si el monto es bajo y la categoría es segura (SaaS/Infra), APROBAR.
        safe_categories = ["compute_infrastructure", "saas_subscription", "developer_tools"]
        if all(i.get('category') in safe_categories for i in items) and amount < 500:
             return {
                "decision": "APPROVED",
                "reasoning": "ACP Signed Intent verified. Safe Category.",
                "risk_score": 0,
                "intent_hash": hashlib.sha256(f"{agent_id}:ACP:{amount}".encode()).hexdigest()
             }

        # Si no es trivialmente seguro, dejamos que la IA lo revise abajo (tier 1/2) pero con los datos limpios.
        description = f"[ACP VERIFIED DATA] Items: {json.dumps(items)}"

    # ---------------------------------------------------------
    # PASO 0.5: NIVEL 1 - INFERENCIA RÁPIDA (GROQ)
    # ---------------------------------------------------------
    # Solo intentamos el "Fast Path" si no es un caso crítico (paranoia alta)
    if sensitivity != "CRITICAL":
        tier1_verdict = _tier1_fast_audit(vendor, amount, description)
        
        if tier1_verdict and tier1_verdict.get("risk") == "LOW":
            # ✅ APROBACIÓN RÁPIDA (Speed-run)
            logger.info(f"⚡ [TIER 1] Aprobado por Groq (Llama 3). Ahorrando llamada a GPT-4.")
            
            # Generamos estructura compatible
            forensic_str = f"{agent_id}|{vendor}|{amount}|APPROVED_TIER1"
            return {
                "decision": "APPROVED",
                "reasoning": f"Fast-Track (Groq): {tier1_verdict.get('reason')}",
                "risk_score": 10,
                "mcc_category": "services", # Default seguro
                "intent_hash": hashlib.sha256(forensic_str.encode()).hexdigest(),
                "short_reason": tier1_verdict.get('reason')
            }
        else:
            # Si Groq dice HIGH o UNCERTAIN, o falla -> SEGUIMOS AL NIVEL 2 (No hacemos nada aquí)
            logger.info(f"🤔 [TIER 1] Groq dudó ({tier1_verdict}). Escalando a The Oracle (GPT-4)...")

    # ---------------------------------------------------------
    # PASO 1, 2, 3, 4: LÓGICA EXISTENTE (NIVEL 2 - GPT-4o)
    # ---------------------------------------------------------
    
    # 1. RECUPERAR MEMORIA (RAG)
    memory_txt = "No history."
    past_approvals = 0
    if db_client:
        similar_txs = await search_memory(db_client, description, vendor)
        if similar_txs:
            past_approvals = sum(1 for tx in similar_txs if tx['status'] == 'APPROVED')
            memory_txt = f"FOUND {len(similar_txs)} SIMILAR PAST CASES. Approved: {past_approvals}. Examples: {[t['description'] for t in similar_txs[:2]]}"

    # 2. CALIBRAR PARANOIA
    suspicion_level = "NEUTRAL"
    if past_approvals >= 3:
        suspicion_level = "VERY LOW (TRUSTED PATTERN)"
    elif past_approvals > 0:
        suspicion_level = "LOW (KNOWN PRECEDENT FOUND)"
    elif sensitivity == "CRITICAL":
        suspicion_level = "HIGH (PARANOID MODE)"

    # 3. POLÍTICAS
    policy_txt = "Standard Logic."
    if corporate_policies:
        limits = corporate_policies.get('spending_limits', {})
        policy_txt = f"Max Item: ${limits.get('max_per_item', 'Unlimited')}. Restricted: {corporate_policies.get('restricted_vendors', [])}"

    # 4. PROMPT MAESTRO (GPT-4o)
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
        
        if result['decision'] != 'APPROVED' and past_approvals >= 3:
            result['decision'] = 'APPROVED'
            result['reasoning'] = f"Auto-Approved based on {past_approvals} past precedents (RAG Override)."
            result['risk_score'] = 10

        forensic_str = f"{agent_id}|{vendor}|{amount}|{result['decision']}"
        result['intent_hash'] = hashlib.sha256(forensic_str.encode()).hexdigest()
        result['mcc_category'] = result.get('category_mcc', 'services')
        result['short_reason'] = result['reasoning']
        
        return result

    except Exception as e:
        logger.error(f"Oracle Error: {e}")
        return {"decision": "FLAGGED", "reasoning": "AI Error", "risk_score": 50, "intent_hash": "ERR"}

# ==========================================
# CAPA 5: AUDITORÍA VISUAL (FACTURAS) [NUEVO]
# ==========================================
async def verify_invoice_match(vendor: str, amount: float, file_url: str):
    """
    [VISION] Usa GPT-4o para leer la factura subida y verificar si coincide
    con el gasto registrado. Detecta fraudes en la conciliación.
    """
    if not AI_ENABLED:
        logger.warning("🔒 [AI GUARD] Servicio de IA no disponible. Aplicando protocolo Fail-Closed.")
        return {
            "is_match": False, 
            "confidence": 0, 
            "reason": "AI Service Unavailable - Manual verification required",
            "flagged": True
        }

    system_prompt = """
    You are a Forensic Accountant AI. 
    Your job is to compare a TRANSACTION with an UPLOADED INVOICE IMAGE/PDF.
    
    Check for:
    1. Vendor Name Match (fuzzy match is ok, e.g. "AWS" vs "Amazon Web Services").
    2. Amount Match (allow small variances for currency exchange or tax).
    3. Date consistency (invoice date should be close to now).
    
    Return JSON:
    {
        "is_match": boolean,
        "extracted_vendor": "string",
        "extracted_amount": float,
        "confidence": 0-100,
        "notes": "Short observation"
    }
    """
    
    user_content = [
        {"type": "text", "text": f"TRANSACTION DATA:\nVendor: {vendor}\nAmount: ${amount}\n\nVerify if the attached document matches this transaction."}
    ]
    
    # Si es una imagen/pdf accesible públicamente, se la pasamos a GPT-4o
    # Nota: GPT-4o acepta URLs de imágenes si son públicas.
    if file_url:
        user_content.append({
            "type": "image_url",
            "image_url": {"url": file_url}
        })

    try:
        response = await client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content}
            ],
            response_format={"type": "json_object"},
            temperature=0.0
        )
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        logger.error(f"❌ Invoice Verification Failed: {e}")
        # FAIL-CLOSED: Rechazamos si la IA falla
        return {
            "is_match": False, 
            "confidence": 0, 
            "reason": f"AI Error: {str(e)} - Manual verification required",
            "flagged": True
        }


# ==========================================
# CAPA 6: AUTO-MATCH RECEIPT TO TRANSACTION
# ==========================================
async def match_receipt_to_transaction(email_body: str, agent_id: str, db_client):
    """
    Analiza el cuerpo de un email entrante y busca si coincide con 
    alguna transacción pendiente de ese agente.
    Retorna el ID de la transacción si hay match.
    """
    if not AI_ENABLED:
        return {"match_found": False, "reason": "AI Offline"}
    
    # 1. Buscar transacciones recientes (últimas 24h) con invoice_status PENDING
    try:
        from datetime import datetime, timedelta
        yesterday = (datetime.utcnow() - timedelta(days=1)).isoformat()
        
        pending_txs = db_client.table("transaction_logs").select(
            "id, vendor, amount, description, created_at"
        ).eq("agent_id", agent_id).eq("status", "APPROVED").gte(
            "created_at", yesterday
        ).execute()
        
        if not pending_txs.data:
            logger.info(f"📧 No hay transacciones pendientes para {agent_id}")
            return {"match_found": False, "reason": "No pending transactions"}
        
        # 2. Pedir a la IA que haga el match
        tx_list = "\n".join([
            f"- ID: {tx['id']} | Vendor: {tx['vendor']} | Amount: ${tx['amount']}" 
            for tx in pending_txs.data
        ])
        
        system_prompt = """
        You are a financial reconciliation AI. 
        Given an EMAIL BODY (likely a receipt or invoice) and a LIST of PENDING TRANSACTIONS,
        determine if the email matches any transaction.
        
        Return JSON:
        {
            "match_found": boolean,
            "transaction_id": "UUID or null",
            "confidence": 0-100,
            "extracted_vendor": "string",
            "extracted_amount": float or null,
            "reason": "Short explanation"
        }
        """
        
        user_prompt = f"""
        PENDING TRANSACTIONS FOR AGENT {agent_id}:
        {tx_list}
        
        EMAIL BODY:
        ---
        {email_body[:2000]}
        ---
        
        Does this email match any of the transactions above?
        """
        
        response = await client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            response_format={"type": "json_object"},
            temperature=0.0
        )
        
        result = json.loads(response.choices[0].message.content)
        logger.info(f"🔍 AI Match Result: {result}")
        return result
        
    except Exception as e:
        logger.error(f"❌ Receipt Matching Failed: {e}")
        return {"match_found": False, "reason": str(e)}

