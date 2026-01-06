-- MIGRACIÓN DE SEGURIDAD Y INTEGRIDAD CONTABLE
-- Ejecutar en Supabase SQL Editor

-- ============================================
-- 1. ELIMINAR SECRETO HARDCODEADO
-- ============================================
-- El DEFAULT con webhook real es una fuga de seguridad
ALTER TABLE public.wallets 
ALTER COLUMN slack_webhook_url SET DEFAULT NULL;

-- ============================================
-- 2. STORED PROCEDURES REQUERIDOS
-- ============================================

-- RPC: deduct_balance (Descuento atómico de saldo)
CREATE OR REPLACE FUNCTION deduct_balance(p_agent_id TEXT, p_amount NUMERIC)
RETURNS BOOLEAN AS $$
DECLARE
    current_balance NUMERIC;
BEGIN
    -- Lock row for update
    SELECT balance INTO current_balance 
    FROM wallets 
    WHERE agent_id = p_agent_id 
    FOR UPDATE;
    
    IF current_balance IS NULL THEN
        RETURN FALSE;
    END IF;
    
    IF current_balance < p_amount THEN
        RETURN FALSE;
    END IF;
    
    UPDATE wallets 
    SET balance = balance - p_amount,
        daily_spent = daily_spent + p_amount
    WHERE agent_id = p_agent_id;
    
    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;

-- RPC: secure_deduct_balance (Con validación de límites)
CREATE OR REPLACE FUNCTION secure_deduct_balance(
    p_agent_id TEXT, 
    p_amount NUMERIC,
    p_max_transaction NUMERIC DEFAULT 50.0
)
RETURNS JSONB AS $$
DECLARE
    wallet_data RECORD;
    result JSONB;
BEGIN
    SELECT balance, max_transaction_limit, daily_limit, daily_spent 
    INTO wallet_data
    FROM wallets 
    WHERE agent_id = p_agent_id 
    FOR UPDATE;
    
    IF wallet_data IS NULL THEN
        RETURN jsonb_build_object('success', false, 'error', 'WALLET_NOT_FOUND');
    END IF;
    
    IF p_amount > wallet_data.max_transaction_limit THEN
        RETURN jsonb_build_object('success', false, 'error', 'EXCEEDS_TRANSACTION_LIMIT');
    END IF;
    
    IF (wallet_data.daily_spent + p_amount) > wallet_data.daily_limit THEN
        RETURN jsonb_build_object('success', false, 'error', 'EXCEEDS_DAILY_LIMIT');
    END IF;
    
    IF wallet_data.balance < p_amount THEN
        RETURN jsonb_build_object('success', false, 'error', 'INSUFFICIENT_FUNDS');
    END IF;
    
    UPDATE wallets 
    SET balance = balance - p_amount,
        daily_spent = daily_spent + p_amount
    WHERE agent_id = p_agent_id;
    
    RETURN jsonb_build_object(
        'success', true, 
        'new_balance', wallet_data.balance - p_amount,
        'daily_remaining', wallet_data.daily_limit - wallet_data.daily_spent - p_amount
    );
END;
$$ LANGUAGE plpgsql;

-- RPC: p2p_transfer (Transferencia atómica entre agentes)
CREATE OR REPLACE FUNCTION p2p_transfer(
    p_from_agent TEXT,
    p_to_agent TEXT,
    p_amount NUMERIC
)
RETURNS JSONB AS $$
DECLARE
    from_balance NUMERIC;
    to_exists BOOLEAN;
BEGIN
    -- Lock sender
    SELECT balance INTO from_balance 
    FROM wallets 
    WHERE agent_id = p_from_agent 
    FOR UPDATE;
    
    IF from_balance IS NULL THEN
        RETURN jsonb_build_object('success', false, 'error', 'SENDER_NOT_FOUND');
    END IF;
    
    IF from_balance < p_amount THEN
        RETURN jsonb_build_object('success', false, 'error', 'INSUFFICIENT_FUNDS');
    END IF;
    
    -- Check receiver exists
    SELECT EXISTS(SELECT 1 FROM wallets WHERE agent_id = p_to_agent) INTO to_exists;
    
    IF NOT to_exists THEN
        RETURN jsonb_build_object('success', false, 'error', 'RECEIVER_NOT_FOUND');
    END IF;
    
    -- Atomic transfer
    UPDATE wallets SET balance = balance - p_amount WHERE agent_id = p_from_agent;
    UPDATE wallets SET balance = balance + p_amount WHERE agent_id = p_to_agent;
    
    RETURN jsonb_build_object(
        'success', true,
        'from_new_balance', from_balance - p_amount
    );
END;
$$ LANGUAGE plpgsql;

-- RPC: refund_with_ledger (Reembolso con partida doble)
CREATE OR REPLACE FUNCTION refund_with_ledger(
    p_agent_id TEXT,
    p_amount NUMERIC,
    p_transaction_id TEXT,
    p_reason TEXT DEFAULT 'Refund'
)
RETURNS JSONB AS $$
DECLARE
    agent_account_id UUID;
    platform_account_id UUID;
BEGIN
    -- 1. Devolver saldo al agente
    UPDATE wallets 
    SET balance = balance + p_amount 
    WHERE agent_id = p_agent_id;
    
    -- 2. Obtener cuentas para partida doble
    SELECT id INTO agent_account_id 
    FROM accounts 
    WHERE agent_id = p_agent_id AND type = 'ASSET' 
    LIMIT 1;
    
    SELECT id INTO platform_account_id 
    FROM accounts 
    WHERE name = 'Platform Revenue' AND type = 'LIABILITY'
    LIMIT 1;
    
    -- 3. Registrar en ledger (Partida Doble)
    IF agent_account_id IS NOT NULL AND platform_account_id IS NOT NULL THEN
        -- CRÉDITO a la cuenta del agente (le devolvemos dinero)
        INSERT INTO ledger_entries (transaction_id, account_id, direction, amount)
        VALUES (p_transaction_id, agent_account_id, 'CREDIT', p_amount);
        
        -- DÉBITO a la cuenta de la plataforma (nos lo restamos)
        INSERT INTO ledger_entries (transaction_id, account_id, direction, amount)
        VALUES (p_transaction_id, platform_account_id, 'DEBIT', p_amount);
    END IF;
    
    -- 4. Actualizar transaction_logs
    UPDATE transaction_logs 
    SET status = 'REFUNDED', 
        reason = p_reason
    WHERE id::text = p_transaction_id;
    
    RETURN jsonb_build_object('success', true, 'refunded_amount', p_amount);
END;
$$ LANGUAGE plpgsql;

-- ============================================
-- 3. CREAR CUENTA DE PLATAFORMA SI NO EXISTE
-- ============================================
INSERT INTO public.accounts (name, type, balance, agent_id)
SELECT 'Platform Revenue', 'LIABILITY', 0.00, NULL
WHERE NOT EXISTS (
    SELECT 1 FROM public.accounts WHERE name = 'Platform Revenue'
);
