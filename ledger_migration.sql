-- 1. Cuentas Contables (El "Mapa" de donde está el dinero)
CREATE TABLE IF NOT EXISTS accounts (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    name TEXT NOT NULL, -- Ej: 'Wallet: Juan', 'Revenue: Fees', 'Liability: User Deposits'
    type TEXT NOT NULL, -- 'ASSET', 'LIABILITY', 'EQUITY', 'REVENUE', 'EXPENSE'
    balance NUMERIC(20, 4) DEFAULT 0.00,
    agent_id TEXT UNIQUE -- Vinculo directo 1:1 con wallets para simplificar
);

-- 2. Asientos Contables (El Movimiento Atómico)
CREATE TABLE IF NOT EXISTS ledger_entries (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    transaction_id TEXT NOT NULL, -- Vincula con tu transaction_logs
    account_id UUID REFERENCES accounts(id),
    direction TEXT CHECK (direction IN ('DEBIT', 'CREDIT')),
    amount NUMERIC(20, 4) NOT NULL CHECK (amount > 0),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now())
);

-- 3. Índices para velocidad
CREATE INDEX IF NOT EXISTS idx_ledger_tx ON ledger_entries(transaction_id);
CREATE INDEX IF NOT EXISTS idx_accounts_agent ON accounts(agent_id);
