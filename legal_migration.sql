-- Si la tabla no existe
CREATE TABLE IF NOT EXISTS liability_certificates (
    certificate_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    platform_url TEXT,
    signature TEXT NOT NULL,
    forensic_hash TEXT NOT NULL, -- Hash del texto legal
    contract_version TEXT,       -- Ej: "2026-01-06_v1.0"
    status TEXT DEFAULT 'ACTIVE_BINDING',
    identity_email TEXT,
    issued_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Si ya existe, añade la columna de versión
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='liability_certificates' AND column_name='contract_version') THEN
        ALTER TABLE liability_certificates ADD COLUMN contract_version TEXT;
    END IF;
END $$;
