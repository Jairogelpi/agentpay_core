-- Tabla para credenciales y cookies de sesión (Para el Hunter Agent)
CREATE TABLE IF NOT EXISTS public.vendor_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id TEXT NOT NULL,
    domain TEXT NOT NULL, -- ej: "amazon" (clave de búsqueda)
    username TEXT NOT NULL,
    encrypted_password TEXT NOT NULL,
    login_url TEXT,
    session_cookies JSONB, -- Cookies de sesión (Playwright/Browser-use)
    last_login_success TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CONSTRAINT vendor_credentials_agent_domain_key UNIQUE (agent_id, domain)
);

-- Cola de revisión manual para cuando el Hunter Agent falla
CREATE TABLE IF NOT EXISTS public.manual_review_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transaction_id TEXT,
    agent_id TEXT,
    vendor TEXT,
    error_log TEXT,
    screenshot_url TEXT,
    status TEXT DEFAULT 'OPEN', -- 'OPEN', 'RESOLVED'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Actualizar transaction_logs para seguimiento de facturas
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='transaction_logs' AND column_name='invoice_status') THEN
        ALTER TABLE transaction_logs ADD COLUMN invoice_status TEXT DEFAULT 'PENDING_HUNT'; -- 'PENDING_HUNT', 'FOUND_EMAIL', 'FOUND_BROWSER', 'FAILED'
    END IF;
END $$;
