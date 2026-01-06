-- 1. Añadir columnas de conciliación a la tabla principal
ALTER TABLE transaction_logs 
ADD COLUMN vendor_invoice_url text,
ADD COLUMN reconciliation_status text DEFAULT 'PENDING_INVOICE', -- PENDING_INVOICE, RECONCILED, FLAGGED
ADD COLUMN reconciliation_notes text;

-- 2. Crear Bucket de Storage (si no existe)
-- Note: 'storage.buckets' usually requires specific privileges.
-- Ensuring extension is enabled (usually default in Supabase)

INSERT INTO storage.buckets (id, name, public) 
VALUES ('vendor-invoices', 'vendor-invoices', true)
ON CONFLICT (id) DO NOTHING;

-- 3. Política de seguridad (Permitir subidas autenticadas)
-- Dropping policy if exists to avoid conflict during re-run or just creating it.
-- Safer to just run creation and let it fail if exists or use DO block.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename = 'objects' AND policyname = 'Allow Agents to Upload Invoices'
    ) THEN
        CREATE POLICY "Allow Agents to Upload Invoices" ON storage.objects 
        FOR INSERT WITH CHECK ( bucket_id = 'vendor-invoices' );
    END IF;
END
$$;
