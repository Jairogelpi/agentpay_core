-- Add client_ip to liability_certificates for forensic location tracking
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='liability_certificates' AND column_name='client_ip') THEN
        ALTER TABLE liability_certificates ADD COLUMN client_ip TEXT DEFAULT '0.0.0.0';
    END IF;
END $$;
