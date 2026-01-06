-- MIGRACIÓN: Unificación de Auditoría
-- Ejecutar en Supabase SQL Editor
-- HACER BACKUP ANTES DE EJECUTAR LOS DROP

-- ============================================
-- PASO 1: CREAR TABLA UNIFICADA
-- ============================================
CREATE TABLE IF NOT EXISTS public.unified_audit_logs (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    created_at timestamp with time zone DEFAULT now(),
    
    -- QUIÉN
    agent_id text,
    ip_address text,
    
    -- QUÉ (Clasificación)
    event_source text NOT NULL, -- 'SESSION', 'CREDIT', 'AML', 'MCP', 'ENGINE'
    event_type text NOT NULL,   -- 'LOGIN', 'LOAN_REQUEST', 'TOOL_USE'
    severity text DEFAULT 'INFO' CHECK (severity IN ('INFO', 'WARN', 'ERROR', 'CRITICAL', 'FATAL')),
    
    -- DÓNDE
    resource_id text,
    
    -- DETALLES
    details jsonb DEFAULT '{}'::jsonb,
    
    -- SEGURIDAD (Anti-tampering)
    hash_signature text,
    
    CONSTRAINT unified_audit_logs_pkey PRIMARY KEY (id)
);

-- Índices para búsquedas rápidas de auditores
CREATE INDEX IF NOT EXISTS idx_audit_agent_time ON public.unified_audit_logs(agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_source ON public.unified_audit_logs(event_source);
CREATE INDEX IF NOT EXISTS idx_audit_severity ON public.unified_audit_logs(severity);

-- ============================================
-- PASO 2: MIGRAR DATOS EXISTENTES
-- ============================================

-- Migrar audit_sessions → unified_audit_logs
INSERT INTO public.unified_audit_logs (agent_id, event_source, event_type, severity, resource_id, ip_address, created_at, details)
SELECT 
    agent_id, 
    'SESSION', 
    action, 
    'INFO', 
    resource_id, 
    ip_address, 
    timestamp, 
    jsonb_build_object('origin', 'legacy_migration')
FROM public.audit_sessions
ON CONFLICT DO NOTHING;

-- Migrar audit_trail → unified_audit_logs
INSERT INTO public.unified_audit_logs (agent_id, event_source, event_type, severity, details, hash_signature, created_at)
SELECT 
    agent_id, 
    'GENERAL', 
    event_type, 
    'INFO', 
    snapshot_data, 
    integrity_hash, 
    created_at
FROM public.audit_trail
ON CONFLICT DO NOTHING;

-- Migrar compliance_alerts → unified_audit_logs (AML)
INSERT INTO public.unified_audit_logs (agent_id, event_source, event_type, severity, details, created_at)
SELECT 
    agent_id, 
    'AML', 
    type, 
    COALESCE(severity, 'WARN'),
    COALESCE(metadata, '{}'::jsonb) || jsonb_build_object('description', description),
    created_at
FROM public.compliance_alerts
ON CONFLICT DO NOTHING;

-- Migrar mcp_audit_log → unified_audit_logs
INSERT INTO public.unified_audit_logs (agent_id, event_source, event_type, severity, details, created_at)
SELECT 
    agent_id, 
    'MCP', 
    tool_name, 
    CASE WHEN result_status = 'ERROR' THEN 'ERROR' ELSE 'INFO' END,
    COALESCE(parameters, '{}'::jsonb) || jsonb_build_object('status', result_status),
    timestamp
FROM public.mcp_audit_log
ON CONFLICT DO NOTHING;

-- ============================================
-- PASO 3: ELIMINAR TABLAS OBSOLETAS
-- ⚠️ SOLO EJECUTAR DESPUÉS DE VERIFICAR MIGRACIÓN
-- ============================================
-- DROP TABLE IF EXISTS public.audit_sessions;
-- DROP TABLE IF EXISTS public.audit_trail;
-- DROP TABLE IF EXISTS public.compliance_alerts;
-- DROP TABLE IF EXISTS public.mcp_audit_log;
