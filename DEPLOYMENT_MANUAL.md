# AgentPay Production Deployment Guide (2026 Observability)

## 1. Environment Configuration (Render Dashboard)
To enable the Banking-Grade Observability stack with Better Stack (Logs) and Grafana Cloud (Traces), configure the following Environment Variables in Render.

| Variable | Value Example | Description |
|----------|---------------|-------------|
| `OTLP_ENDPOINT` | `https://otlp-gateway-prod-eu-central-0.grafana.net/v1/traces` | **HTTP**: Full URL ending in `/v1/traces`. |
| `GRAFANA_API_TOKEN` | `glc_eyJ...`| Your Grafana Cloud Access Policy Token. |
| `OTEL_SERVICE_NAME` | `AgentPay-Core` | Service Identifier for traces in Tempo. |
| `LOGURU_SERIALIZE` | `TRUE` | Forces JSON logging output (Legacy, now handled by Logtail). |
| `ENVIRONMENT` | `production` | Tag to filter production traces. |
| `SENTRY_DSN` | `https://x@y.ingest.sentry.io/z` | Error Tracking. |

## 2. Grafana Cloud Integration (Traces)
We are using the **HTTP/Proto** export protocol.

### Setup Steps
1. Log in to your Grafana Cloud account.
2. Go to **"OpenTelemetry"** or **"Integrations"**.
3. Look for the **OTLP/HTTP** endpoint URL.
4. It MUST end in `/v1/traces`. Example: `https://otlp-gateway-prod-eu-central-0.grafana.net/v1/traces`.
5. Set this URL as `OTLP_ENDPOINT` in Render.

## 3. Vertification
Once deployed:
1. **Logs (Better Stack)**: Check Better Stack Live Tail.
2. **Traces (Tempo)**: Go to "Explore" > "Tempo". Filter by Service Name `AgentPay-Core`.
