# AgentPay Production Deployment Guide (Simplified OTLP/HTTP - 2026)

## 1. Environment Configuration (Render Dashboard)
We have simplified the Observability configuration to rely on standard OpenTelemetry environment variables.

### Required Environment Variables

| Variable | Value (Example) | Description |
|----------|---------------|-------------|
| `OTLP_ENDPOINT` | `https://otlp-gateway-prod-eu-central-0.grafana.net/otlp` | **HTTP**: The base OTLP/HTTP endpoint. |
| `OTLP_HEADERS` | `Authorization=Basic YTE...` | **CRITICAL**: The full Authorization header key-value pair. |
| `OTEL_SERVICE_NAME` | `AgentPay-Core` | Service Identifier in Tempo. |
| `ENVIRONMENT` | `production` | Tag to filter production traces. |

### How to get `OTLP_HEADERS`
1. Go to **Grafana Cloud** > **OpenTelemetry**.
2. Find the section for **Environment Variables**.
3. Copy the value for `OTEL_EXPORTER_OTLP_HEADERS` (it will look like `Authorization=Basic ...`).
4. Paste this entire string as the value for `OTLP_HEADERS` in Render.

## 2. Verification
Once user credentials are set:
1. **Logs (Better Stack)**: Check Better Stack Live Tail.
2. **Traces (Tempo)**: Search for service `AgentPay-Core` in Tempo Explore.
