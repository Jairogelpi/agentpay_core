# AgentPay Production Deployment Guide (Grafana Cloud gRPC Edition - 2026)

## 1. Environment Configuration (Render Dashboard)
To enable the Banking-Grade Observability stack with Grafana Cloud via **gRPC** (Recommended for `glc_` tokens), you must configure the following Environment Variables in the Render Dashboard. DO NOT commit these to the repository.

| Variable | Value Example | Description |
|----------|---------------|-------------|
| `OTLP_ENDPOINT` | `otlp-gateway-prod-eu-central-0.grafana.net:443` | **CRITICAL**: Use the host:port format without `https://`. Port is usually 443. |
| `GRAFANA_API_TOKEN` | `glc_eyJ...`| Your Grafana Cloud Access Policy Token. |
| `OTEL_SERVICE_NAME` | `AgentPay-Core` | Service Identifier for traces in Tempo. |
| `LOGURU_SERIALIZE` | `TRUE` | Forces JSON logging output for Loki ingestion. |
| `ENVIRONMENT` | `production` | Tag to filter production traces. |
| `SENTRY_DSN` | `https://x@y.ingest.sentry.io/z` | Existing usage for Error Tracking. |

## 2. Grafana Cloud Integration
We are now using the **gRPC** export protocol, which is the native and most efficient way to send traces to Grafana Cloud.

### Setup Steps
1. Log in to your Grafana Cloud account.
2. Go to **"OpenTelemetry"** or **"Integrations"**.
3. Look for the **OTLP/gRPC** endpoint URL.
   - Example Target: `otlp-gateway-prod-eu-central-0.grafana.net:443`
4. Generate an **Access Policy Token**.
5. Set `GRAFANA_API_TOKEN` in Render. The code will automatically handle the `Authorization: Bearer ...` header.

## 3. Verification
Once deployed:
1. **Logs (Better Stack)**: Check Better Stack Live Tail (as we switched logs there).
2. **Traces (Tempo)**: Go to "Explore" > "Tempo". Filter by Service Name `AgentPay-Core`.
3. **Correlation**: Find a log entry with `trace_id`. Copy it and query it in Tempo.
