# AgentPay Production Deployment Guide (Grafana Cloud HTTP Edition - 2026)

## 1. Environment Configuration (Render Dashboard)
To enable the Banking-Grade Observability stack with Grafana Cloud via HTTP (Robust), you must configure the following Environment Variables in the Render Dashboard. DO NOT commit these to the repository.

| Variable | Value Example | Description |
|----------|---------------|-------------|
| `OTLP_ENDPOINT` | `https://otlp-gateway-prod-eu-central-0.grafana.net/otlp/v1/traces` | **CRITICAL**: Must match your region and end with `/v1/traces` for HTTP export. |
| `OTLP_HEADERS` | `Authorization=Basic YV...=` | Basic Auth Header (Instance ID + Token). Generated in Grafana Cloud Portal. |
| `OTEL_SERVICE_NAME` | `AgentPay-Core` | Service Identifier for traces in Tempo. |
| `LOGURU_SERIALIZE` | `TRUE` | Forces JSON logging output for Loki ingestion. |
| `ENVIRONMENT` | `production` | Tag to filter production traces. |
| `SENTRY_DSN` | `https://x@y.ingest.sentry.io/z` | Existing usage for Error Tracking. |

## 2. Grafana Cloud Integration
We are using the **HTTP (Protobuf)** export protocol, which is more reliable than gRPC in restrictive network environments (like some shared cloud containers).

### Setup Steps
1. Log in to your Grafana Cloud account.
2. Go to **"OpenTelemetry"** or **"Integrations"**.
3. Look for the **HTTP** endpoint URL (it usually ends in `/otlp` or similar).
   - **IMPORTANT**: Append `/v1/traces` to the base URL if using the HTTP exporter directly.
   - Example Base: `https://otlp-gateway-prod-eu-central-0.grafana.net/otlp`
   - Example Target: `https://otlp-gateway-prod-eu-central-0.grafana.net/otlp/v1/traces`
4. Generate an **Access Policy Token**.
5. Construct your `OTLP_HEADERS` value: `Authorization=Basic <base64_instance_id:token>`.

## 3. Verification
Once deployed and Env Vars updated:
1. **Logs (Loki)**: Go to "Explore" > "Loki" in Grafana. Query `{app="AgentPay-Core"}`. You should see JSON logs.
2. **Traces (Tempo)**: Go to "Explore" > "Tempo". Filter by Service Name `AgentPay-Core`.
3. **Correlation**: Find a log entry with `trace_id`. Copy it and query it in Tempo to see the full "Waterfall" view of the transaction, split by "AI Guard" and "Stripe".
