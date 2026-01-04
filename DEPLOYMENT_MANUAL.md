# AgentPay Production Deployment Guide (Grafana Cloud Edition - 2026)

## 1. Environment Configuration (Render Dashboard)
To enable the Banking-Grade Observability stack with Grafana Cloud, you must configure the following Environment Variables in the Render Dashboard. DO NOT commit these to the repository.

| Variable | Value Example | Description |
|----------|---------------|-------------|
| `OTLP_ENDPOINT` | `https://otlp-gateway-prod-us-east-0.grafana.net/otlp` | Your Grafana Cloud OTLP HTTP/gRPC Endpoint. |
| `OTLP_HEADERS` | `Authorization=Basic YV...=` | Basic Auth Header (Instance ID + Token). Generated in Grafana Cloud Portal. |
| `OTEL_SERVICE_NAME` | `AgentPay-Core` | Service Identifier for traces in Tempo. |
| `LOGURU_SERIALIZE` | `TRUE` | Forces JSON logging output for Loki ingestion. |
| `ENVIRONMENT` | `production` | Tag to filter production traces. |
| `SENTRY_DSN` | `https://x@y.ingest.sentry.io/z` | Existing usage for Error Tracking. |

## 2. Grafana Cloud Integration
We are skipping the sidecar collector in favor of direct robust export to Grafana Cloud, as supported by the `opentelemetry-exporter-otlp` library.

### Setup Steps
1. Log in to your Grafana Cloud account.
2. Go to **"OpenTelemetry"** or **"Integrations"**.
3. Copy the **OTLP gRPC Endpoint**. Set this as `OTLP_ENDPOINT`.
4. Generate an **Access Policy Token**.
5. Construct your `OTLP_HEADERS` value. It is usually `Authorization=Basic <base64_instance_id:token>`. Grafana usually provides the full header string to copy.

## 3. Verification
Once deployed:
1. **Logs (Loki)**: Go to "Explore" > "Loki" in Grafana. Query `{app="AgentPay-Core"}`. You should see JSON logs.
2. **Traces (Tempo)**: Go to "Explore" > "Tempo". Filter by Service Name `AgentPay-Core`.
3. **Correlation**: Find a log entry with `trace_id`. Copy it and query it in Tempo to see the full "Waterfall" view of the transaction, split by "AI Guard" and "Stripe".
