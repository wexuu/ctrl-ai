# Observability: OpenTelemetry for operations, the audit log for security

## Why OpenTelemetry

OpenTelemetry (OTel) is the vendor-neutral standard for traces, metrics and logs. An organisation usually runs a monitoring stack already (Splunk, Datadog, Grafana, Elastic, Dynatrace); all of them ingest OTLP, the OTel wire protocol. If the gateway speaks OTLP, its telemetry lands in the organisation's existing dashboards and alerting without custom integration work, and the organisation can change monitoring vendors without touching the gateway.

## Pipeline

```
 gateway (LiteLLM "otel" callback)
   │  OTLP/HTTP  http://otel-collector:4318/v1/traces
   ▼
 otel-collector (otel/opentelemetry-collector-contrib:0.137.0, deploy/otel/collector.yaml)
   │  processors: attributes/redact → transform/redact → batch
   │  connector:  spanmetrics (calls and duration histograms per span name, model, ct.* attributes)
   ├──► debug exporter (sampled; for local checks)          ── in production: Splunk / Datadog / Tempo / Elastic exporter
   └──► prometheus exporter :8889
          ▼
        prometheus (prom/prometheus:v3.6.0, deploy/otel/prometheus.yml), scrapes otel-collector:8889
          ▼
        ui Operations tab (CTRL_AI_PROMETHEUS_URL=http://prometheus:9090): per-span p95
```

Both services are defined in `deploy/docker/compose.yml`, on the internal network only (no published ports).

## Gateway settings

`deploy/litellm/config.yaml`:

- `litellm_settings.callbacks` gets `"otel"` appended.
- `litellm_settings.turn_off_message_logging: true`: LiteLLM never puts prompts or responses into spans or callback logs.

Environment variables the gateway needs (found in LiteLLM v1.103.2's `litellm/integrations/opentelemetry.py`):

| Variable | Value | Why |
|---|---|---|
| `OTEL_EXPORTER` | `otlp_http` | Exporter type (`console` by default, which prints spans to stdout). `OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf` also works |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://otel-collector:4318` | Collector; LiteLLM appends `/v1/traces` |
| `OTEL_SERVICE_NAME` | `ctrl-ai-gateway` | Set in `compose.yml` |
| `OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT` | `false` | Explicit "no message content" for the GenAI instrumentation, on top of `turn_off_message_logging` |
| `OTEL_EXPORTER_OTLP_HEADERS` | (empty) | Only for a SaaS backend that needs an API key header |

The `ui` service needs `CTRL_AI_PROMETHEUS_URL=http://prometheus:9090` for the per-span figures; without it the Operations tab shows audit-derived figures only and says so.

## Redaction rules (in the collector, defence in depth)

1. `attributes/redact` deletes the well-known content keys: `gen_ai.prompt`, `gen_ai.completion`, `gen_ai.input.messages`, `gen_ai.output.messages`, `gen_ai.system_instructions`, `input.value`, `output.value`, `llm.input_messages`, `llm.output_messages`, client headers (`metadata.requester_custom_headers`, `metadata.requester_metadata`: they can carry gateway keys or break-glass tokens) and key material; it **hashes** user identifiers (`user`, `enduser.id`, `gen_ai.request.user`, `metadata.user_api_key_user_id`) and the client IP.
2. `transform/redact` deletes by pattern: indexed variants (`gen_ai.prompt.0.content`, `llm.input_messages.1.…`), anything whose key contains `content`, `messages`, `prompt`, `completion_text`, `response_text`, `raw_request`, `raw_response`, and anything that looks like a credential (`api_key`, `authorization`, `token`, `secret`). All span-event attributes are dropped.

To check the redaction: send a request with a unique marker string and search the collector's debug output (`docker compose logs otel-collector`) for it; it must not appear. Prometheus exposes `traces_span_metrics_calls_total` and `traces_span_metrics_duration_milliseconds_bucket` for LiteLLM's spans (`Received Proxy Server Request`, `auth`, `proxy_pre_call`, `guardrail`, `router`, `litellm_request`, `self`). The end-to-end suite checks the audit log for prompt text and keys (`tests/e2e/test_zz_no_secrets.py`), not the collector output.

## GenAI semantic conventions

LiteLLM emits the OpenTelemetry GenAI attributes, for example `gen_ai.system`, `gen_ai.request.model`, `gen_ai.response.model`, `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`, `gen_ai.cost.*`; the metric `gen_ai.client.operation.duration` is defined by the same conventions. These conventions are still marked "development" upstream, so names may change; the collector is the place to rename them if the organisation's backend expects other names.

## Audit log and OpenTelemetry: two records, two jobs

| | Audit log (`logs/audit.jsonl`) | OpenTelemetry |
|---|---|---|
| Purpose | Security and compliance record: who sent what kind of data to which model, what was decided and why | Operations: latency, errors, throughput, saturation |
| Content | One row per decision and per usage, fixed fields, versioned schema (v2), never text | Spans and metrics, sampled, content stripped |
| Consumers | Dashboard (Management, Security), auditor export, SIEM | The organisation's monitoring (dashboards, SLOs, on-call alerts) |
| Retention | Long (regulatory) | Short (operational) |

The dashboard's Operations tab uses both: audit-derived p50/p95 and error rates always, and OTel per-span p95 from Prometheus when available.

## Per-stage spans (not implemented)

The per-span view shows LiteLLM's own spans (`guardrail` covers all of ctrl-ai's checks). Custom spans for each guardrail stage would give a per-stage p95 and let the organisation alert on, for example, Jev latency:

- span names: `ct.rules`, `ct.jev`, `ct.judge`, `ct.masking`, `ct.identity`, `ct.budget`;
- attributes: `ct.decision`, `ct.rule`, `ct.team`, `ct.profile`, `ct.jev.score`, `ct.jev.status`, `ct.route_reason` (never text, never a key).

The collector's `spanmetrics` connector already lists `ct.decision`, `ct.rule`, `ct.team`, `ct.profile` as dimensions, so these become Prometheus labels without further changes.
