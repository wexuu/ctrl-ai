# ctrl-ai gateway image: the pinned LiteLLM image plus the ctrl_ai package and its config.
# Build from the repository root:  docker build -t ctrl-ai-gateway:dev -f deploy/docker/Dockerfile .
# The pinned image ships without pip, so the package is copied onto PYTHONPATH rather than installed.
FROM ghcr.io/berriai/litellm:v1.103.2@sha256:f63fb81b831b170ec16851e23c36ac5bf52ef106b271406429524a2ed730bbfd

COPY src/ctrl_ai/ /app/ctrl_ai/
COPY deploy/litellm/ /app/gateway/
COPY config/ /app/config/

ENV PYTHONPATH=/app \
    CTRL_AI_POLICY_FILE=/app/config/policy.yaml \
    CTRL_AI_MODELS_FILE=/app/config/models.yaml \
    CTRL_AI_TEAMS_FILE=/app/config/teams.yaml \
    CTRL_AI_SIGNATURES_FILE=/app/config/signatures.yaml \
    CTRL_AI_MCP_FILE=/app/config/mcp.yaml \
    CTRL_AI_KEYS_FILE=/app/state/keys.json \
    CTRL_AI_BREAKGLASS_FILE=/app/state/break_glass.json \
    CTRL_AI_AUDIT_LOG=/dev/stdout \
    LITELLM_LOCAL_MODEL_COST_MAP=True

# Non-root. The audit log goes to stdout in a cluster; /app/logs and /app/state are volumes.
RUN mkdir -p /app/logs /app/state && chown -R 10001:10001 /app/logs /app/state
USER 10001:10001

EXPOSE 4000
# Never /health: it makes a real model call for every configured model.
HEALTHCHECK --interval=10s --timeout=3s --retries=6 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:4000/health/liveliness', timeout=2)"]
CMD ["--config", "/app/gateway/config.yaml", "--port", "4000"]
