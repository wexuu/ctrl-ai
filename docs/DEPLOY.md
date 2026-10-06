# Deploying ctrl-ai: laptop, team, enterprise

ctrl-ai is a few stateless services around one pinned image (`ghcr.io/berriai/litellm:v1.103.2`):

| Service | What it does | State |
|---|---|---|
| `gateway` | LiteLLM proxy + ctrl-ai guardrail, logger and MCP guard | none (config files read-only, keys and break-glass register read-only, counters in Redis) |
| `ui` | Staging chat, admin panel, dashboard | writes config history, keys file, admin log |
| `redis` | Shared counters (loops, budgets) for all gateway replicas | ephemeral |
| `otel-collector`, `prometheus` | OpenTelemetry pipeline (docs/OBSERVABILITY.md) | metrics only |
| `mcp-stub` | Fake Jira/wiki MCP server for tests | none |
| `gateway-lane` | Degraded lane, started only on demand | none |

## 1. Laptop: Docker Compose

```
cp .env.example .env       # set LITELLM_MASTER_KEY, JEV_API_KEY, GROQ_API_KEY
make setup && make up      # gateway :4000, ui :4100 (localhost only)
make smoke
```

`deploy/docker/compose.yml` defines the gateway, the admin panel, Redis, the OpenTelemetry collector, Prometheus, the MCP stubs and the degraded lane (profile `lane`); `deploy/docker/compose.test.yml` adds the keyless stubs for the test stack.

## 2. Team: Kubernetes (Kustomize)

```
deploy/docker/Dockerfile          gateway image: pinned LiteLLM (by digest) + src/ctrl_ai/, deploy/litellm/, config/; non-root (uid 10001); HEALTHCHECK on /health/liveliness
deploy/docker/Dockerfile.admin    admin panel image
deploy/k8s/base/           gateway (Deployment, Service, HPA, PDB), ui, otel-collector, NetworkPolicies, state PVC, ConfigMaps
deploy/k8s/overlays/local  kind/minikube: 1 replica, NodePort 30400 (gateway) / 30410 (ui), Redis in the cluster, secrets from a git-ignored secrets.env
deploy/k8s/overlays/aws    EKS: ECR images, internal ALB with TLS (ACM), IRSA, External Secrets (AWS Secrets Manager), ElastiCache, EFS
```

```
docker build -t ctrl-ai-gateway:dev -f deploy/docker/Dockerfile .
docker build -t ctrl-ai-ui:dev -f deploy/docker/Dockerfile.admin .
make k8s-render OVERLAY=local | kubectl apply -f -     # on a kind or minikube cluster
make k8s-validate                                      # renders both overlays and checks every object, no cluster needed
```

Design points:

- **Gateway Deployment**: 3 replicas spread across zones (`topologySpreadConstraints`), readiness `/health/readiness`, liveness `/health/liveliness` (never `/health`, which calls every model), requests 500m CPU / 768Mi, limits 2 CPU / 1.5Gi, non-root, read-only root filesystem with an `emptyDir` for `/tmp`, all capabilities dropped. HPA on 70 % CPU (3 to 12), PodDisruptionBudget `minAvailable: 2`.
- **Configuration**: `configMapGenerator` builds ConfigMaps from `config/*.yaml` and `deploy/litellm/config.yaml`, so a change gets a new hash name and rolls out. Inside a running pod the gateway's live reload also works with ConfigMap volume updates: kubelet swaps a symlink atomically and the stores' `os.stat()` follows it, so `(mtime, size)` changes. In the cluster, configuration is GitOps-managed: the admin panel shows and validates it; the change itself is a pull request (the panel's history and diff are the review material). On a single host, the panel saves directly.
- **Secrets** are referenced, never included: the local overlay generates `ctrl-ai-secrets` from `secrets.env` (git-ignored, created from `secrets.env.example`); the AWS overlay uses an `ExternalSecret` (External Secrets Operator) reading `ctrl-ai/gateway` from AWS Secrets Manager.
- **NetworkPolicy**: default deny; gateway ingress only from namespaces labelled `ai-gateway-client=true` and from the UI; egress only to DNS, Redis, the collector, MCP servers and HTTPS. Narrowing HTTPS to the provider and Jev hostnames (`api.anthropic.com`, `api.groq.com`, `api.mistral.ai`, `api.typesafe.ai`) needs a CNI with FQDN policies, such as Cilium (`toFQDNs`).
- **Logs**: in Kubernetes the audit log is JSON on stdout (`CTRL_AI_AUDIT_LOG=/dev/stdout`) and the cluster's log agent ships it to the log store / SIEM. The dashboard then reads from the log store instead of a file: future work (an `analytics` reader for OpenSearch or CloudWatch Logs Insights).
- **State**: `ctrl-ai-state` (ReadWriteMany: EFS on AWS) holds `keys.json` (hashes only) and `break_glass.json`; the gateway mounts it read-only.

Validation run on this machine (no cluster; minikube was not started):

```
$ make k8s-validate
local: 21 objects rendered
  ConfigMap, Deployment, HorizontalPodAutoscaler, Namespace, NetworkPolicy, PersistentVolumeClaim, PodDisruptionBudget, Secret, Service
aws: 20 objects rendered
  ConfigMap, Deployment, ExternalSecret, HorizontalPodAutoscaler, Ingress, Namespace, NetworkPolicy, PersistentVolumeClaim, PodDisruptionBudget, Service, ServiceAccount
```

`kubectl apply --dry-run=client` needs API discovery from a cluster and fails without one, so the check renders and verifies every object's `apiVersion`, `kind` and `metadata.name` instead. Both images were built once (`docker build ... -f deploy/docker/Dockerfile .` and `deploy/docker/Dockerfile.admin`) and run as uid 10001.

## 3. Enterprise: EKS or ECS

- **EKS**: the `aws` overlay as above. Put the gateway behind an internal ALB; developers reach `https://ai-gateway.example.internal`, admins `https://ai-control.example.internal` behind the organisation's SSO (docs/ADMIN.md). Replace `example.internal` with your internal domain.
- **ECS (Fargate)**: map each compose service one-to-one to a task definition: `gateway` (desired count 3, ALB target group on `/health/liveliness`), `ui` (1), `otel-collector` (sidecar or service), Redis as ElastiCache, secrets from Secrets Manager in the task definition's `secrets`, config files from S3 or EFS. AWS's own reference architecture for a multi-provider generative-AI gateway runs LiteLLM on ECS or EKS, so this is a well-trodden path.

Scaling notes:

- Gateway replicas are stateless; anything shared (loop counters, budget spend) lives in Redis, so replicas can be added freely.
- Jev's per-account rate limit (80 requests per second) is shared by all replicas: at high volume, either raise the account limit or sample the semantic check for low-risk profiles.
- The deterministic checks add a few milliseconds per request; the semantic check (Jev) runs in parallel with them and dominates the gateway overhead.

## 4. Degraded lane runbook (break-glass)

**What it is.** A minimal second gateway (`gateway-lane`, compose profile `lane`, `deploy/litellm/config.lane.yaml`, policy `deploy/lane/policy.lane.yaml`): the same approved models, the deterministic checks only (rules, the personal-data and secret packs, signatures, masking), no Jev, no AI judge, no MCP, no OpenTelemetry, tight loop limits and a daily spend cap. Secrets and personal-data rules stay on.

**When to use it.** The main gateway is down or unusable (for example its dependencies, Jev or Redis, are failing in a way that blocks work) and developers are blocked on urgent work. It is not a way around a policy decision: for a single wrongly blocked request use a break-glass override (`scripts/break-glass.py`) instead.

**How.**

1. Incident open, ticket number in hand; security on-call agrees.
2. `make lane-up` (host port `CTRL_AI_LANE_PORT`, default 4050) on the gateway host, or scale up the `gateway-lane` Deployment in the cluster.
3. Switch clients: push the managed settings (Claude Code `ANTHROPIC_BASE_URL`, the OpenAI SDK `base_url`) to the lane's URL, or move the DNS name (`ai-gateway.example.internal`) to the lane's load balancer. A DNS switch needs no client change.
4. The lane writes the same audit log (decision rows record `jev.status: "skipped"` and the lane policy's version), so the dashboard keeps showing traffic and the auditor can see exactly which requests went through the lane.
5. Time-box: the lane is stopped as soon as the main gateway is healthy (`make lane-down`, clients switched back). Record start, end and ticket in the incident.

Verified on this machine: `CTRL_AI_LANE_PORT=4450 docker compose -p ctrl-ai-b-lane --profile lane up -d --wait gateway-lane` started healthy; a normal `chat-groq` request answered 200; a prompt with a fake AWS key was refused (`Blocked by ctrl-ai: rule aws-access-key`); both decision rows had `jev.status: "skipped"` and `policy_version` equal to the lane policy's hash (`4b2a2cbd`).
