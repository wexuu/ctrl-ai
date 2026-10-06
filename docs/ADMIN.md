# Admin panel: access, roles and change control

The admin panel (`/admin/policy`, `/admin/security`, `/admin/models`, `/admin/teams`, `/admin/tools`, `/admin/history`), the dashboard (`/dashboard`), the audit page (`/audit`) and the Jev trust page (`/jev-trust`) are one FastAPI app (`ctrl_ai.admin.app:create_app`, port 4100). It reads its settings from the environment once, when it starts (`src/ctrl_ai/admin/settings.py`); [RUNNING.md](RUNNING.md) describes the pages.

## Open access: no sign-in

The panel and the dashboard are open: there is no password and no login page. Every page shows a small banner saying so. Every admin and dashboard route still goes through one FastAPI dependency, `ctrl_ai.admin.auth.current_admin(request) -> Admin(name, roles)`, which returns

```
Admin(name="local-admin", roles=["platform-admin", "security-officer", "finance-viewer"])
```

and every admin audit row records `actor: "local-admin"`. `CTRL_AI_ADMIN_PASSWORD` and `CTRL_AI_SESSION_SECRET` are not used.

What stays on:

- **CSRF protection.** The UI can be reached over the LAN, so every `POST`, `PUT`, `PATCH` and `DELETE` must carry the header `X-CTRL-AI-CSRF` with the token from `GET /api/auth/session` (random per process). A cross-site form or script cannot read that token, so it cannot change the configuration.
- **Validation, versioning and audit.** Every save is validated against the JSON Schema contract (`config/schema/`) plus cross-file checks, refused on a version conflict (HTTP 409), written atomically, copied to `state/history/<file>/` and recorded in `logs/admin.jsonl` with actor, versions and a mandatory reason. Every change can be rolled back from `/admin/history`, and the rollback is itself a new audited version.
- **No secrets on screen.** Gateway keys are shown once when issued and stored only as SHA-256 hashes. The panel never receives the master key.

## Production design: single sign-on through the organisation's identity provider

In production the panel sits behind the organisation's central identity provider (for example Microsoft Entra ID or Okta), using OIDC (authorization code flow with PKCE) or SAML 2.0:

1. The panel is registered as an application in the IdP. Users authenticate there, with the organisation's MFA and conditional-access rules; the panel never sees a password.
2. The panel (or the reverse proxy in front of it, such as oauth2-proxy or the ingress controller's OIDC module) validates the ID token or SAML assertion and keeps a short-lived, signed, HttpOnly, SameSite=Strict session.
3. **Group-to-role mapping.** IdP groups map to three roles:

| Role | IdP group (example) | May do |
|---|---|---|
| Platform admin | `ai-platform-admins` | Edit policy, model catalogue, teams, budgets and gateway keys; roll back; read everything |
| Security officer | `secops-ai` | Edit the policy and revoke break-glass overrides; read everything, including the security view and the auditor export |
| Finance viewer | `finance-ai-costs` | Read the Management view of the dashboard only (spend, budgets, forecast) |

4. **Where it plugs in.** Only `ctrl_ai.admin.auth.resolve_admin(request)` changes: it reads the verified identity (from the session, or from trusted headers such as `X-Forwarded-User` / `X-Forwarded-Groups` set by the proxy) and returns `Admin(name=<user principal>, roles=<mapped roles>)`. Each route then checks `admin.has("platform-admin")` and so on; the audit rows already carry `admin.name` as the actor. Nothing else in the panel changes.
5. Every admin action stays in the admin audit log, which in production is shipped to the organisation's SIEM together with the gateway's audit log.

## Files the panel writes

| File | Page | Schema |
|---|---|---|
| `config/policy.yaml` | Policy, Security | `config/schema/policy.schema.json` |
| `config/models.yaml` | Models | `config/schema/models.schema.json` |
| `config/teams.yaml` | Teams | `config/schema/teams.schema.json` |
| `config/mcp.yaml` | Tools | `config/schema/mcp.schema.json` |
| `state/keys.json` | Teams (keys) | `config/schema/keys.schema.json` |
| `state/break_glass.json` | Teams (revoking overrides, the semantic-outage switch) | `config/schema/break_glass.schema.json` |

The gateway re-reads each file when it changes (live reload); no restart. Break-glass overrides are issued from the command line (`make break-glass ARGS="issue ..."`, `scripts/break-glass.py`), not from the panel.
