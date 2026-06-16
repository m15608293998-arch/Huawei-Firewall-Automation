# Trade Access API Layer Design

> Historical design: the combined `X-API-Key` adapter described below has been
> removed. See `docs/Keycloak标准认证鉴权实施说明.md` for the current admin OIDC and user SK design.

## 1. Architecture

```text
Caller X-API-Key
  -> FastAPI credential adapter
  -> Keycloak token endpoint and in-memory token cache
  -> verified OAuth2 access token claims
  -> local client-to-operation permission check
  -> FastAPI
  -> SQLite persistent queue
  -> single Worker
  -> ansible-runner
  -> Huawei USG6000E
```

Keycloak handles Client credential lifecycle, identity and broad user/admin
roles. FastAPI adapts one combined caller key into Client Credentials, validates
the resulting access token, and enforces operation permissions at API routes.
The Ansible execution and firewall behavior remain unchanged.

## 2. Credential Boundary

An administrator builds one caller-facing key from a Keycloak Client ID and
Client Secret:

```text
kc1.<base64url(client_id)>.<base64url(client_secret)>
```

The caller sends it as `X-API-Key`. FastAPI exchanges the decoded credentials
at the Keycloak token endpoint and caches only verified token claims in memory.
It never persists the combined key, Client Secret or Access Token. Direct
`Authorization: Bearer <access_token>` remains supported for diagnostics.

The API validates:

- RS256 signature and `kid` against the realm JWKS.
- `iss` against the configured realm issuer.
- `aud` against `trade-access-api`.
- `exp`, `iat` and `sub`.

The API reads client roles from the standard Keycloak claim:

```text
resource_access.trade-access-api.roles
```

IP, CIDR, port and action permissions are not stored in credential claims.

The combined key contains a long-lived Client Secret and therefore requires
HTTPS. Base64URL is packaging, not encryption.

## 3. Roles And Routes

Keycloak client roles:

```text
trade-access-user
trade-access-admin
```

Normal routes accept either role:

```text
POST /api/v1/trade-access/allow
POST /api/v1/trade-access/deny
GET  /api/v1/trade-access/jobs
GET  /api/v1/trade-access/jobs/{job_id}
GET  /api/v1/trade-access/jobs/{job_id}/events
```

Normal reads are owner-scoped by the stable Keycloak `sub`. Access token
rotation does not change task ownership.

Administrator-only routes:

```text
GET /api/v1/admin/trade-access/jobs
GET /api/v1/admin/trade-access/jobs/{job_id}
GET /api/v1/admin/trade-access/jobs/{job_id}/events
GET /api/v1/admin/clients
POST /api/v1/admin/clients
PATCH /api/v1/admin/clients/{client_id}
POST /api/v1/admin/clients/{client_id}/rotate-secret
```

Administrators can inspect jobs across subjects. More privileged operations
should be added under `/api/v1/admin` rather than encoded as custom token
attributes.

FastAPI additionally binds each route to a local operation permission:

```text
firewall.allow
firewall.deny
firewall.job.read
firewall.job.audit
identity.client.manage
```

The permission table is keyed by Keycloak `client_id`. It stores no secret.

## 4. Business Request Model

```json
{
  "target_ip": "192.168.66.22",
  "mask": 32,
  "ports": [12001, 12002],
  "description": "temporary trade server access",
  "client_request_id": "REQ-20260608-001"
}
```

Rules:

- `allow` requires one or more valid TCP ports.
- `deny` rejects `ports` and removes all access for the target.
- The selected endpoint determines `allow` or `deny`; callers do not submit an
  `action` field.
- Ordinary users may only submit an administrator-assigned IP with mask `32`.
- Administrators may submit a valid network target.
- `requester` and `requester_id` are never accepted from request JSON.
- `requester` is derived from the authenticated Keycloak principal.

Ports are business input, not identity attributes. Existing additive allow,
application splitting and complete deny behavior remain in the Ansible role.

## 5. Identity Persistence

Each new job stores:

```text
principal_id       Keycloak sub, used for ownership
principal_subject  preferred_username, clientId or azp for audit display
principal_client_id Keycloak azp/clientId
auth_type          keycloak_client_key or keycloak_bearer
principal_type     user or admin audit classification
permission_code    API operation used to create the job
```

The legacy `principal_key_id` column remains for database compatibility.
Existing `api_keys` tables are not dropped, but they are no longer read or
created by the application.

## 6. Keycloak Setup

1. Create realm `trade-access`.
2. Create resource client `trade-access-api`.
3. Create client roles `trade-access-user` and `trade-access-admin` on it.
4. Create one confidential Provisioning Client with service accounts enabled.
5. Grant its service account the minimum required `realm-management` roles:
   `manage-clients`, `query-clients`, `manage-users`, and `query-users`.
6. Configure its Client ID and Secret only on the API server.
7. Use `/admin-ui` to create caller clients, assign roles and local permissions,
   configure user IP assignments, and generate the combined X-API-Key.

For human users, use Authorization Code Flow rather than distributing one
confidential client secret per person. For machine callers, use Client
Credentials and service accounts.

## 7. Runtime Configuration

```bash
export TRADE_ACCESS_API_KEYCLOAK_SERVER_URL=https://keycloak.internal.example
export TRADE_ACCESS_API_KEYCLOAK_REALM=trade-access
export TRADE_ACCESS_API_KEYCLOAK_CLIENT_ID=trade-access-api
export TRADE_ACCESS_API_KEYCLOAK_USER_ROLE=trade-access-user
export TRADE_ACCESS_API_KEYCLOAK_ADMIN_ROLE=trade-access-admin
export TRADE_ACCESS_API_KEYCLOAK_ADMIN_CLIENT_ID=trade-access-provisioner
export TRADE_ACCESS_API_KEYCLOAK_ADMIN_CLIENT_SECRET='provisioner-client-secret'
```

JWKS keys are cached for five minutes by default. Key rotation is handled by
refreshing JWKS when the token `kid` is unknown.

Client Credentials access tokens are cached in memory by a SHA-256 credential
fingerprint and refreshed before expiry. Permission changes are read from
SQLite on each authenticated request and therefore apply immediately.

## 8. Dynamic Permission Management

The combined key represents stable Keycloak Client credentials, not a frozen
permission snapshot. API permissions and exact user IP assignments are stored
locally by `client_id` and loaded on every request. Changing either does not
require a new key. Keycloak user/admin role changes invalidate the cached token
claims for that Client. Only Client Secret rotation requires distributing a new
combined key.
