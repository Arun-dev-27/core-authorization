# miqaat-core-identity-authorization-service

Dynamic authorization and client registry for the Miqaat embedded login federation.

NestJS 11 · Fastify 5 · PostgreSQL (**Authorization DB**, separate from the Authentication DB) · Redis

**Never stores passwords or password hashes.** The ITS ID is the shared key with Identity Federation.

## Model

User → Business Unit / Utility → Application → Environment → Module → Role → Permission — all data, no hardcoded
applications. See `docs/data-model.md`.

## Project structure

```
src/
  main.ts · bootstrap.ts · app.module.ts
  config/                configuration.ts (zod env schema + .env loading) · config.module.ts (AppConfig)
  common/
    constants/           api-version (API_V1) · api-scopes · client · record-status · validation patterns
    decorators/          @Public() · @RequireScopes() · @AdminResource()
    dto/                 StatusQueryDto
    errors/ filters/     DomainError · global exception filter
    logging/             pino with redaction · request context (correlation id, actor)
    utils/               uri-policy (origin / redirect URI validation)
  core/                  app-wide infra
    audit/               authorization audit log (global)
    cache/               Redis client (global)
    database/            Authorization DB DataSource · sql helpers · migrations/
    health/              liveness / readiness
  modules/
    auth/                services/ (JWKS resolver, service principals, token verifier) · guards/ (global JwtAuthGuard)
    catalog/             code → id lookups shared by catalog features
    authorization/ business-units/ utilities/ environments/ applications/ app-modules/
    roles/ permissions/ users/ access/ clients/ federation/
      services/                        version-agnostic domain logic (+ <feature>.types.ts service inputs)
      <feature>-services.module.ts     the shared-services seam (reused by any /vN edge)
      <feature>.module.ts              feature aggregator
      v1/                              the HTTP edge
        <feature>.controller.ts        @Controller({ path, version: API_V1 })
        <feature>-v1.module.ts
        dto/                           v1 request contract (frozen; satisfies the service input types)
  shared/types/          Principal (service | user) + Fastify request augmentation
docker/                  Dockerfile · docker-compose.yml · postgres-init/
scripts/                 seed catalog · seed access · register service principal · OpenAPI export
test/                    e2e
```

TS path aliases: `@config` `@common` `@core/*` `@modules/*` `@shared` (see `tsconfig.json`). `npm run build` runs
`nest build` then `tsc-alias`. Services never import `v1/dto`: they accept `*Input` interfaces, so a `/v2` edge
(copy `v1/` → `v2/`, `@Controller({ path, version: '2' })`, register `…V2Module` in the aggregator) leaves `services/` untouched.

## API (bearer JWT verified via JWKS — no API keys)

| Caller | Endpoints |
|---|---|
| public | `GET /health`, `GET /health/ready` |
| Signed-in user, **before** selecting a workspace | `GET /me/assignments` |
| Signed-in user with an **active workspace** (token from Identity `POST /select-scope`) | `GET /me`, `GET /me/permissions`; the management APIs below, each guarded by a module permission of the active scope and filtered to it |
| &nbsp;&nbsp;BUSINESS_UNIT_MGMT / UTILITY_MGMT | `GET/POST /tenants`, `PATCH /tenants/:tenantId` (CORE) · `GET/POST /business-units`, `PATCH /business-units/:buId` · `GET/POST /utilities`, `PATCH /utilities/:utilityId` |
| &nbsp;&nbsp;ROLE_MGMT | `GET/POST /modules`, `GET/POST /permissions` (creates need CORE) · `GET/POST /roles`, `GET/PATCH /roles/:roleId` · `POST /role-permissions` (`"action": "GRANT" \| "REVOKE"`) |
| &nbsp;&nbsp;USER_MGMT | `POST /users`, `GET/PATCH /users/:itsId`, `GET /users/:itsId/roles`, `POST/DELETE /user-roles` |
| &nbsp;&nbsp;CONFIGURATION | `GET/POST /applications`, `GET/POST /environments`, `GET/POST /clients`, `GET/PATCH /clients/:clientId`, `GET/POST/DELETE /clients/:clientId/origins` and `/callbacks`; writes need a CORE workspace |
| FEDERATION — Identity Federation service token | `POST /users/sync`, `GET /internal/federation/clients/:clientId`, `GET /internal/federation/users/:itsId/assignments`, `POST /internal/federation/assignments/resolve`, `GET /internal/federation/users/:itsId/applications?environment=` |
| AUTHZ_CHECK — BU backend service token, restricted to its own client IDs | `POST /authorization/check`, `POST /authorization/effective-permissions` |

Scope rules (enforced in `RbacService`, never trusted from the client):

* **CORE** workspaces see the whole tenant. **BUSINESS_UNIT** workspaces see their BU and the utilities under it. **UTILITY** workspaces see only their utility.
* A workspace can manage roles and assignments only at its own level or below (CORE → all, BU → BU + UTILITY, UTILITY → UTILITY).
* No privilege escalation: a non-CORE actor can't grant a permission it doesn't hold. System roles can only be changed from a CORE workspace.
* Every request re-checks that the token's assignment still exists (`ASSIGNMENT_NOT_ACTIVE` otherwise) and resolves permissions from `role_permissions`.

### Authentication (no API keys)

| Token | Header `typ` | Signed by / verified with | Claims |
|---|---|---|---|
| Service token | `client-authentication+jwt` | the caller's own RSA key / the `jwks_uri` registered for the service principal | `iss = sub = principal_id`, `aud = AUTHZ_AUDIENCE`, `jti` (single use), `exp - iat ≤ 300 s` |
| User access token | `at+jwt` | Identity Federation signing key / `IDENTITY_JWKS_URI` | `iss = IDENTITY_ISSUER`, `sub = ITS ID`, `aud = AUTHZ_AUDIENCE`, `token_use = access`, `sid`, and after `POST /select-scope`: `role_id`, `scope_type`, `scope_id` (null for CORE); ≤ 15 min |

Both: RS256 only, `kid` required, exact audience, expiry with 5 s tolerance. Tokens never carry permissions.
Service principals hold only a public JWKS URI (`service_principals` table).

### Managing embed origins and callbacks

An origin is the parent page allowed to frame the Core login iframe (`frame-ancestors`) and to receive the assertion by
`postMessage`. It must be an exact `scheme://host[:port]`. It uses https, with http allowed only for localhost when
`ALLOW_INSECURE_LOCALHOST_URIS=true`, which production rejects. No wildcard, path, query or credentials are accepted.

| Action | API (CORE workspace + CONFIGURATION edit) | CLI (database access) |
|---|---|---|
| list | `GET /clients/:clientId/origins` | `npm run client -- origins list rms-web-dev` |
| add | `POST /clients/:clientId/origins` `{ "origin": "http://localhost:3000" }` | `npm run client -- origins add rms-web-dev http://localhost:3000` |
| remove | `DELETE /clients/:clientId/origins?origin=…` or body `{ "origin": "…" }` | `npm run client -- origins remove rms-web-dev http://localhost:3000` |
| callbacks | `GET/POST/DELETE /clients/:clientId/callbacks` `{ "uri", "uri_type": CALLBACK\|POST_LOGOUT_REDIRECT\|BACK_CHANNEL_LOGOUT }` | `npm run client -- callbacks add rms-web-dev <uri> --type CALLBACK` |

Rules: adding is idempotent. Removing an unknown value returns `404 ORIGIN_NOT_REGISTERED` / `URI_NOT_REGISTERED`. The last
origin or callback of an ACTIVE embedded client can't be removed (`409 CLIENT_CONFIGURATION_INCOMPLETE`); suspend the client first.
Every change is audited (`CLIENT_ORIGIN_ADDED`, `CLIENT_ORIGIN_REMOVED`, `CLIENT_URI_ADDED`, `CLIENT_URI_REMOVED`) with the actor.
Identity Federation reads client configuration fresh when a transaction is created, the login page opens and a user signs in,
so the change applies to the next sign-in. Its other cached lookups follow within `CLIENT_CACHE_TTL_SECONDS` (30 s), or immediately through
`POST <identity>/federation/clients/:clientId/refresh`.

Every feature route is served at both `/<path>` and `/v1/<path>`; `/health*` is version-neutral only. Swagger: `http://localhost:3002/docs` · OpenAPI: `docs/openapi.json` ·
Postman: `postman/miqaat-authorization.postman_collection.json`

```http
POST /authorization/check
{ "its_id": "30337752", "client_id": "rms-web-prod", "module": "RMS_REGISTRATION", "permission": "RMS_REGISTRATION_VIEW" }

200 { "allowed": true, "its_id": "30337752", "client_id": "rms-web-prod", "permission": "RMS_REGISTRATION_VIEW" }
200 { "allowed": false, "reason": "PERMISSION_DENIED" }
```

Deny reasons: `CLIENT_NOT_FOUND`, `CLIENT_NOT_ACTIVE`, `APPLICATION_INACTIVE`, `USER_NOT_FOUND`, `USER_INACTIVE`,
`APPLICATION_ACCESS_DENIED`, `PERMISSION_DENIED`, `MODULE_MISMATCH`.

## Status: activate, suspend, deactivate

### Client lifecycle

`PENDING → SECURITY_REVIEW → ACTIVE ⇄ SUSPENDED → RETIRED`. Only ACTIVE clients authenticate or pass checks.
Origins/callbacks are validated (exact `scheme://host[:port]`, https, no wildcard) and there is one `client_id` per environment.

| From | Allowed next status | Meaning |
|---|---|---|
| `PENDING` | `SECURITY_REVIEW`, `RETIRED` | new client, not usable |
| `SECURITY_REVIEW` | `ACTIVE`, `PENDING`, `RETIRED` | under review |
| `ACTIVE` | `SUSPENDED`, `RETIRED` | sign-in allowed |
| `SUSPENDED` | `ACTIVE`, `RETIRED` | temporarily disabled |
| `RETIRED` | none | permanent (`409 CLIENT_RETIRED`) |

```bash
# CORE workspace + CONFIGURATION edit
curl -s -X PATCH http://localhost:3002/clients/rms-web-dev -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"status":"SUSPENDED","reason":"incident #42"}'     # deactivate
curl -s -X PATCH http://localhost:3002/clients/rms-web-dev -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"status":"ACTIVE","reason":"incident resolved"}'   # reinstate
# apply in Identity now (token from select-scope with "audience": "identity")
curl -s -X POST http://localhost:3001/federation/clients/rms-web-dev/refresh -H "Authorization: Bearer $ID_TOKEN"
```

Every status change is written to `client_status_history` with the `reason` and actor, and audited as `CLIENT_STATUS_CHANGED`.
Errors: `409 INVALID_CLIENT_STATUS_TRANSITION` (`details.allowed`), `409 CLIENT_CONFIGURATION_INCOMPLETE` (ACTIVE needs at least one
callback URI, plus one embed origin for `EMBEDDED` / `EMBEDDED_OR_REDIRECT`), `409 CLIENT_RETIRED`.
Other client settings: `PATCH /clients/:clientId { name, authentication_mode, back_channel_logout_uri, initiate_login_uri }` (`null` removes a URI).

### Other records

| Record | Status values | Change with | Permission |
|---|---|---|---|
| Tenant | `active` · `inactive` | `PATCH /tenants/:tenantId { "status" }` | CORE + `BUSINESS_UNIT_MGMT` edit |
| Business unit | `active` · `inactive` | `PATCH /business-units/:buId { "status" }` (also `name`) | `BUSINESS_UNIT_MGMT` edit |
| Utility | `active` · `inactive` | `PATCH /utilities/:utilityId { "status" }` (also `name`) | `UTILITY_MGMT` edit |
| Application | `active` · `inactive` | set on `POST /applications`; there is no update endpoint | CORE + `CONFIGURATION` edit |
| User | `active` · `inactive` · `suspended` | `PATCH /users/:itsId { "status" }` (also `name`, `email`) | `USER_MGMT` edit |
| Role | no status | revoke permissions (`POST /role-permissions`, `"action": "REVOKE"`) or assignments (`DELETE /user-roles`) | `ROLE_MGMT` / `USER_MGMT` edit |

A user who isn't `active` fails every check with `USER_INACTIVE`; end their live sign-ins with Identity
`POST /federation/logout { "its_id" }`. Revoking an assignment makes tokens for that workspace return `403 ASSIGNMENT_NOT_ACTIVE` immediately.

## Connecting to Identity Federation

| `core-authorization/.env` | Must equal in `core-authentication/.env` |
|---|---|
| `PORT=3002` | `AUTHZ_BASE_URL=http://localhost:3002` |
| `AUTHZ_AUDIENCE=miqaat-core-authorization` | `AUTHZ_AUDIENCE` |
| `IDENTITY_ISSUER=http://localhost:3001` | `ISSUER` |
| `IDENTITY_JWKS_URI=http://localhost:3001/.well-known/jwks.json` | `<ISSUER>/.well-known/jwks.json` |

`npm run seed` registers the service principals: `identity-federation` (scope `FEDERATION`, JWKS = Identity) and `rms-backend` /
`ams-backend` / `vms-backend` (scope `AUTHZ_CHECK`, only their own client IDs). Check them:

```sql
SELECT principal_id, jwks_uri, scopes, allowed_client_ids, status, last_used_at FROM service_principals;
```

A moving `last_used_at` for `identity-federation` and `200` responses on `/internal/federation/*` in this service's log mean the trust
works. Identity's `/health/ready` `"authorization_service": "up"` only proves this service is reachable. Symptoms and fixes:
`../core-authentication/README.md` section 1.1.

## Postman

Import `postman/miqaat-authorization.postman_collection.json`. Sign in first with the Identity collection
(`../core-authentication/postman/miqaat-federation.postman_collection.json`, folder **1. Sign in**): its select-scope requests store the
globals `access_token` (inherited by every request here) and `identity_access_token` (used by **Clients → Apply in Identity**).
Create requests store `tenant_id`, `bu_id`, `utility_id`, `role_id` and `client_id` for the requests that follow.

Order: **Organisation** → **Applications** → **Roles & permissions** → **Clients** (create, origins, callbacks, status, Apply in Identity) →
**Users & assignments**. The service-token folders need a single-use token signed by the calling principal
(`federation_service_token`, `bu_service_token`).

## Setup

```bash
npm run infra:up                      # docker/docker-compose.yml: Postgres :5442, Redis :6392
cp .env.example .env
npm install
npm run migration:run
npm run seed                          # catalog + clients + service principals (JWKS URIs, no secrets)
npm run start:dev                     # http://localhost:3002
npm run principal:register -- --id hbs-backend --name "HBS backend" --jwks-uri https://hbs.example.com/.well-known/jwks.json --scopes AUTHZ_CHECK --clients hbs-web-prod
npm run seed:access                   # after users are synced from Identity Federation
```

## Tests

* `npm test` — URI policy, client lifecycle, decision engine, JWKS token verifier (alg none, HS256, unknown kid, wrong key, aud, iss, expiry, lifetime, replay, typ confusion, revoked principal)
* `npm run test:e2e` — real Postgres/Redis: onboarding via APIs, lifecycle, wildcard rejection, per-app roles,
  bearer-token authentication (service principals + admin tokens, API keys rejected), cross-application isolation, principal client scoping, immediate revocation/suspension, audit, **no password columns**

## Docs

`docs/data-model.md` · `docs/onboarding-new-application.md` · `deploy/k8s/core-authorization.yaml` ·
architecture, sequence diagrams and security checklist in `../core-authentication/docs/`.
