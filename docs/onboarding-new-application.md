# Onboarding a new application (no code changes)

Everything below is data in the Authorization DB, created through the API with a **workspace token**:
sign in to the Core Portal (Identity `POST /login`), select your **Platform Administrator (CORE)** workspace with
`POST /select-scope`, and use the returned `token`. Each call is checked against that workspace's permissions
(`BUSINESS_UNIT_MGMT`, `UTILITY_MGMT`, `ROLE_MGMT`, `USER_MGMT`, `CONFIGURATION`). There are no API keys.
Identity Federation reads client configuration fresh when a transaction is created, the login page opens and a user signs in,
so new or changed clients, origins, callbacks and status apply to the next sign-in without a refresh call. Its other cached
lookups (portal launcher, logout) follow within `CLIENT_CACHE_TTL_SECONDS` (30 s) or at once via `POST <identity>/federation/clients/:clientId/refresh`.

Example: a new **Hall Booking System (HBS)** owned by a new utility under the RMS business unit.

```bash
AUTHZ=http://localhost:3002
TOKEN=<token from POST /select-scope (CORE workspace)>
H=(-H "Authorization: Bearer $TOKEN" -H "content-type: application/json")
```

## 1. Owner (business unit or utility)

```bash
RMS_BU=$(curl -s "${H[@]}" $AUTHZ/business-units | jq -r '.[] | select(.name=="RMS") | .bu_id')
HBS_UTIL=$(curl -s "${H[@]}" -X POST $AUTHZ/utilities -d "{\"bu_id\":\"$RMS_BU\",\"name\":\"Hall Booking\"}" | jq -r .utility_id)
```

## 2. Application

```bash
curl -s "${H[@]}" -X POST $AUTHZ/applications -d "{\"code\":\"hbs\",\"name\":\"HBS Web\",\"utility_id\":\"$HBS_UTIL\"}"
```

## 3. Module and permissions (non-default module owned by the application)

```bash
curl -s "${H[@]}" -X POST $AUTHZ/modules \
  -d '{"module_code":"HBS_BOOKINGS","module_name":"Hall Bookings","application_code":"hbs","actions":["view","create","delete"]}'
# -> HBS_BOOKINGS_VIEW / HBS_BOOKINGS_CREATE / HBS_BOOKINGS_DELETE   (add one later: POST /permissions {"module_code","action"})
```

## 4. Role with permissions

A role has a `scope_level` (CORE, BUSINESS_UNIT or UTILITY). It can only be assigned in a scope of that level.

```bash
ROLE=$(curl -s "${H[@]}" -X POST $AUTHZ/roles \
  -d '{"role_name":"HBS Booking Manager","scope_level":"UTILITY","permission_codes":["HBS_BOOKINGS_VIEW","HBS_BOOKINGS_CREATE","HBS_BOOKINGS_DELETE"]}' | jq -r .role_id)
# later changes: POST /role-permissions {"role_id":"...","permission_codes":["HBS_BOOKINGS_DELETE"],"action":"REVOKE"}
```

## 5. Clients — one per environment, never reused

```bash
curl -s "${H[@]}" -X POST $AUTHZ/clients -d '{
  "client_id": "hbs-web-prod",
  "application_code": "hbs",
  "environment_code": "PROD",
  "client_type": "WEB",
  "authentication_mode": "EMBEDDED",
  "allowed_embed_origins": ["https://hbs.example.com"],
  "callback_uris": ["https://hbs.example.com/auth/core/callback"],
  "back_channel_logout_uri": "https://hbs.example.com/auth/core/logout",
  "post_logout_redirect_uris": ["https://hbs.example.com/logout/callback"],
  "initiate_login_uri": "https://hbs.example.com/auth/core/login"
}'   # status PENDING
```

Validation enforced: exact `scheme://host[:port]` origins, https only (localhost http only in dev), no wildcards,
no fragments/credentials, unique client ID.

## 6. Lifecycle

```bash
curl -s "${H[@]}" -X PATCH $AUTHZ/clients/hbs-web-prod -d '{"status":"SECURITY_REVIEW","reason":"CHG-1234 submitted"}'
# security review: origins, callback ownership, back-channel endpoint, CSP, verifier implementation, pen-test evidence
curl -s "${H[@]}" -X PATCH $AUTHZ/clients/hbs-web-prod -d '{"status":"ACTIVE","reason":"Approved by SecOps"}'
```

`PENDING → SECURITY_REVIEW → ACTIVE → SUSPENDED → RETIRED` (suspended may be reinstated; retired is terminal).
Only `ACTIVE` clients can start embedded login or pass authorization checks.

## 7. BU backend service principal (no API key)

The BU backend creates an RSA key pair (private key in its own secret manager) and publishes the public key at
`/.well-known/jwks.json` (see `core-authentication/examples/bu-reference-app/src/service-credentials.ts`). Register it:

```bash
npm run principal:register -- --id hbs-backend --name "HBS backend" \
  --jwks-uri https://hbs.example.com/.well-known/jwks.json --scopes AUTHZ_CHECK --clients hbs-web-uat,hbs-web-prod
```

The backend then signs a fresh service token per call: `typ client-authentication+jwt`, `iss = sub = hbs-backend`,
`aud = miqaat-core-authorization`, `jti`, lifetime ≤ 300 s. Revoke with `--revoke`.

## 8. Grant users (role × scope)

```bash
curl -s "${H[@]}" -X POST $AUTHZ/user-roles -d "{\"its_id\":\"30337752\",\"role_id\":\"$ROLE\",\"scope_type\":\"UTILITY\",\"scope_id\":\"$HBS_UTIL\"}"
# revoke: DELETE /user-roles with the same body
```

The user now has an extra workspace, "HBS Booking Manager · Hall Booking", on the Select Workspace screen. BU applications are
authorized by scope coverage: a CORE assignment covers every application, a BU assignment covers the BU and its utilities, and a
utility assignment covers only that utility.

## 9. Integrate the BU application

Follow `../core-authentication/docs/bu-integration-guide.md` (or copy `examples/bu-reference-app`).

## 10. Verify

```bash
curl -s -H "Authorization: Bearer <service token signed by hbs-backend>" -H "content-type: application/json" -X POST $AUTHZ/authorization/check \
  -d '{"its_id":"30337752","client_id":"hbs-web-prod","module":"HBS_BOOKINGS","permission":"HBS_BOOKINGS_CREATE"}'
# {"allowed":true,...}
```
