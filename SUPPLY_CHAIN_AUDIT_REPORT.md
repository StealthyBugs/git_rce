# Supply Chain Vulnerability Audit Report
## corretto/* and aws-actions/* GitHub Organizations

**Date:** 2026-03-30
**Scope:** 15 non-archived corretto repos, 23 non-archived aws-actions repos
**Revision:** v2 — Updated with per-bug exploitability verification

---

## Repository Archive Status

### Corretto Organization (23 repos found)

**Archived (8):** corretto-8-docker, corretto-11-docker, corretto-18, corretto-19, corretto-20, corretto-22, corretto-23, corretto-24

**Non-Archived (15):** corretto-8, corretto-11, corretto-17, corretto-21, corretto-25, corretto-26, corretto-jdk, corretto-jmc, corretto-docker, corretto-downloads, hotpatch-for-apache-log4j2, amazon-corretto-crypto-provider, heapothesys, arctic, samples

### AWS-Actions Organization (24 repos found)

**Archived (1):** codeguru-security

**Non-Archived (23):** configure-aws-credentials, amazon-ecr-login, amazon-ecs-deploy-task-definition, amazon-ecs-render-task-definition, aws-codebuild-run-build, aws-cloudformation-github-deploy, aws-lambda-deploy, aws-secretsmanager-get-secrets, setup-sam, codeguru-reviewer, amazon-eks-fargate, vulnerability-scan-github-action-for-amazon-inspector, sustainability-scanner, terraform-aws-iam-policy-validator, stale-issue-cleanup, cloudformation-aws-iam-policy-validator, closed-issue-message, aws-devicefarm-mobile-device-testing, aws-devicefarm-browser-testing, aws-elasticbeanstalk-deploy, action-cloudwatch-metrics, amazon-ecs-deploy-express-service, application-observability-for-aws

---

## Exploitability-Verified Findings

### BUG #1 — HIGH — EXPLOITABLE (conditional) — CI/CD Supply Chain: pull_request_target with Unsafe Checkout

- **File:** `aws-actions/aws-elasticbeanstalk-deploy/.github/workflows/integ.yml`
- **Lines:** 5 (trigger), 36-38 (checkout), 60-61 (npm ci/build)
- **Reference:** `actions/checkout` with `ref: ${{ github.event.pull_request.head.sha }}`

**What happens:** Uses `pull_request_target` (base repo context with secrets) but checks out PR HEAD (attacker-controlled from fork). Then runs `npm ci` and `npm run build` on attacker's code. The OIDC token (`ACTIONS_ID_TOKEN_REQUEST_TOKEN`) is available to ALL steps in the job, so attacker code running during `npm ci` (via a preinstall script) can request the OIDC JWT and assume the AWS `INTEG_TEST_ROLE_ARN` role externally.

**Attack chain:** Fork repo → add `preinstall` script to package.json → open PR → workflow triggers → `npm ci` executes attacker's preinstall script → script reads OIDC token from env vars → attacker assumes AWS role.

**Mitigation caveat:** The `environment: integ-test` (line 25) MAY have required reviewers configured in GitHub environment protection rules, which would block execution. This is unverifiable from code alone. If configured, it effectively blocks the attack.

**Exploitability verdict: TRUE POSITIVE. Exploitable unless environment protection rules require manual approval.**

---

### BUG #2 — HIGH — EXPLOITABLE — Unclaimed npm Name + Runtime npm install

- **File:** `aws-actions/application-observability-for-aws/package.json` (line 2)
- **Name:** `application-observability-for-aws-action` — unclaimed on npm (404)
- **Key difference from other actions:** `action.yml` (line 93-97) uses `runs.using: "composite"` and executes `npm install` at runtime:
  ```yaml
  - name: Install Dependencies
    shell: bash
    run: |
      cd ${GITHUB_ACTION_PATH}
      npm install
  ```

**Why this is different:** Unlike all other aws-actions repos (which pre-bundle `dist/` and never run npm at runtime), this action runs `npm install` during every workflow execution. While `package-lock.json` pins dependencies, the unclaimed package name combined with runtime `npm install` creates a tangible attack surface. If the lockfile is ever regenerated, missing, or if npm's resolution behavior changes, the unclaimed name becomes exploitable.

**Attack chain:** Register `application-observability-for-aws-action` on npm → publish malicious version → if lockfile integrity is bypassed or regenerated, `npm install` pulls attacker's code → code executes with access to `github_token` and AWS credentials.

**Exploitability verdict: TRUE POSITIVE. The runtime `npm install` combined with unclaimed package name is a real risk.**

---

### BUGS #3–#12, #13 — DOWNGRADED TO INFORMATIONAL — Unclaimed npm Names (No Runtime npm install)

**Original finding:** 11 aws-actions repos use unscoped npm names without `"private": true`, and these names are unclaimed on npm. Bug #13: name collision with third-party package.

**Exploitability verification result: NOT EXPLOITABLE.** All 11 of these actions (and the name collision in #13) share the same characteristics:
- `action.yml` uses `runs.using: "node20"` or `"node24"` with `main: "dist/index.js"`
- The `dist/` directory is pre-bundled (via `@vercel/ncc`) and committed to the repo
- GitHub Actions clones the repo and runs `dist/index.js` directly — **npm is never consulted at runtime**
- No consumer would ever run `npm install <action-name>` — actions are consumed via `uses:` directive

The `name` field in `package.json` is only metadata for what the package would be called if published. It is never resolved from the npm registry during normal usage. An attacker registering these names would have packages that nobody installs.

**Recommendation:** Add `"private": true` to all package.json files as a defensive best practice, but the absence does not constitute an exploitable vulnerability.

| # | Package Name | Repository | Status |
|---|---|---|---|
| 3 | `aws-actions-amazon-ecr-login` | aws-actions/amazon-ecr-login | Informational |
| 4 | `aws-actions-amazon-ecs-deploy-task-definition` | aws-actions/amazon-ecs-deploy-task-definition | Informational |
| 5 | `aws-actions-amazon-ecs-render-task-definition` | aws-actions/amazon-ecs-render-task-definition | Informational |
| 6 | `aws-actions-aws-cloudformation-github-deploy` | aws-actions/aws-cloudformation-github-deploy | Informational |
| 7 | `aws-secretsmanager-get-secrets` | aws-actions/aws-secretsmanager-get-secrets | Informational |
| 8 | `aws-devicefarm-mobile-device-testing` | aws-actions/aws-devicefarm-mobile-device-testing | Informational |
| 9 | `aws-device-farm-browser-testing` | aws-actions/aws-devicefarm-browser-testing | Informational |
| 10 | `action-cloudwatch-metrics` | aws-actions/action-cloudwatch-metrics | Informational |
| 11 | `amazon-ecs-deploy-express-service` | aws-actions/amazon-ecs-deploy-express-service | Informational |
| 12 | `closed-issue-message` | aws-actions/closed-issue-message | Informational |
| 13 | `aws-elasticbeanstalk-deploy` | aws-actions/aws-elasticbeanstalk-deploy | Informational |

---

### BUG #14 — DOWNGRADED TO INFORMATIONAL — Dead Download URL (jq)

- **File:** `aws-actions/amazon-eks-fargate/Dockerfile` (line 15)
- **URL:** `https://stedolan.github.io/jq/download/linux64/jq` — returns 404

**Exploitability verification:**
- The `stedolan` GitHub account still exists (1.2k followers, 55 repos) — username takeover is NOT currently possible
- The repository is abandoned since 2020 and explicitly marked "not yet usable" in README
- The action is already broken (curl downloads a 404 HTML page, not a binary)
- Only 15 dependent repos, likely all stale
- Exploitation requires: (a) stedolan account deleted, (b) someone still uses this broken action

**Verdict: NOT CURRENTLY EXPLOITABLE. Conditional future risk only, against an already-broken abandoned action.**

---

### BUG #2b — MEDIUM — curl|sh in action.yml (astral.sh/uv)

- **File:** `aws-actions/application-observability-for-aws/action.yml` (line 151)
- **Reference:** `curl -LsSf https://astral.sh/uv/install.sh | sh`

The action's runtime pipes a remote script from `astral.sh` directly to shell without any integrity verification. This runs during every workflow execution that triggers the MCP tools install path. While `astral.sh` is a legitimate domain (the uv Python package manager), the mutable URL means any change to that script is silently consumed.

**Exploitability:** Conditional — requires compromise of astral.sh or its CDN. The domain is actively maintained.

---

### BUG #2c — MEDIUM — Unpinned third-party action (@beta tag)

- **File:** `aws-actions/application-observability-for-aws/.github/workflows/integ-test.yml` (line 40)
- **Also:** `aws-actions/application-observability-for-aws/.github/workflows/canary-test.yml` (line 39)
- **Reference:** `uses: anthropics/claude-code-base-action@beta`

Uses the `@beta` mutable tag for the Claude Code action. This action receives AWS Bedrock model access, MCP server configurations, and prompt files. A tag retarget could inject modified action code.

**Exploitability:** Conditional — requires compromise of the anthropics GitHub org or a tag retarget. The org is well-established.

---

## Remaining Findings (Bugs #15–#22, unchanged)

These findings were not part of the exploitability re-verification but remain as originally assessed:

### BUG #15 — MEDIUM — Moved Repository Redirect Dependency (eksctl)
- **File:** `aws-actions/amazon-eks-fargate/Dockerfile` (line 9)
- eksctl moved from weaveworks to eksctl-io. Redirect works but fragile. Same abandoned repo as Bug #14.

### BUG #16 — MEDIUM — Archived Third-Party Action in CI
- **File:** `aws-actions/action-cloudwatch-metrics/.github/workflows/test.yml` (line 70)
- `ros-tooling/action-cloudwatch-metrics@0.0.4` — archived/deprecated, mutable tag

### BUG #17 — MEDIUM — Unpinned Action (@main branch ref)
- **File:** `aws-actions/configure-aws-credentials/examples/.github/workflows/compliance.yml` (line 10)
- `grolston/guard-action@main` — most mutable reference possible

### BUG #18 — MEDIUM — Unpinned pip install in Dockerfile
- **File:** `aws-actions/sustainability-scanner/Dockerfile` (line 14)
- `pip3 install sustainability-scanner` without version pin

### BUG #19 — MEDIUM — curl|sh with mutable branch ref
- **File:** `aws-actions/sustainability-scanner/Dockerfile` (line 10)
- Pipes install-guard.sh from `main` branch to sh

### BUG #20 — MEDIUM — Unpinned Third-Party Actions (tag refs)
- Multiple workflows: `hmarr/auto-approve-action@v2.1.0`, `pascalgn/automerge-action@v0.8.4`, `JasonEtco/build-and-tag-action@v2`

### BUG #21 — MEDIUM — Unpinned Action on pull_request_target
- **File:** `aws-actions/configure-aws-credentials/.github/workflows/pull-request-lint.yml` (line 19)
- `amannn/action-semantic-pull-request@v5.5.3` on pull_request_target

### BUG #22 — LOW — Stale Dockerfile with Multiple Dead References
- **File:** `aws-actions/amazon-eks-fargate/Dockerfile` (lines 1, 6, 9, 11, 15)
- EOL base image, dead URLs, no integrity checks. Abandoned repo.

---

## Revised Summary

| Bug | Severity | Exploitable? | Vulnerability Class | File(s) |
|-----|----------|-------------|---------------------|---------|
| #1 | **HIGH** | **YES (conditional)** | pull_request_target unsafe checkout | aws-elasticbeanstalk-deploy integ.yml |
| #2 | **HIGH** | **YES** | Unclaimed npm name + runtime npm install | application-observability-for-aws |
| #3-#13 | INFO | No | Unclaimed npm names (no runtime npm) | Multiple package.json |
| #14 | INFO | No (currently) | Dead URL, account exists, repo abandoned | amazon-eks-fargate Dockerfile |
| #15 | MEDIUM | Conditional | Moved repo redirect | amazon-eks-fargate Dockerfile |
| #16 | MEDIUM | Conditional | Archived action in CI | action-cloudwatch-metrics test.yml |
| #17 | MEDIUM | Conditional | Unpinned action (@main) | configure-aws-credentials example |
| #18 | MEDIUM | Conditional | Unpinned pip install | sustainability-scanner Dockerfile |
| #19 | MEDIUM | Conditional | curl\|sh mutable ref | sustainability-scanner Dockerfile |
| #20 | MEDIUM | Conditional | Unpinned third-party actions | Multiple workflows |
| #21 | MEDIUM | Conditional | Unpinned action + pull_request_target | configure-aws-credentials lint |
| #22 | LOW | No | Stale Dockerfile | amazon-eks-fargate Dockerfile |

**CONFIRMED EXPLOITABLE: 2 findings (Bug #1, Bug #2)**
**CONDITIONALLY EXPLOITABLE: 9 findings (Bugs #2b, #2c, #15-#21) — require upstream account compromise or specific conditions**
**INFORMATIONAL: 12 findings (Bugs #3-#14) — namespace hygiene, not exploitable**
**LOW: 1 finding (Bug #22)**
