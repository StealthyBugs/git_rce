# Supply Chain Vulnerability Audit Report
## corretto/* and aws-actions/* GitHub Organizations

**Date:** 2026-03-30
**Scope:** 15 non-archived corretto repos, 23 non-archived aws-actions repos

---

## Repository Archive Status

### Corretto Organization (23 repos found)

**Archived (8):** corretto-8-docker, corretto-11-docker, corretto-18, corretto-19, corretto-20, corretto-22, corretto-23, corretto-24

**Non-Archived (15):** corretto-8, corretto-11, corretto-17, corretto-21, corretto-25, corretto-26, corretto-jdk, corretto-jmc, corretto-docker, corretto-downloads, hotpatch-for-apache-log4j2, amazon-corretto-crypto-provider, heapothesys, arctic, samples

### AWS-Actions Organization (24 repos found)

**Archived (1):** codeguru-security

**Non-Archived (23):** configure-aws-credentials, amazon-ecr-login, amazon-ecs-deploy-task-definition, amazon-ecs-render-task-definition, aws-codebuild-run-build, aws-cloudformation-github-deploy, aws-lambda-deploy, aws-secretsmanager-get-secrets, setup-sam, codeguru-reviewer, amazon-eks-fargate, vulnerability-scan-github-action-for-amazon-inspector, sustainability-scanner, terraform-aws-iam-policy-validator, stale-issue-cleanup, cloudformation-aws-iam-policy-validator, closed-issue-message, aws-devicefarm-mobile-device-testing, aws-devicefarm-browser-testing, aws-elasticbeanstalk-deploy, action-cloudwatch-metrics, amazon-ecs-deploy-express-service, application-observability-for-aws

---

## Validated Findings

### BUG #1 — HIGH — CI/CD Supply Chain: pull_request_target with Unsafe Checkout

- **File:** `aws-actions/aws-elasticbeanstalk-deploy/.github/workflows/integ.yml`
- **Lines:** 36-38
- **Reference:** `actions/checkout` with `ref: ${{ github.event.pull_request.head.sha }}`

Uses `pull_request_target` (base repo context with secrets) but checks out PR HEAD (attacker-controlled from fork). Then runs `npm ci` and `npm run build` on attacker's code with AWS OIDC credentials.

**Attack:** Fork repo → modify source → open PR → CI executes attacker code with `id-token:write` and AWS role access.

**Remediation:** Split into two workflows or ensure the `integ-test` environment has required reviewers.

---

### BUG #2–#12 — HIGH — Dependency Confusion: Unclaimed npm Package Names

11 aws-actions repos use unscoped npm package names without `"private": true`, and these names do NOT exist on the npm public registry (confirmed 404 via registry.npmjs.org). An attacker can register any of them.

| # | Package Name | Repository |
|---|---|---|
| 2 | `aws-actions-amazon-ecr-login` | aws-actions/amazon-ecr-login |
| 3 | `aws-actions-amazon-ecs-deploy-task-definition` | aws-actions/amazon-ecs-deploy-task-definition |
| 4 | `aws-actions-amazon-ecs-render-task-definition` | aws-actions/amazon-ecs-render-task-definition |
| 5 | `aws-actions-aws-cloudformation-github-deploy` | aws-actions/aws-cloudformation-github-deploy |
| 6 | `aws-secretsmanager-get-secrets` | aws-actions/aws-secretsmanager-get-secrets |
| 7 | `aws-devicefarm-mobile-device-testing` | aws-actions/aws-devicefarm-mobile-device-testing |
| 8 | `aws-device-farm-browser-testing` | aws-actions/aws-devicefarm-browser-testing |
| 9 | `action-cloudwatch-metrics` | aws-actions/action-cloudwatch-metrics |
| 10 | `amazon-ecs-deploy-express-service` | aws-actions/amazon-ecs-deploy-express-service |
| 11 | `application-observability-for-aws-action` | aws-actions/application-observability-for-aws |
| 12 | `closed-issue-message` | aws-actions/closed-issue-message |

**Attack:** Register unclaimed name on npm → publish malicious version → users/CI running `npm install <name>` by name get attacker's package.

**Remediation:** Add `"private": true` to all package.json files, or defensively register the names.

---

### BUG #13 — HIGH — Third-Party npm Name Collision

- **File:** `aws-actions/aws-elasticbeanstalk-deploy/package.json`
- **Line:** 2
- **Reference:** `"name": "aws-elasticbeanstalk-deploy"`

This name is ALREADY registered on npm by a third party (Adriaan Pelzer / 4dr144n, version 0.0.4, published 2016). The AWS repo lacks `"private": true` and includes `"prepublishOnly"`, `"files"`, and `"main"` fields — configured as publishable.

**Attack:** If third-party maintainer account is compromised, attacker controls what `npm install aws-elasticbeanstalk-deploy` delivers.

**Remediation:** Add `"private": true`. Consider contacting npm about the name.

---

### BUG #14 — HIGH — Dead Download URL in Dockerfile (jq)

- **File:** `aws-actions/amazon-eks-fargate/Dockerfile`
- **Line:** 15
- **Reference:** `https://stedolan.github.io/jq/download/linux64/jq`

URL returns HTTP 404. jq project moved to jqlang/jq. The stedolan GitHub account still exists (preventing immediate takeover), but if deleted, an attacker registers the username and serves a malicious binary. No integrity verification on the download.

**Attack:** Account deletion → register "stedolan" → serve trojanized binary at exact path → Docker builds execute it.

**Remediation:** Replace URL with `https://github.com/jqlang/jq/releases/download/...` + SHA-256 checksum.

---

### BUG #15 — MEDIUM — Moved Repository Redirect Dependency (eksctl)

- **File:** `aws-actions/amazon-eks-fargate/Dockerfile`
- **Line:** 9
- **Reference:** `https://github.com/weaveworks/eksctl/releases/latest/download/...`

eksctl transferred from weaveworks to eksctl-io. GitHub 301 redirect works now, but if a new "eksctl" repo is created under weaveworks (defunct company), redirect breaks and new repo takes precedence.

**Remediation:** Update to `eksctl-io/eksctl`. Pin version. Add checksum.

---

### BUG #16 — MEDIUM — Archived Third-Party Action in CI

- **File:** `aws-actions/action-cloudwatch-metrics/.github/workflows/test.yml`
- **Line:** 70
- **Reference:** `ros-tooling/action-cloudwatch-metrics@0.0.4`

Archived/deprecated action used in CI that has access to AWS credentials. Tag is mutable.

**Remediation:** Replace with `uses: ./` (self-reference) or pin to SHA.

---

### BUG #17 — MEDIUM — Unpinned Action (@main branch ref)

- **File:** `aws-actions/configure-aws-credentials/examples/cfn-deploy-example/.github/workflows/compliance.yml`
- **Line:** 10
- **Reference:** `grolston/guard-action@main`

Example workflow with most mutable reference possible. Users copy examples verbatim.

**Remediation:** Pin to SHA hash.

---

### BUG #18 — MEDIUM — Unpinned pip install in Dockerfile

- **File:** `aws-actions/sustainability-scanner/Dockerfile`
- **Line:** 14
- **Reference:** `pip3 install sustainability-scanner` (no version pin)

Any new PyPI version auto-installed on next build.

**Remediation:** Pin version: `pip3 install sustainability-scanner==X.Y.Z`

---

### BUG #19 — MEDIUM — curl|sh with mutable branch ref

- **File:** `aws-actions/sustainability-scanner/Dockerfile`
- **Line:** 10
- **Reference:** `curl ... https://raw.githubusercontent.com/aws-cloudformation/cloudformation-guard/main/install-guard.sh | sh`

Pipes script from mutable `main` branch to sh. Source is AWS-owned (lower risk) but not pinned.

**Remediation:** Pin URL to specific commit SHA.

---

### BUG #20 — MEDIUM — Unpinned Third-Party Actions (tag refs)

Multiple workflows use third-party personal-account actions with mutable version tags:

- `aws-actions/action-cloudwatch-metrics/.github/workflows/autoapprove.yml:15` → `hmarr/auto-approve-action@v2.1.0`
- `aws-actions/action-cloudwatch-metrics/.github/workflows/automerge.yml:19` → `pascalgn/automerge-action@v0.8.4`
- `aws-actions/aws-codebuild-run-build/.github/workflows/publish.yaml:32` → `JasonEtco/build-and-tag-action@v2`

**Remediation:** Pin all to SHA hashes.

---

### BUG #21 — MEDIUM — Unpinned Action on pull_request_target

- **File:** `aws-actions/configure-aws-credentials/.github/workflows/pull-request-lint.yml`
- **Line:** 19
- **Reference:** `amannn/action-semantic-pull-request@v5.5.3`

Third-party action with mutable tag on a pull_request_target workflow (write permissions).

**Remediation:** Pin to SHA hash.

---

### BUG #22 — LOW — Stale Dockerfile with Multiple Dead References

- **File:** `aws-actions/amazon-eks-fargate/Dockerfile`
- **Lines:** 1, 6, 9, 11, 15

EOL base image (amazonlinux:2018.03), 2020-era binaries, multiple dead/moved download URLs, no integrity verification on any download.

**Remediation:** Complete Dockerfile rewrite with current images, pinned versions, and checksums.

---

## Summary

| Bug | Severity | Vulnerability Class | File(s) |
|-----|----------|---------------------|---------|
| #1 | HIGH | pull_request_target unsafe checkout | aws-elasticbeanstalk-deploy integ.yml |
| #2-12 | HIGH | Unclaimed npm package names (11 repos) | Multiple package.json |
| #13 | HIGH | Third-party npm name collision | aws-elasticbeanstalk-deploy package.json |
| #14 | HIGH | Dead download URL (jq) | amazon-eks-fargate Dockerfile |
| #15 | MEDIUM | Moved repo redirect dependency | amazon-eks-fargate Dockerfile |
| #16 | MEDIUM | Archived action in CI | action-cloudwatch-metrics test.yml |
| #17 | MEDIUM | Unpinned action (@main) | configure-aws-credentials example |
| #18 | MEDIUM | Unpinned pip install | sustainability-scanner Dockerfile |
| #19 | MEDIUM | curl\|sh mutable ref | sustainability-scanner Dockerfile |
| #20 | MEDIUM | Unpinned third-party actions | Multiple workflows |
| #21 | MEDIUM | Unpinned action + pull_request_target | configure-aws-credentials lint |
| #22 | LOW | Stale Dockerfile | amazon-eks-fargate Dockerfile |

**TOTAL: 22 validated findings**
**CRITICAL: 0 | HIGH: 14 | MEDIUM: 7 | LOW: 1**
