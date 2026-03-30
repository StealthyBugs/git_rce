# Supply Chain Vulnerability Audit Report (Round 2)
## amazonlinux + amazon-contributing + strands-agents
### Date: 2026-03-30

---

## Repository Classification

### amazonlinux (12 total)
- **Archived (2):** upgrade-modules, rust-bundled-packaging
- **Non-archived (10):** amazon-linux-2023, container-images, amazon-ec2-net-utils, amazon-ec2-utils, autotune, smart-restart, dnf-plugin-support-info, al1-support-statements, kiwi-image-descriptions-examples, update-motd

### amazon-contributing (21 total)
- **Archived (0):** None
- **Non-archived (21):** All repos active (redis-rs, .github, opentelemetry-collector-contrib, upstreaming-to-obs-studio, alertmanager, hadoop, upstream-to-fluent-bit, upstream-to-obs-localvocal, aws-sql-server-maintenance-solution, aurora-dsql-benchbase-benchmarking, upstream-to-pion-webrtc, grafana-aws-sdk, grafana-aws-sdk-react, upstream-to-ipxe, upstream-to-str0m, alerting, upstream-to-pytorch, upstream-to-torchtitan, upstream-to-ao, upstream-to-openfga, upstream-to-nvshmem)

### strands-agents (11 total)
- **Archived (0):** None
- **Non-archived (11):** sdk-python, tools, agent-sop, samples, sdk-typescript, agent-builder, mcp-server, docs, evals, devtools, extension-template-python

**Total non-archived repos audited: 42**

---

## Validated Findings

### BUG #1 -- MEDIUM: pull_request_target with Unsafe Checkout (docs-preview)

- **Vulnerability Class:** CI/CD Supply Chain
- **File:** `strands-agents/docs/.github/workflows/docs-preview.yml`, lines 4, 57-58
- **Vulnerable Reference:** `pull_request_target` + `ref: ${{ env.PR_HEAD_SHA }}`

**Description:**
Workflow triggers on `pull_request_target` (base repo context with secrets) and checks out the PR head commit (attacker-controlled code from fork). Then runs `npm install` and `npm run cms:build` on that code with access to AWS credentials (STRANDS_DOCS_DEPLOY_ROLE, S3_BUCKET, CLOUDFRONT).

**Exploitability:**
External attacker submits PR from fork. Authorization check routes non-collaborators to "manual-approval" environment. Requires a maintainer to approve the environment for the attack to execute. The authorization check action (`strands-agents/devtools/authorization-check@main`) is pinned to a mutable branch.

**Remediation:**
1. Never checkout PR head in `pull_request_target` workflows
2. Use `pull_request` trigger and deploy from artifacts
3. Pin authorization-check action to SHA

---

### BUG #2 -- MEDIUM: pull_request_target with Unsafe Checkout (integration-test)

- **Vulnerability Class:** CI/CD Supply Chain
- **File:** `strands-agents/agent-builder/.github/workflows/integration-test.yml`, lines 4, 57
- **Vulnerable Reference:** `pull_request_target` + `ref: ${{ github.event.pull_request.head.sha }}`

**Description:**
Same pattern as Bug #1. Checks out attacker-controlled PR code and runs `hatch test tests_integ` with AWS credentials (STRANDS_INTEG_TEST_ROLE via OIDC). Non-collaborators get `manual-approval` environment gate.

**Remediation:**
Use `workflow_run` pattern or require manual trigger for fork PR integration tests.

---

### BUG #3 -- MEDIUM: Mutable Branch Pin on Authorization Actions

- **Vulnerability Class:** CI/CD Supply Chain
- **Files:**
  - `strands-agents/docs/.github/workflows/docs-preview.yml`, line 21
  - `strands-agents/docs/.github/workflows/auto-strands-review.yml`
  - `strands-agents/docs/.github/workflows/strands-command.yml`
- **Vulnerable Reference:** `strands-agents/devtools/*@main`

**Description:**
Multiple workflows reference composite actions from `strands-agents/devtools` pinned to `@main` (mutable branch). These actions control authorization gates and receive secrets (AWS_ROLE_ARN, LANGFUSE keys, etc.). A compromise of the devtools repo's main branch would bypass authorization gates in Bugs #1 and #2.

**Remediation:**
Pin all devtools action references to full SHA hashes.

---

### BUG #4 -- MEDIUM: Mutable Branch Pin on Reusable Workflow

- **Vulnerability Class:** CI/CD Supply Chain
- **File:** `amazon-contributing/upstream-to-openfga/.github/workflows/claude-code-review.yaml`, line 18
- **Vulnerable Reference:** `auth0/auth0-ai-pr-analyzer-gh-action/.github/workflows/claude-code-review.yml@main`

**Description:**
Reusable workflow from auth0 org pinned to `@main` with elevated permissions (contents:write, issues:write, pull-requests:write, id-token:write). The entire reusable workflow code is externally controlled and not SHA-pinned.

**Remediation:**
Pin to specific SHA hash instead of @main.

---

### BUG #5 -- LOW: Unregistered PyPI Package Name

- **Vulnerability Class:** Name Squatting
- **File:** `strands-agents/extension-template-python/pyproject.toml`, line 6
- **Vulnerable Reference:** `name = "strands-template"` (PyPI returns HTTP 404)

**Description:**
The extension template declares "strands-template" as its package name but this is NOT registered on PyPI. This is a template repo designed to be cloned and renamed -- no other package depends on it. Risk is limited to user confusion.

**Remediation:**
Register "strands-template" defensively on PyPI or change name to "CHANGE-ME-strands-template".

---

### BUG #6 -- LOW: Unpinned npx Execution in Release Script

- **Vulnerability Class:** CI Pipeline Hygiene
- **File:** `amazon-contributing/upstream-to-openfga/scripts/create-release-pr.sh`, line 124
- **Vulnerable Reference:** `npx keep-a-changelog`

**Description:**
Release script runs `npx keep-a-changelog` without version pinning. npx downloads and executes the latest version at runtime. If the npm package is compromised, arbitrary code runs in release context with git push and PR creation permissions.

**Remediation:**
Pin version: `npx keep-a-changelog@2.0.0`

---

## Summary Table

| Bug | Severity | Vulnerability Class | File(s) |
|-----|----------|---------------------|---------|
| #1  | MEDIUM   | pull_request_target unsafe checkout | strands-agents/docs docs-preview.yml |
| #2  | MEDIUM   | pull_request_target unsafe checkout | strands-agents/agent-builder integ-test.yml |
| #3  | MEDIUM   | Mutable branch pin on auth actions | strands-agents/docs (3 workflows) |
| #4  | MEDIUM   | Mutable branch pin on reusable workflow | amazon-contributing/openfga claude-review |
| #5  | LOW      | Unregistered PyPI package name | strands-agents/extension-template-python |
| #6  | LOW      | Unpinned npx execution | amazon-contributing/openfga release script |

**TOTAL: 6 validated findings**
**CRITICAL: 0 | HIGH: 0 | MEDIUM: 4 | LOW: 2**

---

## Ecosystems Audited (Clean)

- **Python/PyPI:** All strands-agents packages registered on PyPI. All dependencies verified. No dependency confusion.
- **TypeScript/npm:** @strands-agents/sdk published on npm. All deps verified. No squattable names.
- **Go:** openfga, alerting, otel-collector-contrib, pion-webrtc all clean. No claimable replace directives.
- **Rust:** upstream-to-str0m, redis-rs all clean. No git dependencies, all from crates.io.
- **Java:** aurora-dsql-benchbase, hadoop all clean. Standard Maven repos.
- **amazon-contributing forks:** All maintain upstream package names. @grafana scope protected. No added internal deps.
- **amazonlinux repos:** Mostly system tools with no external package dependencies.

## Methodology

- Shallow-cloned all 42 non-archived repositories
- Deployed 6 parallel audit agents (Python, TypeScript, CI/CD, Go/Rust/Java, Dockerfiles/scripts, forks)
- Verified package existence on npm/PyPI/crates.io registries
- Verified GitHub org/repo existence for all action references
- Applied strict exploitability criteria excluding MITM, insider-only, and theoretical issues
