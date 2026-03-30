# Supply Chain Vulnerability Audit Report
## aws-cloudformation GitHub Organization (30 Non-Archived Repositories)
### Date: 2026-03-30

---

## Repository Classification

- **Total repos in org:** 141
- **Archived:** 111
- **Non-archived (audited):** 30

### Non-Archived Repositories Audited:
1. aws-cloudformation-templates
2. cfn-lint
3. cloudformation-guard
4. cloudformation-coverage-roadmap
5. rain
6. awesome-cloudformation
7. custom-resource-helper
8. cloudformation-cli
9. cfn-lint-visual-studio-code
10. cfn-language-discussion
11. aws-cloudformation-samples
12. cloudformation-template-schema
13. aws-guard-rules-registry
14. cloudformation-cli-python-plugin
15. cloudformation-resource-schema
16. aws-cloudformation-resource-providers-awsutilities-commandrunner
17. cloudformation-cli-go-plugin
18. resource-providers-list
19. cloudformation-cli-typescript-plugin
20. cloudformation-cli-java-plugin
21. cfn-lint-atom
22. cloudformation-pkl
23. cloudformation-languageserver
24. aws-cloudformation-resource-providers-kms
25. resource-schema-guard-rail
26. iac-model-evaluation
27. aws-cloudformation-resource-providers-organizations
28. aws-cloudformation-resource-providers-athena
29. cloudformation-cli-hooks-extension
30. cloudformation-cli-java-plugin-testing-support

---

## Validated Findings

### BUG #1 -- MEDIUM (Revised from CRITICAL): Unregistered npm Package Name "cfn-guard"

- **Vulnerability Class:** Name Squatting / Unregistered Package Name
- **File:** `cloudformation-guard/guard/package.json`, line 2
- **Also:** `cloudformation-guard/guard/ts-lib/package.json`, line 2
- **Vulnerable Reference:** `"name": "cfn-guard"` (npm registry returns HTTP 404)

**Description:**
The package is named "cfn-guard" on npm but this name is NOT registered on the public npm registry (confirmed HTTP 404). No `"private": true` is set. However, current consumers use URL or file: specifiers that do NOT fall back to the npm registry.

**Exploitability Analysis:**
- `action/package.json:80` consumes via URL specifier (`https://gitpkg.now.sh/...`) -- npm resolves the URL directly, NOT the npm registry. **Not vulnerable to classic dependency confusion.**
- `cloudformation-languageserver/package.json:70` consumes via `file:./vendor/cfn-guard` -- local path. **Not vulnerable.**
- The real risk is **name squatting**: an attacker registers "cfn-guard" on npm, and anyone who independently runs `npm install cfn-guard` (e.g., following docs or searching npm) gets the attacker's package.
- Missing `"private": true` also means accidental `npm publish` could succeed if the attacker hasn't claimed the name first.

**Attack Scenario:**
1. Attacker registers "cfn-guard" on npmjs.com with malicious postinstall script
2. Users searching npm for the cfn-guard tool install the attacker's package
3. Postinstall executes, achieving RCE on the developer's machine

**Remediation:**
1. Register "cfn-guard" on npm defensively as a placeholder
2. Add `"private": true` to guard/package.json and guard/ts-lib/package.json
3. Consider using a scoped name: `@aws-cloudformation/cfn-guard`

---

### BUG #2 -- HIGH (Revised from CRITICAL): Third-Party Proxy Service Dependency (gitpkg.now.sh)

- **Vulnerability Class:** Third-Party Proxy Service Dependency
- **File:** `cloudformation-guard/action/package.json`, line 80
- **Vulnerable Reference:** `"cfn-guard": "https://gitpkg.now.sh/aws-cloudformation/cloudformation-guard/guard/ts-lib?33d9931"`

**Description:**
The cfn-guard dependency in the GitHub Action is fetched via gitpkg.now.sh, a third-party service (redirects to gitpkg.vercel.app) operated by an individual developer. This creates a single point of failure external to both npm and GitHub.

**Exploitability Analysis:**
The lockfile (`action/package-lock.json:3067`) contains an `integrity` hash (`sha512-ihSpq...`). When `npm install` runs with the lockfile present, npm verifies the downloaded tarball against this hash. If gitpkg is compromised and serves different content, the hash check **fails and installation errors out**. This provides defense-in-depth.

However, the risk materializes when:
- A developer deletes the lockfile and runs `npm install` (fresh resolution, no hash check)
- The dependency is upgraded and the lockfile is regenerated (new hash from compromised source)
- The CI uses `npm install` (action-ci.yml:22) rather than `npm ci --frozen-lockfile`

**Attack Scenario:**
1. gitpkg.now.sh/gitpkg.vercel.app service is compromised or domain lapses
2. Attacker takes control of the domain/service
3. During a lockfile regeneration, npm fetches a malicious tarball
4. New lockfile is committed with the attacker's integrity hash
5. All subsequent CI runs execute attacker code

**Remediation:**
1. Vendor the cfn-guard ts-lib directly into the action directory
2. Or publish to npm under a scoped name and reference that instead
3. Or use a git submodule/subtree instead of a proxy service
4. Switch CI from `npm install` to `npm ci --frozen-lockfile`

---

### BUG #3 -- LOW (Revised from HIGH): Unregistered npm Package Name "vscode-cfn-lint"

- **Vulnerability Class:** Name Squatting (Hygiene Issue)
- **Files:** `cfn-lint-visual-studio-code/package.json`, `server/package.json`, `client/package.json` (all line 2)
- **Vulnerable Reference:** `"name": "vscode-cfn-lint"` (npm registry returns HTTP 404)

**Description:**
Three package.json files use the name "vscode-cfn-lint" which does not exist on npm (HTTP 404). None have `"private": true`.

**Exploitability Analysis (Revised):**
This is a **VS Code extension** (`"engines": {"vscode": "^1.52.0"}`, `"publisher": "kddejong"`), distributed via the VS Code Marketplace, NOT npm. Nobody runs `npm install vscode-cfn-lint`. The `name` field identifies the extension for VS Code packaging. The postinstall script installs subdirectory dependencies — npm never resolves `vscode-cfn-lint` from the registry. **Not practically exploitable.**

**Remediation:**
Add `"private": true` to all three package.json files (hygiene fix).

---

### BUG #4 -- LOW (Revised from HIGH): Unregistered npm Package Name "guard-rail-vscode"

- **Vulnerability Class:** Name Squatting (Hygiene Issue)
- **File:** `resource-schema-guard-rail/vscode-extension/package.json`, line 2
- **Vulnerable Reference:** `"name": "guard-rail-vscode"` (npm registry returns HTTP 404)

**Description:**
Package named "guard-rail-vscode" does not exist on npm (HTTP 404). No `"private": true` set.

**Exploitability Analysis (Revised):**
This is a **VS Code extension** (`"engines": {"vscode": "^1.80.0"}`, `"publisher": "guard-rail"`), distributed via VS Code Marketplace. No npm install path exists. **Not practically exploitable.**

**Remediation:**
Add `"private": true` to package.json (hygiene fix).

---

### BUG #5 -- LOW (Revised from HIGH): Unregistered npm Package Name "atom-cfn-lint"

- **Vulnerability Class:** Name Squatting (Hygiene Issue)
- **File:** `cfn-lint-atom/package.json`, line 2
- **Vulnerable Reference:** `"name": "atom-cfn-lint"` (npm registry returns HTTP 404)

**Description:**
Package named "atom-cfn-lint" does not exist on npm (HTTP 404). No `"private": true`.

**Exploitability Analysis (Revised):**
This is an **Atom editor package** (`"engines": {"atom": ">=1.0.0 <2.0.0"}`). Atom was discontinued Dec 2022. Packages were installed via `apm` (Atom's own registry, not npm). The apm infrastructure is defunct. Zero user base. **Not practically exploitable.**

**Remediation:**
Archive the repository since Atom is discontinued.

---

### BUG #6 -- LOW (Revised from HIGH): Unpinned GitHub Action on Master Branch (crate-ci/typos)

- **Vulnerability Class:** GitHub Actions Hygiene
- **File:** `cloudformation-guard/.github/workflows/pr.yml`, line 100
- **Vulnerable Reference:** `uses: crate-ci/typos@master`

**Description:**
GitHub Action pinned to "master" branch instead of a SHA hash.

**Exploitability Analysis (Revised):**
crate-ci/typos has ~3,862 stars, was pushed to recently, and is actively maintained. Exploitation requires compromising a crate-ci maintainer account (nation-state level). On the `pull_request` trigger path (external PRs), the action has **no secrets access** and a read-only token. **Not practically exploitable by external attacker.**

**Remediation:**
Pin to a specific SHA (hygiene improvement).

---

### BUG #7 -- LOW (Revised from HIGH): Curl-Pipe-Shell with Secrets in Scope

- **Vulnerability Class:** CI Pipeline Hygiene (Requires Insider Access)
- **Files:**
  - `aws-guard-rules-registry/.github/workflows/ci.yml`, lines 20, 28
  - `aws-guard-rules-registry/.github/workflows/build.yml`, lines 19, 27
  - `aws-guard-rules-registry/.github/workflows/publish.yml`, lines 25, 33
- **Vulnerable Reference:** `curl ... https://raw.githubusercontent.com/aws-cloudformation/cloudformation-guard/main/install-guard.sh | sh`

**Description:**
Six instances across three workflow files download and execute install-guard.sh from the main branch.

**Exploitability Analysis (Revised):**
The script is fetched from **another repo in the same AWS org** (`aws-cloudformation/cloudformation-guard`). External attacker cannot modify it. The `publish.yml` with ECR credentials only triggers on **push to the `publish` branch** (requires write access). The `ci.yml` triggered by external PRs has **no secrets in scope**. **Requires insider access — not exploitable by external attacker.**

**Remediation:**
Pin to a specific commit SHA in the URL (hygiene improvement).

---

### BUG #8 -- LOW (Revised from HIGH): Remote Unpinned requirements.txt Install

- **Vulnerability Class:** CI Pipeline Hygiene (Requires Insider Access)
- **Files:**
  - `cloudformation-cli-go-plugin/.github/workflows/pr-ci.yml`, line 39
  - `cloudformation-cli-python-plugin/.github/workflows/pr-ci.yml`, line 26
  - `cloudformation-cli-typescript-plugin/.github/workflows/ci.yml`, line 74
- **Vulnerable Reference:** `pip install -r https://raw.githubusercontent.com/aws-cloudformation/aws-cloudformation-rpdk/master/requirements.txt`

**Description:**
Three CI workflows install Python dependencies from a remote requirements.txt from a sibling repo.

**Exploitability Analysis (Revised):**
All requirements.txt URLs point to **sibling repos in the same `aws-cloudformation` org**. External attacker cannot modify them. CI workflows triggered by fork PRs have **no secrets** (TypeScript plugin uses the well-known AWS example key `AKIAIOSFODNN7EXAMPLE`). **Requires insider access — not exploitable by external attacker.**

**Remediation:**
Pin to specific commit SHA or vendor locally (hygiene improvement).

---

### BUG #9 -- LOW (Revised from HIGH): Curl-Pipe-Shell for golangci-lint Installer

- **Vulnerability Class:** CI Pipeline Hygiene
- **File:** `cloudformation-cli-go-plugin/.github/workflows/pr-ci.yml`, line 44
- **Vulnerable Reference:** `curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.55.2`

**Description:**
The golangci-lint installer script is fetched from the master branch and piped to sh.

**Exploitability Analysis (Revised):**
golangci-lint has **18,730 stars**, was pushed yesterday, and is one of the most popular Go tools. The install script **does checksum verification** of downloaded binaries. The version is pinned (`v1.55.2`). The CI runner has **no secrets**. Exploitation requires compromising a massively popular project (nation-state level). **Not practically exploitable.**

**Remediation:**
Use the official golangci-lint GitHub Action pinned to SHA (hygiene improvement).

---

### BUG #10 -- LOW (Revised from HIGH): Hardcoded S3 Bucket for Lambda Code Source

- **Vulnerability Class:** Infrastructure Hygiene
- **File:** `aws-cloudformation-templates/Solutions/WebApp/webapp.yaml`, lines 12, 716
- **Also:** `aws-cloudformation-templates/Solutions/WebApp/webapp.json`, lines 12, 1295-1296
- **Vulnerable Reference:** `S3Bucket: rain-artifacts-207567786752-us-east-1`

**Description:**
A CloudFormation sample template hardcodes an S3 bucket as the default source for Lambda code.

**Exploitability Analysis (Revised):**
The bucket **currently exists** and is owned by an active AWS account (Rain project maintainer). The template is explicitly a **sample** ("Adapt this template to your needs and thoroughly test it"). No reasonable user deploys this unmodified — it creates a full web app requiring custom business logic. The attack requires the bucket owner to delete it first (extremely unlikely for an active AWS team). Note: line 716 hardcodes the bucket instead of referencing the parameter (line 635 uses `!Ref`) — this is a **code quality bug**, not a security vulnerability. **Not practically exploitable.**

**Remediation:**
Fix line 716 to use `!Ref LambdaCodeS3Bucket` instead of hardcoding (code quality fix).

---

### BUG #11 -- MEDIUM: Unmaintained GitHub Action (actions-rs/cargo)

- **Vulnerability Class:** GitHub Actions Supply Chain
- **File:** `cloudformation-guard/.github/workflows/pr.yml`, line 118
- **Vulnerable Reference:** `uses: actions-rs/cargo@v1`

**Description:**
The actions-rs organization has been unmaintained since 2022. While the repos still exist, the org is effectively abandoned. The v1 tag is mutable and the org could be transferred or compromised.

**Remediation:**
Replace with actions-rust-lang equivalents or pin to SHA.

---

### BUG #12 -- MEDIUM: Deprecated Codecov Bash Uploader

- **Vulnerability Class:** CI Pipeline Supply Chain
- **File:** `cloudformation-cli-typescript-plugin/.github/workflows/ci.yml`, lines 98-100
- **Vulnerable Reference:** `curl -s https://codecov.io/bash > codecov.sh`

**Description:**
Uses the deprecated Codecov bash uploader (famously compromised in April 2021 supply chain attack). Downloads the uploader script without integrity verification.

**Remediation:**
1. Replace with `codecov/codecov-action` GitHub Action (pinned to SHA)
2. Or use the new Codecov CLI uploader with integrity verification

---

### BUG #13 -- MEDIUM: Archived Repo CI Script Download

- **Vulnerability Class:** CI Pipeline Supply Chain
- **File:** `cfn-lint-atom/.travis.yml`, line 20
- **Vulnerable Reference:** `curl -s -O https://raw.githubusercontent.com/atom/ci/master/build-package.sh`

**Description:**
Travis CI downloads and executes a build script from the atom/ci repo. The Atom editor project was archived by GitHub in December 2022. The atom org and repo still exist but are frozen -- no security patches.

**Remediation:**
1. Archive the cfn-lint-atom repo since Atom is discontinued
2. Or vendor the build script locally

---

### BUG #14 -- MEDIUM: Docker Image with Deleted Source Repo

- **Vulnerability Class:** Docker Supply Chain
- **File:** `cloudformation-cli-typescript-plugin/.github/workflows/cd.yml`, line 78
- **Vulnerable Reference:** `uses: docker://antonyurchenko/git-release:v3.4.2`

**Description:**
References a Docker Hub image whose GitHub source repo (antonyurchenko/git-release) returns 404. The Docker Hub image still exists (published 2020-10-25) but the source code is no longer auditable. Docker tags are mutable -- the account owner or a compromiser could replace the image.

**Remediation:**
1. Replace with a maintained GitHub Action (e.g., softprops/action-gh-release)
2. Or pin Docker image by digest (`sha256:...`)

---

### BUG #15 -- MEDIUM: Go Module Repo Transfer Redirect

- **Vulnerability Class:** Dependency Reference to Redirected Resource
- **File:** `rain/go.mod`, line 7
- **Vulnerable Reference:** `github.com/appscode/jsonpatch`

**Description:**
The Go module path references `github.com/appscode/jsonpatch` which returns HTTP 301 redirect to `github.com/gomodules/jsonpatch`. If the appscode org recreates a repo named "jsonpatch", the redirect breaks and the new repo takes precedence.

**Remediation:**
Update go.mod to reference `github.com/gomodules/jsonpatch` directly.

---

### BUG #16 -- MEDIUM: Unpinned Cross-Repo Schema Fetch in CI

- **Vulnerability Class:** CI Pipeline Supply Chain
- **File:** `cloudformation-cli/.github/workflows/schema-updater.yaml`, lines 15-18
- **Vulnerable Reference:** `curl https://raw.githubusercontent.com/aws-cloudformation/aws-cloudformation-resource-schema/master/src/main/resources/schema/*.json`

**Description:**
Automated workflow fetches JSON schema files from another repo's master branch via curl without integrity verification and commits them directly to the repository. Schemas are distributed in the cloudformation-cli PyPI package.

**Remediation:**
Pin to specific commit SHA in the curl URLs.

---

### BUG #17 -- MEDIUM: Generic S3 Bucket Name Defaults in Templates

- **Vulnerability Class:** Infrastructure Resource Squatting
- **Files:**
  - `aws-cloudformation-templates/EMR/EMRCLusterGangliaWithSparkOrS3backedHbase.yaml`, lines 38, 43
  - `aws-cloudformation-templates/EMR/EMRClusterWithAdditionalSecurityGroups.yaml`, lines 45, 50
- **Vulnerable Reference:** `s3://emrclusterlogbucket/`, `s3://emrclusterdatabucket/`

**Description:**
EMR CloudFormation templates use generic S3 bucket names as default parameter values. These buckets currently exist (owned by unknown party). Users deploying with defaults send EMR logs/data to buckets they don't own.

**Remediation:**
Remove default values for S3 bucket parameters or use clearly-marked placeholder values.

---

## Summary Table

| Bug | Severity | Vulnerability Class | File(s) |
|-----|----------|---------------------|---------|
| #1  | MEDIUM   | Unregistered npm package: cfn-guard (name squat) | cloudformation-guard/guard/package.json |
| #2  | HIGH     | Third-party proxy service dependency | cloudformation-guard/action/package.json |
| #3  | LOW      | VS Code ext name not on npm (hygiene) | cfn-lint-visual-studio-code/*.json |
| #4  | LOW      | VS Code ext name not on npm (hygiene) | resource-schema-guard-rail/vscode-extension/package.json |
| #5  | LOW      | Atom pkg name not on npm (discontinued) | cfn-lint-atom/package.json |
| #6  | LOW      | Unpinned GH Action (well-maintained) | cloudformation-guard/.github/workflows/pr.yml |
| #7  | LOW      | Curl-pipe-sh (requires insider access) | aws-guard-rules-registry/.github/workflows/*.yml |
| #8  | LOW      | Remote requirements.txt (requires insider) | 3 repos' .github/workflows/pr-ci.yml |
| #9  | LOW      | Curl-pipe-sh (well-maintained, no secrets) | cloudformation-cli-go-plugin/.github/workflows/pr-ci |
| #10 | LOW      | Hardcoded S3 bucket (sample template) | aws-cloudformation-templates/Solutions/WebApp/webapp |
| #11 | MEDIUM   | Unmaintained GH Action (actions-rs) | cloudformation-guard/.github/workflows/pr.yml |
| #12 | MEDIUM   | Deprecated codecov bash uploader | cloudformation-cli-typescript-plugin/.github/wf/ci |
| #13 | MEDIUM   | Archived repo CI script download | cfn-lint-atom/.travis.yml |
| #14 | MEDIUM   | Docker image with deleted source repo | cloudformation-cli-typescript-plugin/.github/wf/cd |
| #15 | MEDIUM   | Go module repo transfer redirect | rain/go.mod |
| #16 | MEDIUM   | Unpinned cross-repo schema fetch | cloudformation-cli/.github/workflows/schema-updater |
| #17 | MEDIUM   | Generic S3 bucket name defaults | aws-cloudformation-templates/EMR/*.yaml |

**TOTAL: 17 findings**
**HIGH: 1 | MEDIUM: 8 | LOW: 8**

**Note:** After deep exploitability analysis, most originally-HIGH findings were downgraded. Bugs #3-#5 are VS Code/Atom extensions not distributed via npm. Bugs #6-#9 require insider access or compromising massively popular projects. Bug #10 is a sample template with an active bucket. Only Bug #2 (gitpkg.now.sh third-party proxy) remains HIGH due to genuine external single-point-of-failure risk.

---

## Ecosystems Audited (Clean)

The following ecosystems were audited and found to have no exploitable findings:

- **Python/PyPI:** All 11 setup.py/requirements.txt files. All packages exist on PyPI, no dependency confusion vectors.
- **Maven/Java:** All 20+ pom.xml files. `software.amazon.*` namespace controlled by AWS. No exploitable SNAPSHOT or repository issues.
- **Rust/Cargo:** All Cargo.toml files. `cfn-guard` crate exists on crates.io, owned by AWS.
- **Pkl:** PklProject files reference `pkg.pkl-lang.org` (official Pkl registry). Clean.
- **Git Submodules:** No `.gitmodules` files found in any repo.

---

## Methodology

- Shallow-cloned all 30 non-archived repositories
- Scanned all package manifests, lockfiles, CI/CD pipelines, Dockerfiles, shell scripts, and source code
- Verified npm/PyPI/crates.io package existence via registry HTTP checks
- Verified GitHub org/repo existence via HTTP status codes
- Checked S3 bucket existence via HTTP probes
- Checked Docker Hub image existence and source repo status
- Cross-referenced all findings to eliminate false positives (MITM, well-maintained packages, properly cached modules)
