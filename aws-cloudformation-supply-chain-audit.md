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

### BUG #1 -- CRITICAL: Unregistered npm Package Name "cfn-guard"

- **Vulnerability Class:** Dependency Confusion / Unregistered Package Name
- **File:** `cloudformation-guard/guard/package.json`, line 2
- **Also:** `cloudformation-guard/guard/ts-lib/package.json`, line 2
- **Vulnerable Reference:** `"name": "cfn-guard"` (npm registry returns HTTP 404)

**Description:**
The package is named "cfn-guard" on npm but this name is NOT registered on the public npm registry (confirmed HTTP 404). No `"private": true` is set. This package is actively consumed as a dependency by other repos in the org.

**Attack Scenario:**
1. Attacker registers "cfn-guard" on npmjs.com
2. Publishes version 99.0.0 with a postinstall script containing malicious code
3. Any developer/CI running `npm install cfn-guard` by name, or any resolver that falls back to the public registry, pulls the attacker's package
4. The postinstall script executes automatically, achieving RCE

**Code Path Trace:**
- `guard/package.json` (name: cfn-guard, no private:true)
- -> `action/package.json:80` (consumed via gitpkg URL)
- -> `cloudformation-languageserver/package.json:70` (consumed via `file:./vendor/cfn-guard`)
- -> `guard/ts-lib/package.json` (also named cfn-guard, also no private:true)

**Production Reachability:**
This package is consumed by the cloudformation-guard GitHub Action and the cloudformation-languageserver. Direct npm install by name hits the public registry.

**Remediation:**
1. Immediately register "cfn-guard" on npm as a placeholder
2. Add `"private": true` to guard/package.json and guard/ts-lib/package.json
3. Consider using a scoped name: `@aws-cloudformation/cfn-guard`

---

### BUG #2 -- CRITICAL: Third-Party Proxy Service Dependency (gitpkg.now.sh)

- **Vulnerability Class:** Third-Party Proxy Service Dependency
- **File:** `cloudformation-guard/action/package.json`, line 80
- **Vulnerable Reference:** `"cfn-guard": "https://gitpkg.now.sh/aws-cloudformation/cloudformation-guard/guard/ts-lib?33d9931"`

**Description:**
The cfn-guard dependency in the GitHub Action is fetched via gitpkg.now.sh, a third-party service (redirects to gitpkg.vercel.app) operated by an individual developer. This creates a single point of failure external to both npm and GitHub.

**Attack Scenario:**
1. gitpkg.now.sh/gitpkg.vercel.app service is compromised, sold, or domain lapses
2. Attacker takes control of the domain/service
3. Service returns a malicious tarball instead of the real package
4. Every `npm install` in the cloudformation-guard action pulls attacker code
5. The action runs in CI with GITHUB_TOKEN and potentially other secrets

**Code Path Trace:**
- `action/package.json:80` -> npm resolver -> gitpkg.now.sh proxy
- -> `action/package-lock.json:3067` (resolved URL)
- -> npm install -> node_modules/cfn-guard -> action execution

**Remediation:**
1. Vendor the cfn-guard ts-lib directly into the action directory
2. Or publish to npm under a scoped name and reference that instead
3. Or use a git submodule/subtree instead of a proxy service

---

### BUG #3 -- HIGH: Unregistered npm Package Name "vscode-cfn-lint"

- **Vulnerability Class:** Dependency Confusion / Unregistered Package Name
- **Files:** `cfn-lint-visual-studio-code/package.json`, `server/package.json`, `client/package.json` (all line 2)
- **Vulnerable Reference:** `"name": "vscode-cfn-lint"` (npm registry returns HTTP 404)

**Description:**
Three package.json files use the name "vscode-cfn-lint" which does not exist on npm (HTTP 404). None have `"private": true`. The root package.json has a postinstall script (line 58) that runs `npm install` in server/ and client/ subdirectories.

**Attack Scenario:**
1. Attacker registers "vscode-cfn-lint" on npm
2. Root package.json has `postinstall: "cd server && npm install && cd ../client && npm install"`
3. Any user running `npm install vscode-cfn-lint` gets attacker's code with automatic postinstall execution

**Remediation:**
1. Register "vscode-cfn-lint" on npm defensively
2. Add `"private": true` to all three package.json files

---

### BUG #4 -- HIGH: Unregistered npm Package Name "guard-rail-vscode"

- **Vulnerability Class:** Dependency Confusion / Unregistered Package Name
- **File:** `resource-schema-guard-rail/vscode-extension/package.json`, line 2
- **Vulnerable Reference:** `"name": "guard-rail-vscode"` (npm registry returns HTTP 404)

**Description:**
Package named "guard-rail-vscode" does not exist on npm (HTTP 404). No `"private": true` set. Unscoped name claimable by any attacker.

**Remediation:**
1. Add `"private": true` to package.json
2. Register the name defensively on npm

---

### BUG #5 -- HIGH: Unregistered npm Package Name "atom-cfn-lint"

- **Vulnerability Class:** Dependency Confusion / Unregistered Package Name
- **File:** `cfn-lint-atom/package.json`, line 2
- **Vulnerable Reference:** `"name": "atom-cfn-lint"` (npm registry returns HTTP 404)

**Description:**
Package named "atom-cfn-lint" does not exist on npm (HTTP 404). No `"private": true`. The Atom editor is discontinued, but the package and Travis CI config are still active.

**Remediation:**
1. Add `"private": true` to package.json
2. Archive the repository since Atom is discontinued

---

### BUG #6 -- HIGH: Unpinned GitHub Action on Master Branch (crate-ci/typos)

- **Vulnerability Class:** GitHub Actions Supply Chain
- **File:** `cloudformation-guard/.github/workflows/pr.yml`, line 100
- **Vulnerable Reference:** `uses: crate-ci/typos@master`

**Description:**
GitHub Action pinned to "master" branch instead of a SHA hash or immutable tag. The master branch is a moving target -- any push to it immediately changes what code runs in CI.

**Attack Scenario:**
1. Attacker compromises a crate-ci org member's GitHub account
2. Pushes malicious code to master branch of typos repo
3. All subsequent PR builds in cloudformation-guard execute the attacker's code with access to GITHUB_TOKEN and repo secrets

**Remediation:**
Pin to a specific SHA: `uses: crate-ci/typos@<full-sha-hash>`

---

### BUG #7 -- HIGH: Curl-Pipe-Shell with Secrets in Scope

- **Vulnerability Class:** CI Pipeline Supply Chain
- **Files:**
  - `aws-guard-rules-registry/.github/workflows/ci.yml`, lines 20, 28
  - `aws-guard-rules-registry/.github/workflows/build.yml`, lines 19, 27
  - `aws-guard-rules-registry/.github/workflows/publish.yml`, lines 25, 33
- **Vulnerable Reference:** `curl ... https://raw.githubusercontent.com/aws-cloudformation/cloudformation-guard/main/install-guard.sh | sh`

**Description:**
Six instances across three workflow files download and execute install-guard.sh from the main branch without integrity verification. The publish.yml workflow has AWS ECR credentials (ECR_AWS_ACCESS_KEY_ID, ECR_AWS_SECRET_ACCESS_KEY) in scope.

**Attack Scenario:**
1. Attacker with write access to cloudformation-guard main branch modifies install-guard.sh
2. All CI runs in aws-guard-rules-registry execute the modified script
3. publish.yml runs with ECR credentials -- attacker exfiltrates them

**Remediation:**
1. Pin to a specific commit SHA in the URL
2. Download, verify checksum, then execute
3. Or vendor the script locally

---

### BUG #8 -- HIGH: Remote Unpinned requirements.txt Install

- **Vulnerability Class:** CI Pipeline Supply Chain
- **Files:**
  - `cloudformation-cli-go-plugin/.github/workflows/pr-ci.yml`, line 39
  - `cloudformation-cli-python-plugin/.github/workflows/pr-ci.yml`, line 26
  - `cloudformation-cli-typescript-plugin/.github/workflows/ci.yml`, line 74
- **Vulnerable Reference:** `pip install -r https://raw.githubusercontent.com/aws-cloudformation/aws-cloudformation-rpdk/master/requirements.txt`

**Description:**
Three CI workflows install Python dependencies from a remote requirements.txt fetched from the master branch of another repo without lockfile or hash verification.

**Attack Scenario:**
1. Attacker with write access to cloudformation-cli adds a malicious package to requirements.txt
2. All three downstream repos' CI pipelines install it on next run

**Remediation:**
1. Pin the URL to a specific commit SHA
2. Or vendor a local copy of requirements.txt
3. Use pip's `--require-hashes` for integrity verification

---

### BUG #9 -- HIGH: Curl-Pipe-Shell for golangci-lint Installer

- **Vulnerability Class:** CI Pipeline Supply Chain
- **File:** `cloudformation-cli-go-plugin/.github/workflows/pr-ci.yml`, line 44
- **Vulnerable Reference:** `curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.55.2`

**Description:**
The golangci-lint installer script is fetched from the master branch (mutable reference) and piped directly to sh. While the binary version is pinned (v1.55.2), the installer script itself is not integrity-verified.

**Remediation:**
1. Use the official golangci-lint GitHub Action (pinned to SHA) instead
2. Or download the script at a pinned commit with checksum verification

---

### BUG #10 -- HIGH: Hardcoded S3 Bucket for Lambda Code Source

- **Vulnerability Class:** Infrastructure Takeover
- **File:** `aws-cloudformation-templates/Solutions/WebApp/webapp.yaml`, lines 12, 716
- **Also:** `aws-cloudformation-templates/Solutions/WebApp/webapp.json`, lines 12, 1295-1296
- **Vulnerable Reference:** `S3Bucket: rain-artifacts-207567786752-us-east-1`

**Description:**
A CloudFormation template hardcodes a specific S3 bucket (including an AWS account ID) as the default source for Lambda function code. If this bucket is ever deleted, the name becomes globally claimable by any AWS account.

**Attack Scenario:**
1. The account 207567786752 owner deletes the bucket
2. Attacker creates bucket with same name in their own account
3. Uploads malicious Lambda code with the expected S3 key
4. Any user deploying this template with default parameters gets attacker's code running as a Lambda function

**Remediation:**
1. Remove the hardcoded bucket reference
2. Require users to provide their own S3 bucket (no default)
3. Or use inline code / SAM packaging

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
| #1  | CRITICAL | Unregistered npm package: cfn-guard | cloudformation-guard/guard/package.json |
| #2  | CRITICAL | Third-party proxy service dependency | cloudformation-guard/action/package.json |
| #3  | HIGH     | Unregistered npm package: vscode-cfn-lint | cfn-lint-visual-studio-code/*.json |
| #4  | HIGH     | Unregistered npm package: guard-rail-vscode | resource-schema-guard-rail/vscode-extension/package.json |
| #5  | HIGH     | Unregistered npm package: atom-cfn-lint | cfn-lint-atom/package.json |
| #6  | HIGH     | Unpinned GH Action (master branch) | cloudformation-guard/.github/workflows/pr.yml |
| #7  | HIGH     | Curl-pipe-sh with secrets in scope | aws-guard-rules-registry/.github/workflows/*.yml |
| #8  | HIGH     | Remote unpinned requirements.txt install | 3 repos' .github/workflows/pr-ci.yml |
| #9  | HIGH     | Curl-pipe-sh for golangci-lint installer | cloudformation-cli-go-plugin/.github/workflows/pr-ci |
| #10 | HIGH     | Hardcoded S3 bucket for Lambda code | aws-cloudformation-templates/Solutions/WebApp/webapp |
| #11 | MEDIUM   | Unmaintained GH Action (actions-rs) | cloudformation-guard/.github/workflows/pr.yml |
| #12 | MEDIUM   | Deprecated codecov bash uploader | cloudformation-cli-typescript-plugin/.github/wf/ci |
| #13 | MEDIUM   | Archived repo CI script download | cfn-lint-atom/.travis.yml |
| #14 | MEDIUM   | Docker image with deleted source repo | cloudformation-cli-typescript-plugin/.github/wf/cd |
| #15 | MEDIUM   | Go module repo transfer redirect | rain/go.mod |
| #16 | MEDIUM   | Unpinned cross-repo schema fetch | cloudformation-cli/.github/workflows/schema-updater |
| #17 | MEDIUM   | Generic S3 bucket name defaults | aws-cloudformation-templates/EMR/*.yaml |

**TOTAL: 17 validated findings**
**CRITICAL: 2 | HIGH: 8 | MEDIUM: 7**

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
