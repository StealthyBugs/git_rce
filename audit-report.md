# Supply Chain & Dependency Confusion Vulnerability Audit Report

**Date:** 2026-03-30
**Scope:** 104 non-archived repositories across `amazon-braket` (14 repos) and `aws-controllers-k8s` (90 repos)
**Methodology:** Automated multi-agent file-by-file analysis with manual validation

---

## Repository Archive Status

### amazon-braket (16 total)
- **Archived (2):** `amazon-braket-ocean-plugin-python`, `amazon-braket-strawberryfields-plugin-python`
- **Active (14):** All others

### aws-controllers-k8s (91 total)
- **Archived (1):** `elasticsearchservice-controller`
- **Active (90):** All others

---

## Validated Findings

---

### BUG #1 — SEVERITY: CRITICAL

**VULNERABILITY CLASS:** Classic Dependency Confusion (Unregistered PyPI Package)
**FILE:** 63+ files: `{controller}/test/e2e/requirements.txt` (line 1 in each)
**VULNERABLE REFERENCE:** `acktest` (package name not registered on PyPI)

**DESCRIPTION:**
The package name `acktest` does NOT exist on PyPI (confirmed 404). It is referenced across 63+ ACK controller repositories. An attacker can register `acktest` on PyPI with a malicious payload containing a postinstall hook that executes arbitrary code.

**ATTACK SCENARIO:**
1. Attacker registers `acktest` on PyPI with a malicious `setup.py` containing a `postinstall` script
2. Any developer who runs `pip install acktest` (without the full git URL) gets the attacker's package
3. Any CI environment where the git URL resolution fails falls back to PyPI resolution
4. Any future project that adds `acktest` as a plain dependency (without `@ git+https://...`) installs the attacker's version

**CODE PATH TRACE:**
`test-infra/setup.py` (defines name='acktest') → `{controller}/test/e2e/requirements.txt` (references it) → `pip install -r requirements.txt` (in CI/dev environments)

**PRODUCTION REACHABILITY:**
While current references use `@ git+https://...` syntax which pins to git, the unregistered name is a standing vulnerability. The package runs in CI environments with access to AWS credentials and source code.

**WHY THIS IS VALID:**
Attacker simply registers `acktest` on PyPI — no privileged access required. Pure external action.

**REMEDIATION:**
Register `acktest` as a placeholder on PyPI owned by the aws-controllers-k8s org. Add `"Private :: Do Not Upload"` classifier if not intended for public distribution.

---

### BUG #2 — SEVERITY: CRITICAL

**VULNERABILITY CLASS:** Classic Dependency Confusion (Unregistered PyPI Package)
**FILE:** `community/docs/requirements.txt` (line 1)
**VULNERABLE REFERENCE:** `acktools` (package name not registered on PyPI)

**DESCRIPTION:**
The package name `acktools` does NOT exist on PyPI (confirmed 404). It is defined in `test-infra/tools/setup.py` and referenced with a git URL in the community docs build.

**ATTACK SCENARIO:**
1. Attacker registers `acktools` on PyPI with malicious code
2. Any developer or CI that runs `pip install acktools` by name gets the attacker's package
3. The community docs build pipeline could be poisoned if git URL resolution fails

**CODE PATH TRACE:**
`test-infra/tools/setup.py` (defines name='acktools') → `community/docs/requirements.txt:1` → docs build pipeline

**WHY THIS IS VALID:**
Attacker registers on PyPI — purely external action, no privileged access.

**REMEDIATION:**
Register `acktools` as a placeholder on PyPI.

---

### BUG #3 — SEVERITY: CRITICAL

**VULNERABILITY CLASS:** GitHub Actions Supply Chain (Mutable Branch Reference on Publish Workflow)
**FILES:**
- `amazon-braket-algorithm-library/.github/workflows/publish-to-pypi.yml` (line 31)
- `amazon-braket-build-tools/.github/workflows/publish-to-pypi.yml` (line 31)
- `amazon-braket-default-simulator-python/.github/workflows/publish-to-pypi.yml` (line 31)
- `amazon-braket-pennylane-plugin-python/.github/workflows/publish-to-pypi.yml` (line 31)
- `amazon-braket-schemas-python/.github/workflows/publish-to-pypi.yml` (line 31)
**VULNERABLE REFERENCE:** `pypa/gh-action-pypi-publish@release/v1`

**DESCRIPTION:**
Five Braket PyPI publish workflows reference `pypa/gh-action-pypi-publish` pinned to the mutable branch `release/v1` instead of a SHA hash. These workflows have `id-token: write` permission for OIDC-based PyPI publishing. A compromise of this branch would allow intercepting the OIDC token and publishing malicious packages to PyPI.

**ATTACK SCENARIO:**
1. Attacker compromises the `pypa/gh-action-pypi-publish` repo (or a maintainer account) and pushes to the `release/v1` branch
2. On next Braket release, the compromised action runs with OIDC token write access
3. Attacker publishes backdoored versions of `amazon-braket-sdk`, `amazon-braket-schemas`, etc. to PyPI

**CODE PATH TRACE:**
`publish-to-pypi.yml` → `pypa/gh-action-pypi-publish@release/v1` (mutable) → OIDC token → PyPI publish

**PRODUCTION REACHABILITY:**
Triggered on every GitHub release publication. These are the actual production package publishing workflows.

**WHY THIS IS VALID:**
Three other Braket repos already correctly SHA-pin this same action to `@ed0c53931b1dc9bd32cbe73a98c7f6766f8a527e`, proving the fix is known. The mutable branch ref is the vulnerability.

**REMEDIATION:**
Pin to SHA: `pypa/gh-action-pypi-publish@ed0c53931b1dc9bd32cbe73a98c7f6766f8a527e`

---

### BUG #4 — SEVERITY: HIGH

**VULNERABILITY CLASS:** GitHub Actions Supply Chain (Mutable Branch Reference — 138-repo blast radius)
**FILES:** 67 `postsubmit.yaml` + 71 `create-release.yml` across all ACK controllers
**Example:** `acm-controller/.github/workflows/postsubmit.yaml` (line 10)
**VULNERABLE REFERENCE:** `aws-controllers-k8s/.github/.github/workflows/reusable-postsubmit.yaml@main`

**DESCRIPTION:**
All ACK controller repos reference reusable workflows from `aws-controllers-k8s/.github` pinned to `@main` instead of a SHA hash. Any push to the `.github` repo's main branch propagates to all controllers.

**ATTACK SCENARIO:**
1. Attacker gains write access to `aws-controllers-k8s/.github` main branch (via compromised maintainer, stolen token, etc.)
2. Modifies reusable workflow to inject malicious code
3. All 67+ controller postsubmit and 71 release workflows execute the injected code with `contents: write` permissions

**CODE PATH TRACE:**
`{controller}/.github/workflows/postsubmit.yaml` → `aws-controllers-k8s/.github/.github/workflows/reusable-postsubmit.yaml@main` (mutable) → runs with write permissions

**REMEDIATION:**
Pin all reusable workflow references to a specific commit SHA.

---

### BUG #5 — SEVERITY: HIGH

**VULNERABILITY CLASS:** GitHub Actions Supply Chain (Third-Party Action — Personal Namespace)
**FILE:** `.github/.github/workflows/reusable-create-release.yaml` (line 16)
**VULNERABLE REFERENCE:** `softprops/action-gh-release@v1`

**DESCRIPTION:**
The release-creation workflow used by all 71 ACK controllers references `softprops/action-gh-release@v1` — a third-party action from a personal GitHub account pinned to a mutable tag. This action runs with `contents: write` permission and creates GitHub releases.

**ATTACK SCENARIO:**
1. If the `softprops` GitHub account is deleted/renamed, the namespace becomes claimable
2. Attacker recreates the account and repo, publishes malicious action at the `v1` tag
3. All ACK controller release workflows execute the attacker's code with write permissions

**CODE PATH TRACE:**
`{controller}/create-release.yml` → `reusable-create-release.yaml` → `softprops/action-gh-release@v1` (mutable tag, personal namespace) → `contents: write`

**REMEDIATION:**
Pin to a specific SHA hash. Consider migrating to `ncipollo/release-action` or GitHub's built-in release API.

---

### BUG #6 — SEVERITY: HIGH

**VULNERABILITY CLASS:** GitHub Actions Supply Chain (Personal Namespace + `pull_request_target`)
**FILES:**
- `amazon-braket-containers/.github/workflows/pr-title-checker.yml` (line 27)
- `amazon-braket-sdk-python/.github/workflows/pr-title-checker.yml` (line 27)
- `amazon-braket-pennylane-plugin-python/.github/workflows/pr-title-checker.yml` (line 27)
**VULNERABLE REFERENCE:** `thehanimo/pr-title-checker@v1.4.3`

**DESCRIPTION:**
Three Braket repos use `thehanimo/pr-title-checker` — a personal GitHub account's action — triggered by `pull_request_target` with `pull-requests: write` permissions and access to `secrets.GITHUB_TOKEN`. If the `thehanimo` account becomes claimable, an attacker can serve a malicious action that runs on every external PR.

**ATTACK SCENARIO:**
1. `thehanimo` account is deleted or renamed, namespace becomes available
2. Attacker registers `thehanimo` on GitHub, creates `pr-title-checker` repo with malicious action at `v1.4.3` tag
3. Malicious action runs with `GITHUB_TOKEN` and `pull-requests: write` on every PR to these Braket repos

**CODE PATH TRACE:**
External PR opened → `pull_request_target` trigger → `thehanimo/pr-title-checker@v1.4.3` → receives `secrets.GITHUB_TOKEN` with write permissions

**REMEDIATION:**
Pin to SHA hash, or replace with a maintained alternative. Remove `pull_request_target` trigger if not needed.

---

### BUG #7 — SEVERITY: HIGH

**VULNERABILITY CLASS:** GitHub Actions Supply Chain (Mutable `@latest` Tag)
**FILES:**
- `Braket.jl/.github/workflows/CI.yml` (lines 40, 81, 122)
- `BraketAHS.jl/.github/workflows/CI.yml` (lines 36, 61)
**VULNERABLE REFERENCE:** `julia-actions/julia-buildpkg@latest`

**DESCRIPTION:**
Five workflow steps reference `julia-actions/julia-buildpkg@latest`, which always resolves to the latest commit on the default branch. This is the most dangerous form of mutable pinning — any push to the `julia-actions` org's repo immediately executes in these workflows.

**ATTACK SCENARIO:**
1. Attacker compromises the `julia-actions` org or a maintainer account
2. Pushes malicious code to `julia-buildpkg` default branch
3. Next CI run of Braket.jl or BraketAHS.jl executes the malicious code

**REMEDIATION:**
Pin to a specific SHA hash.

---

### BUG #8 — SEVERITY: HIGH

**VULNERABILITY CLASS:** Dependency Confusion (Unregistered npm Package with Public Publish Config)
**FILE:** `community/docs/package.json` (lines 2, 10-12)
**VULNERABLE REFERENCE:** `ack-community-docs` (not registered on npm)

**DESCRIPTION:**
The package is named `ack-community-docs` with `"publishConfig": {"access": "public"}` but is NOT registered on npm (confirmed 404). It also lacks `"private": true`. An attacker could register this name on npm.

**ATTACK SCENARIO:**
1. Attacker registers `ack-community-docs` on npm with a malicious `postinstall` script
2. Any environment that runs `npm install ack-community-docs` by name gets the attacker's package

**CODE PATH TRACE:**
`community/docs/package.json` (name: "ack-community-docs") → npm registry (unregistered)

**REMEDIATION:**
Add `"private": true` to package.json (as done in `docs/website/package.json`), or register the name on npm as a placeholder.

---

### BUG #9 — SEVERITY: HIGH

**VULNERABILITY CLASS:** Dependency Confusion (Unregistered PyPI Package)
**FILE:** `test-infra/prow/agent-workflows/agents/pyproject.toml` (line 6)
**VULNERABLE REFERENCE:** `ack-codegen-agent` (not registered on PyPI)

**DESCRIPTION:**
The package name `ack-codegen-agent` does NOT exist on PyPI (confirmed 404). It declares dependencies on `strands-agents`, `boto3`, `mcp`, etc. An attacker could register this name on PyPI.

**ATTACK SCENARIO:**
1. Attacker registers `ack-codegen-agent` on PyPI
2. Any developer or CI that runs `pip install ack-codegen-agent` by name gets the attacker's package

**REMEDIATION:**
Register as placeholder on PyPI, or add `Private :: Do Not Upload` classifier.

---

### BUG #10 — SEVERITY: HIGH

**VULNERABILITY CLASS:** Dependency Reference to Claimable Resource (Personal GitHub Fork)
**FILE:** `sqs-controller/test/e2e/requirements.txt` (line 1)
**VULNERABLE REFERENCE:** `git+https://github.com/michaelhtm/ack-test-infra.git@a9fe15e...`

**DESCRIPTION:**
The sqs-controller uniquely references a **personal fork** (`michaelhtm/ack-test-infra`) instead of the official `aws-controllers-k8s/test-infra` used by all other 62+ controllers. If this personal account is deleted, the namespace becomes claimable.

**ATTACK SCENARIO:**
1. `michaelhtm` account is deleted or renamed
2. Attacker registers `michaelhtm` on GitHub, creates `ack-test-infra` repo
3. sqs-controller CI installs attacker-controlled test framework code

**REMEDIATION:**
Change to `git+https://github.com/aws-controllers-k8s/test-infra.git@<commit>` to match all other controllers.

---

### BUG #11 — SEVERITY: MEDIUM

**VULNERABILITY CLASS:** Subdomain & Infrastructure Takeover (S3 Bucket)
**FILES:**
- `amazon-braket-containers/base/jobs/docker/1.0/py3/Dockerfile.cpu` (line 150)
- `amazon-braket-containers/cudaq/jobs/docker/0.13/py3/Dockerfile.cpu` (line 35)
- `amazon-braket-containers/tensorflow/jobs/docker/2.19/py3/Dockerfile.gpu` (line 30)
**VULNERABLE REFERENCE:** `https://aws-dlinfra-utilities.s3.amazonaws.com/oss_compliance.zip`

**DESCRIPTION:**
Three Dockerfiles download and execute content from S3 bucket `aws-dlinfra-utilities`. S3 bucket names are globally unique; if this bucket is ever deleted, an attacker could recreate it with the same name and serve malicious content. The downloaded zip is unzipped and a script (`generate_oss_compliance.sh`) is `chmod +x` and executed — full RCE.

**ATTACK SCENARIO:**
1. S3 bucket `aws-dlinfra-utilities` is deleted (through account migration, cleanup, etc.)
2. Attacker creates bucket with same name in their AWS account
3. Uploads malicious `oss_compliance.zip` containing backdoored `generate_oss_compliance.sh`
4. Next Docker build fetches and executes attacker's code

**CODE PATH TRACE:**
`Dockerfile.cpu:150` → `curl` from S3 → `unzip` → `chmod +x generate_oss_compliance.sh` → execution

**REMEDIATION:**
Add SHA-256 checksum verification after download. Consider hosting in a dedicated, protected artifact store.

---

### BUG #12 — SEVERITY: MEDIUM

**VULNERABILITY CLASS:** CI/CD Supply Chain (Git Dependencies Pinned to Mutable Branch)
**FILES:**
- `amazon-braket-sdk-python/.github/workflows/additional-pr-checks.yml` (lines 36-37)
- `amazon-braket-default-simulator-python/.github/workflows/additional-pr-checks.yml` (line 35)
**VULNERABLE REFERENCE:**
```
pip install --upgrade git+https://github.com/aws/amazon-braket-schemas-python.git@main
pip install --upgrade git+https://github.com/aws/amazon-braket-default-simulator-python.git@main
```

**DESCRIPTION:**
CI workflows install Python packages from `@main` branches without commit pinning or integrity verification. A compromise of these upstream repos would inject malicious code into CI.

**REMEDIATION:**
Pin to specific commit SHAs instead of `@main`.

---

### BUG #13 — SEVERITY: MEDIUM

**VULNERABILITY CLASS:** CI/CD Supply Chain (Unpinned Git Clone in Workflow)
**FILE:** `BraketSimulator.jl/.github/workflows/codescan-analysis.yml` (line 23)
**VULNERABLE REFERENCE:** `git clone https://github.com/JuliaComputing/semgrep-rules-julia.git`

**DESCRIPTION:**
The code scanning workflow clones a third-party repo (`JuliaComputing/semgrep-rules-julia`) with no ref/commit pinning — it always pulls the latest default branch.

**REMEDIATION:**
Pin to a specific commit SHA: `git clone --branch <tag> --single-branch <url>` or use a commit checkout.

---

### BUG #14 — SEVERITY: MEDIUM

**VULNERABILITY CLASS:** Lockfile Integrity (No Lockfiles for Python Libraries)
**FILES:**
- `amazon-braket-algorithm-library/pyproject.toml`
- `amazon-braket-build-tools/pyproject.toml`
- `amazon-braket-containers/pyproject.toml`
- `amazon-braket-default-simulator-python/pyproject.toml`
- `amazon-braket-pennylane-plugin-python/pyproject.toml`
- `amazon-braket-schemas-python/pyproject.toml`
- `amazon-braket-sdk-python/pyproject.toml`
- `amazon-braket-simulator-v2-python/pyproject.toml`
- `autoqasm/pyproject.toml`

**DESCRIPTION:**
Nine Python library projects declare dependencies in pyproject.toml/setup.cfg but have no corresponding lockfile (no `poetry.lock`, `Pipfile.lock`, or pinned `requirements.txt`). At build/install time, the resolver fetches the latest compatible versions from PyPI, creating a window for supply chain attacks via compromised transitive dependencies.

**REMEDIATION:**
Generate and commit lockfiles, or use `pip-compile` to create pinned requirements files for CI.

---

### BUG #15 — SEVERITY: MEDIUM

**VULNERABILITY CLASS:** Lockfile Integrity (Fully Unpinned Dependencies)
**FILE:** `amazon-braket-containers/src/requirements.txt`
**VULNERABLE REFERENCE:** 11 out of 12 dependencies have no version pins

**DESCRIPTION:**
Dependencies `wheel`, `docker`, `fabric`, `invoke`, `pyfiglet`, `reprint`, `ruamel.yaml`, `boto3`, `black`, `junit-xml`, `urllib3` are all unpinned — any version will be installed. This maximizes the attack surface for compromised package versions.

**REMEDIATION:**
Pin all dependencies to specific versions with hash verification.

---

### BUG #16 — SEVERITY: LOW

**VULNERABILITY CLASS:** Dependency Confusion (Unregistered PyPI Project Names)
**FILES:**
- `amazon-braket-containers/pyproject.toml` (name: "amazon-braket-containers")
- `amazon-braket-examples/pyproject.toml` (name: "amazon-braket-examples")

**DESCRIPTION:**
These project names are not registered on PyPI but follow the `amazon-braket-*` naming convention of packages that ARE on PyPI. An attacker could register them to target developers who assume all `amazon-braket-*` packages are on PyPI.

**REMEDIATION:**
Register as placeholder packages on PyPI, or add `Private :: Do Not Upload` classifier.

---

### BUG #17 — SEVERITY: LOW

**VULNERABILITY CLASS:** Lockfile Integrity (Non-Standard go.local.sum Files)
**FILES:**
- `acmpca-controller/go.local.sum`
- `cloudwatchlogs-controller/go.local.sum`
- `ec2-controller/go.local.sum`
- `eks-controller/go.local.sum`
- `iam-controller/go.local.sum`
- `rds-controller/go.local.sum`

**DESCRIPTION:**
Six controllers have non-standard `go.local.sum` files committed to the repository. These are not recognized by the Go toolchain and could cause confusion about which checksums are authoritative.

**REMEDIATION:**
Remove `go.local.sum` files and add to `.gitignore`.

---

## Summary Table

```
┌─────┬──────────┬──────────────────────────────────────────────┬──────────────────────────────────────────┐
│ Bug │ Severity │ Vulnerability Class                          │ File(s)                                  │
├─────┼──────────┼──────────────────────────────────────────────┼──────────────────────────────────────────┤
│ #1  │ CRITICAL │ Unregistered PyPI package (acktest)           │ 63+ controller test/e2e/requirements.txt │
│ #2  │ CRITICAL │ Unregistered PyPI package (acktools)          │ community/docs/requirements.txt          │
│ #3  │ CRITICAL │ Mutable branch ref on PyPI publish action     │ 5 braket publish-to-pypi.yml             │
│ #4  │ HIGH     │ Mutable branch ref on reusable workflows      │ 138 ACK controller workflow files         │
│ #5  │ HIGH     │ Third-party action (personal namespace)       │ reusable-create-release.yaml             │
│ #6  │ HIGH     │ Personal namespace + pull_request_target       │ 3 braket pr-title-checker.yml            │
│ #7  │ HIGH     │ Mutable @latest tag on CI action              │ Braket.jl, BraketAHS.jl CI.yml           │
│ #8  │ HIGH     │ Unregistered npm package (ack-community-docs) │ community/docs/package.json              │
│ #9  │ HIGH     │ Unregistered PyPI package (ack-codegen-agent) │ test-infra pyproject.toml                │
│ #10 │ HIGH     │ Personal GitHub fork dependency               │ sqs-controller test/e2e/requirements.txt │
│ #11 │ MEDIUM   │ S3 bucket takeover in Dockerfile              │ 3 braket-containers Dockerfiles          │
│ #12 │ MEDIUM   │ Git deps pinned to @main in CI               │ 2 braket workflow files                  │
│ #13 │ MEDIUM   │ Unpinned git clone in CI workflow             │ BraketSimulator.jl codescan-analysis.yml │
│ #14 │ MEDIUM   │ No lockfiles for Python libraries             │ 9 braket pyproject.toml files            │
│ #15 │ MEDIUM   │ Fully unpinned dependencies                   │ braket-containers/src/requirements.txt   │
│ #16 │ LOW      │ Unregistered PyPI project names               │ 2 braket pyproject.toml files            │
│ #17 │ LOW      │ Non-standard go.local.sum files               │ 6 ACK controller repos                  │
└─────┴──────────┴──────────────────────────────────────────────┴──────────────────────────────────────────┘

TOTAL: 17 validated findings
CRITICAL: 3 | HIGH: 7 | MEDIUM: 5 | LOW: 2
```

## Areas Found Clean (No Issues)

- **Go modules:** All 77 go.mod files clean. No `replace` directives. All 141 unique GitHub dependency repos verified as existing. All vanity Go module domains active.
- **Julia packages:** All 8 Project.toml files clean. All deps registered in Julia General registry with matching UUIDs.
- **npm lockfiles:** Both package-lock.json files resolve from registry.npmjs.org with SHA-512 integrity hashes.
- **Python setup.py files:** All 10 setup.py files clean — no cmdclass overrides, no subprocess calls, no external fetches.
- **Python build backends:** All pyproject.toml build-system entries use standard backends (setuptools, hatchling).
- **Docker base images:** All FROM references use official registries (public.ecr.aws, docker.io/library). No claimable namespaces.
- **S3 references:** All other S3 references are test fixtures with fake/parameterized names.
- **.gitmodules:** No submodule files found in any repo.
- **Amazon Braket PyPI packages:** All library packages (amazon-braket-sdk, amazon-braket-schemas, etc.) confirmed registered on PyPI.
