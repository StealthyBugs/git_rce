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

### BUG #1 — SEVERITY: LOW (Downgraded from CRITICAL after validation)

**VULNERABILITY CLASS:** Classic Dependency Confusion (Unregistered PyPI Package — Mitigated by PEP 440 Direct References)
**FILE:** 63+ files: `{controller}/test/e2e/requirements.txt` (line 1 in each)
**VULNERABLE REFERENCE:** `acktest` (package name not registered on PyPI)

**DESCRIPTION:**
The package name `acktest` does NOT exist on PyPI (confirmed 404). It is referenced across 63+ ACK controller repositories. However, **every single reference** uses PEP 440 direct reference syntax (`acktest @ git+https://github.com/aws-controllers-k8s/test-infra.git@<commit-sha>`), which is a hard binding — pip will always fetch from the git URL and will **never fall back to PyPI**. This was confirmed by tracing all install paths (Dockerfile.pytest-image, soak/Dockerfile, build-docs.sh).

**ACTUAL RISK:**
The only exploitation path is social engineering: a developer who sees `acktest` in the codebase and independently runs `pip install acktest`. The current CI/build pipelines are NOT vulnerable through this vector.

**REMEDIATION:**
Register `acktest` as a defensive placeholder on PyPI to prevent social engineering attacks. This is best practice but not urgent.

---

### BUG #2 — SEVERITY: LOW (Downgraded from CRITICAL after validation)

**VULNERABILITY CLASS:** Classic Dependency Confusion (Unregistered PyPI Package — Mitigated by PEP 440 Direct References)
**FILE:** `community/docs/requirements.txt` (line 1)
**VULNERABLE REFERENCE:** `acktools` (package name not registered on PyPI)

**DESCRIPTION:**
The package name `acktools` does NOT exist on PyPI (confirmed 404). It is defined in `test-infra/tools/setup.py` and referenced in `community/docs/requirements.txt`. However, the reference uses PEP 440 direct reference syntax (`acktools @ git+https://...@<commit-sha>#subdirectory=tools`), which means pip will always fetch from the git URL and will **never query PyPI**.

**ACTUAL RISK:**
Same as #1 — social engineering only. The `build-docs.sh` CI script runs `pip install -r requirements.txt` which will use the git URL, not PyPI.

**REMEDIATION:**
Register `acktools` as a defensive placeholder on PyPI.

---

### BUG #3 — SEVERITY: HIGH (Downgraded from CRITICAL after validation)

**VULNERABILITY CLASS:** GitHub Actions Supply Chain (Mutable Branch Reference on Publish Workflow)
**FILES:**
- `amazon-braket-algorithm-library/.github/workflows/publish-to-pypi.yml` (line 31)
- `amazon-braket-build-tools/.github/workflows/publish-to-pypi.yml` (line 31)
- `amazon-braket-default-simulator-python/.github/workflows/publish-to-pypi.yml` (line 31)
- `amazon-braket-pennylane-plugin-python/.github/workflows/publish-to-pypi.yml` (line 31)
- `amazon-braket-schemas-python/.github/workflows/publish-to-pypi.yml` (line 31)
**VULNERABLE REFERENCE:** `pypa/gh-action-pypi-publish@release/v1`

**DESCRIPTION:**
Five Braket PyPI publish workflows reference `pypa/gh-action-pypi-publish` pinned to the mutable branch `release/v1` instead of a SHA hash. These workflows have `id-token: write` permission for OIDC-based PyPI publishing.

**WHY THIS IS HIGH, NOT CRITICAL:**
The `pypa` (Python Packaging Authority) GitHub org is one of the most well-secured open source organizations — they maintain pip, setuptools, and PyPI itself. Exploitation requires compromising the pypa org or a maintainer account with push access to the `release/v1` branch. This is NOT the same as "registering an unclaimed resource" — it requires compromising an established, actively maintained project. However, it IS a real supply chain hygiene gap: 3 sibling Braket repos already correctly SHA-pin to `@ed0c53931b1dc9bd32cbe73a98c7f6766f8a527e`, proving the fix is known and easy.

**CODE PATH TRACE:**
`publish-to-pypi.yml` → `pypa/gh-action-pypi-publish@release/v1` (mutable) → OIDC token → PyPI publish

**PRODUCTION REACHABILITY:**
Triggered on every GitHub release publication. These are the actual production package publishing workflows.

**REMEDIATION:**
Pin to SHA: `pypa/gh-action-pypi-publish@ed0c53931b1dc9bd32cbe73a98c7f6766f8a527e`

---

### BUG #4 — SEVERITY: MEDIUM (Downgraded from HIGH after validation)

**VULNERABILITY CLASS:** GitHub Actions Supply Chain (Mutable Branch Reference — 138-repo blast radius)
**FILES:** 67 `postsubmit.yaml` + 71 `create-release.yml` across all ACK controllers
**Example:** `acm-controller/.github/workflows/postsubmit.yaml` (line 10)
**VULNERABLE REFERENCE:** `aws-controllers-k8s/.github/.github/workflows/reusable-postsubmit.yaml@main`

**DESCRIPTION:**
All ACK controller repos reference reusable workflows from `aws-controllers-k8s/.github` pinned to `@main` instead of a SHA hash. Any push to the `.github` repo's main branch propagates to all controllers.

**WHY MEDIUM, NOT HIGH:**
The `aws-controllers-k8s` is an AWS-owned GitHub org with org-level security controls. An external attacker cannot push to `main` without first compromising an AWS employee's credentials or the org itself — this is NOT registering an unclaimed resource. Notably, the reusable-postsubmit workflow already correctly SHA-pins `actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8`. The `@main` ref is a defense-in-depth gap (internal trust boundary), not an externally exploitable vulnerability.

**REMEDIATION:**
Pin all reusable workflow references to a specific commit SHA.

---

### BUG #5 — SEVERITY: MEDIUM (Downgraded from HIGH after validation)

**VULNERABILITY CLASS:** GitHub Actions Supply Chain (Third-Party Action — Personal Namespace)
**FILE:** `.github/.github/workflows/reusable-create-release.yaml` (line 16)
**VULNERABLE REFERENCE:** `softprops/action-gh-release@v1`

**DESCRIPTION:**
The release-creation workflow used by all 71 ACK controllers references `softprops/action-gh-release@v1` — a third-party action from a personal GitHub account pinned to a mutable tag. This action runs with `contents: write` permission and creates GitHub releases.

**WHY MEDIUM, NOT HIGH:**
`softprops` (Doug Tangren) has 473 repos, 957 followers, works at MongoDB Atlas, and is one of the most prominent GitHub Actions authors. `action-gh-release` has 5,513 stars and was last pushed 3 days ago. The account is extremely active and well-established. GitHub also has protections against re-registering recently-active usernames. The theoretical namespace-reclaim scenario is vanishingly unlikely for such an active account. The real risk is a mutable `@v1` tag (force-push attack if account is compromised), which requires compromising the account — not claiming an unclaimed resource.

**REMEDIATION:**
Pin to a specific SHA hash. Consider migrating to `ncipollo/release-action` or GitHub's built-in release API.

---

### BUG #6 — SEVERITY: MEDIUM (Downgraded from HIGH after validation)

**VULNERABILITY CLASS:** GitHub Actions Supply Chain (Personal Namespace + `pull_request_target`)
**FILES:**
- `amazon-braket-containers/.github/workflows/pr-title-checker.yml` (line 27)
- `amazon-braket-sdk-python/.github/workflows/pr-title-checker.yml` (line 27)
- `amazon-braket-pennylane-plugin-python/.github/workflows/pr-title-checker.yml` (line 27)
**VULNERABLE REFERENCE:** `thehanimo/pr-title-checker@v1.4.3`

**DESCRIPTION:**
Three Braket repos use `thehanimo/pr-title-checker` — a personal GitHub account's action — triggered by `pull_request_target` with `pull-requests: write` permissions and access to `secrets.GITHUB_TOKEN`.

**WHY MEDIUM, NOT HIGH:**
Two factors limit the real-world exploitability:
1. **Account still active**: `thehanimo` (Hani) exists with 62 repos and 35 followers. Account is smaller/less prominent than softprops, but still active. Namespace reclaim requires account deletion first.
2. **Limited blast radius**: The workflow only grants `pull-requests: write` — NOT `contents: write`. Even if exploited, the attacker can only manipulate PR metadata (comments, approvals, labels), NOT modify code or create releases. No code execution in the repository itself.

**The `pull_request_target` trigger is concerning in principle** (it runs in base branch context with elevated privileges), but this specific workflow does NOT checkout PR code — it only reads PR title metadata. The `@v1.4.3` pin is to a specific semver tag (not `@latest` or `@main`), which is slightly better than branch pinning.

**REMEDIATION:**
Pin to SHA hash. Consider replacing with a maintained alternative or a simple regex check in a trusted inline script.

---

### BUG #7 — SEVERITY: MEDIUM (Downgraded from HIGH after validation)

**VULNERABILITY CLASS:** GitHub Actions Supply Chain (Mutable `@latest` Tag)
**FILES:**
- `Braket.jl/.github/workflows/CI.yml` (lines 40, 81, 122)
- `BraketAHS.jl/.github/workflows/CI.yml` (lines 36, 61)
**VULNERABLE REFERENCE:** `julia-actions/julia-buildpkg@latest`

**DESCRIPTION:**
Five workflow steps reference `julia-actions/julia-buildpkg@latest`, which always resolves to the latest commit on the default branch. This is the worst form of mutable pinning — any push to the `julia-actions` org's repo immediately executes in these workflows.

**WHY MEDIUM, NOT HIGH:**
`julia-actions` is an **organization** (not a personal account) with 35 repos and multiple maintainers, run by the Julia community. Exploitation requires compromising the org or a maintainer — not claiming an unclaimed resource. The `@latest` pin is the worst possible practice (worse than `@v1` or `@main`), but the attack surface is org compromise, same class as Bugs #3-5. These are CI workflows (not publish/release), so the blast radius is limited to CI test runs on Braket.jl and BraketAHS.jl.

**ATTACK SCENARIO:**
1. Attacker compromises the `julia-actions` org or a maintainer account
2. Pushes malicious code to `julia-buildpkg` default branch
3. Next CI run of Braket.jl or BraketAHS.jl executes the malicious code

**REMEDIATION:**
Pin to a specific SHA hash.

---

### BUG #8 — SEVERITY: LOW (Downgraded from HIGH after validation)

**VULNERABILITY CLASS:** Unregistered npm Package Name (Project Identity Only — Not a Dependency)
**FILE:** `community/docs/package.json` (lines 2, 10-12)
**VULNERABLE REFERENCE:** `ack-community-docs` (not registered on npm)

**DESCRIPTION:**
The package is named `ack-community-docs` with `"publishConfig": {"access": "public"}` and no `"private": true`. The name is NOT registered on npm.

**WHY LOW, NOT HIGH:**
`ack-community-docs` is the project's own `"name"` field — NOT a dependency of anything. It does not appear in `dependencies` or `devDependencies` of any package.json in the codebase. No code runs `npm install ack-community-docs` by name. When `build-docs.sh` runs `npm install`, it installs devDependencies (babel, bootstrap, hugo-installer, etc.) — not the project's own name. A `package-lock.json` (lockfileVersion 2) is present and pins all actual dependencies to `registry.npmjs.org`. An attacker registering this name on npm accomplishes nothing against this codebase.

The missing `"private": true` is an internal hygiene issue (prevents accidental `npm publish`), not an external attack vector.

**REMEDIATION:**
Add `"private": true` to package.json for hygiene (as done in `docs/website/package.json`).

---

### BUG #9 — SEVERITY: LOW (Downgraded from HIGH after validation)

**VULNERABILITY CLASS:** Unregistered PyPI Package Name (Project Identity Only — Not a Dependency)
**FILE:** `test-infra/prow/agent-workflows/agents/pyproject.toml` (line 6)
**VULNERABLE REFERENCE:** `ack-codegen-agent` (not registered on PyPI)

**DESCRIPTION:**
The package name `ack-codegen-agent` does NOT exist on PyPI (confirmed 404).

**WHY LOW, NOT HIGH:**
`ack-codegen-agent` is the project's own name — NOT a dependency of anything. It is not listed in any requirements.txt or other pyproject.toml. The project uses `uv` for dependency management with a `uv.lock` file that lists it as `source = { editable = "." }` (local directory). The Makefile runs `uv run --refresh python -m ack_builder_agent` (local invocation). The CI script (`prow-job.sh`) runs `python -m workflows resource-addition` (also local). No code anywhere runs `pip install ack-codegen-agent` by name. An attacker registering this on PyPI accomplishes nothing against this codebase.

**REMEDIATION:**
Defensive registration on PyPI is optional hygiene.

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
│ #1  │ LOW      │ Unregistered PyPI name (acktest) — mitigated  │ 63+ controller test/e2e/requirements.txt │
│ #2  │ LOW      │ Unregistered PyPI name (acktools) — mitigated │ community/docs/requirements.txt          │
│ #3  │ HIGH     │ Mutable branch ref on PyPI publish action     │ 5 braket publish-to-pypi.yml             │
│ #4  │ MEDIUM   │ Mutable branch ref on reusable workflows      │ 138 ACK controller workflow files         │
│ #5  │ MEDIUM   │ Third-party action (personal namespace)       │ reusable-create-release.yaml             │
│ #6  │ MEDIUM   │ Personal namespace + pull_request_target       │ 3 braket pr-title-checker.yml            │
│ #7  │ MEDIUM   │ Mutable @latest tag on CI action              │ Braket.jl, BraketAHS.jl CI.yml           │
│ #8  │ LOW      │ Unregistered npm name (project, not dep)      │ community/docs/package.json              │
│ #9  │ LOW      │ Unregistered PyPI name (project, not dep)     │ test-infra pyproject.toml                │
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
CRITICAL: 0 | HIGH: 2 | MEDIUM: 9 | LOW: 6
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
