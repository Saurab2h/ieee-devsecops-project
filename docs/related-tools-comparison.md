# Related Tools Survey — Scan-Output Policy Gates
# Addresses Reviewer 1 Critique #9

This document surveys existing tools that perform security-gate decisions
on vulnerability scan output, positioning this paper's OPA approach against
each. This comparison belongs in the paper's Related Work section.

---

## Tool Comparison Table

| Tool | Input | Gate Decision Output | Second Policy | Cross-Input | Jenkins-Native | Reference |
|------|-------|---------------------|---------------|-------------|----------------|-----------|
| **Trivy `--exit-code`** | Trivy scan (internal) | Exit code 0/1 only | No (re-run required) | No | Yes (CLI) | [Trivy docs] |
| **`conftest`** | Any structured data (JSON/YAML) | Pass/Fail + violation messages | Yes (new Rego rule) | No (one input at a time) | Yes (CLI) | [Open Policy Agent] |
| **`trivy-operator`** | Kubernetes cluster scan | Kubernetes CRD events | Via Kubernetes policies | No | No (K8s only) | [Aqua Security] |
| **GitHub dependency-review-action** | GitHub dependency graph | PR check pass/fail | Via config YAML | No | No (GitHub Actions only) | [GitHub docs] |
| **This paper's OPA gate** | Trivy JSON + Docker inspect | Structured JSON + violation messages | Yes (+3 Rego lines) | Yes (provenance gate) | Yes (CLI + Jenkins) | This work |

---

## Detailed Analysis

### 1. Trivy `--exit-code 1 --severity CRITICAL`

**What it does:** Trivy has a built-in `--exit-code` flag that exits non-zero
if any vulnerability of the specified severity is found. This is the simplest
possible severity gate.

**Why this paper's approach is different:**

- `--exit-code` produces **no structured output about the decision**. It exits
  1, but Jenkins cannot interrogate *which* CVE triggered it, *how many* were
  found, or what the policy rule ID was. Our OPA gate produces a full JSON
  decision document with per-rule violation messages.

- `--exit-code` **only evaluates Trivy output**. It cannot be composed with
  the Docker config gate (docker.rego) in a single policy evaluation.

- `--exit-code` **cannot cross-reference two inputs**. Our provenance gate
  (policies/provenance-gate.rego) correlates Trivy CVE IDs with
  Dependency-Check CVE IDs simultaneously — identifying the 27 dual-scope
  CVEs. This is architecturally impossible with `--exit-code`.

- `--exit-code` is **not policy-as-code**. There is no policy file, no
  version control for the threshold, no unit test suite. The OPA Rego files
  in this repository are version-controlled, testable with `opa test`, and
  auditable independently of the tool that runs them.

**Cite as:** Aquasecurity. "Trivy: severity filtering." 
https://aquasecurity.github.io/trivy/latest/docs/configuration/filtering/

---

### 2. `conftest` (Open Policy Agent project)

**What it does:** `conftest` is a CLI wrapper around OPA that evaluates
Rego policies against structured data files. It is commonly used for
Kubernetes manifests and Terraform plans.

**Why this paper's approach is different:**

- `conftest` is the **closest prior art** to this paper's OPA gate approach.
  Both use Rego policies evaluated against JSON. The key difference is:
  `conftest` is designed for **one input document** (e.g., one Kubernetes
  YAML file). Our provenance gate uses `opa eval` directly to correlate
  **two JSON documents** (Trivy + Dependency-Check) in a single evaluation.

- `conftest` has **no published Rego examples** for evaluating Trivy JSON
  vulnerability scan output as of the paper's writing date. Its published
  example library focuses on configuration files (Dockerfiles, K8s YAMLs).
  Our severity-gate.rego is the first published Rego policy evaluated
  against Trivy's `trivy image --format json` output in a CI/CD context.

- `conftest` **does not natively integrate** with Jenkins via a documented
  Jenkins plugin. Our approach uses `opa eval` directly, which is a single
  binary already installed in the Jenkins container.

**Cite as:** Open Policy Agent. "conftest: write tests against structured 
configuration data." https://www.conftest.dev/

---

### 3. `trivy-operator` (Aqua Security)

**What it does:** A Kubernetes operator that continuously scans workloads
in a cluster and surfaces findings as Kubernetes CRD (Custom Resource
Definition) objects.

**Why this paper's approach is different:**

- `trivy-operator` is a **runtime/cluster-level** tool. It scans running
  containers in a Kubernetes cluster. This paper's gate is a
  **pre-deployment CI/CD** gate — it prevents the container from being
  deployed to any environment if it fails.

- `trivy-operator` **requires Kubernetes**. The pipeline in this paper is
  deliberately environment-agnostic — it runs on bare Jenkins with Docker,
  with no Kubernetes dependency.

- `trivy-operator` surfaces findings but does **not block deployments** by
  default — it creates advisory CRD objects. A separate admission controller
  (e.g., Gatekeeper) would be needed to block. Our OPA gate is a hard stop
  in the CI/CD pipeline itself.

**Cite as:** Aquasecurity. "trivy-operator: Kubernetes-native security scanner."
https://github.com/aquasecurity/trivy-operator

---

### 4. GitHub dependency-review-action

**What it does:** A GitHub Actions action that evaluates a pull request's
dependency changes against GitHub's Advisory Database and blocks the PR
if a dependency introduces a vulnerability above a configured severity.

**Why this paper's approach is different:**

- **GitHub Actions only.** This paper's approach works with any Jenkins
  installation, including air-gapped and self-hosted environments.

- **Dependency manifests only.** The dependency-review-action only evaluates
  dependencies introduced by a PR diff. It does not scan the compiled Docker
  image, does not run config gate checks, and does not perform DAST.

- **No Policy-as-Code.** The severity threshold is a simple YAML config value,
  not a Rego policy. It cannot be extended to cross-input correlation or
  custom business rules without forking the action.

**Cite as:** GitHub. "dependency-review-action: enforce policies on
dependency review." https://github.com/actions/dependency-review-action

---

## Gap Statement (for paper's Related Work section)

> "No existing tool in the surveyed literature simultaneously: 
> (1) evaluates vulnerability scan output as a Rego policy (not just 
> a severity threshold); (2) composes a container configuration gate 
> and a CVE severity gate in a single OPA policy package; and (3) 
> supports cross-input correlation across two independent scanner 
> outputs (Trivy + Dependency-Check) in a single evaluation step. 
> The closest prior art is `conftest`, which supports Rego evaluation 
> against structured data but has no published policies for Trivy JSON 
> scan output and does not support multi-input cross-correlation in a 
> standard evaluation mode."
