# IEEE DevSecOps Paper — Additions & Execution Guide

## What Was Added (Paper-Ready Additions)

### 1. OPA Negative Test — Proves Gate Actually Blocks

**File:** `app/vuln-noncompliant/Dockerfile`

A deliberately non-compliant Docker image that violates two policies:
- **No `USER` directive** → runs as root (CWE-269, OWASP A04:2021)
- **No `EXPOSE 8080`** → required port not declared (OWASP A05:2021)

**Test result (live):**
```json
[
  "POLICY VIOLATION [A05:2021]: Required application port 8080/tcp is not declared via EXPOSE.",
  "POLICY VIOLATION [CWE-269]: Container runs as root. Set a non-root USER in Dockerfile."
]
```

**To reproduce (screenshot for paper Fig 5):**
```bash
# Build non-compliant image
docker build -t vuln-noncompliant -f app/vuln-noncompliant/Dockerfile app/vuln-noncompliant/

# Run OPA gate — should return 2 violations
docker image inspect vuln-noncompliant > /tmp/nc-image.json
opa eval --input /tmp/nc-image.json --data policies/docker.rego --format pretty "data.devsecops.deny"
```

---

### 2. OPA Severity Gate — Novel Contribution

**File:** `policies/severity-gate.rego`

OPA now reads **Trivy scan JSON output** and makes deployment decisions based on real CVE data. This is the core novelty — policy-as-code driven by actual scan results.

**Gates:**
- ANY CRITICAL CVE → BLOCKED
- HIGH CVEs > 10 → BLOCKED
- MEDIUM CVEs > 25 → WARN (logged, not blocked)

**Test result (live against vulnapp):**
```
deny: ["SEVERITY GATE BLOCKED: 3 CRITICAL CVE(s) found. First: CVE-2026-41293..."]
summary_status: "BLOCKED"
summary_critical: 3
summary_high: 19
```

**To run:**
```bash
opa eval \
  --input results/trivy-report.json \
  --data policies/severity-gate.rego \
  --format pretty "data.devsecops.severity.deny"
```

---

### 3. Updated Jenkinsfile — Gates That Actually Fail

**File:** `Jenkinsfile`

Key changes from previous version:
- **OPA Config Gate**: `error()` called on violations → Jenkins pipeline FAILS and halts
- **OPA Severity Gate**: New stage, reads Trivy JSON
- **ZAP**: Docker-based scanner (stable, no native install needed)
- **Timing**: Each stage records `duration_seconds` to `results/timing/stage-timings.txt`
- **Structured results**: `results/semgrep/`, `results/trivy/`, `results/opa/`, etc.

---

### 4. Multi-App Pipeline (N=3)

**File:** `Jenkinsfile.multiapp`

Runs Trivy + OPA + ZAP across:
| App | Image | Purpose |
|-----|-------|---------|
| `vulnapp` | eclipse-temurin:17 | Your Spring Boot app |
| `DVWA` | vulnerables/web-dvwa | Known PHP vulns |
| `Juice Shop` | bkimminich/juice-shop | OWASP benchmark |

Outputs go to `results/multiapp/{app}/` with `summary.txt` for the comparison table.

---

### 5. Figures (Paper-Ready, 300 DPI)

**Script:** `scripts/generate-figures.py`

Run: `python3 scripts/generate-figures.py`

| Figure | File | Content |
|--------|------|---------|
| Fig 2 | `fig2_stage_timing.png` | Stage duration bar chart |
| Fig 3 | `fig3_cve_distribution.png` | CVE severity per app |
| Fig 4 | `fig4_tool_complementarity.png` | Tool coverage heatmap |
| Fig 5 | `fig5_opa_gate_results.png` | OPA gate decisions |
| Fig 6 | `fig6_owasp_top10_heatmap.png` | OWASP Top 10 mapping |

---

### 6. Tables (Markdown + LaTeX)

**Script:** `scripts/tabulate-results.py`

Run: `python3 scripts/tabulate-results.py`

Outputs to `results/tables/` — both `.md` and embedded LaTeX.

| Table | Content |
|-------|---------|
| Table I | Stage timing + security overhead |
| Table II | Trivy CVE comparison across 3 apps |
| Table III | OPA gate decisions |
| Table IV | ZAP DAST OWASP Top 10 mapping |
| Table V | Tool complementarity |

---

## Jenkins Pipelines — How to Run

### A. Normal Pipeline (vulnapp)
In Jenkins, point to `Jenkinsfile` (already in repo root).

### B. OPA Negative Test (for paper Fig 5)
Create a new Jenkins job → point to `Jenkinsfile.opa-negative-test`.
Expected: Pipeline FAILS at "OPA Docker Config Gate" — screenshot this.

### C. Multi-App Scan (N=3)
Create a new Jenkins job → point to `Jenkinsfile.multiapp`.

---

## Checklist for Paper Submission

- [ ] Run `Jenkinsfile.opa-negative-test` → screenshot Jenkins failure at OPA stage
- [ ] Run `Jenkinsfile.multiapp` → get real Trivy+ZAP data for DVWA and Juice Shop
- [ ] Re-run `python3 scripts/generate-figures.py` (picks up new JSON data)
- [ ] Re-run `python3 scripts/tabulate-results.py` (picks up new JSON data)
- [ ] Add 8–10 citations to the paper's Related Work section
- [ ] Write paper Section 7 (Results) using the tables + figures

## Suggested Research Question (for Abstract/Intro)

> "We evaluate the security-velocity tradeoff of a multi-layer DevSecOps pipeline integrating SAST (Semgrep), SCA (OWASP Dependency-Check), container scanning (Trivy), Policy-as-Code enforcement (OPA), and DAST (ZAP), quantifying per-stage security overhead, tool complementarity across three open-source applications, and the efficacy of data-driven OPA gates in preventing deployment of vulnerable artifacts."
