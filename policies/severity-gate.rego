package devsecops.severity

# =============================================================
# OPA Severity Gate Policy
# Evaluates: Trivy scan output (trivy-report.json)
#
# This policy enables OPA to make deployment decisions based on
# actual vulnerability scan data — not just container config.
#
# This is the key novelty of our pipeline: Policy-as-Code
# gates driven by real CVE severity data from Trivy.
#
# Thresholds (configurable):
#   - Any CRITICAL CVE → BLOCK
#   - HIGH CVEs > 10   → BLOCK
#   - Medium CVEs > 25 → WARN (logged, not blocked)
# =============================================================

import future.keywords.if
import future.keywords.contains
import future.keywords.in

# -------------------------------------------------------
# Helper: Collect all vulnerabilities across all results
# -------------------------------------------------------
all_vulnerabilities := [vuln |
    result := input.Results[_]
    vuln := result.Vulnerabilities[_]
]

# Count by severity
critical_vulns := [v | v := all_vulnerabilities[_]; v.Severity == "CRITICAL"]
high_vulns     := [v | v := all_vulnerabilities[_]; v.Severity == "HIGH"]
medium_vulns   := [v | v := all_vulnerabilities[_]; v.Severity == "MEDIUM"]

# -------------------------------------------------------
# GATE 1: Block on ANY CRITICAL CVE
# -------------------------------------------------------
deny contains msg if {
    count(critical_vulns) > 0
    v := critical_vulns[0]
    msg := sprintf(
        "SEVERITY GATE BLOCKED: %d CRITICAL CVE(s) found. First: %v (%v). Fix before deploying.",
        [count(critical_vulns), v.VulnerabilityID, v.Title]
    )
}

# -------------------------------------------------------
# GATE 2: Block if HIGH CVE count exceeds threshold
# -------------------------------------------------------
deny contains msg if {
    count(critical_vulns) == 0   # Only report high gate if critical gate didn't fire
    count(high_vulns) > 10
    msg := sprintf(
        "SEVERITY GATE BLOCKED: %d HIGH CVE(s) found (threshold: 10). Remediate before deploying.",
        [count(high_vulns)]
    )
}

# -------------------------------------------------------
# WARN (informational, does not block)
# -------------------------------------------------------
warn contains msg if {
    count(medium_vulns) > 25
    msg := sprintf(
        "SEVERITY WARNING: %d MEDIUM CVE(s) found. Consider remediation.",
        [count(medium_vulns)]
    )
}

# -------------------------------------------------------
# Summary (always emitted for logging)
# -------------------------------------------------------
summary_critical := count(critical_vulns)
summary_high     := count(high_vulns)
summary_medium   := count(medium_vulns)
summary_total    := count(all_vulnerabilities)

default summary_status := "PASS"
summary_status := "BLOCKED" if count(deny) > 0
