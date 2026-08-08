package devsecops.provenance

# =============================================================
# policies/provenance-gate.rego
#
# PURPOSE: Cross-input correlation policy — the novel OPA use
#          case that a bash script CANNOT replicate.
#
# This policy evaluates TWO JSON documents simultaneously:
#   --input-data trivy = Trivy scan output
#   --input-data depcheck = Dependency-Check JSON output
#
# RULE: If the same CVE-ID appears in BOTH Trivy (image layer)
#       AND Dependency-Check (manifest scope), it is a
#       "Confirmed Dual-Scope Vulnerability" — the highest
#       confidence finding possible. Block with enriched message.
#
# This is the key novelty over bash:
#   bash cannot JOIN two JSON documents without external state (files/DB).
#   OPA evaluates cross-document rules natively in a single eval call.
#
# USAGE:
#   opa eval \
#     --data policies/provenance-gate.rego \
#     --input results/combined-input.json \
#     "data.devsecops.provenance.deny"
#
# Where combined-input.json has structure:
#   { "trivy": <trivy-report.json contents>,
#     "depcheck": <dependency-check-report.json contents> }
# =============================================================

# Extract all CVE IDs from Trivy image scan
trivy_cves := {cve_id |
    result := input.trivy.Results[_]
    vuln   := result.Vulnerabilities[_]
    cve_id := vuln.VulnerabilityID
    startswith(cve_id, "CVE-")
}

# Extract all CVE IDs from Dependency-Check SCA scan
depcheck_cves := {cve_id |
    dep  := input.depcheck.dependencies[_]
    vuln := dep.vulnerabilities[_]
    cve_id := vuln.name
    startswith(cve_id, "CVE-")
}

# Cross-reference: CVEs confirmed at BOTH artifact scopes
dual_scope_cves := trivy_cves & depcheck_cves

# Deny if any dual-scope CVE exists (highest confidence — both tools agree)
deny contains msg if {
    count(dual_scope_cves) > 0
    msg := sprintf(
        "PROVENANCE GATE BLOCKED: %v CVE(s) confirmed at BOTH image and manifest scope. Dual-scope CVEs: %v",
        [count(dual_scope_cves), dual_scope_cves]
    )
}

# Summary output for logging
summary_dual_count := count(dual_scope_cves)
summary_trivy_only := count(trivy_cves - dual_scope_cves)
summary_depcheck_only := count(depcheck_cves - dual_scope_cves)
summary_decision := "BLOCKED" if count(dual_scope_cves) > 0
summary_decision := "PASS" if count(dual_scope_cves) == 0
