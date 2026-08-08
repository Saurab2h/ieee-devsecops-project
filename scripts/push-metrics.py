#!/usr/bin/env python3
import os
import re
import json
import urllib.request
import urllib.error

PUSHGATEWAY_URL = "http://pushgateway:9091/metrics/job/jenkins_pipeline"
TIMINGS_FILE = "results/multiapp/timings.txt"

# FP Rate Models
FP_RATES = {
    "semgrep": 0.0,
    "depcheck": 0.22,
    "trivy": 0.0,
    "zap": 0.30
}

metrics = []

def add_metric(name, value, labels=None):
    if labels:
        label_str = ",".join(f'{k}="{v}"' for k, v in labels.items())
        metrics.append(f"{name}{{{label_str}}} {value}")
    else:
        metrics.append(f"{name} {value}")

def parse_timings():
    if not os.path.exists(TIMINGS_FILE):
        return
    
    with open(TIMINGS_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if "=" in line:
                key, val = line.split("=", 1)
                try:
                    duration = int(val)
                    # key looks like vulnapp_trivy_seconds
                    parts = key.replace("_seconds", "").split("_")
                    if len(parts) >= 2:
                        app = parts[0]
                        stage = "_".join(parts[1:])
                        add_metric("devsecops_stage_duration_seconds", duration, {"app": app, "stage": stage})
                except ValueError:
                    pass

def calculate_fp_models():
    # Hardcoded values for the paper based on our JSON analyses
    # In a real environment, these would be pulled dynamically from JSON files
    
    # 1. Semgrep (vulnapp only)
    add_metric("devsecops_findings_total", 1, {"app": "vulnapp", "tool": "semgrep"})
    add_metric("devsecops_findings_fp", 0, {"app": "vulnapp", "tool": "semgrep"})
    add_metric("devsecops_fp_rate", FP_RATES["semgrep"], {"tool": "semgrep"})

    # 2. Dependency-Check (vulnapp only)
    add_metric("devsecops_findings_total", 59, {"app": "vulnapp", "tool": "depcheck"})
    add_metric("devsecops_findings_fp", 13, {"app": "vulnapp", "tool": "depcheck"})
    add_metric("devsecops_fp_rate", FP_RATES["depcheck"], {"tool": "depcheck"})

    # 3. Trivy
    trivy_totals = {"vulnapp": 201, "dvwa": 1447, "juiceshop": 81}
    for app, count in trivy_totals.items():
        add_metric("devsecops_findings_total", count, {"app": app, "tool": "trivy"})
        add_metric("devsecops_findings_fp", 0, {"app": app, "tool": "trivy"})
    add_metric("devsecops_fp_rate", FP_RATES["trivy"], {"tool": "trivy"})
    
    # Trivy Criticals specifically for the dashboard
    add_metric("devsecops_cve_critical_total", 3, {"app": "vulnapp"})
    add_metric("devsecops_cve_critical_total", 254, {"app": "dvwa"})
    add_metric("devsecops_cve_critical_total", 7, {"app": "juiceshop"})

    # 4. ZAP DAST
    zap_totals = {"vulnapp": 1, "dvwa": 6, "juiceshop": 2}
    for app, count in zap_totals.items():
        fp_count = int(count * FP_RATES["zap"])
        add_metric("devsecops_findings_total", count, {"app": app, "tool": "zap"})
        add_metric("devsecops_findings_fp", fp_count, {"app": app, "tool": "zap"})
    add_metric("devsecops_fp_rate", FP_RATES["zap"], {"tool": "zap"})

    # 5. OPA
    add_metric("devsecops_fp_rate", 0.0, {"tool": "opa_config"})
    add_metric("devsecops_fp_rate", 0.0, {"tool": "opa_severity"})

def push_metrics():
    payload = "\n".join(metrics) + "\n"
    req = urllib.request.Request(PUSHGATEWAY_URL, data=payload.encode("utf-8"), method="POST")
    try:
        urllib.request.urlopen(req)
        print("Metrics successfully pushed to Pushgateway.")
    except urllib.error.URLError as e:
        print(f"Failed to push metrics: {e}")
        # In a real pipeline, we might not fail the build if metrics fail

if __name__ == "__main__":
    parse_timings()
    calculate_fp_models()
    push_metrics()
