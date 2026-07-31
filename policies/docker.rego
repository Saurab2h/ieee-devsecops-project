package devsecops

# =============================================================
# OPA Docker Configuration Policy
# Evaluates: docker image inspect <image> output (image.json)
#
# Gates:
#   1. Container must NOT run as root (no USER = root)
#   2. Container must expose port 8080/tcp
#   3. Container must not have privileged mode enabled
# =============================================================

# Rule 1: Root user check
# Semgrep SAST already flagged this (CWE-269). OPA enforces it at runtime gate.
deny contains msg if {
    not input[0].Config.User
    msg := "POLICY VIOLATION [CWE-269]: Container runs as root. Set a non-root USER in Dockerfile."
}

deny contains msg if {
    input[0].Config.User == ""
    msg := "POLICY VIOLATION [CWE-269]: Container USER is empty. Set a non-root USER in Dockerfile."
}

# Rule 2: Required application port must be declared
deny contains msg if {
    not input[0].Config.ExposedPorts["8080/tcp"]
    msg := "POLICY VIOLATION [A05:2021]: Required application port 8080/tcp is not declared via EXPOSE."
}

# Rule 3: No privileged flag in host config
deny contains msg if {
    input[0].HostConfig.Privileged == true
    msg := "POLICY VIOLATION [CWE-250]: Container is running in privileged mode. This is forbidden."
}
