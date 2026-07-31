# ============================================================
# NON-COMPLIANT DOCKERFILE — FOR OPA NEGATIVE TEST ONLY
# Intentionally violates security policies to demonstrate
# OPA gate blocking a deployment.
#
# Violations:
#   1. No USER directive → runs as root (CWE-269)
#   2. No EXPOSE 8080 → required port not declared
#   3. Old base image (ubuntu:18.04) → known OS-level CVEs
# ============================================================

FROM ubuntu:18.04

WORKDIR /app

# Simulate a minimal app (no USER, no EXPOSE)
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

COPY . .

# No USER directive — container will run as root
# No EXPOSE — port not declared

ENTRYPOINT ["/bin/bash", "-c", "echo 'Non-compliant app running as root' && sleep infinity"]
