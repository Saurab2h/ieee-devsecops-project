# ============================================================
# Jenkins Dockerfile
# Base: jenkins/jenkins:lts-jdk17
#
# Pre-installs ALL tools needed by the DevSecOps pipeline:
#   - jq           (JSON parsing in Aggregate Results)
#   - curl, wget   (general utilities)
#   - Docker CLI   (to run Trivy, ZAP, build images)
#   - Trivy        (container/SCA scanner)
#   - OPA          (policy-as-code engine)
#   - Semgrep      (SAST)
# ============================================================

FROM jenkins/jenkins:lts-jdk17

USER root

# ── 1. System packages (including jq) ────────────────────────
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        jq \
        curl \
        wget \
        unzip \
        gnupg \
        lsb-release \
        ca-certificates \
        apt-transport-https \
        software-properties-common && \
    rm -rf /var/lib/apt/lists/*

# ── 2. Docker CLI (so Jenkins can run docker commands) ────────
RUN curl -fsSL https://download.docker.com/linux/debian/gpg \
      | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg && \
    echo "deb [arch=$(dpkg --print-architecture) \
      signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] \
      https://download.docker.com/linux/debian \
      $(lsb_release -cs) stable" \
      > /etc/apt/sources.list.d/docker.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends docker-ce-cli && \
    rm -rf /var/lib/apt/lists/*

# ── 3. Trivy ─────────────────────────────────────────────────
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
      | sh -s -- -b /usr/local/bin

# ── 4. OPA ───────────────────────────────────────────────────
RUN curl -Lo /usr/local/bin/opa \
      https://openpolicyagent.org/downloads/latest/opa_linux_$(dpkg --print-architecture) && \
    chmod +x /usr/local/bin/opa

# ── 5. Semgrep ───────────────────────────────────────────────
RUN apt-get update && \
    apt-get install -y python3-pip && \
    pip3 install semgrep && \
    rm -rf /var/lib/apt/lists/*

# ── 6. Verify all tools are present at build time ────────────
RUN echo "=== Tool verification ===" && \
    jq        --version && \
    docker    --version && \
    trivy     --version && \
    opa       version   && \
    semgrep   --version && \
    echo "=== All tools OK ==="

# ── 7. Add jenkins user to docker group ──────────────────────
RUN groupadd -f docker && usermod -aG docker jenkins

USER jenkins

# Pre-install useful Jenkins plugins via plugin manager
COPY plugins.txt /usr/share/jenkins/ref/plugins.txt
RUN jenkins-plugin-cli --plugin-file /usr/share/jenkins/ref/plugins.txt || true
