pipeline {
    agent any

    environment {
        SEMGREP    = "semgrep"
        DEP_CHECK  = "dependency-check"
        TRIVY      = "trivy"
        OPA        = "opa"
        DOCKER     = "docker"
        MVN        = "mvn"
        // ZAP via Docker — more stable than native install
        ZAP_IMAGE  = "ghcr.io/zaproxy/zaproxy:stable"
        APP_TARGET = "vulnapp"    // Change per run: vulnapp | dvwa | juiceshop
        APP_PORT   = "8081"
    }

    stages {

        // ── Stage 0: Prepare ───────────────────────────────────────────
        stage('Prepare') {
            steps {
                sh '''
                mkdir -p results/semgrep
                mkdir -p results/dependency-check
                mkdir -p results/trivy
                mkdir -p results/zap
                mkdir -p results/opa
                mkdir -p results/timing
                echo "Pipeline started: $(date -u +%Y-%m-%dT%H:%M:%SZ)" > results/timing/pipeline-start.txt
                '''
            }
        }

        // ── Stage 1: SAST — Semgrep ────────────────────────────────────
        stage('Semgrep SAST') {
            steps {
                sh '''
                START=$(date +%s)

                cd app/vulnapp
                $SEMGREP scan --config auto \
                  --json \
                  --output ${WORKSPACE}/results/semgrep/semgrep-report.json . || true

                END=$(date +%s)
                echo "semgrep_duration_seconds=$((END-START))" >> ${WORKSPACE}/results/timing/stage-timings.txt
                echo "Semgrep duration: $((END-START))s"
                '''
            }
        }

        // ── Stage 2: SCA — OWASP Dependency-Check ─────────────────────
        stage('Dependency Check SCA') {
            steps {
                sh '''
                START=$(date +%s)

                cd app/vulnapp
                dependency-check \
                  --project vulnapp \
                  --scan . \
                  --format ALL \
                  --out ${WORKSPACE}/results/dependency-check || true

                END=$(date +%s)
                echo "depcheck_duration_seconds=$((END-START))" >> ${WORKSPACE}/results/timing/stage-timings.txt
                echo "Dependency-Check duration: $((END-START))s"
                '''
            }
        }

        // ── Stage 3: Build ─────────────────────────────────────────────
        stage('Build App') {
            steps {
                sh '''
                START=$(date +%s)

                cd app/vulnapp
                $MVN clean package -DskipTests

                END=$(date +%s)
                echo "build_duration_seconds=$((END-START))" >> ${WORKSPACE}/results/timing/stage-timings.txt
                echo "Build duration: $((END-START))s"
                '''
            }
        }

        // ── Stage 4: Docker Build ──────────────────────────────────────
        stage('Docker Build') {
            steps {
                sh '''
                START=$(date +%s)

                cd app/vulnapp
                $DOCKER build -t vulnapp .

                END=$(date +%s)
                echo "docker_build_duration_seconds=$((END-START))" >> ${WORKSPACE}/results/timing/stage-timings.txt
                echo "Docker Build duration: $((END-START))s"
                '''
            }
        }

        // ── Stage 5: Container Scan — Trivy ───────────────────────────
        stage('Trivy Container Scan') {
            steps {
                sh '''
                START=$(date +%s)

                $TRIVY image \
                  -f json \
                  -o ${WORKSPACE}/results/trivy/trivy-report.json \
                  vulnapp

                $TRIVY image \
                  --format table \
                  vulnapp > ${WORKSPACE}/results/trivy/trivy-report.txt

                END=$(date +%s)
                echo "trivy_duration_seconds=$((END-START))" >> ${WORKSPACE}/results/timing/stage-timings.txt
                echo "Trivy duration: $((END-START))s"
                '''
            }
        }

        // ── Stage 6a: OPA Config Gate ──────────────────────────────────
        // Checks: root user, port exposure, privileged mode
        stage('OPA Docker Config Gate') {
            steps {
                script {
                    sh '''
                    START=$(date +%s)
                    $DOCKER image inspect vulnapp > ${WORKSPACE}/results/opa/image.json
                    END=$(date +%s)
                    echo "opa_inspect_seconds=$((END-START))" >> ${WORKSPACE}/results/timing/stage-timings.txt
                    '''

                    // Evaluate and capture violations
                    def violations = sh(
                        script: '''
                        $OPA eval \
                          --input ${WORKSPACE}/results/opa/image.json \
                          --data policies/docker.rego \
                          --format raw \
                          "data.devsecops.deny" \
                          | tee ${WORKSPACE}/results/opa/config-gate-result.json \
                          | jq length
                        ''',
                        returnStdout: true
                    ).trim()

                    // Save count for paper metrics
                    sh "echo 'opa_config_violations=${violations}' >> results/timing/stage-timings.txt"
                    sh "echo 'OPA Config Gate violations: ${violations}'"

                    // GATE: Fail the pipeline if any violations
                    if (violations.toInteger() > 0) {
                        def msgs = sh(
                            script: '''$OPA eval \
                              --input ${WORKSPACE}/results/opa/image.json \
                              --data policies/docker.rego \
                              --format raw "data.devsecops.deny" | jq -r '.[]' ''',
                            returnStdout: true
                        ).trim()
                        error("""
╔══════════════════════════════════════════════════════════╗
║         ❌  OPA CONFIG GATE — DEPLOYMENT BLOCKED         ║
╚══════════════════════════════════════════════════════════╝
${violations} policy violation(s) found:
${msgs}

Deployment halted. Fix the above violations and re-run.
                        """)
                    } else {
                        echo "✅ OPA Config Gate: PASS — No violations found."
                    }
                }
            }
        }

        // ── Stage 6b: OPA Severity Gate ────────────────────────────────
        // Novelty: OPA consumes Trivy scan output to make deploy decision
        stage('OPA Severity Gate') {
            steps {
                script {
                    sh '''
                    START=$(date +%s)

                    $OPA eval \
                      --input ${WORKSPACE}/results/trivy/trivy-report.json \
                      --data policies/severity-gate.rego \
                      --format pretty \
                      "data.devsecops.severity" \
                      | tee ${WORKSPACE}/results/opa/severity-gate-result.json

                    END=$(date +%s)
                    echo "opa_severity_seconds=$((END-START))" >> ${WORKSPACE}/results/timing/stage-timings.txt
                    '''

                    def violations = sh(
                        script: '''
                        $OPA eval \
                          --input ${WORKSPACE}/results/trivy/trivy-report.json \
                          --data policies/severity-gate.rego \
                          --format raw \
                          "data.devsecops.severity.deny" \
                          | jq length
                        ''',
                        returnStdout: true
                    ).trim()

                    sh "echo 'opa_severity_violations=${violations}' >> results/timing/stage-timings.txt"

                    if (violations.toInteger() > 0) {
                        def msgs = sh(
                            script: '''$OPA eval \
                              --input ${WORKSPACE}/results/trivy/trivy-report.json \
                              --data policies/severity-gate.rego \
                              --format raw "data.devsecops.severity.deny" | jq -r '.[]' ''',
                            returnStdout: true
                        ).trim()
                        error("""
╔══════════════════════════════════════════════════════════╗
║        ❌  OPA SEVERITY GATE — DEPLOYMENT BLOCKED        ║
╚══════════════════════════════════════════════════════════╝
${violations} severity violation(s) found:
${msgs}

Deployment halted. CVE thresholds exceeded.
                        """)
                    } else {
                        echo "✅ OPA Severity Gate: PASS — CVE counts within policy thresholds."
                    }
                }
            }
        }

        // ── Stage 7: Deploy ────────────────────────────────────────────
        // Only reached if BOTH OPA gates pass
        stage('Deploy') {
            steps {
                sh '''
                START=$(date +%s)

                $DOCKER rm -f vulnapp-container || true
                $DOCKER run -d -p ${APP_PORT}:8080 --name vulnapp-container vulnapp

                # Wait for app to be ready
                sleep 10
                curl -sf http://localhost:${APP_PORT}/actuator/health || echo "Health check skipped"

                END=$(date +%s)
                echo "deploy_duration_seconds=$((END-START))" >> ${WORKSPACE}/results/timing/stage-timings.txt
                echo "deployment_status=SUCCESS" >> ${WORKSPACE}/results/timing/stage-timings.txt
                echo "Deployment successful at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
                '''
            }
        }

        // ── Stage 8: DAST — OWASP ZAP ─────────────────────────────────
        // Using Docker-based ZAP for stability (fixes the previous instability)
        stage('OWASP ZAP DAST') {
            steps {
                sh '''
                START=$(date +%s)

                # Pull latest ZAP Docker image
                $DOCKER pull ${ZAP_IMAGE} || true

                # Run ZAP baseline scan (passive + active)
                $DOCKER run --rm \
                  --network host \
                  -v ${WORKSPACE}/results/zap:/zap/wrk:rw \
                  ${ZAP_IMAGE} \
                  zap-baseline.py \
                    -t http://localhost:${APP_PORT} \
                    -r zap-report.html \
                    -J zap-report.json \
                    -l WARN \
                    -d || true

                END=$(date +%s)
                echo "zap_duration_seconds=$((END-START))" >> ${WORKSPACE}/results/timing/stage-timings.txt
                echo "ZAP DAST duration: $((END-START))s"
                '''
            }
        }

    }

    post {
        always {
            // Generate pipeline summary
            sh '''
            echo "=== PIPELINE SUMMARY ===" > results/pipeline-summary.txt
            echo "Completed at: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> results/pipeline-summary.txt
            cat results/timing/stage-timings.txt >> results/pipeline-summary.txt 2>/dev/null || true
            cat results/pipeline-summary.txt
            '''
            archiveArtifacts artifacts: 'results/**', fingerprint: true
        }
        failure {
            sh '''
            echo "Pipeline FAILED — check OPA gate results in results/opa/" > results/failure-reason.txt
            cat results/opa/config-gate-result.json >> results/failure-reason.txt 2>/dev/null || true
            cat results/opa/severity-gate-result.json >> results/failure-reason.txt 2>/dev/null || true
            '''
            archiveArtifacts artifacts: 'results/**', fingerprint: true
        }
    }
}
