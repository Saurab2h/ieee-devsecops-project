pipeline {
    agent any

    environment {
        SEMGREP = "/opt/homebrew/bin/semgrep"
        DEP_CHECK = "/opt/homebrew/bin/dependency-check"
        TRIVY = "/opt/homebrew/bin/trivy"
        OPA = "/opt/homebrew/bin/opa"
        DOCKER = "/usr/local/bin/docker"
        MVN = "/opt/homebrew/bin/mvn"
        ZAP = "/Applications/ZAP.app/Contents/Java/zap.sh"
    }

    stages {

        stage('Prepare') {
            steps {
                sh 'mkdir -p results'
            }
        }

        stage('Semgrep SAST') {
            steps {
                sh '''
                cd app/vulnapp
                $SEMGREP scan --config auto \
                  --json \
                  --output ${WORKSPACE}/results/semgrep-report.json .
                '''
            }
        }

        stage('Dependency Check') {
            steps {
                sh '''
                cd app/vulnapp
                mkdir -p ${WORKSPACE}/results/dependency-check

                $DEP_CHECK \
                  --project vulnapp \
                  --scan . \
                  --format ALL \
                  --noupdate \
                  --out ${WORKSPACE}/results/dependency-check
                '''
            }
        }

        stage('Build App') {
            steps {
                sh '''
                cd app/vulnapp
                $MVN clean package -DskipTests
                '''
            }
        }

        stage('Docker Build') {
            steps {
                sh '''
                cd app/vulnapp
                $DOCKER build -t vulnapp .
                '''
            }
        }

        stage('Trivy Scan') {
            steps {
                sh '''
                $TRIVY image \
                  -f json \
                  -o ${WORKSPACE}/results/trivy-report.json \
                  vulnapp

                $TRIVY image \
                  --format table \
                  vulnapp > ${WORKSPACE}/results/trivy-report.txt
                '''
            }
        }

        stage('OPA Policy Check') {
            steps {
                sh '''
                $DOCKER image inspect vulnapp > ${WORKSPACE}/results/image.json

                $OPA eval \
                  --input ${WORKSPACE}/results/image.json \
                  --data policies/docker.rego \
                  "data.devsecops.deny"
                '''
            }
        }

        stage('Deploy') {
            steps {
                sh '''
                $DOCKER rm -f vulnapp-container || true
                $DOCKER run -d -p 8081:8080 --name vulnapp-container vulnapp
                '''
            }
        }

        stage('OWASP ZAP DAST') {
            steps {
                sh '''
                chmod +x $ZAP

                $ZAP \
                  -cmd \
                  -quickurl http://host.docker.internal:8081 \
                  -quickout ${WORKSPACE}/results/zap-report.html
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'results/**', fingerprint: true
        }
    }
}
