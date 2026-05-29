pipeline {
    agent any

    tools {
        nodejs 'NodeJS_18'
    }

    parameters {
        string(
            name: 'TARGET_PROJECT_DIR',
            defaultValue: 'examples/vulnerable-rest-api',
            description: 'Đường dẫn (tương đối với WORKSPACE) tới thư mục project mục tiêu cần quét.'
        )
    }

    environment {
        // Toàn bộ artifacts pipeline (immutable trong build này)
        CONTEXT_DIR = "${WORKSPACE}/security-context-output"
        REPORTS_DIR = "${WORKSPACE}/security-context-output/scan-reports"
        FINAL_DIR   = "${WORKSPACE}/security-context-output/final-report"
        RUNTIME_DIR = "${WORKSPACE}/runtime"

        // Target project: tham số động — không còn hardcode "vulnerable-rest-api"
        TARGET_DIR  = "${WORKSPACE}/${params.TARGET_PROJECT_DIR}"

        GEMINI_API_KEY = credentials('GEMINI_API_KEY')
    }

    stages {
        stage('1. Init') {
            steps {
                echo "=== Target project: ${TARGET_DIR} ==="
                // Xoá artifact cũ từ build trước để quality gate / report không đọc nhầm
                sh "rm -rf ${CONTEXT_DIR} ${RUNTIME_DIR}"
                sh "mkdir -p ${CONTEXT_DIR} ${REPORTS_DIR} ${FINAL_DIR} ${RUNTIME_DIR}"
                sh 'node -v && docker -v'
            }
        }

        stage('2. Install deps') {
            steps {
                sh 'npm ci || npm install'
            }
        }

        stage('3. Collect context') {
            steps {
                sh "node collector/contextCollector.js ${TARGET_DIR} --output ${CONTEXT_DIR}"
            }
        }

        stage('4. AI analyze') {
            steps {
                sh "node ai/aiAnalyzer.js ${CONTEXT_DIR}/context.json ${CONTEXT_DIR}"
            }
        }

        stage('5. Generate pipeline scripts') {
            steps {
                sh "node ai/pipelineGenerator.js ${CONTEXT_DIR} ${RUNTIME_DIR} ${TARGET_DIR}"
                sh "cat ${RUNTIME_DIR}/runtime-info.json"
            }
        }

        stage('6. SAST + SCA') {
            steps {
                sh "${RUNTIME_DIR}/run-sast.sh"
            }
        }

        stage('7. Deploy + DAST') {
            steps {
                sh "${RUNTIME_DIR}/deploy-target.sh"
                sh "${RUNTIME_DIR}/run-dast.sh"
            }
        }

        stage('8. AI Report') {
            steps {
                // Thứ tự: <reportsDir> <contextPath> <outputDir>
                sh "node ai/reportGenerator.js ${REPORTS_DIR} ${CONTEXT_DIR}/context.json ${FINAL_DIR}"
            }
        }
    }

    post {
        always {
            echo '=== Teardown ==='
            sh "${RUNTIME_DIR}/teardown.sh || true"

            // Quality Gate (FR-04): fail build nếu có critical
            script {
                if (fileExists("${FINAL_DIR}/security-report.json")) {
                    def finalReport = readJSON file: "${FINAL_DIR}/security-report.json"
                    def execSummary = finalReport.executive_summary
                    echo "Security posture: ${execSummary.security_posture_score}/100"
                    echo "Critical: ${execSummary.critical_count}, High: ${execSummary.high_count}"

                    if (execSummary.critical_count > 0) {
                        currentBuild.result = 'FAILURE'
                        error("Quality Gate failed: ${execSummary.critical_count} CRITICAL findings")
                    }
                }
            }

            archiveArtifacts artifacts: "security-context-output/**/*, runtime/runtime-info.json", allowEmptyArchive: true

            publishHTML(target: [
                allowMissing: true,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: "${FINAL_DIR}",
                reportFiles: 'security-report.html',
                reportName: 'AI Security Triage Report'
            ])
        }
    }
}
