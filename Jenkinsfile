def shQuote(String value) {
    return "'${value.replace("'", "'\\''")}'"
}

def validateTargetProjectDir(String value) {
    if (!value?.trim()) {
        error('TARGET_PROJECT_DIR must not be empty')
    }
    if (value.startsWith('/') || value.startsWith('\\') || value ==~ /^[A-Za-z]:.*/) {
        error('TARGET_PROJECT_DIR must be relative to WORKSPACE')
    }
    if (value.contains('..')) {
        error('TARGET_PROJECT_DIR must not contain .. path traversal')
    }
    if (!(value ==~ /^[A-Za-z0-9._\/-]+$/)) {
        error('TARGET_PROJECT_DIR contains unsupported characters')
    }
    return value
}

pipeline {
    agent any

    tools {
        nodejs 'NodeJS_18'
    }

    parameters {
        string(
            name: 'TARGET_PROJECT_DIR',
            defaultValue: 'benchmarks/juice-shop',
            description: 'Đường dẫn (tương đối với WORKSPACE) tới thư mục project mục tiêu cần quét.'
        )
        booleanParam(
          name: 'KEEP_STAGING',
          defaultValue: true,
          description: 'Giữ môi trường staging sau khi deploy để manual test'
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
                script {
                    validateTargetProjectDir(params.TARGET_PROJECT_DIR)
                    def workspaceCanonical = new File(env.WORKSPACE).canonicalPath
                    def targetCanonical = new File(env.TARGET_DIR).canonicalPath
                    if (!targetCanonical.startsWith(workspaceCanonical + File.separator)) {
                        error("TARGET_PROJECT_DIR escapes WORKSPACE: ${params.TARGET_PROJECT_DIR}")
                    }
                }
                echo "=== Target project: ${TARGET_DIR} ==="
                // Xoá artifact cũ từ build trước để quality gate / report không đọc nhầm
                // KHÔNG xoá ${RUNTIME_DIR} vì chứa source code (sanitize.js, servicePicker.js)
                sh "rm -rf ${shQuote(CONTEXT_DIR)}"
                sh "find ${shQuote(RUNTIME_DIR)} -maxdepth 1 \\( -name '*.sh' -o -name 'runtime-info.json' \\) -type f -delete"
                sh "mkdir -p ${shQuote(CONTEXT_DIR)} ${shQuote(REPORTS_DIR)} ${shQuote(FINAL_DIR)} ${shQuote(RUNTIME_DIR)}"
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
                sh "node collector/contextCollector.js ${shQuote(TARGET_DIR)} --output ${shQuote(CONTEXT_DIR)}"
            }
        }

        stage('4. AI analyze') {
            steps {
                sh "node ai/aiAnalyzer.js ${shQuote("${CONTEXT_DIR}/context.json")} ${shQuote(CONTEXT_DIR)}"
            }
        }

        stage('5. Generate pipeline scripts') {
            steps {
                sh "node ai/pipelineGenerator.js ${shQuote(CONTEXT_DIR)} ${shQuote(RUNTIME_DIR)} ${shQuote(TARGET_DIR)}"
                sh "cat ${shQuote("${RUNTIME_DIR}/runtime-info.json")}"
            }
        }

        stage('6. SAST + SCA') {
            steps {
                sh script: shQuote("${RUNTIME_DIR}/run-sast.sh")
            }
        }

        stage('7. Deploy + DAST') {
            steps {
                sh script: shQuote("${RUNTIME_DIR}/deploy-target.sh")
                sh script: shQuote("${RUNTIME_DIR}/run-dast.sh")
            }
        }

        stage('8. AI Report') {
            steps {
                // Thứ tự: <reportsDir> <contextPath> <outputDir>
                sh "node ai/reportGenerator.js ${shQuote(REPORTS_DIR)} ${shQuote("${CONTEXT_DIR}/context.json")} ${shQuote(FINAL_DIR)}"
            }
        }

        stage('9. Manual Test Gate') {
            when {
                expression { return params.KEEP_STAGING }
            }
            steps {
                echo "Manual tests: ${CONTEXT_DIR}/manual_tests.json"
                echo "Staging API: xem runtime/runtime-info.json"
                input message: 'Manual test?', ok: 'Tiếp tục teardown/report'
            }
  }
    }

    post {
        always {
            echo '=== Teardown ==='
            sh script: "${shQuote("${RUNTIME_DIR}/teardown.sh")} || true"

            // Quality Gate (FR-04): fail build nếu có critical
            script {
                if (fileExists("${FINAL_DIR}/security-report.json")) {
                    def finalReport = readJSON file: "${FINAL_DIR}/security-report.json"
                    def execSummary = finalReport.executive_summary
                    echo "Security posture: ${execSummary.security_posture_score}/100"
                    echo "Critical: ${execSummary.critical_count}, High: ${execSummary.high_count}"

                    if (execSummary.critical_count > 20) {
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
