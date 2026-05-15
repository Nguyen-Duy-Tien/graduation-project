// Jenkinsfile — DevSecOps Pipeline AI-Assisted
// 9 stages: Checkout → Setup → Context → AI Analysis → SAST → SCA → DAST → Report → Publish
// Node.js ≥ 18 required (fetch native), GEMINI_API_KEY in Jenkins Credentials

pipeline {
    agent any

    environment {
        GEMINI_API_KEY        = credentials('gemini-api-key')  // Secret Text credential
        TARGET_URL            = "${env.STAGING_URL ?: 'http://app:8080'}"
        OUTPUT_DIR            = "${WORKSPACE}/security-context-output"
        REPORTS_DIR           = "${WORKSPACE}/scan-reports"
        FINAL_REPORT_DIR      = "${WORKSPACE}/final-report"
        NODE_OPTIONS          = "--max-old-space-size=512"
    }

    options {
        timeout(time: 60, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '15'))
        timestamps()
        disableConcurrentBuilds()
    }

    stages {

        // ════════════════════════════════════════════════════════════════
        // STAGE 1: Checkout
        // ════════════════════════════════════════════════════════════════
        stage('Checkout') {
            steps {
                checkout scm
                sh """
                    mkdir -p ${OUTPUT_DIR} ${REPORTS_DIR} ${FINAL_REPORT_DIR}
                    echo "Branch: ${GIT_BRANCH} | Commit: ${GIT_COMMIT}"
                    node --version
                    npm --version
                """
            }
        }

        // ════════════════════════════════════════════════════════════════
        // STAGE 2: Setup — install ai-module dependencies
        // ════════════════════════════════════════════════════════════════
        stage('Setup') {
            steps {
                dir("${WORKSPACE}/pipeline/ai-module") {
                    sh """
                        npm ci --prefer-offline || npm install
                        echo "[OK] Dependencies installed: js-yaml + glob"
                    """
                }
            }
        }

        // ════════════════════════════════════════════════════════════════
        // STAGE 3: Context Collection (Tuần 7 — collectors/)
        //
        // Chạy contextCollector.js → sinh context.json
        // Không gọi AI — chỉ static scan song song
        // ════════════════════════════════════════════════════════════════
        stage('Context Collection') {
            steps {
                echo "════════════ STAGE 3: CONTEXT COLLECTION (Week 7) ════════════"
                dir("${WORKSPACE}/pipeline/ai-module") {
                    sh """
                        node collectors/contextCollector.js \
                            "${WORKSPACE}" \
                            --output "${OUTPUT_DIR}"
                    """
                }

                // Verify output
                sh """
                    test -f ${OUTPUT_DIR}/context.json \
                        || { echo "[FAIL] context.json not generated"; exit 1; }
                    echo "[OK] context.json generated ($(wc -c < ${OUTPUT_DIR}/context.json) bytes)"
                """

                // Print attack surface summary to Jenkins console
                sh """
                    node -e "
const ctx = JSON.parse(require('fs').readFileSync('${OUTPUT_DIR}/context.json','utf8'));
const s = ctx.attackSurfaceSummary;
console.log('━━━ Attack Surface Summary ━━━');
console.log('  Language      :', ctx.techStack?.language, '/', ctx.techStack?.framework);
console.log('  Endpoints     :', s.totalEndpoints, '(', s.highRiskEndpoints, 'high-risk)');
console.log('  Patterns      :', s.dangerousPatterns?.total, '(critical:', s.dangerousPatterns?.bySeverity?.critical ?? 0, ')');
console.log('  Swagger spec  :', s.hasSwaggerSpec ? 'found' : 'not found - AI will infer');
console.log('  Scan strategy :', s.scanRecommendation);
"
                """
            }
            post {
                always {
                    archiveArtifacts artifacts: 'security-context-output/context.json',
                                     allowEmptyArchive: true
                }
            }
        }

        // ════════════════════════════════════════════════════════════════
        // STAGE 4: AI Analysis (ai/aiAnalyzer.js)
        //
        // Gemini Call #1: tool selection → tool_config.json
        // Gemini Call #2: manual test cases → manual_tests.json
        // ════════════════════════════════════════════════════════════════
        stage('AI Analysis') {
            steps {
                echo "════════════ STAGE 4: AI ANALYSIS (2 Gemini calls) ════════════"
                dir("${WORKSPACE}/pipeline/ai-module") {
                    sh """
                        GEMINI_API_KEY=${GEMINI_API_KEY} node ai/aiAnalyzer.js \
                            "${OUTPUT_DIR}/context.json" \
                            "${OUTPUT_DIR}"
                    """
                }

                // Verify outputs
                sh """
                    test -f ${OUTPUT_DIR}/tool_config.json \
                        || { echo "[FAIL] tool_config.json missing"; exit 1; }
                    test -f ${OUTPUT_DIR}/manual_tests.json \
                        || { echo "[FAIL] manual_tests.json missing"; exit 1; }
                """

                // Load tool decisions into env for downstream stages
                script {
                    def cfg = readJSON file: "${OUTPUT_DIR}/tool_config.json"
                    env.RUN_SEMGREP       = cfg.semgrep?.enabled?.toString()  ?: 'false'
                    env.RUN_BANDIT        = cfg.bandit?.enabled?.toString()   ?: 'false'
                    env.RUN_ZAP          = cfg.zap?.enabled?.toString()       ?: 'false'
                    env.RUN_NUCLEI       = cfg.nuclei?.enabled?.toString()    ?: 'false'
                    env.RUN_NIKTO        = cfg.nikto?.enabled?.toString()     ?: 'false'
                    env.SEMGREP_RULES    = cfg.semgrep?.rulesets?.join(',')   ?: 'p/owasp-top-ten'
                    env.ZAP_MODE         = cfg.zap?.mode                      ?: 'baseline'
                    env.NUCLEI_TAGS      = cfg.nuclei?.templateTags?.join(',') ?: ''
                    env.SCAN_STRATEGY    = cfg.scanStrategy                    ?: 'full'

                    echo "Tool config loaded:"
                    echo "  Scan: ${env.SCAN_STRATEGY} | Semgrep: ${env.RUN_SEMGREP} | ZAP: ${env.RUN_ZAP} (${env.ZAP_MODE}) | Nuclei: ${env.RUN_NUCLEI} | Bandit: ${env.RUN_BANDIT}"
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'security-context-output/tool_config.json,security-context-output/manual_tests.json',
                                     allowEmptyArchive: true
                }
            }
        }

        // ════════════════════════════════════════════════════════════════
        // STAGE 5: SAST — Semgrep + Bandit (conditional)
        // ════════════════════════════════════════════════════════════════
        stage('SAST') {
            parallel {
                stage('Semgrep') {
                    when { expression { env.RUN_SEMGREP == 'true' } }
                    steps {
                        sh """
                            echo "[SAST] Semgrep: ${SEMGREP_RULES}"
                            semgrep scan \
                                --config ${SEMGREP_RULES} \
                                --json \
                                --output ${REPORTS_DIR}/semgrep-report.json \
                                --error \
                                --max-memory 2048 \
                                ${WORKSPACE} || true
                            echo "[SAST] Semgrep done"
                        """
                    }
                }
                stage('Bandit') {
                    when { expression { env.RUN_BANDIT == 'true' } }
                    steps {
                        sh """
                            echo "[SAST] Bandit (Python)"
                            bandit -r ${WORKSPACE} \
                                -f json \
                                -o ${REPORTS_DIR}/bandit-report.json \
                                --exclude ${WORKSPACE}/.venv,${WORKSPACE}/node_modules \
                                -ll || true
                            echo "[SAST] Bandit done"
                        """
                    }
                }
            }
        }

        // ════════════════════════════════════════════════════════════════
        // STAGE 6: SCA — Trivy (always)
        // ════════════════════════════════════════════════════════════════
        stage('SCA: Trivy') {
            steps {
                sh """
                    echo "[SCA] Trivy filesystem scan (strategy: ${SCAN_STRATEGY})"
                    trivy fs \
                        --format json \
                        --output ${REPORTS_DIR}/trivy-report.json \
                        --exit-code 0 \
                        --scanners vuln,secret \
                        ${WORKSPACE} || true
                    echo "[SCA] Trivy done"
                """
            }
        }

        // ════════════════════════════════════════════════════════════════
        // STAGE 7: DAST — ZAP + Nuclei (conditional)
        // ════════════════════════════════════════════════════════════════
        stage('DAST') {
            parallel {
                stage('ZAP') {
                    when { expression { env.RUN_ZAP == 'true' } }
                    steps {
                        sh """
                            echo "[DAST] ZAP ${ZAP_MODE} → ${TARGET_URL}"
                            if [ "${ZAP_MODE}" = "baseline" ]; then
                                docker run --rm \
                                    -v ${REPORTS_DIR}:/zap/wrk:rw \
                                    ghcr.io/zaproxy/zaproxy:stable \
                                    zap-baseline.py \
                                    -t ${TARGET_URL} \
                                    -J zap-report.json \
                                    -I || true
                            elif [ "${ZAP_MODE}" = "api-scan" ]; then
                                docker run --rm \
                                    -v ${REPORTS_DIR}:/zap/wrk:rw \
                                    ghcr.io/zaproxy/zaproxy:stable \
                                    zap-api-scan.py \
                                    -t ${TARGET_URL} \
                                    -f openapi \
                                    -J zap-report.json \
                                    -I || true
                            else
                                docker run --rm \
                                    -v ${REPORTS_DIR}:/zap/wrk:rw \
                                    ghcr.io/zaproxy/zaproxy:stable \
                                    zap-full-scan.py \
                                    -t ${TARGET_URL} \
                                    -J zap-report.json \
                                    -I || true
                            fi
                            echo "[DAST] ZAP done"
                        """
                    }
                }
                stage('Nuclei') {
                    when { expression { env.RUN_NUCLEI == 'true' } }
                    steps {
                        sh """
                            echo "[DAST] Nuclei tags: ${NUCLEI_TAGS}"
                            TAGS=""
                            for tag in \$(echo "${NUCLEI_TAGS}" | tr ',' ' '); do
                                TAGS="\$TAGS -tags \$tag"
                            done
                            nuclei \
                                -u ${TARGET_URL} \
                                \$TAGS \
                                -json-export ${REPORTS_DIR}/nuclei-report.json \
                                -severity medium,high,critical \
                                -silent || true
                            echo "[DAST] Nuclei done"
                        """
                    }
                }
            }
        }

        // ════════════════════════════════════════════════════════════════
        // STAGE 8: AI Report (ai/reportGenerator.js — Gemini Call #3)
        //
        // readSemgrep + readBandit + readTrivy + readZap
        // → dedup → triageWithGemini → buildHtml
        // ════════════════════════════════════════════════════════════════
        stage('AI Report') {
            steps {
                echo "════════════ STAGE 8: AI REPORT (Gemini Call #3) ════════════"
                dir("${WORKSPACE}/pipeline/ai-module") {
                    sh """
                        GEMINI_API_KEY=${GEMINI_API_KEY} node ai/reportGenerator.js \
                            "${REPORTS_DIR}" \
                            "${OUTPUT_DIR}/context.json" \
                            "${FINAL_REPORT_DIR}"
                    """
                }

                sh "test -f ${FINAL_REPORT_DIR}/security-report.html || { echo '[FAIL] security-report.html missing'; exit 1; }"
            }
        }

        // ════════════════════════════════════════════════════════════════
        // STAGE 9: Publish — HTML report + build status
        //
        // Mark build UNSTABLE nếu có critical finding trên main branch
        // ════════════════════════════════════════════════════════════════
        stage('Publish') {
            steps {
                publishHTML(target: [
                    allowMissing:          false,
                    alwaysLinkToLastBuild: true,
                    keepAll:               true,
                    reportDir:             'final-report',
                    reportFiles:           'security-report.html',
                    reportName:            'Security Report',
                    reportTitles:          'DevSecOps Security Report',
                ])

                // Mark UNSTABLE nếu critical finding trên main
                script {
                    if (fileExists("${FINAL_REPORT_DIR}/security-report.json")) {
                        def report  = readJSON file: "${FINAL_REPORT_DIR}/security-report.json"
                        def summary = report.executive_summary
                        def criticals = summary?.critical_count ?: 0

                        if (criticals > 0 && env.GIT_BRANCH ==~ /.*main.*|.*master.*/) {
                            unstable(message: "Build UNSTABLE: ${criticals} critical security finding(s) on main branch — review Security Report")
                        } else if (criticals > 0) {
                            echo "WARNING: ${criticals} critical finding(s) found (not blocking on branch ${env.GIT_BRANCH})"
                        } else {
                            echo "No critical findings."
                        }
                    }
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'scan-reports/**,final-report/**,security-context-output/**',
                                     allowEmptyArchive: true
                }
            }
        }

    }

    post {
        success  { echo "[PIPELINE] SUCCESS — Security Report published" }
        unstable { echo "[PIPELINE] UNSTABLE — Critical findings detected, review report" }
        failure  { echo "[PIPELINE] FAILED — check stage logs above" }
    }
}
