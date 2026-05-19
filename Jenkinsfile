pipeline {
    agent any

    environment {
        // Định nghĩa các thư mục đầu ra (sẽ tự động sinh ra tại thư mục gốc khi chạy)
        CONTEXT_DIR = "security-context-output"
        REPORTS_DIR = "security-context-output/scan-reports"
        FINAL_DIR   = "security-context-output/final-report"
        
        // Thư mục chứa mã nguồn ứng dụng mục tiêu cần phân tích
        TARGET_APP_DIR = "vulnerable-rest-api"
        
        // Gọi API Key bảo mật từ Jenkins Credentials Manager
        GEMINI_API_KEY = credentials('GEMINI_API_KEY')
    }

    stages {
        stage('Môi trường & Khởi tạo') {
            steps {
                echo '=== STAGE 1: KHỞI TẠO CÁC THƯ MỤC ĐỆM BÁO CÁO ==='
                // Khởi tạo trước cấu trúc thư mục để các công cụ quét có chỗ lưu file
                sh "mkdir -p ${CONTEXT_DIR} ${REPORTS_DIR} ${FINAL_DIR}"
                
                echo 'Kiểm tra trạng thái các công cụ trên máy chủ:'
                sh 'node -v'
                sh 'docker -v'
            }
        }

        stage('Cài đặt Phụ thuộc AI Module') {
            steps {
                echo '=== STAGE 2: CÀI ĐẶT DEPENDENCIES CHO AI MODULE (GỐC REPO) ==='
                // Cài đặt các thư viện lõi (js-yaml, glob, etc.) ở ngang hàng với Jenkinsfile
                sh 'npm install'
            }
        }

        stage('Thu thập Ngữ cảnh (Week 7)') {
            steps {
                echo '=== STAGE 3: CHẠY MODULE THU THẬP NGỮ CẢNH TRÊN THƯ MỤC ỨNG DỤNG ==='
                // CHỈNH SỬA QUAN TRỌNG: Chỉ định chính xác mục tiêu cần quét là thư mục TARGET_APP_DIR
                sh "node collector/contextCollector.js ${TARGET_APP_DIR} --output ${CONTEXT_DIR}"
            }
        }

        stage('AI Phân tích & Định hướng (Week 8)') {
            steps {
                echo '=== STAGE 4: GỌI GEMINI PHÂN TÍCH NGỮ CẢNH & SINH CẤU HÌNH QUÉT ==='
                // Đọc file context.json vừa tạo và ghi cấu hình tool_config.json, manual_tests.json vào CONTEXT_DIR
                sh "node ai/aiAnalyzer.js ${CONTEXT_DIR}/context.json ${CONTEXT_DIR}"
            }
        }

        stage('Kiểm thử Tự động SAST & SCA (Week 9)') {
            steps {
                echo '=== STAGE 5: ĐIỀU PHỐI CÁC CÔNG CỤ KIỂM THỬ TĨNH THEO CHỈ ĐỊNH CỦA AI ==='
                script {
                    def toolConfig = readJSON file: "${CONTEXT_DIR}/tool_config.json"
                    echo "Chiến lược quét được AI đề xuất: ${toolConfig.scanStrategy}"
                    
                    // 1. Thực thi Semgrep SAST
                    if (toolConfig.semgrep && toolConfig.semgrep.enabled) {
                        echo "AI kích hoạt Semgrep với các Rulesets: ${toolConfig.semgrep.rulesets}"
                        def rulesArgs = ""
                        for (ruleset in toolConfig.semgrep.rulesets) {
                            rulesArgs += " --config=${ruleset}"
                        }
                        // Quét bên trong thư mục TARGET_APP_DIR/server để tìm lỗi backend code
                        sh "docker run --rm -v \$(pwd):/src returntocorp/semgrep semgrep scan ${rulesArgs} --json --output=${REPORTS_DIR}/semgrep-report.json src/${TARGET_APP_DIR}/server || true"
                    }

                    // 2. Thực thi Trivy SCA (Kiểm tra thư viện phụ thuộc của Server)
                    if (toolConfig.trivy && toolConfig.trivy.enabled) {
                        echo "AI kích hoạt Trivy SCA kiểm tra lỗ hổng thư viện package.json"
                        sh "docker run --rm -v \$(pwd):/src aquasec/trivy fs --format json --output /src/${REPORTS_DIR}/trivy-report.json /src/${TARGET_APP_DIR}/server || true"
                    }
                    
                    // 3. Thực thi Bandit (Chỉ chạy nếu AI phát hiện có Python, ứng dụng của bạn dùng Node nên mặc định sẽ bỏ qua)
                    if (toolConfig.bandit && toolConfig.bandit.enabled) {
                        echo "AI kích hoạt Bandit SAST cho mã nguồn Python"
                        sh "docker run --rm -v \$(pwd):/md openstackhelm/bandit bandit -r /md/${TARGET_APP_DIR} -f json -o /md/${REPORTS_DIR}/bandit-report.json || true"
                    }
                }
            }
        }

        stage('Triển khai Môi trường Target (Staging)') {
            steps {
                echo '=== STAGE 6: TRIỂN KHAI ỨNG DỤNG LÊN CỔNG 3001 ĐỂ LÀM BIA BẮN DAST ==='
                // CHỈNH SỬA QUAN TRỌNG: Di chuyển vào thư mục vulnerable-rest-api để gọi đúng file docker-compose.yml
                sh "cd ${TARGET_APP_DIR} && sudo docker-compose up -d --build"
                // Nghỉ 15 giây để Node.js server hoàn thành việc kết nối DB và chạy database migrations công việc tuần 9
                sh 'sleep 15'
            }
        }

        stage('Kiểm thử Động DAST & Nuclei (Week 9)') {
            steps {
                echo '=== STAGE 7: CHẠY CÁC CÔNG CỤ TẤN CÔNG ĐỘNG DAST ==='
                script {
                    def toolConfig = readJSON file: "${CONTEXT_DIR}/tool_config.json"
                    
                    // 1. Thực thi OWASP ZAP Tấn công Động dựa vào Gateway IP của Docker (172.19.0.1) hoặc Localhost
                    if (toolConfig.zap && toolConfig.zap.enabled) {
                        echo "AI kích hoạt OWASP ZAP ở chế độ: ${toolConfig.zap.mode}"
                        if (toolConfig.zap.mode == "api-scan") {
                            // Quét dựa trên một Endpoint thực tế của API để kiểm tra cấu trúc dữ liệu JSON trả về
                            sh "docker run --rm -v \$(pwd):/zap/wrk/:rw -t ghcr.io/zaproxy/zaproxy:stable zap-api-scan.py -t http://172.19.0.1:3001/api/books -f openapi -J zap-report.json || true"
                        } else {
                            sh "docker run --rm -v \$(pwd):/zap/wrk/:rw -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://172.19.0.1:3001 -J zap-report.json || true"
                        }
                        sh "mv zap-report.json ${REPORTS_DIR}/zap-report.json || true"
                    }

                    // 2. Thực thi Nuclei quét dựa trên lỗ hổng mẫu cấu hình
                    if (toolConfig.nuclei && toolConfig.nuclei.enabled) {
                        echo "AI kích hoạt Nuclei Scan với các Tags: ${toolConfig.nuclei.templateTags}"
                        def tagsArgs = toolConfig.nuclei.templateTags.join(",")
                        sh "docker run --rm -v \$(pwd):/src projectdiscovery/nuclei -target http://172.19.0.1:3001 -tags ${tagsArgs} -json-export /src/${REPORTS_DIR}/nuclei-report.json || true"
                    }
                }
            }
        }

        stage('AI Triage & Sinh Báo cáo Đồ án (Week 10)') {
            steps {
                echo '=== STAGE 8: GỌI AI PHÂN LOẠI, KHỬ TRÙNG LẶP & XUẤT BÁO CÁO HỢP NHẤT ==='
                // Đọc toàn bộ các file report trong REPORTS_DIR, đối chiếu context.json để lọc lỗi giả và xuất ra FINAL_DIR
                sh "node ai/reportGenerator.js ${REPORTS_DIR} ${CONTEXT_DIR}/context.json ${FINAL_DIR}"
            }
        }
    }

    post {
        always {
            echo '=== DỌN DẸP HẠ TẦNG & LƯU TRỮ KẾT QUẢ KIỂM THỬ ==='
            // Hạ ứng dụng vulnerable-rest-api xuống sau khi kết thúc đợt quét tấn công để giải phóng tài nguyên RAM/Port
            sh "cd ${TARGET_APP_DIR} && sudo docker-compose down"
            
            // Đọc kết quả phân loại từ AI để áp dụng cơ chế bẻ gãy build (Quality Gate - FR-04)
            script {
                if (fileExists("${FINAL_DIR}/security-report.json")) {
                    def finalReport = readJSON file: "${FINAL_DIR}/security-report.json"
                    def execSummary = finalReport.executive_summary
                    echo "=== KẾT QUẢ ĐÁNH GIÁ BẢO MẬT TỪ AI ==="
                    echo "Điểm an toàn của dự án: ${execSummary.security_posture_score}/100"
                    echo "Số lỗ hổng thực tế mức độ cực kỳ nguy hiểm (Critical): ${execSummary.critical_count}"
                    
                    if (execSummary.critical_count > 0) {
                        currentBuild.result = 'FAILURE'
                        error("Quality Gate thất bại! Phát hiện thấy ${execSummary.critical_count} lỗ hổng nguy hiểm mức độ CRITICAL.")
                    }
                }
            }

            // Lưu trữ toàn bộ thư mục output làm minh chứng (Artifacts) cho đồ án tốt nghiệp (FR-05)
            archiveArtifacts artifacts: "${CONTEXT_DIR}/**/*", allowEmptyArchive: true
            
            // Xuất trực tiếp giao diện báo cáo HTML trực quan hóa kết quả lên thanh menu của Jenkins build
            publishHTML(target: [
                allowMissing: false,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: "${FINAL_DIR}",
                reportFiles: 'security-report.html',
                reportName: 'AI Security Triage Report'
            ])
        }
    }
}