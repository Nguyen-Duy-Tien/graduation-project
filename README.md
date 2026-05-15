# AI-Assisted DevSecOps Pipeline Module

Module tích hợp AI vào pipeline CI/CD để tự động phân tích bảo mật ứng dụng web — từ thu thập ngữ cảnh, lựa chọn công cụ quét, đến tổng hợp và phân loại kết quả thành báo cáo.

---

## Mục lục

- [Tổng quan kiến trúc](#tổng-quan-kiến-trúc)
- [Yêu cầu hệ thống](#yêu-cầu-hệ-thống)
- [Cài đặt](#cài-đặt)
- [Cấu trúc thư mục](#cấu-trúc-thư-mục)
- [Cách sử dụng](#cách-sử-dụng)
- [Luồng hoạt động chi tiết](#luồng-hoạt-động-chi-tiết)
- [Cấu hình Jenkins](#cấu-hình-jenkins)
- [Output files](#output-files)
- [Chạy tests](#chạy-tests)
- [Các framework được hỗ trợ](#các-framework-được-hỗ-trợ)
- [Giải thích 3 Gemini API calls](#giải-thích-3-gemini-api-calls)

---

## Tổng quan kiến trúc

```
Source code
     │
     ▼
┌─────────────────────────────────────┐
│  Stage 3: Context Collection        │  ← 5 collectors chạy song song
│  techStack + routes + codePatterns  │    không gọi AI
│  + apiSurface + gitDiff + container │
└──────────────────┬──────────────────┘
                   │ context.json
                   ▼
┌─────────────────────────────────────┐
│  Stage 4: AI Analysis               │
│  Gemini Call #1 → tool_config.json  │  ← Chọn tool + cấu hình tối ưu
│  Gemini Call #2 → manual_tests.json │  ← Sinh test case thủ công
└──────────────────┬──────────────────┘
                   │
          ┌────────┴────────┐
          ▼                 ▼
┌──────────────┐   ┌─────────────────┐
│ Stage 5 SAST │   │  Stage 7 DAST   │
│ Semgrep      │   │  ZAP + Nuclei   │
│ Bandit       │   │  + Nikto        │
└──────┬───────┘   └────────┬────────┘
       │    Stage 6 SCA     │
       │    Trivy           │
       └──────────┬─────────┘
                  │ scan-reports/
                  ▼
┌─────────────────────────────────────┐
│  Stage 8: AI Report                 │
│  Gemini Call #3 → triage + score    │  ← Phân loại, risk score, remediation
│  → security-report.html/.json       │
└─────────────────────────────────────┘
```

---

## Yêu cầu hệ thống

| Thành phần | Phiên bản tối thiểu | Ghi chú |
|---|---|---|
| Node.js | ≥ 18.0.0 | Cần `fetch` native và `node:test` |
| Jenkins | ≥ 2.400 | Pipeline plugin, HTML Publisher plugin |
| Docker | bất kỳ | Để chạy ZAP container |
| Semgrep | ≥ 1.0 | Cài trên Jenkins agent |
| Trivy | ≥ 0.50 | Cài trên Jenkins agent |
| Nuclei | ≥ 3.0 | Cài trên Jenkins agent |
| Nikto | ≥ 2.1 | Cài trên Jenkins agent (chỉ cần nếu PHP) |
| Bandit | ≥ 1.7 | Cài trên Jenkins agent (chỉ cần nếu Python) |
| Gemini API Key | — | Google AI Studio → [aistudio.google.com](https://aistudio.google.com) |

---

## Cài đặt

**1. Clone module vào Jenkins workspace:**

```bash
# Đặt module tại pipeline/ai-module/ trong repo của dự án
git clone <repo> pipeline/ai-module
```

**2. Cài dependencies:**

```bash
cd pipeline/ai-module
npm install
```

**3. Thêm credentials vào Jenkins:**

Vào `Manage Jenkins → Credentials → Global` và thêm:

| ID | Loại | Mô tả |
|---|---|---|
| `gemini-api-key` | Secret Text | Gemini API Key từ Google AI Studio |
| `zap-username` | Username with password | Tài khoản đăng nhập app (nếu cần auth) |
| `zap-password` | Secret Text | Mật khẩu tương ứng |

**4. Thêm biến môi trường Jenkins (tuỳ chọn):**

```
STAGING_URL   = http://your-app:8080     # URL target cho DAST
ZAP_LOGIN_URL = http://your-app/login    # URL login (nếu app cần auth)
```

---

## Cấu trúc thư mục

```
pipeline/ai-module/
├── ai/
│   ├── aiAnalyzer.js        # Gemini Call #1 (tool selection) + #2 (manual tests)
│   ├── geminiClient.js      # Wrapper Gemini API: callGemini, retry, parseJson
│   └── reportGenerator.js  # Gemini Call #3 (triage) + HTML report builder
├── collectors/
│   ├── contextCollector.js  # Entry point: chạy 5 collector song song
│   ├── techStack.js         # Nhận diện ngôn ngữ, framework, dependencies
│   ├── routeScanner.js      # Quét 9 route pattern, phân loại 6 flag
│   ├── codePattern.js       # Quét 20 dangerous pattern, 9 category
│   └── apiSurface.js        # OpenAPI/Swagger + git diff + Docker info
├── Jenkinsfile              # Pipeline 9 stages
├── package.json
└── test.js                  # 30 unit tests cho các hàm pure
```

---

## Cách sử dụng

### Chạy thủ công từng bước

```bash
# Bước 1 — Thu thập context (không cần API key)
npm run collect /path/to/your-project
# Output: /path/to/your-project/security-context-output/context.json

# Bước 2 — AI phân tích, chọn tool, sinh test cases
GEMINI_API_KEY=your_key npm run analyze \
  ./security-context-output/context.json \
  ./security-context-output
# Output: tool_config.json, manual_tests.json

# Bước 3 — Chạy các tool scan (ví dụ Semgrep + Trivy)
semgrep scan --config p/nodejs --json --output ./scan-reports/semgrep-report.json .
trivy fs --format json --output ./scan-reports/trivy-report.json .

# Bước 4 — AI tổng hợp báo cáo
GEMINI_API_KEY=your_key npm run report \
  ./scan-reports \
  ./security-context-output/context.json \
  ./final-report
# Output: final-report/security-report.html
```

### Chạy trong Jenkins

Copy `Jenkinsfile` vào root của repo dự án, đảm bảo module nằm tại `pipeline/ai-module/`, rồi tạo Pipeline job trỏ vào `Jenkinsfile`.

---

## Luồng hoạt động chi tiết

### Stage 3 — Context Collection

5 collector chạy **song song** với `Promise.all()`, không gọi AI:

| Collector | Tác dụng | Output chính |
|---|---|---|
| `techStack` | Đọc `package.json` / `requirements.txt` / `pom.xml`... | language, framework, features (jwt/orm/fileUpload) |
| `routeScanner` | Quét 9 regex pattern tìm route declarations | danh sách endpoint + classification flags |
| `codePattern` | Quét 20 dangerous pattern trên toàn bộ source | findings theo severity/category |
| `apiSurface` | Tìm file OpenAPI/Swagger nếu có | specSummary với endpoint list |
| `gitDiff` + `containerInfo` | `git diff HEAD~1`, đọc Dockerfile/docker-compose | changedFiles, recommendation (full/incremental) |

**6 classification flags cho endpoint:**

| Flag | Ý nghĩa | Ví dụ path |
|---|---|---|
| `auth` | Xác thực / phân quyền | `/login`, `/auth/refresh` |
| `fileUpload` | Nhận file từ user | `/upload/avatar`, `/import` |
| `idor_candidate` | Có tham số ID trong path | `/users/:id`, `/orders/123` |
| `admin` | Chức năng quản trị | `/admin/dashboard` |
| `export` | Xuất dữ liệu hàng loạt | `/reports/download`, `/export.csv` |
| `payment` | Thanh toán | `/checkout`, `/stripe/webhook` |

---

### Stage 4 — AI Analysis (2 Gemini calls)

**Gemini Call #1 — Tool Selection**

- Input: techStack + top 20 high-risk routes + top 15 dangerous patterns + git diff recommendation
- Output: `tool_config.json` — danh sách tool enabled/disabled, rulesets Semgrep, mode ZAP, tags Nuclei
- Logic: JWT patterns → bật `p/jwt`; file upload endpoints → bật Nuclei `file-upload` templates; PHP → bật Nikto; không thay đổi security-sensitive → incremental scan

**Gemini Call #2 — Manual Test Cases**

- Input: endpoints có flag `idor_candidate`, `fileUpload`, `auth`, `admin` (tối đa 25)
- Output: `manual_tests.json` — test case chi tiết cho IDOR, BFLA, JWT logic flaw, race condition, mass assignment
- Mỗi test case có: steps cụ thể, HTTP request mẫu, chỉ số xác nhận lỗ hổng, gợi ý fix

---

### Stage 8 — AI Report (Gemini Call #3)

- Đọc output của Semgrep, Bandit, Trivy, ZAP, Nikto → **deduplication** theo `category:ruleId:location`
- Gửi tối đa 40 findings (ưu tiên critical/high) lên Gemini
- Gemini phân loại mỗi finding: `confirmed_vulnerability` | `likely_vulnerability` | `needs_manual_review` | `false_positive`
- Tính `risk_score` 0–100, sinh `remediation` cụ thể cho framework đang dùng
- Render `security-report.html` dark-themed với executive summary, severity stats, per-finding details

---

## Cấu hình Jenkins

### Credentials cần có

```groovy
// Trong Jenkinsfile environment block
GEMINI_API_KEY = credentials('gemini-api-key')   // Secret Text
ZAP_USERNAME   = credentials('zap-username')      // Username/Password
ZAP_PASSWORD   = credentials('zap-password')      // Secret Text
```

### Biến môi trường tuỳ chỉnh

```groovy
environment {
    STAGING_URL   = "${env.STAGING_URL ?: 'http://app:8080'}"
    ZAP_LOGIN_URL = "${env.ZAP_LOGIN_URL ?: ''}"
}
```

### ZAP Authentication

Khi AI phát hiện app cần xác thực (có JWT, login endpoint), `tool_config.json` sẽ có `authRequired: true`. Jenkinsfile tự động build `AUTH_FLAGS` cho ZAP sử dụng form-based auth. Để hoạt động cần:

1. Thêm credential `zap-username` và `zap-password` vào Jenkins
2. Set `ZAP_LOGIN_URL` (mặc định dùng `TARGET_URL/login`)

### Build status

Pipeline mark **UNSTABLE** (không fail) khi có critical finding trên nhánh `main`/`master`. Các nhánh khác chỉ log cảnh báo.

---

## Output files

| File | Vị trí | Mô tả |
|---|---|---|
| `context.json` | `security-context-output/` | Toàn bộ ngữ cảnh dự án: tech stack, routes, patterns |
| `tool_config.json` | `security-context-output/` | Cấu hình tool do AI chọn, đọc bởi Jenkinsfile stages |
| `manual_tests.json` | `security-context-output/` | Test case thủ công cho IDOR/BFLA/JWT/Race condition |
| `semgrep-report.json` | `scan-reports/` | Kết quả SAST từ Semgrep |
| `bandit-report.json` | `scan-reports/` | Kết quả SAST từ Bandit (Python) |
| `trivy-report.json` | `scan-reports/` | Kết quả SCA từ Trivy |
| `zap-report.json` | `scan-reports/` | Kết quả DAST từ ZAP |
| `nikto-report.json` | `scan-reports/` | Kết quả DAST từ Nikto (PHP) |
| `nuclei-report.json` | `scan-reports/` | Kết quả DAST từ Nuclei |
| `security-report.html` | `final-report/` | Báo cáo HTML đầy đủ, hiển thị qua Jenkins HTML Publisher |
| `security-report.json` | `final-report/` | Báo cáo JSON machine-readable, dùng cho tích hợp tiếp theo |

---

## Chạy tests

```bash
node --test test.js
```

30 test cases phủ các hàm pure của module:

| Nhóm | Số tests | Hàm được test |
|---|---|---|
| `classifyEndpoint` | 7 | auth, fileUpload, idor_candidate, admin, payment, general, multi-flag |
| `deduplicate` | 4 | dedup theo key, sort severity, empty input |
| `parseJson` | 7 | JSON thuần, markdown fences, leading text, array, lỗi |
| `buildToolConfig` | 6 | scan strategy, ZAP auth flag, bandit disabled, `_meta`, defaults |
| Report readers | 6 | missing file graceful + parse Semgrep + parse Nikto |

---

## Các framework được hỗ trợ

| Ngôn ngữ | Framework | Tool profile |
|---|---|---|
| Node.js | Express, Fastify, Koa, NestJS | `nodejs-rest-api` |
| Node.js | Express + template engine, Next.js | `nodejs-fullstack` |
| Python | Flask | `python-flask` |
| Python | FastAPI | `python-fastapi` |
| Python | Django | `python-django` |
| Java | Spring Boot, Spring MVC | `java-spring` |
| PHP | Laravel | `php-laravel` |
| PHP | Generic | `php-generic` |
| Go | Gin | `golang-gin` |
| Ruby | Rails | `ruby-rails` |

Framework không nhận ra sẽ dùng profile `unknown` với Semgrep `p/owasp-top-ten` + ZAP baseline.

---

## Giải thích 3 Gemini API calls

```
Call #1 (aiAnalyzer.js)
  temperature: 0.15  |  max_tokens: 4096
  Input:  ~2–5KB (compact payload: tech stack + top 20 high-risk routes + top 15 patterns)
  Output: tool_config.json (~1–2KB)
  Mục đích: quyết định tool nào chạy, với cấu hình gì

Call #2 (aiAnalyzer.js)
  temperature: 0.20  |  max_tokens: 6144
  Input:  ~3–6KB (tối đa 25 endpoint liên quan + code evidence)
  Output: manual_tests.json (~3–8KB, 5–15 test cases)
  Mục đích: sinh test case cho lỗ hổng logic mà tool tự động không phát hiện được

Call #3 (reportGenerator.js)
  temperature: 0.10  |  max_tokens: 8192
  Input:  tối đa 40 findings đã dedup (~5–10KB)
  Output: triaged findings với risk score + remediation + executive summary
  Mục đích: loại bỏ false positive, ưu tiên findings, đưa ra hướng fix cụ thể
```




