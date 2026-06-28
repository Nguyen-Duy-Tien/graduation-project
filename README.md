# AI-Assisted DevSecOps Pipeline Module

Module Node.js hỗ trợ xây dựng pipeline DevSecOps cho ứng dụng web. Module thu thập ngữ cảnh từ mã nguồn, dùng Gemini để chọn cấu hình công cụ kiểm thử, sinh checklist kiểm thử thủ công, chạy scanner qua Docker adapter và tổng hợp báo cáo HTML/JSON.

Repo hiện tại được thiết kế để chạy như một module CI/CD, không phải một web app độc lập.

## Mục lục

- [Tổng quan](#tổng-quan)
- [Yêu cầu](#yêu-cầu)
- [Cài đặt](#cài-đặt)
- [Cấu trúc thư mục](#cấu-trúc-thư-mục)
- [Chạy local](#chạy-local)
- [Chạy Jenkins](#chạy-jenkins)
- [Artifact đầu ra](#artifact-đầu-ra)
- [Tool adapters](#tool-adapters)
- [Collector và AI flow](#collector-và-ai-flow)
- [Đánh giá thực nghiệm](#đánh-giá-thực-nghiệm)
- [Chạy test](#chạy-test)
- [Giới hạn hiện tại](#giới-hạn-hiện-tại)

## Tổng quan

Luồng chính của hệ thống:

```text
Target source code
  |
  | 1. collector/contextCollector.js
  v
security-context-output/context.json
  |
  | 2. ai/aiAnalyzer.js
  v
tool_config.json + manual_tests.json
  |
  | 3. ai/pipelineGenerator.js
  v
runtime/run-sast.sh + deploy-target.sh + run-dast.sh + teardown.sh
  |
  | 4. Docker scanner adapters
  v
scan-reports/*
  |
  | 5. ai/reportGenerator.js
  v
final-report/security-report.html + security-report.json
```

Các scanner không được hardcode trong Jenkinsfile. Jenkins chỉ gọi các bước cố định, còn cấu hình công cụ được sinh từ `tool_config.json` và các script runtime.

## Yêu cầu

| Thành phần | Mục đích |
|---|---|
| Node.js >= 18 | Chạy ESM, `fetch` native và `node:test` |
| npm | Cài dependency Node.js |
| Docker | Chạy scanner container và target Docker Compose |
| `docker-compose` | Script deploy hiện dùng lệnh `docker-compose`, không phải `docker compose` |
| Gemini API key | Cần cho bước AI analyze và AI report |
| Jenkins Linux agent | Cần nếu chạy `Jenkinsfile`; pipeline dùng `sh` |

Jenkins cần cấu hình thêm:

- NodeJS tool tên `NodeJS_18`.
- Credential Secret Text có ID `GEMINI_API_KEY`.
- Docker permission cho Jenkins agent.
- Plugin HTML Publisher để publish `security-report.html`.
- Pipeline Utility Steps nếu dùng `readJSON` trong quality gate.

## Cài đặt

```bash
npm install
```

Nếu cần chạy benchmark submodule:

```bash
git submodule update --init --recursive
```

Thiết lập Gemini key:

```bash
export GEMINI_API_KEY="your_key"
```

PowerShell:

```powershell
$env:GEMINI_API_KEY = "your_key"
```

## Cấu trúc thư mục

```text
ai/
  geminiClient.js        Gemini REST client, retry, JSON parser
  aiAnalyzer.js          Chọn tool + sinh manual tests
  pipelineGenerator.js   Sinh runtime-info.json và shell scripts
  reportGenerator.js     Đọc scanner reports, AI triage, render report

collector/
  contextCollector.js    Entry point thu thập context
  techStack.js           Nhận diện language/framework/profile
  routeScanner.js        Quét route và risk signal
  codePattern.js         Quét dangerous code patterns
  schemaScanner.js       Trích model/schema và sensitive fields
  apiSurface.js          OpenAPI, git diff, Docker/Compose context

tools/
  index.js               Registry adapter
  semgrep.js             Semgrep SAST adapter
  bandit.js              Bandit Python SAST adapter
  trivy.js               Trivy SCA adapter
  zap.js                 OWASP ZAP DAST adapter
  nuclei.js              Nuclei DAST adapter
  nikto.js               Nikto DAST adapter

runtime/
  sanitize.js            Whitelist/sanitize giá trị từ AI trước khi đưa vào shell
  servicePicker.js       Chọn service target từ Docker Compose
  *.sh, runtime-info.json
                         Artifact sinh bởi pipelineGenerator

examples/sqli/           Flask/MySQL SQL Injection demo
benchmarks/              Juice Shop, crAPI, OWASP Benchmark submodules
evaluation/              Script và báo cáo đánh giá thực nghiệm
Jenkinsfile              Pipeline Jenkins 9 stage
```

Lưu ý: `runtime/` vừa có source runtime, vừa có artifact sinh ra. Nếu dọn thủ công, chỉ xoá `runtime/*.sh` và `runtime/runtime-info.json`; không xoá `runtime/sanitize.js` hoặc `runtime/servicePicker.js`.

## Chạy local

Ví dụ với target có sẵn:

```bash
node collector/contextCollector.js examples/sqli --output ./security-context-output
```

Chạy AI analyze để sinh cấu hình tool và checklist thủ công:

```bash
node ai/aiAnalyzer.js ./security-context-output/context.json ./security-context-output
```

Sinh các script runtime:

```bash
node ai/pipelineGenerator.js ./security-context-output ./runtime examples/sqli
```

Chạy scanner. Các script này là Bash script, phù hợp Linux/Jenkins agent; trên Windows nên dùng WSL hoặc Git Bash có Docker access.

```bash
bash ./runtime/run-sast.sh
bash ./runtime/deploy-target.sh
bash ./runtime/run-dast.sh
```

Sinh báo cáo:

```bash
node ai/reportGenerator.js \
  ./security-context-output/scan-reports \
  ./security-context-output/context.json \
  ./security-context-output/final-report
```

Teardown target:

```bash
bash ./runtime/teardown.sh
```

Nếu chỉ muốn thu thập context thì không cần `GEMINI_API_KEY`. Các bước `aiAnalyzer.js` và `reportGenerator.js` bắt buộc có key.

## Chạy Jenkins

`Jenkinsfile` hiện có các parameter:

| Parameter | Mặc định | Ý nghĩa |
|---|---|---|
| `TARGET_PROJECT_DIR` | `benchmarks/juice-shop` | Đường dẫn tương đối trong `WORKSPACE` tới target cần quét |
| `KEEP_STAGING` | `true` | Giữ staging và dừng ở manual gate trước teardown |

Các stage chính:

1. `Init`: validate `TARGET_PROJECT_DIR`, xoá artifact cũ, tạo thư mục output.
2. `Install deps`: chạy `npm ci || npm install`.
3. `Collect context`: sinh `security-context-output/context.json`.
4. `AI analyze`: sinh `tool_config.json` và `manual_tests.json`.
5. `Generate pipeline scripts`: sinh script trong `runtime/`.
6. `SAST + SCA`: chạy `runtime/run-sast.sh`.
7. `Deploy + DAST`: deploy target qua Docker Compose và chạy DAST.
8. `AI Report`: sinh `security-report.html` và `security-report.json`.
9. `Manual Test Gate`: nếu `KEEP_STAGING=true`, Jenkins chờ input để người kiểm thử chạy checklist thủ công.

Post action luôn gọi `runtime/teardown.sh`, archive artifact và publish HTML report. Quality gate hiện đánh dấu build `FAILURE` khi `executive_summary.critical_count > 20`.

## Artifact đầu ra

| File | Vị trí | Mô tả |
|---|---|---|
| `context.json` | `security-context-output/` | Tech stack, routes, schemas, patterns, API surface, git diff, container info |
| `tool_config.json` | `security-context-output/` | Cấu hình scanner do Gemini sinh hoặc fallback profile |
| `manual_tests.json` | `security-context-output/` | Checklist IDOR/BFLA/JWT/race/mass assignment/auth bypass |
| `runtime-info.json` | `runtime/` | Service, port, network, compose file và trạng thái skip DAST |
| `semgrep-report.json` | `security-context-output/scan-reports/` | Semgrep output |
| `bandit-report.json` | `security-context-output/scan-reports/` | Bandit output nếu target Python |
| `trivy-report.json` | `security-context-output/scan-reports/` | Trivy filesystem SCA output |
| `zap-report.json` | `security-context-output/scan-reports/` | OWASP ZAP output |
| `nuclei-report.jsonl` | `security-context-output/scan-reports/` | Nuclei JSONL output |
| `nikto-report.json` | `security-context-output/scan-reports/` | Nikto output |
| `security-report.html` | `security-context-output/final-report/` | Báo cáo HTML publish trên Jenkins |
| `security-report.json` | `security-context-output/final-report/` | Báo cáo máy đọc được cho đánh giá/tích hợp tiếp |

## Tool adapters

Scanner được chạy qua Docker image:

| Tool | Loại | Image / hành vi |
|---|---|---|
| Semgrep | SAST | `returntocorp/semgrep`; hỗ trợ target là Git submodule bằng cách mount superproject |
| Bandit | SAST Python | `ghcr.io/pycqa/bandit/bandit`; chỉ chạy khi `techStack.language === "python"` |
| Trivy | SCA | `aquasec/trivy`; hiện chỉ thực thi target `fs` |
| ZAP | DAST | `ghcr.io/zaproxy/zaproxy:stable`; mode `baseline`, `api-scan`, `full-scan` |
| Nuclei | DAST | `projectdiscovery/nuclei`; dùng severity và tags từ `tool_config.json` |
| Nikto | DAST | `alpine/nikto` |

Các adapter đều sanitize đầu vào từ AI trước khi render shell command. Nhiều scanner được nối `|| true` để pipeline vẫn đi tiếp tới bước report dù scanner trả exit code khác 0.

## Collector và AI flow

`contextCollector.js` chạy `techStack` trước để xác định ngôn ngữ/framework. Sau đó các collector còn lại chạy song song:

- `routeScanner`: quét route cho Express/NestJS/Flask/FastAPI/Django/Spring/Laravel/Gin/Rails, phân loại endpoint và suy ra risk signal như `missing_auth`, `missing_admin`, `missing_ownership_check`.
- `codePattern`: tìm pattern nguy hiểm như SQLi, NoSQLi, RCE, JWT weakness, mass assignment, SSRF, XSS, secret, path traversal, auth bypass, info leak, ReDoS.
- `schemaScanner`: trích model/schema, sensitive fields, ownership fields và mass assignment targets.
- `apiSurface`: đọc OpenAPI/Swagger nếu có.
- `gitDiff`: lấy thay đổi gần nhất và đề xuất `full` hoặc `incremental`.
- `containerInfo`: đọc Dockerfile/Docker Compose, service, port, network và biến môi trường dạng key.

`aiAnalyzer.js` gọi Gemini cho hai mục đích:

- Chọn scanner và cấu hình scanner, ghi `tool_config.json`.
- Sinh checklist thủ công theo batch, ghi `manual_tests.json`.

Các biến có thể dùng để điều chỉnh manual-test batching:

| Biến | Mặc định |
|---|---:|
| `MANUAL_TEST_BATCH_SIZE` | `4` |
| `MANUAL_TEST_BATCH_DELAY_MS` | `5000` |
| `MANUAL_TEST_MAX_OUTPUT_TOKENS` | `8192` |

`reportGenerator.js` đọc report của các tool, deduplicate theo nguồn/category/rule/location, gọi Gemini triage theo chunk, sau đó render HTML/JSON. Nếu không có scanner finding, report vẫn được sinh với risk thấp và checklist thủ công nếu có.

## Đánh giá thực nghiệm

Các script trong `evaluation/` phục vụ đánh giá artifact đã sinh. Nên truyền path rõ ràng thay vì dựa vào default legacy trong một số script.

Đánh giá OWASP Benchmark từ Semgrep report:

```bash
npm run evaluate:owasp -- \
  --expected benchmarks/owasp-benchmark/expectedresults-1.2.csv \
  --semgrep-report security-context-output-benchmark/scan-reports/semgrep-report.json \
  --output evaluation/owasp-benchmark-evaluation.md \
  --json-output evaluation/owasp-benchmark-evaluation.json
```

Đánh giá Juice Shop theo challenge/context:

```bash
node evaluation/evaluateJuiceShopContext.js \
  --challenges benchmarks/juice-shop/data/static/challenges.yml \
  --report security-context-output/final-report/security-report.json \
  --html security-context-output/final-report/security-report.html \
  --output evaluation/juice-shop-context-evaluation.md \
  --json-output evaluation/juice-shop-context-evaluation.json
```

Script generic `evaluation/evaluateBenchmark.js` kỳ vọng target có file `vulnerabilities/vulnerabilities.md`. Nếu target không có ground truth theo format đó, hãy truyền `--context`, `--report` và `--manual-tests` để chỉ tính các metric có thể tính được.

## Chạy test

```bash
npm test
```

Script `npm test` hiện chạy test trong `runtime/`, `collector/` và `ai/` theo cấu hình `package.json`.

Các test adapter trong `tools/*.test.js` có thể chạy trực tiếp:

```bash
node --test tools/*.test.js
```

## Framework/profile được hỗ trợ

Các profile chính trong `collector/techStack.js`:

| Profile | Framework/ngôn ngữ |
|---|---|
| `nodejs-rest-api` | Express, Fastify, Koa, Restify, NestJS |
| `nodejs-fullstack` | Express có template engine, Next/Nuxt style dependency |
| `python-flask` | Flask |
| `python-fastapi` | FastAPI |
| `python-django` | Django |
| `java-spring` | Spring Boot/MVC/WebFlux |
| `php-laravel` | Laravel |
| `php-generic` | PHP generic |
| `golang-gin` | Gin |
| `ruby-rails` | Rails |
| `unknown` | Fallback với Semgrep OWASP Top Ten + ZAP baseline |

Một số framework được detect nhưng chưa có profile riêng đầy đủ sẽ rơi về `unknown` hoặc profile generic.

## Giới hạn hiện tại

- ZAP chưa có form-based authentication tự động; `authRequired` chủ yếu phục vụ report/manual tests.
- DAST chỉ chạy khi target có Docker Compose và service có port mapping hợp lệ.
- `servicePicker` chọn một service target theo heuristic, có thể cần chỉnh compose hoặc output runtime nếu compose phức tạp.
- Trivy adapter hiện chỉ chạy `fs`; `image` và `config` được sanitize nhưng chỉ log skip.
- Manual tests là hypothesis để kiểm chứng, không phải vulnerability đã xác nhận.
- Gemini model endpoint đang được hardcode trong `ai/geminiClient.js`; nếu provider thay đổi API/model name cần cập nhật file đó.
- Pipeline sinh Bash script, nên môi trường chạy thực tế nên là Linux/Jenkins agent hoặc WSL/Git Bash có Docker access.
