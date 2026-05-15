// ai/aiAnalyzer.js
// Chức năng 1: analyzeAndSelectTools()  — Gemini Call #1
//   Input:  context.json (techStack + attackSurface + codePatterns)
//   Output: tool_config.json (danh sách tool, ruleset, cấu hình ZAP/Semgrep/Trivy)
//
// Chức năng 2: generateManualTestCases() — Gemini Call #2
//   Input:  attack surface đã phân loại (routes có flag idor, fileUpload, auth, admin)
//   Output: manual_tests.json (test cases chi tiết cho IDOR, JWT, BFLA, Race Condition)
//
// buildToolConfig() — hàm thuần (không AI) format output cho Jenkins

import { readFileSync, writeFileSync, mkdirSync } from 'fs';
import { join, resolve } from 'path';
import { callGeminiWithRetry, parseJson, logUsage } from './geminiClient.js';

// ── System prompts ────────────────────────────────────────────────────────────

const TOOL_SELECTION_SYSTEM = `You are a senior penetration tester and DevSecOps engineer specializing in automated security pipeline configuration.

Your task: analyze a web application's context (tech stack, endpoint scan results, dangerous code patterns) and produce a precise tool configuration for a Jenkins DevSecOps pipeline.

CRITICAL REQUIREMENTS:
- Output ONLY valid JSON. No explanation text, no markdown, no fences.
- Be specific: choose exact Semgrep rulesets, ZAP scan mode, Nuclei template categories.
- Justify each tool decision based on the actual evidence in the context.
- If the git diff shows only non-sensitive changes, recommend incremental scan to save time.
- If JWT handling patterns are detected, always enable jwt-specific rules.
- If file upload endpoints are detected, always enable file-upload Nuclei templates.

Output schema (strict):
{
  "scan_strategy": "full" | "incremental",
  "strategy_reason": "string",
  "tools": {
    "semgrep": {
      "enabled": boolean,
      "rulesets": ["p/...", ...],
      "extra_flags": "string | null",
      "reason": "string"
    },
    "bandit": {
      "enabled": boolean,
      "reason": "string"
    },
    "trivy": {
      "enabled": boolean,
      "targets": ["fs", "image", "config"],
      "reason": "string"
    },
    "zap": {
      "enabled": boolean,
      "mode": "baseline" | "api-scan" | "full-scan",
      "auth_required": boolean,
      "focus_paths": ["string", ...],
      "reason": "string"
    },
    "nuclei": {
      "enabled": boolean,
      "template_tags": ["string", ...],
      "severity": "medium,high,critical",
      "reason": "string"
    },
    "nikto": {
      "enabled": boolean,
      "reason": "string"
    }
  },
  "priority_findings": [
    {
      "type": "string",
      "evidence": "specific file:line or pattern from context",
      "risk": "CRITICAL" | "HIGH" | "MEDIUM",
      "tool_to_verify": "string"
    }
  ]
}`;

const MANUAL_TESTS_SYSTEM = `You are a senior web application penetration tester.

Your task: generate detailed manual test cases for vulnerability classes that automated tools CANNOT detect — specifically IDOR, Broken Function Level Authorization (BFLA), JWT logic flaws, race conditions, and mass assignment. These require multi-session interaction or business logic understanding.

Base your test cases on the actual endpoint list provided. Do NOT invent endpoints not in the input.

CRITICAL REQUIREMENTS:
- Output ONLY valid JSON. No explanation, no markdown.
- Each test case must have concrete, actionable steps a junior pentester can follow.
- Reference specific endpoint paths from the input data.
- Include the exact HTTP requests (method, path, headers, body) where possible.

Output schema (strict):
{
  "manual_test_cases": [
    {
      "id": "TC-001",
      "vulnerability_type": "IDOR" | "BFLA" | "JWT_Logic_Flaw" | "Race_Condition" | "Mass_Assignment" | "Auth_Bypass",
      "target_endpoint": "METHOD /path",
      "severity": "CRITICAL" | "HIGH" | "MEDIUM",
      "preconditions": ["string"],
      "steps": [
        {
          "step": 1,
          "action": "string",
          "http_request": "optional — curl or raw HTTP snippet",
          "expected_if_vulnerable": "string"
        }
      ],
      "confirmed_vulnerable_indicator": "string",
      "remediation_hint": "string",
      "tools": ["Burp Suite", "curl", "Postman"]
    }
  ]
}`;

// ── Gemini Call #1: Tool Selection ────────────────────────────────────────────

/**
 * Phân tích context và chọn tool + cấu hình tối ưu.
 * @param {object} context  — output của collectContext()
 * @param {object} options  — { apiKey }
 * @returns {Promise<object>}  — raw AI result (tool selection schema)
 */
export async function analyzeAndSelectTools(context, options = {}) {
  const { techStack, routes, codePatterns, apiSurface, gitDiff, containerInfo, attackSurfaceSummary } = context;

  // Build compact payload — tránh gửi toàn bộ 1000 routes lên AI
  const payload = {
    techStack: {
      language:    techStack.language,
      framework:   techStack.framework,
      features:    techStack.features,
      profileKey:  techStack.profileKey,
      isContainerized: techStack.isContainerized,
    },
    attackSurface: {
      totalEndpoints:      routes.totalEndpoints,
      classificationStats: routes.classificationStats,
      highRiskCount:       routes.highRiskCount,
      // Chỉ gửi high-risk routes + sample để AI có evidence
      highRiskRoutes:      routes.highRiskRoutes?.slice(0, 20) ?? [],
      sampleRoutes:        routes.routes?.slice(0, 15) ?? [],
    },
    dangerousPatterns: {
      summary:     codePatterns.bySeverity,
      categories:  Object.keys(codePatterns.byCategory ?? {}),
      topFindings: codePatterns.topFindings?.slice(0, 15) ?? [],
    },
    swaggerAvailable:  apiSurface.specFound,
    swaggerEndpoints:  apiSurface.specSummary?.endpoints?.slice(0, 20) ?? [],
    gitDiff: {
      recommendation:    gitDiff.recommendation,
      sensitiveChanged:  gitDiff.sensitiveChanged?.slice(0, 10) ?? [],
      changedFileCount:  gitDiff.changedFileCount,
    },
    containerInfo: {
      hasDockerfile:    containerInfo.hasDockerfile,
      hasDockerCompose: containerInfo.hasDockerCompose,
      services:         containerInfo.dockerCompose?.services ?? [],
      exposedPorts:     containerInfo.dockerCompose?.allPorts ?? containerInfo.dockerfile?.ports ?? [],
    },
  };

  const prompt = `Analyze the following web application security context and select the optimal tool configuration for the Jenkins DevSecOps pipeline:

\`\`\`json
${JSON.stringify(payload, null, 2)}
\`\`\`

Based on this context, produce the tool_config JSON. Remember: if JWT patterns are detected → enable jwt rules. If file upload endpoints exist → enable nuclei file-upload templates. If PHP → enable nikto.`;

  console.log('[AI] Gemini Call #1: Tool selection & attack surface analysis...');
  const result = await callGeminiWithRetry(prompt, TOOL_SELECTION_SYSTEM, {
    apiKey:          options.apiKey,
    temperature:     0.15,
    maxOutputTokens: 4096,
  });

  logUsage('Call#1-ToolSelection', result.usageMetadata);
  return parseJson(result.text);
}

// ── Gemini Call #2: Manual Test Cases ────────────────────────────────────────

/**
 * Sinh manual test cases cho lỗ hổng không tự động phát hiện được.
 * @param {object} context  — output của collectContext()
 * @param {object} options  — { apiKey }
 * @returns {Promise<object>}  — { manual_test_cases: [...] }
 */
export async function generateManualTestCases(context, options = {}) {
  const { routes } = context;

  // Chỉ gửi endpoints có flag liên quan để prompt không quá dài
  const relevantEndpoints = (routes.routes ?? []).filter(r =>
    r.classification.some(c => ['idor_candidate', 'fileUpload', 'auth', 'admin', 'payment'].includes(c))
  ).slice(0, 25);

  // Nếu không có endpoint nào relevant, thêm sample từ highRiskRoutes
  const endpointsForAI = relevantEndpoints.length > 0
    ? relevantEndpoints
    : (routes.highRiskRoutes ?? []).slice(0, 15);

  if (endpointsForAI.length === 0) {
    console.log('[AI] Gemini Call #2: No relevant endpoints found — generating generic test cases');
  }

  // Kèm code pattern evidence để AI có context
  const jwtEvidence    = context.codePatterns?.byCategory?.jwt?.findings?.slice(0, 3) ?? [];
  const idorEvidence   = context.codePatterns?.byCategory?.['auth_bypass']?.findings?.slice(0, 3) ?? [];
  const uploadEvidence = context.codePatterns?.byCategory?.['path_traversal']?.findings?.slice(0, 3) ?? [];

  const payload = {
    techStack: {
      language:  context.techStack?.language,
      framework: context.techStack?.framework,
      features:  context.techStack?.features,
    },
    endpoints: endpointsForAI.map(ep => ({
      method:         ep.method,
      path:           ep.path,
      classification: ep.classification,
      file:           ep.file,
      line:           ep.line,
    })),
    codeEvidence: {
      jwt:         jwtEvidence,
      authBypass:  idorEvidence,
      fileUpload:  uploadEvidence,
    },
    classificationStats: routes.classificationStats ?? {},
  };

  const prompt = `Generate detailed manual penetration test cases for the following web application endpoints. Focus on vulnerabilities that automated tools cannot detect:

\`\`\`json
${JSON.stringify(payload, null, 2)}
\`\`\`

Generate test cases for: IDOR (for idor_candidate endpoints), BFLA (for admin + auth endpoints), JWT logic flaws (if jwt code evidence exists), file upload bypass (if fileUpload endpoints exist), and mass assignment (for POST/PUT endpoints). Create at least one test case per vulnerability class that has evidence.`;

  console.log('[AI] Gemini Call #2: Generating manual test cases...');
  const result = await callGeminiWithRetry(prompt, MANUAL_TESTS_SYSTEM, {
    apiKey:          options.apiKey,
    temperature:     0.2,
    maxOutputTokens: 6144,
  });

  logUsage('Call#2-ManualTests', result.usageMetadata);
  return parseJson(result.text);
}

// ── buildToolConfig — hàm thuần (không AI) ───────────────────────────────────
// Format output từ AI result thành file đúng chuẩn cho Jenkins đọc

/**
 * Format AI tool selection result thành tool_config.json chuẩn cho Jenkins.
 * @param {object} aiResult     — output của analyzeAndSelectTools()
 * @param {object} context      — context.json (dùng để thêm metadata)
 * @returns {object}            — tool_config object sẵn sàng ghi ra file
 */
export function buildToolConfig(aiResult, context) {
  const tools = aiResult.tools ?? {};
  return {
    _meta: {
      generatedBy:  'aiAnalyzer/gemini-2.0-flash',
      generatedAt:  new Date().toISOString(),
      scanStrategy: aiResult.scan_strategy ?? 'full',
      strategyReason: aiResult.strategy_reason ?? '',
      project: {
        language:  context.techStack?.language,
        framework: context.techStack?.framework,
        riskLevel: aiResult.priority_findings?.[0]?.risk ?? 'UNKNOWN',
      },
    },
    scanStrategy: aiResult.scan_strategy ?? 'full',
    semgrep: {
      enabled:    tools.semgrep?.enabled  ?? false,
      rulesets:   tools.semgrep?.rulesets ?? [],
      extraFlags: tools.semgrep?.extra_flags ?? null,
      reason:     tools.semgrep?.reason ?? '',
    },
    bandit: {
      enabled: tools.bandit?.enabled ?? false,
      reason:  tools.bandit?.reason  ?? '',
    },
    trivy: {
      enabled: tools.trivy?.enabled  ?? true,
      targets: tools.trivy?.targets  ?? ['fs'],
      reason:  tools.trivy?.reason   ?? '',
    },
    zap: {
      enabled:      tools.zap?.enabled       ?? false,
      mode:         tools.zap?.mode          ?? 'baseline',
      authRequired: tools.zap?.auth_required ?? false,
      focusPaths:   tools.zap?.focus_paths   ?? [],
      reason:       tools.zap?.reason        ?? '',
    },
    nuclei: {
      enabled:       tools.nuclei?.enabled        ?? false,
      templateTags:  tools.nuclei?.template_tags  ?? [],
      severity:      tools.nuclei?.severity       ?? 'medium,high,critical',
      reason:        tools.nuclei?.reason         ?? '',
    },
    nikto: {
      enabled: tools.nikto?.enabled ?? false,
      reason:  tools.nikto?.reason  ?? '',
    },
    priorityFindings: aiResult.priority_findings ?? [],
  };
}

// ── CLI runner (dùng bởi Jenkinsfile Stage 4) ─────────────────────────────────

async function main() {
  const args        = process.argv.slice(2);
  const contextPath = args[0] ?? './security-context-output/context.json';
  const outputDir   = args[1] ?? './security-context-output';
  const apiKey      = process.env.GEMINI_API_KEY;

  if (!apiKey) {
    console.error('[ERROR] GEMINI_API_KEY environment variable not set');
    process.exit(1);
  }

  console.log(`[INFO] Reading context: ${contextPath}`);
  const context = JSON.parse(readFileSync(resolve(contextPath), 'utf8'));

  mkdirSync(resolve(outputDir), { recursive: true });

  // Call #1: tool selection
  const toolSelectionResult = await analyzeAndSelectTools(context, { apiKey });
  const toolConfig = buildToolConfig(toolSelectionResult, context);
  const toolConfigPath = join(resolve(outputDir), 'tool_config.json');
  writeFileSync(toolConfigPath, JSON.stringify(toolConfig, null, 2), 'utf8');
  console.log(`[OUTPUT] tool_config.json → ${toolConfigPath}`);

  // Call #2: manual test cases
  const manualTestsResult = await generateManualTestCases(context, { apiKey });
  const manualTestsPath = join(resolve(outputDir), 'manual_tests.json');
  writeFileSync(manualTestsPath, JSON.stringify(manualTestsResult, null, 2), 'utf8');
  console.log(`[OUTPUT] manual_tests.json → ${manualTestsPath}`);

  // Summary
  const tcCount = manualTestsResult.manual_test_cases?.length ?? 0;
  const tools   = Object.entries(toolConfig)
    .filter(([k, v]) => v?.enabled === true && k !== '_meta')
    .map(([k]) => k);
  console.log(`\n[DONE] Tool selection: ${tools.join(', ')}`);
  console.log(`[DONE] Manual test cases generated: ${tcCount}`);
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  main().catch(err => { console.error('[FATAL]', err.message); process.exit(1); });
}
