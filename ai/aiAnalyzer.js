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
      "images": ["optional image refs from Docker Compose, if known"],
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
Treat each test case as a verification hypothesis, not as a confirmed vulnerability.

CRITICAL REQUIREMENTS:
- Output ONLY valid JSON. No explanation, no markdown.
- Each test case must have concrete, actionable steps a junior pentester can follow.
- Reference specific endpoint paths from the input data.
- Include the exact HTTP requests (method, path, headers, body) where possible.
- Prefer test cases backed by route middleware evidence, role expectations, ownership signals, dangerous code patterns, or sensitive schema fields.
- Every test case must include why_generated and evidence so DevOps can trace why the checklist item exists.

Output schema (strict):
{
  "manual_test_cases": [
    {
      "id": "TC-001",
      "vulnerability_type": "IDOR" | "BFLA" | "JWT_Logic_Flaw" | "Race_Condition" | "Mass_Assignment" | "Auth_Bypass",
      "target_endpoint": "METHOD /path",
      "severity": "CRITICAL" | "HIGH" | "MEDIUM",
      "why_generated": "string explaining the exact signal that caused this test",
      "evidence": {
        "route": "file:line",
        "classification": ["string"],
        "middleware": ["string"],
        "risk_signals": ["string"],
        "schema_fields": ["string"]
      },
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

const MANUAL_TEST_RELEVANT_FLAGS = [
  'idor_candidate',
  'fileUpload',
  'auth',
  'admin',
  'payment',
  'authz',
  'missing_auth',
  'missing_admin',
  'missing_ownership_check',
];

const DEFAULT_MANUAL_TEST_BATCH_SIZE = 4;
const DEFAULT_MANUAL_TEST_BATCH_DELAY_MS = 5000;
const DEFAULT_MANUAL_TEST_MAX_OUTPUT_TOKENS = 8192;
const DEFAULT_MANUAL_TEST_PARSE_RETRIES = 2;
const MANUAL_TEST_CODE_EVIDENCE_LIMIT = 2;
const MANUAL_TEST_SCHEMA_LIMIT = 6;
const MANUAL_TEST_SNIPPET_LIMIT = 220;

function getPositiveIntegerEnv(name, fallback) {
  const value = Number.parseInt(process.env[name] ?? '', 10);
  return Number.isFinite(value) && value > 0 ? value : fallback;
}

function chunkArray(items, size) {
  const chunks = [];
  for (let i = 0; i < items.length; i += size) {
    chunks.push(items.slice(i, i + size));
  }
  return chunks;
}

function normalizeManualTestIds(testCases) {
  return testCases.map((tc, index) => ({
    ...tc,
    id: `TC-AI-${String(index + 1).padStart(3, '0')}`,
  }));
}

function truncateText(value, maxLength = MANUAL_TEST_SNIPPET_LIMIT) {
  if (value == null) return value;
  const text = String(value).replace(/\s+/g, ' ').trim();
  return text.length > maxLength ? `${text.slice(0, maxLength - 3)}...` : text;
}

function isManualTestRelevantEndpoint(route) {
  return route.classification?.some(c => MANUAL_TEST_RELEVANT_FLAGS.includes(c))
    || route.security?.riskSignals?.length > 0;
}

function endpointRiskScore(route) {
  const flags = new Set(route.classification ?? []);
  const signals = route.security?.riskSignals ?? [];
  let score = signals.length * 3;

  if (flags.has('missing_auth')) score += 9;
  if (flags.has('missing_admin')) score += 8;
  if (flags.has('missing_ownership_check')) score += 8;
  if (flags.has('idor_candidate')) score += 6;
  if (flags.has('authz')) score += 5;
  if (flags.has('admin')) score += 5;
  if (flags.has('auth')) score += 4;
  if (flags.has('fileUpload')) score += 4;
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(route.method)) score += 2;

  return score;
}

function compactEndpoint(ep) {
  return {
    method: ep.method,
    path: ep.path,
    classification: ep.classification,
    file: ep.file,
    line: ep.line,
    snippet: truncateText(ep.snippet),
    security: ep.security ? {
      middleware: ep.security.middleware ?? [],
      hasAuthMiddleware: ep.security.hasAuthMiddleware ?? false,
      hasAdminMiddleware: ep.security.hasAdminMiddleware ?? false,
      hasRoleCheck: ep.security.hasRoleCheck ?? false,
      hasOwnershipCheck: ep.security.hasOwnershipCheck ?? false,
      hasValidationMiddleware: ep.security.hasValidationMiddleware ?? false,
      riskSignals: ep.security.riskSignals ?? [],
      expectedRoles: ep.security.expectedRoles ?? {},
    } : undefined,
  };
}

function tokenizeForRelevance(...values) {
  const stopWords = new Set([
    'api', 'v1', 'v2', 'get', 'post', 'put', 'patch', 'delete', 'id',
    'route', 'routes', 'controller', 'controllers', 'service', 'services',
  ]);
  return new Set(values
    .filter(Boolean)
    .join(' ')
    .replace(/([a-z])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(token => token.length >= 3 && !stopWords.has(token)));
}

function hasAnyToken(text, tokens) {
  const normalized = String(text ?? '').toLowerCase();
  for (const token of tokens) {
    if (normalized.includes(token)) return true;
  }
  return false;
}

function routeBatchTokens(endpointBatch) {
  return tokenizeForRelevance(...endpointBatch.flatMap(route => [
    route.path,
    route.file,
    ...(route.classification ?? []),
    ...(route.security?.riskSignals ?? []),
  ]));
}

function relevantCodeEvidenceForBatch(context, endpointBatch) {
  const flags = new Set(endpointBatch.flatMap(route => route.classification ?? []));
  const tokens = routeBatchTokens(endpointBatch);
  const byCategory = context.codePatterns?.byCategory ?? {};

  const categories = new Set();
  if (flags.has('auth') || flags.has('missing_auth') || flags.has('authz') || flags.has('missing_admin')) {
    categories.add('auth_bypass');
  }
  if (flags.has('auth')) categories.add('jwt');
  if (flags.has('fileUpload')) categories.add('path_traversal');
  if (endpointBatch.some(route => ['POST', 'PUT', 'PATCH'].includes(route.method))) {
    categories.add('mass_assign');
  }

  const result = {};
  for (const category of categories) {
    const findings = byCategory[category]?.findings ?? [];
    const relevant = findings
      .filter(finding => hasAnyToken(`${finding.file} ${finding.label} ${finding.snippet}`, tokens))
      .slice(0, MANUAL_TEST_CODE_EVIDENCE_LIMIT);
    result[category] = relevant.length
      ? relevant
      : findings.slice(0, MANUAL_TEST_CODE_EVIDENCE_LIMIT);
  }
  return result;
}

function relevantSchemaForBatch(context, endpointBatch) {
  const tokens = routeBatchTokens(endpointBatch);
  const models = (context.schemas?.modelsWithSensitiveFields ?? [])
    .map(compactSchemaModel);

  const directMatches = models.filter(model => hasAnyToken([
    model.name,
    model.file,
    ...(model.sensitiveFields ?? []).map(item => item.field),
    ...(model.ownershipFields ?? []),
    ...(model.massAssignmentTargets ?? []),
  ].join(' '), tokens));

  const fallbackMatches = models.filter(model =>
    (model.ownershipFields ?? []).length > 0 || (model.massAssignmentTargets ?? []).length > 0
  );

  const selected = directMatches.length ? directMatches : fallbackMatches;
  return selected.slice(0, MANUAL_TEST_SCHEMA_LIMIT);
}

function compactSchemaModel(model) {
  return {
    name: model.name,
    file: model.file,
    line: model.line,
    schemaType: model.schemaType,
    sensitiveFields: model.sensitiveFields ?? [],
    ownershipFields: model.ownershipFields ?? [],
    massAssignmentTargets: model.massAssignmentTargets ?? [],
  };
}

async function callGeminiAndParseJson(prompt, systemInstruction, options, callName, parseRetries = DEFAULT_MANUAL_TEST_PARSE_RETRIES) {
  let lastError;

  for (let attempt = 1; attempt <= parseRetries; attempt += 1) {
    const strictPrompt = attempt === 1
      ? prompt
      : `${prompt}

Your previous response was not parseable by JSON.parse.
Return exactly one JSON object matching the requested schema.
Do not include markdown fences, prose, comments, duplicate JSON objects, or trailing text.`;

    const result = await callGeminiWithRetry(strictPrompt, systemInstruction, options);
    const usageName = attempt === 1 ? callName : `${callName}-ParseRetry${attempt}`;
    logUsage(usageName, result.usageMetadata);

    if (result.finishReason === 'MAX_TOKENS') {
      throw new Error(`${callName} exceeded Gemini output limit. Reduce MANUAL_TEST_BATCH_SIZE or tighten the prompt.`);
    }

    try {
      return {
        parsed: parseJson(result.text),
        result,
        parseAttempts: attempt,
      };
    } catch (err) {
      lastError = err;
      const shortMessage = String(err.message ?? err).split('\n')[0];
      if (attempt < parseRetries) {
        console.warn(`[AI] ${callName} returned malformed JSON (${shortMessage}). Retrying with stricter JSON-only instruction...`);
      }
    }
  }

  throw lastError;
}

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
    maxOutputTokens: 8192,
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
export async function generateManualTestCasesSingleRequest(context, options = {}) {
  const { routes } = context;

  // Chỉ gửi endpoints có flag liên quan để prompt không quá dài
  const relevantEndpoints = (routes.routes ?? [])
    .filter(isManualTestRelevantEndpoint)
    .sort((a, b) => endpointRiskScore(b) - endpointRiskScore(a));

  // Nếu không có endpoint nào relevant, thêm sample từ highRiskRoutes
  const endpointsForAI = relevantEndpoints.length > 0
    ? relevantEndpoints
    : (routes.highRiskRoutes ?? []);

  if (endpointsForAI.length === 0) {
    console.log('[AI] Gemini Call #2: No relevant endpoints found — generating generic test cases');
  }

  // Kèm code pattern evidence để AI có context
  const jwtEvidence    = context.codePatterns?.byCategory?.jwt?.findings ?? [];
  const idorEvidence   = context.codePatterns?.byCategory?.['auth_bypass']?.findings ?? [];
  const uploadEvidence = context.codePatterns?.byCategory?.['path_traversal']?.findings ?? [];
  const massAssignmentEvidence = context.codePatterns?.byCategory?.mass_assign?.findings ?? [];
  const authBypassEvidence = context.codePatterns?.byCategory?.auth_bypass?.findings ?? [];
  const sensitiveModels = (context.schemas?.modelsWithSensitiveFields ?? [])
    .map(compactSchemaModel);

  const payload = {
    techStack: {
      language:  context.techStack?.language,
      framework: context.techStack?.framework,
      features:  context.techStack?.features,
    },
    endpointSelectionPolicy: {
      source: 'automated route scanner, middleware analyzer, code pattern scanner, and schema scanner',
      relevantFlags: MANUAL_TEST_RELEVANT_FLAGS,
      note: 'These are candidates for manual verification, not confirmed vulnerabilities.',
    },
    endpoints: endpointsForAI.map(compactEndpoint),
    schemaContext: {
      totalModels: context.schemas?.totalModels ?? 0,
      sensitiveFieldCount: context.schemas?.sensitiveFieldCount ?? 0,
      modelsWithSensitiveFields: sensitiveModels,
    },
    codeEvidence: {
      jwt:         jwtEvidence,
      authBypass:  authBypassEvidence.length ? authBypassEvidence : idorEvidence,
      fileUpload:  uploadEvidence,
      massAssignment: massAssignmentEvidence,
    },
    classificationStats: routes.classificationStats ?? {},
  };

  const prompt = `Generate detailed manual penetration test cases for the following web application endpoints. Focus on vulnerabilities that automated tools cannot detect:

\`\`\`json
${JSON.stringify(payload, null, 2)}
\`\`\`

Generate test cases for:
- IDOR/BOLA when an endpoint has idor_candidate or missing_ownership_check. Use two normal users and object IDs.
- BFLA/Auth_Bypass when a state-changing endpoint has authz, missing_auth, missing_admin, or role expectations showing anonymous/user should be rejected.
- Mass_Assignment when POST/PUT/PATCH endpoints align with sensitive schema fields or massAssignment code evidence. Include payload fields from schemaContext.massAssignmentTargets.
- JWT logic flaws only when jwt code evidence or auth endpoints exist.
- Race condition only when endpoint/business context suggests repeatable state change, credit, balance, quota, invite, order, or payment behavior.

Do not invent endpoints. For each test case, set why_generated and evidence using endpoint.security, classification, codeEvidence, and schemaContext. Generate all high-value manual test cases justified by the provided endpoints. Return complete JSON only.`;

  console.log('[AI] Gemini Call #2: Generating manual test cases...');
  const result = await callGeminiWithRetry(prompt, MANUAL_TESTS_SYSTEM, {
    apiKey:          options.apiKey,
    temperature:     0.2,
    maxOutputTokens: 8192,
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
      generatedBy:  'aiAnalyzer/gemini-2.5-flash',
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
      images:  tools.trivy?.images   ?? tools.trivy?.image_refs ?? [],
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

export async function generateManualTestCases(context, options = {}) {
  const { routes } = context;
  const relevantEndpoints = (routes.routes ?? [])
    .filter(isManualTestRelevantEndpoint)
    .sort((a, b) => endpointRiskScore(b) - endpointRiskScore(a));

  const endpointsForAI = relevantEndpoints.length > 0
    ? relevantEndpoints
    : (routes.highRiskRoutes ?? []);

  if (endpointsForAI.length === 0) {
    return {
      _meta: {
        generatedBy: 'aiAnalyzer/gemini-2.5-flash',
        strategy: 'batched-manual-test-generation',
        batchSize: 0,
        totalBatches: 0,
        endpointCount: 0,
        batchMeta: [],
      },
      manual_test_cases: [],
    };
  }

  const batchSize = options.batchSize
    ?? getPositiveIntegerEnv('MANUAL_TEST_BATCH_SIZE', DEFAULT_MANUAL_TEST_BATCH_SIZE);
  const batchDelayMs = options.batchDelayMs
    ?? getPositiveIntegerEnv('MANUAL_TEST_BATCH_DELAY_MS', DEFAULT_MANUAL_TEST_BATCH_DELAY_MS);
  const maxOutputTokens = options.maxOutputTokens
    ?? getPositiveIntegerEnv('MANUAL_TEST_MAX_OUTPUT_TOKENS', DEFAULT_MANUAL_TEST_MAX_OUTPUT_TOKENS);
  const endpointBatches = chunkArray(endpointsForAI, batchSize);
  const allTestCases = [];
  const batchMeta = [];

  console.log(`[AI] Gemini Call #2: Generating manual test cases in ${endpointBatches.length} batch(es), ${batchSize} endpoints/batch...`);

  for (const [batchIndex, endpointBatch] of endpointBatches.entries()) {
    const batchCodeEvidence = relevantCodeEvidenceForBatch(context, endpointBatch);
    const batchSchemas = relevantSchemaForBatch(context, endpointBatch);
    const batchEvidenceCount = Object.values(batchCodeEvidence)
      .reduce((sum, findings) => sum + (findings?.length ?? 0), 0);
    const payload = {
      batch: {
        index: batchIndex + 1,
        total: endpointBatches.length,
        endpointCount: endpointBatch.length,
      },
      techStack: {
        language: context.techStack?.language,
        framework: context.techStack?.framework,
        features: context.techStack?.features,
      },
      endpointSelectionPolicy: {
        source: 'automated route scanner, middleware analyzer, code pattern scanner, and schema scanner',
        relevantFlags: MANUAL_TEST_RELEVANT_FLAGS,
        note: 'These are candidates for manual verification, not confirmed vulnerabilities.',
      },
      endpoints: endpointBatch.map(compactEndpoint),
      schemaContext: {
        totalModels: context.schemas?.totalModels ?? 0,
        sensitiveFieldCount: context.schemas?.sensitiveFieldCount ?? 0,
        selectedModelsWithSensitiveFields: batchSchemas,
      },
      codeEvidence: batchCodeEvidence,
      classificationStats: routes.classificationStats ?? {},
    };

    const prompt = `Generate detailed manual penetration test cases for this batch of web application endpoints. Focus on vulnerabilities that automated tools cannot detect:

\`\`\`json
${JSON.stringify(payload, null, 2)}
\`\`\`

Generate test cases for:
- IDOR/BOLA when an endpoint has idor_candidate or missing_ownership_check. Use two normal users and object IDs.
- BFLA/Auth_Bypass when a state-changing endpoint has authz, missing_auth, missing_admin, or role expectations showing anonymous/user should be rejected.
- Mass_Assignment when POST/PUT/PATCH endpoints align with sensitive schema fields or massAssignment code evidence. Include payload fields from schemaContext.massAssignmentTargets.
- JWT logic flaws only when jwt code evidence or auth endpoints exist.
- Race condition only when endpoint/business context suggests repeatable state change, credit, balance, quota, invite, order, or payment behavior.

Do not invent endpoints. Generate at most one strongest manual test per endpoint unless two distinct vulnerability classes are clearly justified. Keep why_generated, http_request, expected_if_vulnerable, and remediation_hint concise. Return complete JSON only.`;

    console.log(`[AI] Gemini Call #2.${batchIndex + 1}/${endpointBatches.length}: Manual tests for ${endpointBatch.length} endpoint(s), ${batchSchemas.length} schema model(s), ${batchEvidenceCount} code evidence item(s)...`);
    const { parsed, result, parseAttempts } = await callGeminiAndParseJson(
      prompt,
      MANUAL_TESTS_SYSTEM,
      {
        apiKey: options.apiKey,
        temperature: 0.2,
        maxOutputTokens,
      },
      `Call#2.${batchIndex + 1}-ManualTests`,
    );
    const testCases = parsed.manual_test_cases ?? parsed.test_cases ?? [];
    allTestCases.push(...testCases);
    batchMeta.push({
      batch: batchIndex + 1,
      endpoints: endpointBatch.length,
      generatedTests: testCases.length,
      finishReason: result.finishReason,
      parseAttempts,
      usageMetadata: result.usageMetadata,
    });

    if (batchIndex < endpointBatches.length - 1 && batchDelayMs > 0) {
      console.log(`[WAIT] Waiting ${batchDelayMs}ms before next manual-test batch...`);
      await sleep(batchDelayMs);
    }
  }

  return {
    _meta: {
      generatedBy: 'aiAnalyzer/gemini-2.5-flash',
      strategy: 'batched-manual-test-generation',
      endpointScope: 'manual-test-relevant-flags',
      batchSize,
      totalBatches: endpointBatches.length,
      endpointCount: endpointsForAI.length,
      batchMeta,
    },
    manual_test_cases: normalizeManualTestIds(allTestCases),
  };
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
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

// === CHỜ 25s ===
  console.log(`[WAIT] Nghỉ 25 giây để làm sạch (reset) Quota của tài khoản Gemini...`);
  await sleep(25000); 
  // ====================================

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
