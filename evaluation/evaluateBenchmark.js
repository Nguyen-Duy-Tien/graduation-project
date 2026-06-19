import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { dirname, join, resolve } from 'path';
import { collectContext } from '../collector/contextCollector.js';

const DEFAULT_TARGET = 'examples/vulnerable-rest-api';

const VULN_CATEGORY_MAP = {
  'broken object property level authorization': 'mass_assign',
  'mass assignment': 'mass_assign',
  'excessive data exposure': 'info_leak',
  'broken object level authorization': 'idor_candidate',
  'broken function level authorization': 'authz',
  'server-side request forgery': 'ssrf',
  'unsafe consumption of apis': 'xss',
  'broken authentication': 'auth',
  'weak implementation of reset password': 'auth',
  'security misconfiguration': 'info_leak',
  'unrestricted resource consumption': 'redos',
  'unrestricted access to sensitive business flows': 'business_logic',
  'nosql injection': 'nosqli',
  'xss': 'xss',
  'web cache deception': 'cache',
};

function parseArgs(argv) {
  const args = {
    target: DEFAULT_TARGET,
    contextPath: null,
    reportPath: null,
    manualTestsPath: null,
    output: 'evaluation/evaluation-report.md',
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--target') args.target = argv[++i];
    else if (arg === '--context') args.contextPath = argv[++i];
    else if (arg === '--report') args.reportPath = argv[++i];
    else if (arg === '--manual-tests') args.manualTestsPath = argv[++i];
    else if (arg === '--output') args.output = argv[++i];
    else if (arg === '--help' || arg === '-h') {
      printHelp();
      process.exit(0);
    }
  }

  return args;
}

function printHelp() {
  console.log(`Usage:
  node evaluation/evaluateBenchmark.js [--target <dir>] [--context <context.json>] [--report <security-report.json>] [--manual-tests <manual_tests.json>] [--output <file>]

Examples:
  node evaluation/evaluateBenchmark.js
  node evaluation/evaluateBenchmark.js --context security-context-output/context.json --report security-context-output/final-report/security-report.json
`);
}

function readJson(path) {
  if (!path || !existsSync(path)) return null;
  return JSON.parse(readFileSync(path, 'utf8'));
}

function normalizeEndpoint(endpoint) {
  const text = endpoint.trim();
  const match = text.match(/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(.+)$/i);
  if (!match) return null;
  const rawPath = match[2].trim();
  if (!isTargetEndpointPath(rawPath)) return null;

  return {
    method: match[1].toUpperCase(),
    path: normalizePath(rawPath),
    raw: `${match[1].toUpperCase()} ${normalizePath(rawPath)}`,
  };
}

function isTargetEndpointPath(path) {
  if (path.startsWith('/')) return true;
  if (/^https?:\/\/localhost[:/]/i.test(path)) return true;
  if (/^localhost[:/]/i.test(path)) return true;
  return false;
}

function normalizePath(path) {
  return path
    .trim()
    .replace(/^https?:\/\/[^/]+/i, '')
    .replace(/^localhost:\d+/i, '')
    .replace(/[).,;:]+$/g, '')
    .replace(/\?.*$/g, '')
    .replace(/\{payload\}/gi, '')
    .replace(/\{[^}]+\}/g, ':param')
    .replace(/:name\b/g, ':param')
    .replace(/:id\b/g, ':param')
    .replace(/:bookId\b/g, ':param')
    .replace(/:authorId\b/g, ':param')
    .replace(/\/+$/g, '') || '/';
}

function routeKey(route) {
  return `${route.method.toUpperCase()} ${normalizePath(route.path)}`;
}

function parseGroundTruth(vulnDocPath) {
  if (!existsSync(vulnDocPath)) return { endpoints: [], categories: [] };

  const lines = readFileSync(vulnDocPath, 'utf8').split(/\r?\n/);
  const endpoints = [];
  const categories = new Set();
  let currentCategory = null;

  for (const line of lines) {
    const heading = line.match(/^#+\s+(.+)$/);
    if (heading) {
      currentCategory = heading[1].trim();
      const mapped = mapCategory(currentCategory);
      if (mapped) categories.add(mapped);
      continue;
    }

    const categoryLine = line.match(/-\s+([A-Za-z].*?)\s*$/);
    if (categoryLine && !/\b(GET|POST|PUT|PATCH|DELETE)\b/i.test(categoryLine[1])) {
      const mapped = mapCategory(categoryLine[1]);
      if (mapped) {
        currentCategory = categoryLine[1];
        categories.add(mapped);
      }
    }

    const endpointMatch = line.match(/\b(GET|POST|PUT|PATCH|DELETE)\s+([^\s`]+)/i);
    if (endpointMatch) {
      const parsed = normalizeEndpoint(`${endpointMatch[1]} ${endpointMatch[2]}`);
      if (parsed) {
        endpoints.push({
          ...parsed,
          category: mapCategory(currentCategory) ?? 'unknown',
          sourceLine: line.trim(),
        });
      }
    }
  }

  const uniqueEndpoints = [...new Map(endpoints.map(ep => [ep.raw, ep])).values()];
  return {
    endpoints: uniqueEndpoints,
    categories: [...categories],
  };
}

function mapCategory(name) {
  if (!name) return null;
  const key = String(name).toLowerCase();
  for (const [needle, category] of Object.entries(VULN_CATEGORY_MAP)) {
    if (key.includes(needle)) return category;
  }
  return null;
}

function evaluateEndpoints(groundTruth, routes) {
  const detectedKeys = new Set(routes.map(routeKey));
  const matched = [];
  const missed = [];

  for (const ep of groundTruth.endpoints) {
    if (detectedKeys.has(ep.raw)) matched.push(ep);
    else missed.push(ep);
  }

  return {
    groundTruthCount: groundTruth.endpoints.length,
    detectedEndpointCount: routes.length,
    matchedCount: matched.length,
    missedCount: missed.length,
    coverage: ratio(matched.length, groundTruth.endpoints.length),
    matched,
    missed,
  };
}

function evaluateCategories(groundTruth, context) {
  const detected = new Set([
    ...Object.keys(context.codePatterns?.byCategory ?? {}),
    ...Object.keys(context.routes?.classificationStats ?? {}),
  ]);

  const matched = groundTruth.categories.filter(category => detected.has(category));
  const missed = groundTruth.categories.filter(category => !detected.has(category));

  return {
    groundTruthCount: groundTruth.categories.length,
    matchedCount: matched.length,
    missedCount: missed.length,
    coverage: ratio(matched.length, groundTruth.categories.length),
    matched,
    missed,
  };
}

function evaluateTriage(report) {
  if (!report?.triaged_findings) return null;

  const findings = report.triaged_findings;
  const counts = countBy(findings, f => f.triage_status ?? 'unknown');

  return {
    findingCount: findings.length,
    counts,
  };
}

function countBy(items, getKey) {
  const result = {};
  for (const item of items) {
    const key = getKey(item);
    result[key] = (result[key] ?? 0) + 1;
  }
  return result;
}

function ratio(n, d) {
  if (!d) return 0;
  return Number((n / d).toFixed(4));
}

function percent(value) {
  return `${(value * 100).toFixed(1)}%`;
}

function buildMarkdown({ target, context, groundTruth, endpointEval, categoryEval, triageEval, manualTests }) {
  const posture = triageEval
    ? `${triageEval.findingCount} findings triaged by AI`
    : 'Chưa có security-report.json để tính AI triage';

  return `# Experimental Evaluation

Target: \`${target}\`

## Summary

| Metric | Value |
|---|---:|
| Ground truth vulnerable endpoints | ${endpointEval.groundTruthCount} |
| Endpoints detected by collector | ${endpointEval.detectedEndpointCount} |
| Ground truth endpoints matched | ${endpointEval.matchedCount} |
| Endpoint coverage | ${percent(endpointEval.coverage)} |
| Ground truth vulnerability categories | ${categoryEval.groundTruthCount} |
| Categories matched by route/pattern collector | ${categoryEval.matchedCount} |
| Category coverage | ${percent(categoryEval.coverage)} |
| Dangerous patterns detected | ${context.codePatterns?.totalFindings ?? 0} |
| Manual test cases generated | ${manualTests.length} |
| AI triage status | ${posture} |

## Ground Truth Endpoint Coverage

| Endpoint | Category | Detected |
|---|---|---|
${groundTruth.endpoints.map(ep => `| \`${ep.raw}\` | ${ep.category} | ${endpointEval.matched.some(m => m.raw === ep.raw) ? 'Yes' : 'No'} |`).join('\n')}

## Vulnerability Category Coverage

| Category | Detected |
|---|---|
${groundTruth.categories.map(category => `| ${category} | ${categoryEval.matched.includes(category) ? 'Yes' : 'No'} |`).join('\n')}

## AI Triage

| Metric | Value |
|---|---:|
| Findings triaged by AI | ${triageEval?.findingCount ?? 'N/A'} |
| Confirmed vulnerabilities | ${triageEval?.counts.confirmed_vulnerability ?? 'N/A'} |
| Likely vulnerabilities | ${triageEval?.counts.likely_vulnerability ?? 'N/A'} |
| Needs manual review | ${triageEval?.counts.needs_manual_review ?? 'N/A'} |

> The AI triage stage does not label or remove false positives. False-positive analysis must be done through manual validation or benchmark ground-truth mapping.

## Missed Ground Truth Endpoints

${endpointEval.missed.length ? endpointEval.missed.map(ep => `- \`${ep.raw}\` (${ep.category})`).join('\n') : 'No missed ground truth endpoints.'}

## Missed Categories

${categoryEval.missed.length ? categoryEval.missed.map(category => `- ${category}`).join('\n') : 'No missed ground truth categories.'}
`;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const target = resolve(args.target);

  const context = readJson(args.contextPath)
    ?? await collectContext(target);
  const report = readJson(args.reportPath);
  const manualTests = readJson(args.manualTestsPath)?.manual_test_cases ?? [];

  const groundTruth = parseGroundTruth(join(target, 'vulnerabilities', 'vulnerabilities.md'));
  const endpointEval = evaluateEndpoints(groundTruth, context.routes?.routes ?? []);
  const categoryEval = evaluateCategories(groundTruth, context);
  const triageEval = evaluateTriage(report);

  const markdown = buildMarkdown({
    target: args.target,
    context,
    groundTruth,
    endpointEval,
    categoryEval,
    triageEval,
    manualTests,
  });

  const outPath = resolve(args.output);
  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, markdown, 'utf8');

  console.log(markdown);
  console.log(`[OUTPUT] ${outPath}`);
}

main().catch(err => {
  console.error('[FATAL]', err.message);
  process.exit(1);
});
