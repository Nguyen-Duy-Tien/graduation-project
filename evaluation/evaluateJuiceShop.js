import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { dirname, resolve } from 'path';
import yaml from 'js-yaml';

const DEFAULT_CHALLENGES = '../output/final-report Juice Shop/challenges.yml';
const DEFAULT_REPORT = '../output/final-report Juice Shop/security-report.json';
const DEFAULT_HTML = '../output/final-report Juice Shop/security-report.html';
const DEFAULT_OUTPUT = 'evaluation/juice-shop-evaluation.md';
const DEFAULT_JSON_OUTPUT = 'evaluation/juice-shop-evaluation.json';

const MANUAL_TRUTH = [
  {
    type: 'Mass_Assignment',
    match: endpointIs('POST', '/api/Users'),
    challengeKey: 'registerAdminChallenge',
    confidence: 'exact',
    reason: 'Juice Shop solves Admin Registration when POST /api/Users contains role=admin.',
  },
  {
    type: 'IDOR',
    match: endpointIs('GET', '/rest/basket/:id'),
    challengeKey: 'basketAccessChallenge',
    confidence: 'exact',
    reason: 'View Basket is solved by reading another user basket via /rest/basket/:id.',
  },
  {
    type: 'IDOR',
    match: endpointIs('POST', '/api/BasketItems'),
    challengeKey: 'basketManipulateChallenge',
    confidence: 'exact',
    reason: 'Manipulate Basket is solved by posting an item with another BasketId.',
  },
  {
    type: 'IDOR',
    match: endpointIs('PUT', '/api/BasketItems/:id'),
    challengeKey: 'basketManipulateChallenge',
    confidence: 'exact',
    reason: 'Manipulate Basket is solved when PUT /api/BasketItems/:id changes another BasketId.',
  },
  {
    type: 'BFLA',
    match: endpointIs('PUT', '/api/Products/:id'),
    challengeKey: 'changeProductChallenge',
    confidence: 'exact',
    reason: 'Product Tampering depends on the intentionally missing authorization for PUT /api/Products/:id.',
  },
  {
    type: 'Mass_Assignment',
    match: endpointIs('PUT', '/api/Products/:id'),
    challengeKey: 'changeProductChallenge',
    confidence: 'partial',
    reason: 'The endpoint is a real product-tampering ground truth, but the root cause is broken access control rather than classic mass assignment.',
  },
  {
    type: 'BFLA',
    match: endpointIs('PUT', '/api/Feedbacks/:id'),
    challengeKey: 'feedbackChallenge',
    confidence: 'exact',
    reason: 'Five-Star Feedback can be solved by deleting/updating all 5-star feedback through exposed feedback APIs.',
  },
  {
    type: 'BFLA',
    match: endpointIs('POST', '/api/Feedbacks'),
    challengeKey: 'captchaBypassChallenge',
    confidence: 'partial',
    reason: 'POST /api/Feedbacks is a real challenge surface for CAPTCHA Bypass and Forged Feedback, but not specifically BFLA.',
  },
  {
    type: 'Auth_Bypass',
    match: endpointIs('POST', '/api/Feedbacks'),
    challengeKey: 'forgedFeedbackChallenge',
    confidence: 'partial',
    reason: 'Forged Feedback is solved by supplying another UserId when posting feedback; the generated label is broader than the challenge.',
  },
  {
    type: 'Mass_Assignment',
    match: endpointIs('POST', '/api/Feedbacks'),
    challengeKey: 'forgedFeedbackChallenge',
    confidence: 'partial',
    reason: 'UserId tampering on feedback is a real Juice Shop challenge, but it is closer to object-level authorization than mass assignment.',
  },
  {
    type: 'BFLA',
    match: endpointIs('PUT', '/rest/products/:id/reviews'),
    challengeKey: 'forgedReviewChallenge',
    confidence: 'exact',
    reason: 'Creating a review as another author is the Forged Review challenge surface.',
  },
  {
    type: 'BFLA',
    match: endpointIs('PATCH', '/rest/products/reviews'),
    challengeKey: 'forgedReviewChallenge',
    confidence: 'exact',
    reason: 'Updating another user review is explicitly handled by the Forged Review challenge.',
  },
  {
    type: 'Race_Condition',
    match: endpointIs('POST', '/rest/products/reviews'),
    challengeKey: 'timingAttackChallenge',
    confidence: 'exact',
    reason: 'Multiple Likes is explicitly implemented as a race condition on POST /rest/products/reviews.',
  },
  {
    type: 'BFLA',
    match: endpointIs('POST', '/rest/products/reviews'),
    challengeKey: 'timingAttackChallenge',
    confidence: 'partial',
    reason: 'The endpoint is a real ground-truth challenge surface, but the intended vulnerability is race condition, not BFLA.',
  },
  {
    type: 'IDOR',
    match: endpointIs('PUT', '/rest/basket/:id/coupon/:coupon'),
    challengeKey: 'basketAccessChallenge',
    confidence: 'partial',
    reason: 'The route can target a basket by id, but the YAML challenge closest to it is View Basket; coupon abuse is mainly coupon/crypto logic.',
  },
  {
    type: 'Race_Condition',
    match: endpointIs('POST', '/rest/basket/:id/checkout'),
    challengeKey: 'negativeOrderChallenge',
    confidence: 'partial',
    reason: 'Checkout is real business-logic ground truth, but Payback Time is negative-order input tampering rather than a race condition.',
  },
  {
    type: 'BFLA',
    match: endpointIs('POST', '/rest/basket/:id/checkout'),
    challengeKey: 'negativeOrderChallenge',
    confidence: 'partial',
    reason: 'Checkout is a real challenge surface, but the intended weakness is business/input logic.',
  },
  {
    type: 'Race_Condition',
    match: endpointIs('POST', '/b2b/v2/orders'),
    challengeKey: 'deprecatedInterfaceChallenge',
    confidence: 'partial',
    reason: 'The B2B endpoint is real ground truth for Deprecated Interface, not a confirmed race condition.',
  },
  {
    type: 'IDOR',
    match: endpointIs('POST', '/rest/user/data-export'),
    challengeKey: 'dataExportChallenge',
    confidence: 'exact',
    reason: 'GDPR Data Theft is solved by exporting another user data through the data export flow.',
  },
  {
    type: 'BFLA',
    match: endpointIs('POST', '/rest/user/data-export'),
    challengeKey: 'dataExportChallenge',
    confidence: 'partial',
    reason: 'The endpoint is a real access-control challenge surface, but the specific issue is object-level data theft.',
  },
  {
    type: 'Mass_Assignment',
    match: endpointIs('POST', '/rest/deluxe-membership'),
    challengeKey: 'freeDeluxeChallenge',
    confidence: 'partial',
    reason: 'Deluxe Fraud is a real business/input logic challenge; the generated mass-assignment label is only approximate.',
  },
  {
    type: 'Race_Condition',
    match: endpointIs('PUT', '/rest/wallet/balance'),
    challengeKey: 'web3WalletChallenge',
    confidence: 'partial',
    reason: 'Wallet balance is business-critical, but the Juice Shop Wallet Depletion challenge is Web3 logic, not this REST race condition.',
  },
  {
    type: 'Auth_Bypass',
    match: endpointIs('GET', '/rest/user/change-password'),
    challengeKey: 'changePasswordBenderChallenge',
    confidence: 'exact',
    reason: 'Change Bender Password is solved through /rest/user/change-password without the current password.',
  },
  {
    type: 'BFLA',
    match: endpointIs('GET', '/rest/admin/application-version'),
    challengeKey: 'adminSectionChallenge',
    confidence: 'partial',
    reason: 'This is an admin-labelled route, but the YAML Admin Section challenge is primarily UI route access.',
  },
  {
    type: 'Auth_Bypass',
    match: endpointIs('POST', '/rest/chat'),
    challengeKey: 'aiDebuggingChallenge',
    confidence: 'partial',
    reason: 'The chat endpoint is a real surface for AI Debugging, but the generated auth-bypass label is broader than the challenge.',
  },
  {
    type: 'JWT_Logic_Flaw',
    match: textIncludes('unsigned jwt'),
    challengeKey: 'jwtUnsignedChallenge',
    confidence: 'exact',
    reason: 'Unsigned JWT is a ground-truth JWT logic challenge.',
  },
  {
    type: 'JWT_Logic_Flaw',
    match: textIncludes('forged signed jwt'),
    challengeKey: 'jwtForgedChallenge',
    confidence: 'exact',
    reason: 'Forged Signed JWT is a ground-truth JWT logic challenge.',
  },
];

const SCANNER_TRUTH = [
  {
    source: 'semgrep',
    match: findingLocationIncludes('/routes/login.ts'),
    challengeKey: 'loginAdminChallenge',
    confidence: 'exact',
    reason: 'SQL injection in login is the ground-truth Login Admin/Login Bender/Login Jim family.',
  },
  {
    source: 'semgrep',
    match: findingLocationIncludes('/routes/search.ts'),
    challengeKey: 'unionSqlInjectionChallenge',
    confidence: 'exact',
    reason: 'SQL injection in search is the User Credentials ground-truth challenge.',
  },
  {
    source: 'semgrep',
    match: findingLocationIncludes('dbSchemaChallenge'),
    challengeKey: 'dbSchemaChallenge',
    confidence: 'exact',
    reason: 'The finding is in the DB schema challenge codefix file.',
  },
  {
    source: 'semgrep',
    match: findingLocationIncludes('unionSqlInjectionChallenge'),
    challengeKey: 'unionSqlInjectionChallenge',
    confidence: 'exact',
    reason: 'The finding is in the Union SQL Injection challenge codefix file.',
  },
  {
    source: 'semgrep',
    match: findingLocationIncludes('/routes/userProfile.ts'),
    challengeKey: 'sstiChallenge',
    confidence: 'partial',
    reason: 'Eval-like route evidence maps to server-side code execution class; Juice Shop ground truth is SSTi/RCE.',
  },
  {
    source: 'semgrep',
    match: findingLocationIncludes('/lib/insecurity.ts'),
    challengeKey: 'jwtUnsignedChallenge',
    confidence: 'partial',
    reason: 'JWT hardcoded/weak secret evidence supports JWT challenge surfaces.',
  },
  {
    source: 'semgrep',
    match: findingLocationIncludes('/routes/fileServer.ts'),
    challengeKey: 'directoryListingChallenge',
    confidence: 'exact',
    reason: 'Public file server is the Confidential Document/file disclosure surface.',
  },
  {
    source: 'semgrep',
    match: findingLocationIncludes('/routes/keyServer.ts'),
    challengeKey: 'nftUnlockChallenge',
    confidence: 'partial',
    reason: 'Key file exposure supports sensitive-data/key-disclosure challenges.',
  },
  {
    source: 'semgrep',
    match: findingLocationIncludes('/routes/logfileServer.ts'),
    challengeKey: 'accessLogDisclosureChallenge',
    confidence: 'exact',
    reason: 'Log file server is the Access Log ground-truth challenge surface.',
  },
  {
    source: 'semgrep',
    match: findingLocationIncludes('/routes/quarantineServer.ts'),
    challengeKey: 'lfrChallenge',
    confidence: 'partial',
    reason: 'Quarantine file serving is file-read/file-disclosure related ground truth.',
  },
  {
    source: 'semgrep',
    match: findingLocationIncludes('/routes/redirect.ts'),
    challengeKey: 'redirectChallenge',
    confidence: 'exact',
    reason: 'Open redirect in redirect.ts maps to Allowlist Bypass/Outdated Allowlist.',
  },
  {
    source: 'semgrep',
    match: findingLocationIncludes('/server.ts'),
    challengeKey: 'directoryListingChallenge',
    confidence: 'partial',
    reason: 'Directory listing in server.ts maps to Confidential Document and related file exposure challenges.',
  },
  {
    source: 'zap',
    match: findingMessageIncludes('backup file disclosure'),
    challengeKey: 'forgottenBackupChallenge',
    confidence: 'partial',
    reason: 'Backup file disclosure maps to forgotten backup/developer backup class, but many ZAP instances are duplicate probes.',
  },
  {
    source: 'zap',
    match: findingMessageIncludes('bypassing 403'),
    challengeKey: 'directoryListingChallenge',
    confidence: 'partial',
    reason: '403 bypass on /ftp files maps to file access challenges.',
  },
  {
    source: 'zap',
    match: findingMessageIncludes('content security policy'),
    challengeKey: 'usernameXssChallenge',
    confidence: 'partial',
    reason: 'Missing CSP is relevant to CSP bypass/XSS challenges but not a direct challenge solution.',
  },
  {
    source: 'zap',
    match: findingMessageIncludes('dangerous js functions'),
    challengeKey: 'localXssChallenge',
    confidence: 'partial',
    reason: 'Dangerous JavaScript functions are XSS-relevant, but this is not a precise challenge match.',
  },
];

function parseArgs(argv) {
  const args = {
    challengesPath: DEFAULT_CHALLENGES,
    reportPath: DEFAULT_REPORT,
    htmlPath: DEFAULT_HTML,
    output: DEFAULT_OUTPUT,
    jsonOutput: DEFAULT_JSON_OUTPUT,
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--challenges') args.challengesPath = argv[++i];
    else if (arg === '--report') args.reportPath = argv[++i];
    else if (arg === '--html') args.htmlPath = argv[++i];
    else if (arg === '--output') args.output = argv[++i];
    else if (arg === '--json-output') args.jsonOutput = argv[++i];
    else if (arg === '--help' || arg === '-h') {
      printHelp();
      process.exit(0);
    }
  }

  return args;
}

function printHelp() {
  console.log(`Usage:
  node evaluation/evaluateJuiceShop.js [options]

Options:
  --challenges <yml>      OWASP Juice Shop challenges.yml ground truth
  --report <json>         security-report.json from this system
  --html <html>           security-report.html containing manual checklist
  --output <md>           Markdown output path
  --json-output <json>    JSON output path
`);
}

function readChallenges(path) {
  if (!existsSync(path)) throw new Error(`challenges.yml not found: ${path}`);
  const rows = yaml.load(readFileSync(path, 'utf8'));
  const byKey = new Map(rows.map(challenge => [challenge.key, challenge]));
  return { rows, byKey };
}

function readReport(path) {
  if (!existsSync(path)) throw new Error(`security-report.json not found: ${path}`);
  return JSON.parse(readFileSync(path, 'utf8'));
}

function readManualTestsFromHtml(path) {
  if (!existsSync(path)) return [];
  const html = readFileSync(path, 'utf8');
  const sectionMatch = html.match(/<h2 class="section-title">Manual Testing Checklist<\/h2>([\s\S]*?)<h2 class="section-title">Vulnerability Findings<\/h2>/);
  if (!sectionMatch) return [];

  return sectionMatch[1]
    .split('<div class="finding manual-test">')
    .slice(1)
    .map(block => {
      const title = decodeHtml(extract(block, /<span class="finding-title">([\s\S]*?)<\/span>/));
      const [type, endpoint] = splitManualTitle(title);
      return {
        id: decodeHtml(extract(block, /<strong class="finding-id">([\s\S]*?)<\/strong>/)),
        title,
        type,
        endpoint,
        method: endpoint.split(/\s+/)[0] ?? '',
        path: normalizePath(endpoint.replace(/^\S+\s+/, '')),
        routeEvidence: decodeHtml(extractDetail(block, 'Route evidence')),
        classification: splitList(decodeHtml(extractDetail(block, 'Classification'))),
        middleware: splitList(decodeHtml(extractDetail(block, 'Middleware'))),
        riskSignals: splitList(decodeHtml(extractDetail(block, 'Risk signals'))),
        whyGenerated: decodeHtml(extract(block, /<div class="analysis-label">Why Generated<\/div><div class="analysis-text">([\s\S]*?)<\/div>/)),
        confirmedIndicator: decodeHtml(extract(block, /<div class="triage-reason"><strong>Confirm:<\/strong>\s*([\s\S]*?)<\/div>/)),
      };
    });
}

function splitManualTitle(title) {
  const parts = title.split(' - ');
  return [parts[0] ?? '', parts.slice(1).join(' - ') || ''];
}

function extract(text, regex) {
  return (text.match(regex) ?? [])[1] ?? '';
}

function extractDetail(text, label) {
  const escaped = label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return extract(text, new RegExp(`<dt>${escaped}<\\/dt>\\s*<dd>([\\s\\S]*?)<\\/dd>`));
}

function splitList(value) {
  return value ? value.split(',').map(item => item.trim()).filter(Boolean) : [];
}

function decodeHtml(value) {
  return String(value ?? '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&amp;/g, '&')
    .replace(/\s+/g, ' ')
    .trim();
}

function dedupeManualTests(tests) {
  return [...new Map(tests.map(test => [`${test.type} ${test.method} ${test.path}`, test])).values()];
}

function normalizePath(path) {
  return String(path ?? '')
    .trim()
    .replace(/^https?:\/\/[^/]+/i, '')
    .replace(/\?.*$/, '')
    .replace(/\/+$/, '')
    .replace(/:continueCode\b/g, ':param')
    .replace(/:coupon\b/g, ':param')
    .replace(/:challenge\b/g, ':param')
    .replace(/:key\b/g, ':param')
    .replace(/:id\b/g, ':id') || '/';
}

function endpointIs(method, path) {
  const normalizedPath = normalizePath(path);
  return item => item.method === method && item.path === normalizedPath;
}

function textIncludes(needle) {
  const lowered = needle.toLowerCase();
  return item => Object.values(item).join(' ').toLowerCase().includes(lowered);
}

function findingLocationIncludes(needle) {
  const lowered = needle.toLowerCase();
  return finding => String(finding.location ?? finding.file ?? '').toLowerCase().includes(lowered);
}

function findingMessageIncludes(needle) {
  const lowered = needle.toLowerCase();
  return finding => String(finding.message ?? '').toLowerCase().includes(lowered);
}

function evaluateManualTests(tests, challengesByKey) {
  const rows = tests.map(test => {
    const match = MANUAL_TRUTH.find(rule => rule.type === test.type && rule.match(test));
    if (!match) {
      return {
        ...test,
        outcome: 'FP',
        challengeKey: null,
        challengeName: null,
        confidence: 'none',
        reason: 'No corresponding Juice Shop ground-truth challenge found for this generated manual test.',
      };
    }

    const challenge = challengesByKey.get(match.challengeKey);
    return {
      ...test,
      outcome: match.confidence === 'exact' ? 'TP' : 'PARTIAL',
      challengeKey: match.challengeKey,
      challengeName: challenge?.name ?? match.challengeKey,
      confidence: match.confidence,
      reason: match.reason,
    };
  });

  return {
    rows,
    summary: summarizeRows(rows),
    byType: summarizeBy(rows, row => row.type),
  };
}

function evaluateScannerFindings(findings, challengesByKey) {
  const rows = findings.map(finding => {
    const original = finding.original_finding ?? {};
    const rule = SCANNER_TRUTH.find(candidate => {
      if (candidate.source && original.source !== candidate.source) return false;
      return candidate.match(original);
    });

    if (!rule) {
      return {
        id: finding.id,
        source: original.source,
        category: original.category,
        severity: original.severity,
        message: original.message,
        location: original.location,
        triageStatus: finding.triage_status,
        outcome: 'FP',
        confidence: 'none',
        challengeKey: null,
        challengeName: null,
        reason: 'No precise Juice Shop challenge mapping for this scanner finding.',
      };
    }

    const challenge = challengesByKey.get(rule.challengeKey);
    return {
      id: finding.id,
      source: original.source,
      category: original.category,
      severity: original.severity,
      message: original.message,
      location: original.location,
      triageStatus: finding.triage_status,
      outcome: rule.confidence === 'exact' ? 'TP' : 'PARTIAL',
      confidence: rule.confidence,
      challengeKey: rule.challengeKey,
      challengeName: challenge?.name ?? rule.challengeKey,
      reason: rule.reason,
    };
  });

  return {
    rows,
    summary: summarizeRows(rows),
    bySource: summarizeBy(rows, row => row.source),
  };
}

function summarizeRows(rows) {
  const counts = countBy(rows, row => row.outcome);
  const exact = counts.TP ?? 0;
  const partial = counts.PARTIAL ?? 0;
  const noChallengeMapping = counts.FP ?? 0;
  return {
    total: rows.length,
    exact,
    partial,
    noChallengeMapping,
    exactPrecision: ratio(exact, rows.length),
    usefulPrecision: ratio(exact + partial, rows.length),
  };
}

function summarizeBy(rows, getKey) {
  const buckets = new Map();
  for (const row of rows) {
    const key = getKey(row) || 'unknown';
    const bucket = buckets.get(key) ?? [];
    bucket.push(row);
    buckets.set(key, bucket);
  }

  return [...buckets.entries()]
    .sort(([a], [b]) => String(a).localeCompare(String(b)))
    .map(([key, bucket]) => ({
      key,
      ...summarizeRows(bucket),
    }));
}

function countBy(rows, getKey) {
  const result = {};
  for (const row of rows) {
    const key = getKey(row);
    result[key] = (result[key] ?? 0) + 1;
  }
  return result;
}

function ratio(numerator, denominator) {
  if (!denominator) return 0;
  return Number((numerator / denominator).toFixed(4));
}

function percent(value) {
  return `${(value * 100).toFixed(1)}%`;
}

function challengeCategorySummary(challenges) {
  return summarizeBy(challenges, challenge => challenge.category).map(row => ({
    category: row.key,
    count: row.total,
  })).sort((a, b) => b.count - a.count || a.category.localeCompare(b.category));
}

function detectedChallengeSummary(manualEval, scannerEval) {
  const exactKeys = new Set();
  const usefulKeys = new Set();

  for (const row of [...manualEval.rows, ...scannerEval.rows]) {
    if (!row.challengeKey) continue;
    if (row.outcome === 'TP') exactKeys.add(row.challengeKey);
    if (row.outcome === 'TP' || row.outcome === 'PARTIAL') usefulKeys.add(row.challengeKey);
  }

  return {
    exactChallengeCount: exactKeys.size,
    usefulChallengeCount: usefulKeys.size,
    exactChallengeKeys: [...exactKeys].sort(),
    usefulChallengeKeys: [...usefulKeys].sort(),
  };
}

function buildMarkdown({ challenges, report, manualRawCount, manualEval, scannerEval, challengeCoverage }) {
  return `# Juice Shop Ground Truth Evaluation

Ground truth: OWASP Juice Shop \`challenges.yml\` (${challenges.rows.length} challenges).

System output: \`security-report.json\` (${report.triaged_findings?.length ?? 0} scanner findings) plus manual checklist extracted from \`security-report.html\`.

## Summary

| Metric | Value |
|---|---:|
| Juice Shop ground-truth challenges | ${challenges.rows.length} |
| Raw scanner findings | ${report.triaged_findings?.length ?? 0} |
| Manual test cases in HTML | ${manualRawCount} |
| Unique manual tests after de-duplication | ${manualEval.rows.length} |
| Exact ground-truth challenges matched | ${challengeCoverage.exactChallengeCount} / ${challenges.rows.length} |
| Useful/exact+partial challenge matches | ${challengeCoverage.usefulChallengeCount} / ${challenges.rows.length} |

## Manual Test Accuracy

| Metric | Value |
|---|---:|
| Unique manual tests | ${manualEval.summary.total} |
| Exact true positives | ${manualEval.summary.exact} |
| Partial / right surface, wrong or broad label | ${manualEval.summary.partial} |
| No challenge mapping | ${manualEval.summary.noChallengeMapping} |
| Strict precision | ${percent(manualEval.summary.exactPrecision)} |
| Useful precision | ${percent(manualEval.summary.usefulPrecision)} |

Strict precision counts only exact vulnerability-type + endpoint matches. Useful precision also counts cases that point to a real Juice Shop challenge surface but with a broad or imperfect label.

## Manual Accuracy By Type

| Type | Tests | Exact TP | Partial | No challenge mapping | Strict Precision | Useful Precision |
|---|---:|---:|---:|---:|---:|---:|
${manualEval.byType.map(row => `| ${row.key} | ${row.total} | ${row.exact} | ${row.partial} | ${row.noChallengeMapping} | ${percent(row.exactPrecision)} | ${percent(row.usefulPrecision)} |`).join('\n')}

## Scanner Match Against Ground Truth

| Metric | Value |
|---|---:|
| Findings | ${scannerEval.summary.total} |
| Exact TP | ${scannerEval.summary.exact} |
| Partial | ${scannerEval.summary.partial} |
| No challenge mapping | ${scannerEval.summary.noChallengeMapping} |
| Strict precision | ${percent(scannerEval.summary.exactPrecision)} |
| Useful precision | ${percent(scannerEval.summary.usefulPrecision)} |

## Manual True Positives

${formatManualRows(manualEval.rows.filter(row => row.outcome === 'TP'))}

## Manual Partial Matches

${formatManualRows(manualEval.rows.filter(row => row.outcome === 'PARTIAL'))}

## Manual No Challenge Mapping

${formatManualRows(manualEval.rows.filter(row => row.outcome === 'FP'))}

## Ground Truth Categories

| Category | Challenges |
|---|---:|
${challengeCategorySummary(challenges.rows).map(row => `| ${row.category} | ${row.count} |`).join('\n')}

## Notes

- The YAML is challenge-level ground truth, not a scanner result file. Several scanner findings and generated manual tests can map to one challenge, and many challenges require solving sequences rather than single endpoint detection.
- Repeated manual test cards in HTML were de-duplicated by \`vulnerability_type + method + endpoint\` before calculating accuracy.
- \`PARTIAL\` means the generated test points at a real Juice Shop challenge surface but its vulnerability type or exploit model is broader than the official challenge.
`;
}

function formatManualRows(rows) {
  if (!rows.length) return 'None.';
  return rows
    .map(row => `- \`${row.title}\` => ${row.challengeName ?? 'N/A'}${row.confidence === 'partial' ? ' (partial)' : ''}: ${row.reason}`)
    .join('\n');
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const challengesPath = resolve(args.challengesPath);
  const reportPath = resolve(args.reportPath);
  const htmlPath = resolve(args.htmlPath);

  const challenges = readChallenges(challengesPath);
  const report = readReport(reportPath);
  const manualTests = readManualTestsFromHtml(htmlPath);
  const uniqueManualTests = dedupeManualTests(manualTests);
  const manualEval = evaluateManualTests(uniqueManualTests, challenges.byKey);
  const scannerEval = evaluateScannerFindings(report.triaged_findings ?? [], challenges.byKey);
  const challengeCoverage = detectedChallengeSummary(manualEval, scannerEval);

  const result = {
    inputs: {
      challengesPath,
      reportPath,
      htmlPath,
    },
    groundTruth: {
      challengeCount: challenges.rows.length,
      categories: challengeCategorySummary(challenges.rows),
    },
    scanner: scannerEval,
    manual: {
      rawCount: manualTests.length,
      uniqueCount: uniqueManualTests.length,
      ...manualEval,
    },
    challengeCoverage,
  };

  const jsonOut = resolve(args.jsonOutput);
  mkdirSync(dirname(jsonOut), { recursive: true });
  writeFileSync(jsonOut, JSON.stringify(result, null, 2), 'utf8');

  const markdown = buildMarkdown({
    challenges,
    report,
    manualRawCount: manualTests.length,
    manualEval,
    scannerEval,
    challengeCoverage,
  });

  const markdownOut = resolve(args.output);
  mkdirSync(dirname(markdownOut), { recursive: true });
  writeFileSync(markdownOut, markdown, 'utf8');

  console.log(markdown);
  console.log(`[OUTPUT] ${markdownOut}`);
  console.log(`[OUTPUT] ${jsonOut}`);
}

main();
