import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { dirname, join, resolve } from 'path';

const DEFAULT_TARGET = 'benchmarks/owasp-benchmark';
const DEFAULT_EXPECTED = 'benchmarks/owasp-benchmark/expectedresults-1.2.csv';
const DEFAULT_REPORT = 'security-context-output-benchmark/scan-reports/semgrep-report.json';
const DEFAULT_OUTPUT = 'evaluation/owasp-benchmark-evaluation.md';
const DEFAULT_JSON_OUTPUT = 'evaluation/owasp-benchmark-evaluation.json';

const CATEGORY_LABELS = {
  cmdi: 'Command Injection',
  crypto: 'Weak Encryption Algorithm',
  hash: 'Weak Hash Algorithm',
  ldapi: 'LDAP Injection',
  pathtraver: 'Path Traversal',
  securecookie: 'Insecure Cookie',
  sqli: 'SQL Injection',
  trustbound: 'Trust Boundary Violation',
  weakrand: 'Weak Random Number',
  xpathi: 'XPath Injection',
  xss: 'Cross-Site Scripting',
};

const CATEGORY_KEYWORDS = {
  cmdi: ['command', 'cmdi', 'exec', 'processbuilder', 'runtime.exec', 'os command'],
  crypto: ['crypto', 'cipher', 'des', 'ecb', 'weak encryption'],
  hash: ['hash', 'md5', 'sha1', 'message digest'],
  ldapi: ['ldap'],
  pathtraver: ['path traversal', 'pathtraver', 'file path', 'directory traversal'],
  securecookie: ['cookie', 'secure flag', 'securecookie'],
  sqli: ['sql', 'sqli', 'injection'],
  trustbound: ['trust boundary', 'trustbound'],
  weakrand: ['random', 'weakrand', 'predictable'],
  xpathi: ['xpath'],
  xss: ['xss', 'cross-site scripting', 'html injection'],
};

function parseArgs(argv) {
  const args = {
    target: DEFAULT_TARGET,
    expected: DEFAULT_EXPECTED,
    semgrepReport: DEFAULT_REPORT,
    output: DEFAULT_OUTPUT,
    jsonOutput: DEFAULT_JSON_OUTPUT,
    strictCategory: false,
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--target') args.target = argv[++i];
    else if (arg === '--expected') args.expected = argv[++i];
    else if (arg === '--semgrep-report') args.semgrepReport = argv[++i];
    else if (arg === '--output') args.output = argv[++i];
    else if (arg === '--json-output') args.jsonOutput = argv[++i];
    else if (arg === '--strict-category') args.strictCategory = true;
    else if (arg === '--help' || arg === '-h') {
      printHelp();
      process.exit(0);
    }
  }

  return args;
}

function printHelp() {
  console.log(`Usage:
  node evaluation/evaluateOwaspBenchmark.js [options]

Options:
  --target <dir>             OWASP Benchmark target root
  --expected <csv>           expectedresults-*.csv path
  --semgrep-report <json>    Semgrep JSON report path
  --output <md>              Markdown report output path
  --json-output <json>       JSON report output path
  --strict-category          Count a detection only if rule text also matches the expected category

Example:
  node evaluation/evaluateOwaspBenchmark.js \\
    --expected benchmarks/owasp-benchmark/expectedresults-1.2.csv \\
    --semgrep-report security-context-output-benchmark/scan-reports/semgrep-report.json
`);
}

function parseExpectedResults(path) {
  if (!existsSync(path)) throw new Error(`Expected results CSV not found: ${path}`);

  const rows = [];
  const lines = readFileSync(path, 'utf8').split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    const parts = splitCsvLine(trimmed).map(part => part.trim());
    if (parts.length < 4) continue;

    const [testName, category, realVulnerability, cwe] = parts;
    rows.push({
      testName,
      category,
      categoryLabel: CATEGORY_LABELS[category] ?? category,
      realVulnerability: realVulnerability.toLowerCase() === 'true',
      cwe: String(cwe),
    });
  }

  return rows;
}

function splitCsvLine(line) {
  const cells = [];
  let cell = '';
  let quoted = false;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    const next = line[i + 1];

    if (quoted && ch === '"' && next === '"') {
      cell += '"';
      i++;
      continue;
    }

    if (ch === '"') {
      quoted = !quoted;
      continue;
    }

    if (ch === ',' && !quoted) {
      cells.push(cell);
      cell = '';
      continue;
    }

    cell += ch;
  }

  cells.push(cell);
  return cells;
}

function readSemgrepFindings(reportPath) {
  if (!existsSync(reportPath)) {
    throw new Error(`Semgrep report not found: ${reportPath}`);
  }

  const raw = JSON.parse(readFileSync(reportPath, 'utf8'));
  return (raw.results ?? []).map(result => {
    const metadata = result.extra?.metadata ?? {};
    const haystack = [
      result.path,
      result.check_id,
      result.extra?.message,
      result.extra?.lines,
      JSON.stringify(metadata),
    ].filter(Boolean).join('\n');

    return {
      testIds: extractBenchmarkTestIds(haystack),
      ruleId: result.check_id ?? '',
      path: result.path ?? '',
      line: result.start?.line ?? 0,
      message: result.extra?.message ?? '',
      cweIds: extractCweIds(metadata),
      text: haystack.toLowerCase(),
    };
  });
}

function extractBenchmarkTestIds(text) {
  const ids = new Set();
  const re = /BenchmarkTest(\d{5})/g;
  let match;

  while ((match = re.exec(text)) !== null) {
    ids.add(`BenchmarkTest${match[1]}`);
  }

  return [...ids];
}

function extractCweIds(metadata) {
  const ids = new Set();

  function visit(value) {
    if (value == null) return;
    if (Array.isArray(value)) {
      for (const item of value) visit(item);
      return;
    }
    if (typeof value === 'object') {
      for (const item of Object.values(value)) visit(item);
      return;
    }
    const text = String(value);
    const re = /CWE[-\s]?(\d+)|\b(\d{2,4})\b/gi;
    let match;
    while ((match = re.exec(text)) !== null) {
      ids.add(match[1] ?? match[2]);
    }
  }

  visit(metadata.cwe);
  visit(metadata.cwe_id);
  return [...ids];
}

function categoryMatchesFinding(expected, finding) {
  if (finding.cweIds.includes(expected.cwe)) return true;
  const keywords = CATEGORY_KEYWORDS[expected.category] ?? [expected.category];
  return keywords.some(keyword => finding.text.includes(keyword));
}

function evaluate(expectedRows, semgrepFindings, { strictCategory }) {
  const detectionsByTest = new Map();
  const unmatchedFindings = [];

  for (const finding of semgrepFindings) {
    if (finding.testIds.length === 0) {
      unmatchedFindings.push(finding);
      continue;
    }

    for (const testId of finding.testIds) {
      const bucket = detectionsByTest.get(testId) ?? [];
      bucket.push(finding);
      detectionsByTest.set(testId, bucket);
    }
  }

  const rows = expectedRows.map(expected => {
    const rawFindings = detectionsByTest.get(expected.testName) ?? [];
    const matchedFindings = strictCategory
      ? rawFindings.filter(finding => categoryMatchesFinding(expected, finding))
      : rawFindings;
    const detected = matchedFindings.length > 0;
    const outcome = expected.realVulnerability
      ? detected ? 'TP' : 'FN'
      : detected ? 'FP' : 'TN';

    return {
      ...expected,
      detected,
      outcome,
      findingCount: matchedFindings.length,
      rawFindingCount: rawFindings.length,
      firstFinding: matchedFindings[0] ? {
        ruleId: matchedFindings[0].ruleId,
        path: matchedFindings[0].path,
        line: matchedFindings[0].line,
        message: matchedFindings[0].message,
      } : null,
    };
  });

  return {
    rows,
    unmatchedFindings,
    summary: buildSummary(rows),
    byCategory: buildCategorySummary(rows),
  };
}

function buildSummary(rows) {
  const counts = countOutcomes(rows);
  return {
    total: rows.length,
    vulnerable: counts.TP + counts.FN,
    safe: counts.TN + counts.FP,
    ...counts,
    truePositiveRate: ratio(counts.TP, counts.TP + counts.FN),
    falseNegativeRate: ratio(counts.FN, counts.TP + counts.FN),
    falsePositiveRate: ratio(counts.FP, counts.FP + counts.TN),
    trueNegativeRate: ratio(counts.TN, counts.FP + counts.TN),
    precision: ratio(counts.TP, counts.TP + counts.FP),
    accuracy: ratio(counts.TP + counts.TN, rows.length),
    benchmarkScore: Number((ratio(counts.TP, counts.TP + counts.FN) - ratio(counts.FP, counts.FP + counts.TN)).toFixed(4)),
  };
}

function buildCategorySummary(rows) {
  const categories = new Map();

  for (const row of rows) {
    const bucket = categories.get(row.category) ?? [];
    bucket.push(row);
    categories.set(row.category, bucket);
  }

  return [...categories.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([category, bucket]) => ({
      category,
      categoryLabel: CATEGORY_LABELS[category] ?? category,
      ...buildSummary(bucket),
    }));
}

function countOutcomes(rows) {
  const counts = { TP: 0, FN: 0, FP: 0, TN: 0 };
  for (const row of rows) counts[row.outcome]++;
  return counts;
}

function ratio(numerator, denominator) {
  if (!denominator) return 0;
  return Number((numerator / denominator).toFixed(4));
}

function percent(value) {
  return `${(value * 100).toFixed(1)}%`;
}

function buildMarkdown({ target, expectedPath, semgrepReportPath, strictCategory, result }) {
  const s = result.summary;
  return `# OWASP Benchmark Evaluation

Target: \`${target}\`

Expected results: \`${expectedPath}\`

Semgrep report: \`${semgrepReportPath}\`

Match mode: ${strictCategory ? 'test id + category/CWE' : 'test id'}

## Summary

| Metric | Value |
|---|---:|
| Total benchmark cases | ${s.total} |
| Vulnerable cases | ${s.vulnerable} |
| Safe cases | ${s.safe} |
| True Positive (TP) | ${s.TP} |
| False Negative (FN) | ${s.FN} |
| False Positive (FP) | ${s.FP} |
| True Negative (TN) | ${s.TN} |
| True Positive Rate / Coverage | ${percent(s.truePositiveRate)} |
| False Negative Rate | ${percent(s.falseNegativeRate)} |
| False Positive Rate | ${percent(s.falsePositiveRate)} |
| Precision | ${percent(s.precision)} |
| Accuracy | ${percent(s.accuracy)} |
| Benchmark score (TPR - FPR) | ${s.benchmarkScore.toFixed(4)} |
| Findings without BenchmarkTest id | ${result.unmatchedFindings.length} |

## By Category

| Category | Cases | TP | FN | FP | TN | Coverage | FPR | Score |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
${result.byCategory.map(row => `| ${row.categoryLabel} | ${row.total} | ${row.TP} | ${row.FN} | ${row.FP} | ${row.TN} | ${percent(row.truePositiveRate)} | ${percent(row.falsePositiveRate)} | ${row.benchmarkScore.toFixed(4)} |`).join('\n')}

## Missed Vulnerable Cases

${formatCaseList(result.rows.filter(row => row.outcome === 'FN').slice(0, 50))}

## False Positive Cases

${formatCaseList(result.rows.filter(row => row.outcome === 'FP').slice(0, 50))}

> Note: this evaluator maps scanner findings to OWASP Benchmark cases by \`BenchmarkTestNNNNN\`. It is suitable for Semgrep JSON reports produced by this pipeline because Semgrep findings include source file paths. Use \`--strict-category\` if you want a stricter match that also checks CWE/category evidence from the finding.
`;
}

function formatCaseList(rows) {
  if (rows.length === 0) return 'None.';
  return rows
    .map(row => `- \`${row.testName}\` (${row.categoryLabel}, CWE-${row.cwe})`)
    .join('\n');
}

function writeOutput(path, content) {
  const out = resolve(path);
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, content, 'utf8');
  return out;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const target = resolve(args.target);
  const expectedPath = resolve(args.expected);
  const semgrepReportPath = resolve(args.semgrepReport);

  const expectedRows = parseExpectedResults(expectedPath);
  const semgrepFindings = readSemgrepFindings(semgrepReportPath);
  const result = evaluate(expectedRows, semgrepFindings, {
    strictCategory: args.strictCategory,
  });

  const payload = {
    target,
    expectedPath,
    semgrepReportPath,
    strictCategory: args.strictCategory,
    generatedAt: new Date().toISOString(),
    summary: result.summary,
    byCategory: result.byCategory,
    unmatchedFindingCount: result.unmatchedFindings.length,
    rows: result.rows,
  };

  const markdown = buildMarkdown({
    target,
    expectedPath,
    semgrepReportPath,
    strictCategory: args.strictCategory,
    result,
  });

  const mdPath = writeOutput(args.output, markdown);
  const jsonPath = writeOutput(args.jsonOutput, JSON.stringify(payload, null, 2));

  console.log(markdown);
  console.log(`[OUTPUT] ${mdPath}`);
  console.log(`[OUTPUT] ${jsonPath}`);
}

main();
