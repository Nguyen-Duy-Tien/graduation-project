// collectors/codePattern.js
// Quét 20 dangerous pattern trên toàn bộ source — không phân biệt ngôn ngữ
// 9 category: sqli, rce, jwt, mass_assign, ssrf, xss, secret, path_traversal, auth_bypass, info_leak
// Mỗi pattern có severity: critical / high / medium

import { readFileSync } from 'fs';
import { relative } from 'path';
import { glob } from 'glob';

// ── 20 Dangerous Pattern Definitions ─────────────────────────────────────────

const DANGEROUS_PATTERNS = [
  // ── sqli ──────────────────────────────────────────────────────────────────
  {
    id:       'sqli-1',
    category: 'sqli',
    severity: 'critical',
    label:    'Raw SQL string concatenation',
    pattern:  /(?:execute|query|rawQuery|createQuery)\s*\(\s*[`'"]\s*SELECT.*?\+/is,
  },
  {
    id:       'sqli-2',
    category: 'sqli',
    severity: 'critical',
    label:    'f-string or template literal SQL injection',
    pattern:  /(?:f['"]|`)[^'"` ]*SELECT[^'"` ]*\$\{|f['"][^'"]*SELECT[^'"]*\{/i,
  },
  {
    id:       'sqli-3',
    category: 'sqli',
    severity: 'high',
    label:    'ORM where() with string concat',
    pattern:  /\.where\s*\(\s*['"`][^'"` ]*['"`]\s*\+\s*(?:req|request|params|body|query)/i,
  },

  // ── rce (Remote Code Execution) ───────────────────────────────────────────
  {
    id:       'rce-1',
    category: 'rce',
    severity: 'critical',
    label:    'Shell execution with user input',
    pattern:  /(?:exec|spawn|execSync|spawnSync)\s*\([^)]*(?:req\.|request\.|params\.|body\.|query\.)/i,
  },
  {
    id:       'rce-2',
    category: 'rce',
    severity: 'critical',
    label:    'Python subprocess shell=True',
    pattern:  /subprocess\s*\.\s*(?:call|run|Popen)[^)]*shell\s*=\s*True/i,
  },
  {
    id:       'rce-3',
    category: 'rce',
    severity: 'critical',
    label:    'PHP shell_exec / system / passthru',
    pattern:  /\b(?:shell_exec|system|passthru|popen|proc_open)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/i,
  },

  // ── jwt ───────────────────────────────────────────────────────────────────
  {
    id:       'jwt-1',
    category: 'jwt',
    severity: 'critical',
    label:    'JWT verify disabled or alg:none',
    pattern:  /(?:verify\s*=\s*[Ff]alse|algorithms?\s*=\s*\[\s*['"]none['"]|algorithm.*none)/i,
  },
  {
    id:       'jwt-2',
    category: 'jwt',
    severity: 'high',
    label:    'JWT decode without verify',
    pattern:  /jwt\.decode\s*\([^)]*(?:,\s*options\s*=\s*\{[^}]*verify\s*:\s*false|,\s*\{[^}]*complete\s*:\s*true(?!.*verify))/i,
  },
  {
    id:       'jwt-3',
    category: 'jwt',
    severity: 'high',
    label:    'Hardcoded JWT secret',
    pattern:  /(?:jwt\.sign|jwt\.verify|SECRET_KEY|JWT_SECRET)\s*[=(,]\s*['"`][A-Za-z0-9!@#$%^&*]{8,}['"`]/,
  },

  // ── mass_assign ───────────────────────────────────────────────────────────
  {
    id:       'mass-1',
    category: 'mass_assign',
    severity: 'high',
    label:    'Mass assignment: spread req.body into model',
    pattern:  /(?:create|update|save|assign)\s*\(\s*(?:\.\.\.)?(?:req\.body|request\.body|request\.json\(\))\s*\)/i,
  },
  {
    id:       'mass-2',
    category: 'mass_assign',
    severity: 'high',
    label:    'Ruby mass-assign without permit',
    pattern:  /\.update\s*\(\s*params(?!\s*\.permit)/i,
  },

  // ── ssrf ──────────────────────────────────────────────────────────────────
  {
    id:       'ssrf-1',
    category: 'ssrf',
    severity: 'high',
    label:    'HTTP request to user-controlled URL',
    pattern:  /(?:fetch|axios\.get|axios\.post|requests\.get|requests\.post|http\.get)\s*\([^)]*(?:req\.|request\.|body\.|params\.|query\.)[^\s)]*(?:url|host|endpoint|uri)/i,
  },
  {
    id:       'ssrf-2',
    category: 'ssrf',
    severity: 'high',
    label:    'curl_exec with user input (PHP)',
    pattern:  /curl_setopt\s*\([^)]*CURLOPT_URL[^)]*\$_(?:GET|POST|REQUEST)/i,
  },

  // ── xss ───────────────────────────────────────────────────────────────────
  {
    id:       'xss-1',
    category: 'xss',
    severity: 'high',
    label:    'innerHTML / dangerouslySetInnerHTML with user data',
    pattern:  /(?:innerHTML|dangerouslySetInnerHTML)\s*=\s*(?:\{[^}]*\}|[^;]*(?:req\.|state\.|params\.))/i,
  },
  {
    id:       'xss-2',
    category: 'xss',
    severity: 'medium',
    label:    'Unescaped template output (Jinja/Twig/Blade)',
    pattern:  /\{\{-\s*[^}]+\s*-?\}\}|<%=\s*(?:raw|html_safe)\s*[^%]+%>/i,
  },

  // ── secret ────────────────────────────────────────────────────────────────
  {
    id:       'secret-1',
    category: 'secret',
    severity: 'critical',
    label:    'Hardcoded credential or API key',
    pattern:  /(?:password|passwd|api_key|apikey|secret|private_key|access_token|client_secret)\s*[=:]\s*['"`][A-Za-z0-9!@#$%^&*\-_+=]{8,}['"`]/i,
  },
  {
    id:       'secret-2',
    category: 'secret',
    severity: 'critical',
    label:    'Private key material in source',
    pattern:  /-----BEGIN\s+(?:RSA\s+)?(?:EC\s+)?PRIVATE\s+KEY-----/,
  },

  // ── path_traversal ────────────────────────────────────────────────────────
  {
    id:       'path-1',
    category: 'path_traversal',
    severity: 'high',
    label:    'File read/write with user-supplied path',
    pattern:  /(?:readFile|writeFile|createReadStream|open|fopen)\s*\([^)]*(?:req\.|request\.|params\.|body\.|query\.)[^\s)]*(?:path|file|name|dir)/i,
  },

  // ── auth_bypass ───────────────────────────────────────────────────────────
  {
    id:       'auth-1',
    category: 'auth_bypass',
    severity: 'high',
    label:    'Auth skip annotation or comment',
    pattern:  /@(?:Public|AllowAnonymous|permit_all|SkipAuth)|\/\/\s*TODO.*auth|#\s*FIXME.*auth|PermitAll/i,
  },
  {
    id:       'auth-2',
    category: 'auth_bypass',
    severity: 'medium',
    label:    'Hardcoded role or permission check',
    pattern:  /if\s*\([^)]*(?:role|permission|isAdmin)\s*===?\s*['"](?:admin|superuser|root)['"]/i,
  },

  // ── info_leak ─────────────────────────────────────────────────────────────
  {
    id:       'info-1',
    category: 'info_leak',
    severity: 'medium',
    label:    'Console.log / print with sensitive data',
    pattern:  /(?:console\.log|console\.error|print|logger\.debug)\s*\([^)]*(?:password|token|secret|key|credential)/i,
  },
];

// ── Scan helpers ──────────────────────────────────────────────────────────────

const SKIP_DIRS = new Set([
  'node_modules', 'vendor', '.git', '__pycache__', 'dist',
  'build', '.venv', 'venv', 'target', '.next', 'coverage', 'tmp',
]);

const SOURCE_EXTENSIONS = ['.js', '.ts', '.mjs', '.cjs', '.py', '.java', '.php', '.go', '.rb'];

function shouldSkip(filePath) {
  return filePath.replace(/\\/g, '/').split('/').some(p => SKIP_DIRS.has(p));
}

function scanFileForPatterns(filePath, projectRoot) {
  let content;
  try {
    content = readFileSync(filePath, 'utf8');
  } catch {
    return [];
  }

  const relPath = relative(projectRoot, filePath).replace(/\\/g, '/');
  const lines   = content.split('\n');
  const results = [];

  for (const def of DANGEROUS_PATTERNS) {
    const re = new RegExp(def.pattern.source, def.pattern.flags.includes('g') ? def.pattern.flags : def.pattern.flags + 'g');
    let match;

    while ((match = re.exec(content)) !== null) {
      const lineNum = content.slice(0, match.index).split('\n').length;
      results.push({
        patternId:  def.id,
        category:   def.category,
        severity:   def.severity,
        label:      def.label,
        file:       relPath,
        line:       lineNum,
        snippet:    (lines[lineNum - 1] ?? '').trim().slice(0, 150),
        matched:    match[0].slice(0, 80),
      });
    }
  }

  return results;
}

// ── Main export ───────────────────────────────────────────────────────────────

/**
 * Scan toàn bộ source code tìm dangerous code patterns.
 * @param {string} projectRoot
 * @returns {Promise<object>}
 */
export async function collectCodePatterns(projectRoot) {
  const fileGlobs = SOURCE_EXTENSIONS.map(ext => `**/*${ext}`);
  const allFiles  = (await Promise.all(
    fileGlobs.map(p => glob(p, { cwd: projectRoot, absolute: true, dot: false }))
  )).flat().filter(f => !shouldSkip(f));

  const uniqueFiles = [...new Set(allFiles)];
  const allFindings = [];

  for (const file of uniqueFiles) {
    const findings = scanFileForPatterns(file, projectRoot);
    allFindings.push(...findings);
  }

  // Aggregate by category
  const byCategory = {};
  const bySeverity  = { critical: 0, high: 0, medium: 0 };

  for (const f of allFindings) {
    byCategory[f.category] = byCategory[f.category] ?? { count: 0, findings: [] };
    byCategory[f.category].count++;
    // Giữ tối đa 5 findings per category để context không quá dài
    if (byCategory[f.category].findings.length < 5) {
      byCategory[f.category].findings.push(f);
    }
    bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
  }

  return {
    totalFindings:  allFindings.length,
    bySeverity,
    byCategory,
    // Top 30 findings sắp xếp theo severity để AI ưu tiên
    topFindings:    allFindings
      .sort((a, b) => {
        const order = { critical: 0, high: 1, medium: 2 };
        return order[a.severity] - order[b.severity];
      })
      .slice(0, 30),
    filesScanned:   uniqueFiles.length,
  };
}
