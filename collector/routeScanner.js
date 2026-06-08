// collectors/routeScanner.js
// Phần cốt lõi: AI tự suy ra attack surface không cần Swagger
// 9 regex pattern → route detection
// classifyEndpoint() → 6 flag: auth, fileUpload, idor_candidate, admin, export, payment

import { existsSync, readFileSync } from 'fs';
import { dirname, join, relative, resolve } from 'path';
import { glob } from 'glob';

// ── 9 Route Detection Patterns ────────────────────────────────────────────────
// Thứ tự: ưu tiên framework phổ biến trước
// Mỗi entry: { name, pattern, methodGroup, pathGroup, extensions }
const ROUTE_PATTERNS = [
  // 1. Express / Fastify / Koa — app.get('/path', ...)
  {
    name: 'express',
    pattern: /\b(app|appDev|router|r)\s*\.\s*(get|post|put|patch|delete|all|use)\s*\(\s*['"`]([^'"`\s]+)['"`]/gi,
    receiverGroup: 1,
    methodGroup: 2,
    pathGroup:   3,
    extensions:  ['.js', '.ts', '.mjs', '.cjs'],
  },
  // Express regex catch-all — router.get(/.*/, ...)
  {
    name: 'express',
    pattern: /\b(app|appDev|router|r)\s*\.\s*(get|post|put|patch|delete|all|use)\s*\(\s*\/\.\*\//gi,
    receiverGroup: 1,
    methodGroup: 2,
    pathGroup:   null,
    literalPath: '/',
    extensions:  ['.js', '.ts', '.mjs', '.cjs'],
  },
  // 2. NestJS decorators — @Get('/path'), @Post('/path'), @Controller('/base')
  {
    name: 'nestjs',
    pattern: /@(Get|Post|Put|Patch|Delete|Controller)\s*\(\s*['"`]([^'"`]*)['"`]/gi,
    methodGroup: 1,
    pathGroup:   2,
    extensions:  ['.ts'],
  },
  // 3. Flask / FastAPI — @app.route('/path'), @router.get('/path')
  {
    name: 'flask_fastapi',
    pattern: /@(?:app|router|bp|blueprint|api)\s*\.(?:route|get|post|put|patch|delete)\s*\(\s*['"]([^'"]+)['"]/gi,
    methodGroup: null,   // method ada di decorator name
    pathGroup:   1,
    extensions:  ['.py'],
  },
  // 4. Django urls.py — path('endpoint/', view), re_path(r'^api/...')
  {
    name: 'django',
    pattern: /(?:path|re_path|url)\s*\(\s*['"]([^'"]+)['"]/gi,
    methodGroup: null,
    pathGroup:   1,
    extensions:  ['.py'],
  },
  // 5. Spring Boot — @GetMapping("/path"), @RequestMapping(value="/path")
  {
    name: 'spring',
    pattern: /@(Get|Post|Put|Patch|Delete|Request)Mapping\s*\(\s*(?:value\s*=\s*)?['"]([^'"]+)['"]/gi,
    methodGroup: 1,
    pathGroup:   2,
    extensions:  ['.java'],
  },
  // 6. Spring @RequestMapping dengan method= di lain tempat
  {
    name: 'spring_requestmapping',
    pattern: /@RequestMapping\s*\([^)]*path\s*=\s*['"]([^'"]+)['"]/gi,
    methodGroup: null,
    pathGroup:   1,
    extensions:  ['.java'],
  },
  // 7. Laravel — Route::get('/path', ...), Route::resource('/path', ...)
  {
    name: 'laravel',
    pattern: /Route\s*::\s*(get|post|put|patch|delete|any|resource|apiResource)\s*\(\s*['"]([^'"]+)['"]/gi,
    methodGroup: 1,
    pathGroup:   2,
    extensions:  ['.php'],
  },
  // 8. Gin / Fiber / Echo (Go) — r.GET("/path", handler), app.Get("/path", ...)
  {
    name: 'gin_fiber',
    pattern: /(?:r|router|app|v\d+|group)\s*\.\s*(GET|POST|PUT|PATCH|DELETE|Any|get|post|put|patch|delete)\s*\(\s*['"]([^'"]+)['"]/g,
    methodGroup: 1,
    pathGroup:   2,
    extensions:  ['.go'],
  },
  // 9. Ruby on Rails routes.rb
  {
    name: 'rails',
    pattern: /^\s*(get|post|put|patch|delete|resources?)\s+['"]([^'"]+)['"]/gim,
    methodGroup: 1,
    pathGroup:   2,
    extensions:  ['.rb'],
  },
];

// ── Endpoint Classification — 6 flag types ───────────────────────────────────

const CLASSIFICATION_RULES = {
  auth: [
    /\b(?:login|logout|signin|signup|register|auth|token|refresh|oauth|2fa|mfa|verify|password|reset|forgot)\b/i,
  ],
  fileUpload: [
    /\b(?:upload|file|image|avatar|attachment|media|document|import|photo|asset)\b/i,
  ],
  idor_candidate: [
    // Path param :id, {id}, <id>, atau query ?id=
    /:(?:id|name|username|slug|uuid|user_?id|account_?id|order_?id|post_?id|item_?id|record_?id)\b/i,
    /\{(?:id|userId|accountId)\}/i,
    /\/\d+(?:\/|$)/,                   // Numeric segment: /api/users/123
    /\[id\]|\[userId\]/i,              // Next.js dynamic routes
  ],
  admin: [
    /\b(?:admin|management|dashboard|internal|console|control|config|setting|panel|backoffice|staff|ops)\b/i,
  ],
  export: [
    /\b(?:export|download|report|extract|dump|csv|excel|pdf|list|search|query|filter)\b/i,
  ],
  payment: [
    /\b(?:payment|checkout|billing|invoice|subscription|stripe|paypal|order|cart|purchase|transaction|refund)\b/i,
  ],
};

/**
 * Klasifikasi satu endpoint path → array of flag strings
 * @param {string} path
 * @returns {string[]}
 */
export function classifyEndpoint(path) {
  const flags = [];
  for (const [flag, patterns] of Object.entries(CLASSIFICATION_RULES)) {
    if (patterns.some(re => re.test(path))) {
      flags.push(flag);
    }
  }
  return flags.length > 0 ? flags : ['general'];
}

const UNSAFE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

const TOKEN_EXCLUDE = new Set([
  'async', 'function', 'return', 'true', 'false', 'null', 'undefined',
  'req', 'request', 'res', 'response', 'next',
]);

const AUTH_NAME_RE = /(?:^|[._-])(?:auth|authenticate|authenticated|requireauth|jwt|session|passport|verifytoken|verifyjwt)(?:$|[._-])/i;
const ADMIN_NAME_RE = /(?:^|[._-])(?:admin|requireadmin|isadmin|superuser|root|authorize|rbac|permission|role|roles)(?:$|[._-])/i;
const VALIDATION_NAME_RE = /(?:validate|validator|schema|joi|zod|celebrate|sanitize|objectid)/i;
const ROLE_CHECK_RE = /(?:\b[A-Za-z_$][\w$]*\.)?(?:role|roles|permission|permissions|isAdmin|is_admin|scope|scopes)\s*(?:===|==|!==|!=)|\.(?:includes|some)\s*\([^)]*['"`](?:ADMIN|admin|superuser|root)['"`]/i;
const REQ_USER_RE = /\b(?:req|request)\.user\b|\bctx\.state\.user\b|\bc\.get\s*\(\s*['"]user['"]\s*\)/i;
const OWNERSHIP_RE = /\b(?:owner|ownerId|owner_id|userId|user_id|accountId|account_id|tenantId|tenant_id|createdBy|created_by)\b|\b(?:req|request)\.user\.(?:_id|id|userId)\b/i;

// ── File scanner helpers ──────────────────────────────────────────────────────

const SKIP_DIRS = new Set([
  'node_modules', 'vendor', '.git', '__pycache__', 'dist',
  'build', '.venv', 'venv', 'target', '.next', 'out',
  'coverage', '.cache', 'tmp', 'temp',
]);

function shouldSkip(filePath) {
  const parts = filePath.replace(/\\/g, '/').split('/');
  return parts.some(p => SKIP_DIRS.has(p));
}

function normalizeRoutePath(path) {
  if (!path || path === '/') return '/';
  return '/' + String(path).replace(/^\/+|\/+$/g, '');
}

function joinRoutePaths(basePath, childPath) {
  const base = normalizeRoutePath(basePath);
  const child = normalizeRoutePath(childPath);
  if (base === '/') return child;
  if (child === '/') return base;
  return `${base}${child}`;
}

function addFlag(flags, flag) {
  if (flags.includes('general')) {
    flags.splice(flags.indexOf('general'), 1);
  }
  if (!flags.includes(flag)) flags.push(flag);
}

function findMatchingParen(text, openIndex) {
  let depth = 0;
  let quote = null;
  let escaped = false;
  let lineComment = false;
  let blockComment = false;

  for (let i = openIndex; i < text.length; i++) {
    const ch = text[i];
    const next = text[i + 1];

    if (lineComment) {
      if (ch === '\n') lineComment = false;
      continue;
    }

    if (blockComment) {
      if (ch === '*' && next === '/') {
        blockComment = false;
        i++;
      }
      continue;
    }

    if (quote) {
      if (escaped) {
        escaped = false;
      } else if (ch === '\\') {
        escaped = true;
      } else if (ch === quote) {
        quote = null;
      }
      continue;
    }

    if (ch === '/' && next === '/') {
      lineComment = true;
      i++;
      continue;
    }

    if (ch === '/' && next === '*') {
      blockComment = true;
      i++;
      continue;
    }

    if (ch === '"' || ch === "'" || ch === '`') {
      quote = ch;
      continue;
    }

    if (ch === '(') depth++;
    else if (ch === ')') {
      depth--;
      if (depth === 0) return i;
    }
  }

  return -1;
}

function getRouteCallParts(content, matchIndex, matchedLength) {
  const openParen = content.indexOf('(', matchIndex);
  if (openParen === -1) return { callText: '', argsAfterPath: '' };

  const closeParen = findMatchingParen(content, openParen);
  if (closeParen === -1) return { callText: '', argsAfterPath: '' };

  return {
    callText: content.slice(matchIndex, closeParen + 1),
    argsAfterPath: content.slice(matchIndex + matchedLength, closeParen),
  };
}

function extractMiddlewarePrefix(argsAfterPath) {
  const tail = String(argsAfterPath ?? '').replace(/^\s*,\s*/, '');
  const markers = [
    /\basync\s*\(/,
    /\basync\s+function\b/,
    /\bfunction\b/,
    /\(\s*(?:req|request|ctx|c)\b[\s\S]{0,120}?\)\s*=>/,
    /\b(?:req|request|ctx|c)\s*=>/,
  ];

  const markerIndex = markers
    .map(re => {
      const match = re.exec(tail);
      return match ? match.index : -1;
    })
    .filter(i => i >= 0)
    .sort((a, b) => a - b)[0];

  return markerIndex >= 0 ? tail.slice(0, markerIndex) : tail;
}

function extractMiddlewareNames(argsAfterPath) {
  const prefix = extractMiddlewarePrefix(argsAfterPath);
  const names = [];
  const re = /[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?/g;
  let match;

  while ((match = re.exec(prefix)) !== null) {
    const token = match[0];
    const leaf = token.split('.').pop();
    if (!leaf || TOKEN_EXCLUDE.has(leaf)) continue;
    if (!names.includes(token)) names.push(token);
  }

  return names;
}

function hasMiddlewareName(names, re) {
  return names.some(name => re.test(name));
}

function buildRoleExpectations({ method, flags, hasAuthMiddleware, hasRoleCheck }) {
  const unsafe = UNSAFE_METHODS.has(method);
  const authEndpoint = flags.includes('auth');
  const adminEndpoint = flags.includes('admin');

  if (authEndpoint) {
    return {
      anonymous: 'allowed for login/reset flow; validate abuse separately',
      user: 'not applicable or already authenticated',
      admin: 'not applicable or already authenticated',
    };
  }

  if (!hasAuthMiddleware) {
    return {
      anonymous: unsafe ? 'should reject unsafe state change or require explicit public design' : 'public or limited data only',
      user: 'same as anonymous unless route enforces auth elsewhere',
      admin: 'same as anonymous unless route enforces auth elsewhere',
    };
  }

  if (hasRoleCheck || adminEndpoint) {
    return {
      anonymous: '401 expected',
      user: '403 expected unless explicitly privileged',
      admin: 'allowed when request is valid',
    };
  }

  return {
    anonymous: '401 expected',
    user: unsafe ? 'allowed only for owned objects or permitted business action' : 'allowed only for permitted data',
    admin: 'allowed when request is valid',
  };
}

function extractRouteSecurity(argsAfterPath, callText) {
  const middleware = extractMiddlewareNames(argsAfterPath);
  const hasAuthMiddleware = hasMiddlewareName(middleware, AUTH_NAME_RE);
  const hasAdminMiddleware = hasMiddlewareName(middleware, ADMIN_NAME_RE);
  const hasValidationMiddleware = hasMiddlewareName(middleware, VALIDATION_NAME_RE);
  const hasReqUserReference = REQ_USER_RE.test(callText);
  const hasOwnershipCheck = hasReqUserReference || OWNERSHIP_RE.test(callText);
  const hasRoleCheck = hasAdminMiddleware || ROLE_CHECK_RE.test(callText);

  return {
    middleware,
    hasAuthMiddleware,
    hasAdminMiddleware,
    hasValidationMiddleware,
    hasReqUserReference,
    hasOwnershipCheck,
    hasRoleCheck,
  };
}

function baseSecurity(security = {}) {
  const {
    riskSignals,
    expectedRoles,
    missingAuthSignal,
    missingAdminSignal,
    missingOwnershipSignal,
    weakFunctionAuthzSignal,
    ...base
  } = security;
  return base;
}

function finalizeRouteMetadata(method, path, security) {
  const flags = classifyEndpoint(path);
  const riskSignals = [];
  const unsafe = UNSAFE_METHODS.has(method);
  const authEndpoint = flags.includes('auth');
  const adminEndpoint = flags.includes('admin');
  const idorCandidate = flags.includes('idor_candidate');
  const hasAuthMiddleware = Boolean(security?.hasAuthMiddleware);
  const hasRoleCheck = Boolean(security?.hasRoleCheck);

  let missingAuthSignal = false;
  let missingAdminSignal = false;
  let missingOwnershipSignal = false;
  let weakFunctionAuthzSignal = false;

  if (unsafe && !authEndpoint) {
    addFlag(flags, 'authz');
  }

  if (unsafe && !authEndpoint && !hasAuthMiddleware) {
    missingAuthSignal = true;
    addFlag(flags, 'missing_auth');
    riskSignals.push('write_route_without_auth_middleware');
  }

  if (unsafe && !authEndpoint && hasAuthMiddleware && !hasRoleCheck) {
    weakFunctionAuthzSignal = true;
    riskSignals.push('state_changing_route_without_role_check');
  }

  if (adminEndpoint && !hasRoleCheck) {
    missingAdminSignal = true;
    addFlag(flags, 'missing_admin');
    riskSignals.push('admin_endpoint_without_role_check');
  }

  if (idorCandidate && hasAuthMiddleware && !security?.hasOwnershipCheck) {
    missingOwnershipSignal = true;
    addFlag(flags, 'missing_ownership_check');
    riskSignals.push('object_identifier_route_without_req_user_ownership_check');
  }

  return {
    classification: flags,
    security: {
      ...security,
      riskSignals,
      missingAuthSignal,
      missingAdminSignal,
      missingOwnershipSignal,
      weakFunctionAuthzSignal,
      expectedRoles: buildRoleExpectations({
        method,
        flags,
        hasAuthMiddleware,
        hasRoleCheck,
      }),
    },
  };
}

function resolveRequiredFile(fromFile, requestPath) {
  if (!requestPath?.startsWith?.('.')) return null;

  const base = resolve(dirname(fromFile), requestPath);
  const candidates = [
    base,
    `${base}.js`,
    `${base}.ts`,
    `${base}.mjs`,
    `${base}.cjs`,
    join(base, 'index.js'),
    join(base, 'index.ts'),
  ];

  return candidates.find(p => existsSync(p)) ?? null;
}

function buildExpressMountMap(files) {
  const mountsByFile = new Map();
  const requireRe = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
  const mountRe = /\b(?:app|appDev|router|r)\s*\.\s*use\s*\(\s*['"`]([^'"`\s]+)['"`]\s*,\s*([A-Za-z_$][\w$]*)/g;

  for (const file of files) {
    if (!/\.(?:js|ts|mjs|cjs)$/.test(file)) continue;

    let content;
    try {
      content = readFileSync(file, 'utf8');
    } catch {
      continue;
    }

    const requires = new Map();
    let match;
    while ((match = requireRe.exec(content)) !== null) {
      const resolvedFile = resolveRequiredFile(file, match[2]);
      if (resolvedFile) requires.set(match[1], resolvedFile);
    }

    while ((match = mountRe.exec(content)) !== null) {
      const basePath = match[1];
      const variable = match[2];
      const mountedFile = requires.get(variable);
      if (!mountedFile) continue;

      const mounts = mountsByFile.get(mountedFile) ?? [];
      mounts.push({
        basePath,
        mountedFrom: file,
        variable,
      });
      mountsByFile.set(mountedFile, mounts);
    }
  }

  return mountsByFile;
}

function expandExpressRoute(route, mounts) {
  if (route.framework !== 'express' || route.method === 'USE' || !mounts?.length) {
    return [route];
  }

  if (!['router', 'r'].includes(route.receiver)) {
    return [route];
  }

  return mounts.map(mount => {
    const fullPath = joinRoutePaths(mount.basePath, route.path);
    const finalized = finalizeRouteMetadata(route.method, fullPath, baseSecurity(route.security));

    return {
      ...route,
      path: fullPath,
      mountPath: mount.basePath,
      mountedFrom: mount.mountedFrom,
      classification: finalized.classification,
      security: finalized.security,
    };
  });
}

function extractRoutesFromFile(filePath, patternEntry) {
  let content;
  try {
    content = readFileSync(filePath, 'utf8');
  } catch {
    return [];
  }

  const results = [];
  const lines   = content.split('\n');
  const re      = new RegExp(patternEntry.pattern.source, patternEntry.pattern.flags);
  let match;

  while ((match = re.exec(content)) !== null) {
    const lineNum  = content.slice(0, match.index).split('\n').length;
    const rawPath  = patternEntry.literalPath ?? match[patternEntry.pathGroup]?.trim() ?? '';
    const rawMethod = patternEntry.methodGroup !== null
      ? (match[patternEntry.methodGroup] ?? 'GET').toUpperCase()
      : 'GET';
    const receiver = patternEntry.receiverGroup
      ? (match[patternEntry.receiverGroup] ?? null)
      : null;
    const callParts = getRouteCallParts(content, match.index, match[0].length);
    const extractedSecurity = patternEntry.name === 'express'
      ? extractRouteSecurity(callParts.argsAfterPath, callParts.callText)
      : {
          middleware: [],
          hasAuthMiddleware: false,
          hasAdminMiddleware: false,
          hasValidationMiddleware: false,
          hasReqUserReference: REQ_USER_RE.test(callParts.callText),
          hasOwnershipCheck: OWNERSHIP_RE.test(callParts.callText),
          hasRoleCheck: ROLE_CHECK_RE.test(callParts.callText),
        };

    // Spring/NestJS method mapping
    const method = rawMethod.replace('MAPPING', '').replace('CONTROLLER', 'BASE');

    if (!rawPath || rawPath.length > 200) continue;

    const finalized = finalizeRouteMetadata(method, rawPath, extractedSecurity);

    results.push({
      method,
      path:           rawPath,
      file:           filePath,
      line:           lineNum,
      framework:      patternEntry.name,
      receiver,
      classification: finalized.classification,
      security:       finalized.security,
      snippet:        (lines[lineNum - 1] ?? '').trim().slice(0, 120),
    });
  }

  return results;
}

// ── Main export ───────────────────────────────────────────────────────────────

/**
 * Scan toàn bộ source code tìm route/endpoint declarations.
 * @param {string} projectRoot
 * @param {object} techStack   — từ collectTechStack(), dùng để ưu tiên pattern
 * @returns {Promise<object>}
 */
export async function collectRoutes(projectRoot, techStack = {}) {
  const lang = techStack.language ?? 'unknown';

  // Xác định extensions cần quét dựa trên language detected
  const langExtMap = {
    nodejs:  ['.js', '.ts', '.mjs', '.cjs'],
    python:  ['.py'],
    java:    ['.java'],
    php:     ['.php'],
    golang:  ['.go'],
    ruby:    ['.rb'],
    unknown: ['.js', '.ts', '.py', '.java', '.php', '.go', '.rb'],
  };
  const targetExts = new Set(langExtMap[lang] ?? langExtMap.unknown);

  // Filter patterns chỉ lấy những pattern match extensions
  const activePatterns = ROUTE_PATTERNS.filter(p =>
    p.extensions.some(ext => targetExts.has(ext))
  );

  // Glob tất cả source files
  const patterns = [...targetExts].map(ext => `**/*${ext}`);
  const allFiles = (await Promise.all(
    patterns.map(p => glob(p, { cwd: projectRoot, absolute: true, dot: false }))
  )).flat().filter(f => !shouldSkip(f));

  // Unique files
  const uniqueFiles = [...new Set(allFiles)];
  const expressMountsByFile = buildExpressMountMap(uniqueFiles);

  // Scan
  const allRoutes = [];
  const seenKeys  = new Set();   // dedup: method+path+file after mount expansion

  for (const file of uniqueFiles) {
    for (const patternEntry of activePatterns) {
      if (!patternEntry.extensions.some(ext => file.endsWith(ext))) continue;

      const routes = extractRoutesFromFile(file, patternEntry);
      for (const route of routes) {
        if (route.framework === 'express' && route.method === 'USE') {
          continue;
        }

        const expandedRoutes = expandExpressRoute(route, expressMountsByFile.get(file));
        for (const expanded of expandedRoutes) {
          // Relative path để output gọn hơn
          expanded.file = relative(projectRoot, expanded.file).replace(/\\/g, '/');
          if (expanded.mountedFrom) {
            expanded.mountedFrom = relative(projectRoot, expanded.mountedFrom).replace(/\\/g, '/');
          }

          const key = `${expanded.method}:${expanded.path}:${expanded.file}`;
          if (!seenKeys.has(key)) {
            seenKeys.add(key);
            allRoutes.push(expanded);
          }
        }
      }
    }
  }

  // Aggregate statistics
  const classificationStats = {};
  for (const route of allRoutes) {
    for (const cls of route.classification) {
      classificationStats[cls] = (classificationStats[cls] ?? 0) + 1;
    }
  }

  // High-risk endpoints — idor_candidate hoặc fileUpload hoặc admin
  const highRiskRoutes = allRoutes.filter(r =>
    r.classification.some(c => [
      'idor_candidate',
      'fileUpload',
      'admin',
      'authz',
      'missing_auth',
      'missing_admin',
      'missing_ownership_check',
    ].includes(c))
  );

  return {
    totalEndpoints:      allRoutes.length,
    classificationStats,
    highRiskCount:       highRiskRoutes.length,
    routes:              allRoutes,
    highRiskRoutes,
    filesScanned:        uniqueFiles.length,
  };
}
