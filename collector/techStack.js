// collectors/techStack.js
// Nhận diện ngôn ngữ, framework và ánh xạ sang tool profile
// Đọc: package.json, requirements.txt, pom.xml, composer.json, go.mod, Gemfile

import { readFileSync, existsSync, readdirSync, statSync } from 'fs';
import { join, relative, resolve } from 'path';
import yaml from 'js-yaml';

// ── Tool profile map ──────────────────────────────────────────────────────────
// Mỗi profile → danh sách tool và cấu hình mặc định
// AI sẽ override cấu hình này ở bước aiAnalyzer.js
export const PROFILE_TOOL_MAP = {
  'nodejs-rest-api': {
    sast:   { tool: 'semgrep', rulesets: ['p/nodejs', 'p/jwt', 'p/injection', 'p/owasp-top-ten'] },
    dast:   { tool: 'zap',     mode: 'api-scan' },
    active: ['semgrep', 'zap', 'nuclei', 'trivy'],
  },
  'nodejs-fullstack': {
    sast:   { tool: 'semgrep', rulesets: ['p/nodejs', 'p/xss', 'p/injection'] },
    dast:   { tool: 'zap',     mode: 'full-scan' },
    active: ['semgrep', 'zap', 'trivy'],
  },
  'python-flask': {
    sast:   { tool: 'semgrep', rulesets: ['p/python', 'p/flask', 'p/injection'] },
    dast:   { tool: 'zap',     mode: 'full-scan' },
    active: ['semgrep', 'bandit', 'zap', 'trivy'],
  },
  'python-fastapi': {
    sast:   { tool: 'semgrep', rulesets: ['p/python', 'p/fastapi', 'p/injection'] },
    dast:   { tool: 'zap',     mode: 'api-scan' },
    active: ['semgrep', 'bandit', 'zap', 'trivy', 'nuclei'],
  },
  'python-django': {
    sast:   { tool: 'semgrep', rulesets: ['p/python', 'p/django', 'p/injection', 'p/xss'] },
    dast:   { tool: 'zap',     mode: 'full-scan' },
    active: ['semgrep', 'bandit', 'zap', 'trivy'],
  },
  'java-spring': {
    sast:   { tool: 'semgrep', rulesets: ['p/java', 'p/spring', 'p/injection'] },
    dast:   { tool: 'zap',     mode: 'api-scan' },
    active: ['semgrep', 'zap', 'trivy', 'nuclei'],
  },
  'php-laravel': {
    sast:   { tool: 'semgrep', rulesets: ['p/php', 'p/laravel', 'p/injection', 'p/xss'] },
    dast:   { tool: 'zap',     mode: 'full-scan' },
    active: ['semgrep', 'zap', 'trivy', 'nuclei', 'nikto'],
  },
  'php-generic': {
    sast:   { tool: 'semgrep', rulesets: ['p/php', 'p/injection', 'p/xss'] },
    dast:   { tool: 'zap',     mode: 'full-scan' },
    active: ['semgrep', 'zap', 'trivy', 'nikto'],
  },
  'golang-gin': {
    sast:   { tool: 'semgrep', rulesets: ['p/golang', 'p/injection'] },
    dast:   { tool: 'zap',     mode: 'api-scan' },
    active: ['semgrep', 'zap', 'trivy', 'nuclei'],
  },
  'ruby-rails': {
    sast:   { tool: 'semgrep', rulesets: ['p/ruby', 'p/rails', 'p/injection'] },
    dast:   { tool: 'zap',     mode: 'full-scan' },
    active: ['semgrep', 'zap', 'trivy'],
  },
  'unknown': {
    sast:   { tool: 'semgrep', rulesets: ['p/owasp-top-ten'] },
    dast:   { tool: 'zap',     mode: 'baseline' },
    active: ['semgrep', 'zap', 'trivy'],
  },
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function safeReadJson(filePath) {
  try {
    return JSON.parse(readFileSync(filePath, 'utf8'));
  } catch {
    return null;
  }
}

function safeReadText(filePath) {
  try {
    return readFileSync(filePath, 'utf8');
  } catch {
    return '';
  }
}

function safeReadYaml(filePath) {
  try {
    return yaml.load(readFileSync(filePath, 'utf8'));
  } catch {
    return null;
  }
}

// ── Candidate discovery for compose/monorepo projects ───────────────────────

const MANIFEST_FILES = [
  'package.json',
  'requirements.txt',
  'Pipfile',
  'pyproject.toml',
  'pom.xml',
  'build.gradle',
  'composer.json',
  'go.mod',
  'Gemfile',
];

const SKIP_DIRS = new Set([
  'node_modules', 'vendor', '.git', '__pycache__', 'dist',
  'build', '.venv', 'venv', 'target', '.next', 'out',
  'coverage', '.cache', 'tmp', 'temp',
]);


const COMPOSE_FILENAMES = ['docker-compose.yml', 'docker-compose.yaml', 'compose.yaml', 'compose.yml'];

const BACKEND_NAME_RE = /(^|[-_])(api|server|backend|gateway|service|app)([-_]|$)|^(api|server|backend|gateway|app|web)$/i;
const FRONTEND_NAME_RE = /(^|[-_])(client|frontend|front|ui|webapp)([-_]|$)|^(client|frontend|ui)$/i;

const BACKEND_FRAMEWORKS = new Set([
  'nodejs-rest-api', 'python-flask', 'python-fastapi', 'python-django',
  'java-spring', 'php-laravel', 'php-generic', 'golang-gin', 'ruby-rails',
]);

const BACKEND_DEPS = new Set([
  'express', 'fastify', 'koa', 'restify', '@nestjs/core', '@nestjs/common',
  'jsonwebtoken', 'passport-jwt', 'mongoose', 'sequelize', 'typeorm', 'prisma',
]);

const FRONTEND_DEPS = new Set([
  'react', 'react-dom', 'vue', '@vue/cli-service', '@angular/core',
  'vite', 'next', 'nuxt', 'svelte',
]);

function hasManifest(root) {
  return MANIFEST_FILES.some(fname => existsSync(join(root, fname)));
}

function hasBackendDeps(rawDeps = []) {
  const names = rawDeps.map(d => d.toLowerCase());
  return names.some(d => BACKEND_DEPS.has(d));
}

function hasFrontendOnlyDeps(rawDeps = []) {
  const names = rawDeps.map(d => d.toLowerCase());
  const hasFrontend = names.some(d => FRONTEND_DEPS.has(d));
  return hasFrontend && !hasBackendDeps(names);
}

function addCandidate(map, projectRoot, root, source, serviceName = null) {
  const absRoot = resolve(root);
  if (!existsSync(absRoot)) return;

  try {
    if (!statSync(absRoot).isDirectory()) return;
  } catch {
    return;
  }

  const key = absRoot.toLowerCase();
  const existing = map.get(key);
  if (existing) {
    if (!existing.serviceName && serviceName) existing.serviceName = serviceName;
    existing.sources.push(source);
    return;
  }

  map.set(key, {
    root: absRoot,
    relativeRoot: relative(projectRoot, absRoot).replace(/\\/g, '/') || '.',
    source,
    sources: [source],
    serviceName,
  });
}

function collectComposeCandidates(projectRoot, map) {
  for (const fname of COMPOSE_FILENAMES) {
    const composePath = join(projectRoot, fname);
    if (!existsSync(composePath)) continue;

    const parsed = safeReadYaml(composePath);
    for (const [serviceName, svc] of Object.entries(parsed?.services ?? {})) {
      const build = svc?.build;
      const context = typeof build === 'string'
        ? build
        : typeof build?.context === 'string' ? build.context : null;

      if (!context) continue;
      addCandidate(map, projectRoot, resolve(projectRoot, context), `compose:${fname}`, serviceName);
    }
  }
}

function collectSubdirCandidates(projectRoot, map) {
  let entries = [];
  try {
    entries = readdirSync(projectRoot, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    if (!entry.isDirectory() || SKIP_DIRS.has(entry.name)) continue;
    const childRoot = join(projectRoot, entry.name);
    if (hasManifest(childRoot)) {
      addCandidate(map, projectRoot, childRoot, 'subdir', entry.name);
    }
  }
}

function discoverProjectCandidates(projectRoot) {
  const map = new Map();
  addCandidate(map, projectRoot, projectRoot, 'root');
  collectComposeCandidates(projectRoot, map);
  collectSubdirCandidates(projectRoot, map);
  return [...map.values()];
}

function detectAtRoot(root) {
  return detectFromPackageJson(root)   ??
    detectFromRequirementsTxt(root)    ??
    detectFromPomXml(root)             ??
    detectFromComposerJson(root)       ??
    detectFromGoMod(root)              ??
    detectFromGemfile(root)            ??
    { language: 'unknown', framework: 'unknown', features: {}, depFile: null };
}

function scoreCandidate(detected, candidate) {
  let score = 0;
  const rel = candidate.relativeRoot.toLowerCase();
  const service = (candidate.serviceName ?? '').toLowerCase();

  if (detected.language !== 'unknown') score += 20;
  else score -= 10;

  if (detected.framework !== 'unknown' && detected.framework in PROFILE_TOOL_MAP) score += 35;
  if (BACKEND_FRAMEWORKS.has(detected.framework)) score += 25;
  if (detected.framework?.endsWith?.('-generic')) score -= 5;

  if (detected.features?.jwt) score += 8;
  if (detected.features?.orm) score += 6;
  if (detected.features?.fileUpload) score += 4;
  if (hasBackendDeps(detected.rawDeps)) score += 12;
  if (hasFrontendOnlyDeps(detected.rawDeps)) score -= 25;

  if (BACKEND_NAME_RE.test(service)) score += 25;
  if (FRONTEND_NAME_RE.test(service)) score -= 30;
  if (BACKEND_NAME_RE.test(rel)) score += 15;
  if (FRONTEND_NAME_RE.test(rel)) score -= 20;

  if (candidate.source === 'root' && detected.language !== 'unknown') score += 5;
  return score;
}

function buildDetectedStack(projectRoot, candidate, detected, score, allCandidates) {
  const profileKey = detected.framework in PROFILE_TOOL_MAP
    ? detected.framework
    : 'unknown';

  const profile = PROFILE_TOOL_MAP[profileKey];
  const isContainerized = existsSync(join(projectRoot, 'Dockerfile'))
                        || COMPOSE_FILENAMES.some(fname => existsSync(join(projectRoot, fname)))
                        || existsSync(join(candidate.root, 'Dockerfile'));

  const depFilePath = detected.depFile
    ? join(candidate.relativeRoot, detected.depFile).replace(/\\/g, '/').replace(/^\.\//, '')
    : null;

  return {
    ...detected,
    profileKey,
    toolProfile: profile,
    isContainerized,
    detectedRoot: candidate.root,
    relativeRoot: candidate.relativeRoot,
    serviceName: candidate.serviceName,
    depFilePath,
    candidateScore: score,
    isMonorepo: allCandidates.length > 1 || candidate.relativeRoot !== '.',
    collectedAt: new Date().toISOString(),
  };
}

// ── Language detectors — một hàm per file ────────────────────────────────────

function detectFromPackageJson(root) {
  const pkgPath = join(root, 'package.json');
  if (!existsSync(pkgPath)) return null;

  const pkg = safeReadJson(pkgPath);
  if (!pkg) return null;

  const deps = {
    ...pkg.dependencies ?? {},
    ...pkg.devDependencies ?? {},
  };
  const names = Object.keys(deps).map(d => d.toLowerCase());

  const hasAny = (...list) => list.some(k => names.includes(k));

  let framework = 'nodejs-generic';
  if (hasAny('express', '@hapi/hapi', 'fastify', 'koa', 'restify')) {
    // Distinguish REST-only vs fullstack
    framework = hasAny('ejs', 'pug', 'handlebars', 'nunjucks', 'next', 'nuxt')
      ? 'nodejs-fullstack'
      : 'nodejs-rest-api';
  } else if (hasAny('@nestjs/core', '@nestjs/common')) {
    framework = 'nodejs-rest-api';  // NestJS → REST API profile
  }

  const hasJwt      = hasAny('jsonwebtoken', '@nestjs/jwt', 'passport-jwt');
  const hasTypeorm  = hasAny('typeorm', 'sequelize', 'mongoose', 'prisma');
  const hasMulter   = hasAny('multer', 'formidable', 'busboy');

  return {
    language:    'nodejs',
    runtime:     `node ${process.version}`,
    framework,
    packageManager: existsSync(join(root, 'yarn.lock')) ? 'yarn'
                  : existsSync(join(root, 'pnpm-lock.yaml')) ? 'pnpm' : 'npm',
    features: {
      jwt:        hasJwt,
      orm:        hasTypeorm,
      fileUpload: hasMulter,
    },
    depFile: 'package.json',
    rawDeps: names.slice(0, 60),   // giới hạn để AI không bị quá dài
  };
}

function detectFromRequirementsTxt(root) {
  // Kiểm tra requirements.txt và pyproject.toml
  let content = '';
  let depFile = '';

  for (const fname of ['requirements.txt', 'Pipfile', 'pyproject.toml']) {
    const p = join(root, fname);
    if (existsSync(p)) {
      content += safeReadText(p).toLowerCase();
      depFile = fname;
      break;
    }
  }
  if (!content) return null;

  const has = (...list) => list.some(k => content.includes(k));

  let framework;
  if (has('fastapi'))                 framework = 'python-fastapi';
  else if (has('flask'))              framework = 'python-flask';
  else if (has('django'))             framework = 'python-django';
  else                                framework = 'python-generic';

  return {
    language:  'python',
    framework,
    features: {
      jwt:        has('pyjwt', 'python-jose', 'authlib'),
      orm:        has('sqlalchemy', 'django.db', 'tortoise', 'peewee'),
      fileUpload: has('python-multipart', 'werkzeug'),
    },
    depFile,
  };
}

function detectFromPomXml(root) {
  const pomPath = join(root, 'pom.xml');
  const gradlePath = join(root, 'build.gradle');

  let content = '';
  let depFile = '';

  if (existsSync(pomPath)) {
    content = safeReadText(pomPath).toLowerCase();
    depFile = 'pom.xml';
  } else if (existsSync(gradlePath)) {
    content = safeReadText(gradlePath).toLowerCase();
    depFile = 'build.gradle';
  }
  if (!content) return null;

  const has = (...list) => list.some(k => content.includes(k));

  return {
    language:  'java',
    framework: has('spring-boot', 'spring-webmvc', 'spring-webflux')
               ? 'java-spring' : 'java-generic',
    features: {
      jwt:        has('jjwt', 'java-jwt', 'nimbus-jose'),
      orm:        has('hibernate', 'jpa', 'mybatis'),
      fileUpload: has('multipartfile', 'commons-fileupload'),
    },
    depFile,
  };
}

function detectFromComposerJson(root) {
  const composerPath = join(root, 'composer.json');
  if (!existsSync(composerPath)) return null;

  const composer = safeReadJson(composerPath);
  if (!composer) return null;

  const requires = Object.keys({
    ...composer.require ?? {},
    ...(composer['require-dev'] ?? {}),
  }).map(k => k.toLowerCase());

  const has = (...list) => list.some(k => requires.some(r => r.includes(k)));

  return {
    language:  'php',
    framework: has('laravel/framework')    ? 'php-laravel'
             : has('symfony/framework')    ? 'php-symfony'
             : has('slim/slim')            ? 'php-slim'
             : 'php-generic',
    features: {
      jwt:        has('firebase/php-jwt', 'lcobusc/jwt'),
      orm:        has('eloquent', 'doctrine'),
      fileUpload: true,   // PHP $_FILES selalu ada
    },
    depFile: 'composer.json',
  };
}

function detectFromGoMod(root) {
  const goModPath = join(root, 'go.mod');
  if (!existsSync(goModPath)) return null;

  const content = safeReadText(goModPath).toLowerCase();
  const has = (...list) => list.some(k => content.includes(k));

  return {
    language:  'golang',
    framework: has('gin-gonic/gin')         ? 'golang-gin'
             : has('gofiber/fiber')          ? 'golang-fiber'
             : has('labstack/echo')          ? 'golang-echo'
             : 'golang-generic',
    features: {
      jwt:        has('golang-jwt', 'dgrijalva/jwt-go', 'lestrrat-go'),
      orm:        has('gorm', 'ent/ent', 'sqlx'),
      fileUpload: has('multipart'),
    },
    depFile: 'go.mod',
  };
}

function detectFromGemfile(root) {
  const gemfilePath = join(root, 'Gemfile');
  if (!existsSync(gemfilePath)) return null;

  const content = safeReadText(gemfilePath).toLowerCase();
  const has = (...list) => list.some(k => content.includes(k));

  return {
    language:  'ruby',
    framework: has("'rails'", '"rails"')    ? 'ruby-rails'
             : has("'sinatra'")             ? 'ruby-sinatra'
             : 'ruby-generic',
    features: {
      jwt:        has('jwt', 'knock', 'devise-jwt'),
      orm:        has('activerecord', 'sequel'),
      fileUpload: has('carrierwave', 'paperclip', 'shrine', 'active_storage'),
    },
    depFile: 'Gemfile',
  };
}

// ── Main export ───────────────────────────────────────────────────────────────

/**
 * Thu thập thông tin tech stack từ project root.
 * @param {string} projectRoot
 * @returns {Promise<object>} techStack context object
 */
export async function collectTechStack(projectRoot) {
  const absRoot = resolve(projectRoot);
  const candidates = discoverProjectCandidates(absRoot);

  const scored = candidates.map(candidate => {
    const detected = detectAtRoot(candidate.root);
    const score = scoreCandidate(detected, candidate);
    return {
      candidate,
      detected,
      score,
      stack: buildDetectedStack(absRoot, candidate, detected, score, candidates),
    };
  });

  scored.sort((a, b) => b.score - a.score);
  const selected = scored[0]?.stack ?? buildDetectedStack(
    absRoot,
    { root: absRoot, relativeRoot: '.', source: 'root', sources: ['root'], serviceName: null },
    { language: 'unknown', framework: 'unknown', features: {}, depFile: null },
    -10,
    []
  );

  return {
    ...selected,
    serviceCandidates: scored.map(({ stack, candidate, score }) => ({
      relativeRoot: stack.relativeRoot,
      serviceName: stack.serviceName,
      language: stack.language,
      framework: stack.framework,
      profileKey: stack.profileKey,
      depFilePath: stack.depFilePath,
      score,
      sources: candidate.sources,
    })),
  };
}
