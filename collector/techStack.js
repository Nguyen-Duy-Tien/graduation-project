// collectors/techStack.js
// Nhận diện ngôn ngữ, framework và ánh xạ sang tool profile
// Đọc: package.json, requirements.txt, pom.xml, composer.json, go.mod, Gemfile

import { readFileSync, existsSync } from 'fs';
import { join } from 'path';

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
  // Thử từng detector — trả về kết quả đầu tiên tìm được
  const detected =
    detectFromPackageJson(projectRoot)   ??
    detectFromRequirementsTxt(projectRoot) ??
    detectFromPomXml(projectRoot)        ??
    detectFromComposerJson(projectRoot)  ??
    detectFromGoMod(projectRoot)         ??
    detectFromGemfile(projectRoot)       ??
    { language: 'unknown', framework: 'unknown', features: {}, depFile: null };

  // Resolve tool profile
  const profileKey = detected.framework in PROFILE_TOOL_MAP
    ? detected.framework
    : 'unknown';

  const profile = PROFILE_TOOL_MAP[profileKey];

  // Kiểm tra containerization (dùng kết quả từ apiSurface.js nếu có, ở đây chỉ flag)
  const isContainerized = existsSync(join(projectRoot, 'Dockerfile'))
                        || existsSync(join(projectRoot, 'docker-compose.yml'))
                        || existsSync(join(projectRoot, 'docker-compose.yaml'));

  return {
    ...detected,
    profileKey,
    toolProfile:     profile,
    isContainerized,
    collectedAt:     new Date().toISOString(),
  };
}
