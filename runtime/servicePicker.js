// runtime/servicePicker.js
// Heuristic chọn target service từ docker-compose để DAST attack vào.
//
// Quy tắc:
//   1. Loại trừ image database/cache/queue (mongo, postgres, mysql, redis, elastic...)
//   2. Loại trừ service không có port mapping (không thể attack từ ngoài)
//   3. Pick service đầu tiên còn lại theo thứ tự khai báo trong YAML
//   4. Nếu không pick được hoặc không có compose → return null → DAST skip
//
// Output:
//   { serviceName, port, networkName, composeFile } | null

import { existsSync, readFileSync } from 'fs';
import { basename, join, resolve } from 'path';
import {
  assertServiceName, assertNetworkName, assertPort,
} from './sanitize.js';

// Image database/cache/queue cần loại trừ — match theo prefix trước dấu ":" hoặc "/"
const DB_IMAGE_PATTERNS = [
  /^mongo(:|$|\/)/i,
  /^postgres(:|$|\/)/i,
  /^mysql(:|$|\/)/i,
  /^mariadb(:|$|\/)/i,
  /^redis(:|$|\/)/i,
  /^valkey(:|$|\/)/i,
  /^elastic(search)?(:|$|\/)/i,
  /^opensearch(:|$|\/)/i,
  /^rabbitmq(:|$|\/)/i,
  /^kafka(:|$|\/)/i,
  /^nats(:|$|\/)/i,
  /^minio(:|$|\/)/i,
  /^memcached(:|$|\/)/i,
  /^cassandra(:|$|\/)/i,
  /^clickhouse(:|$|\/)/i,
  /^influxdb(:|$|\/)/i,
  /^neo4j(:|$|\/)/i,
];

const DB_SERVICE_RE = /(^|[-_])(db|database|mongo|postgres|mysql|mariadb|redis|cache)([-_]|$)|^(db|mongo|postgres|mysql|redis)$/i;
const BACKEND_NAME_RE = /(^|[-_])(api|server|backend|gateway|service|app)([-_]|$)|^(api|server|backend|gateway|app|web)$/i;
const FRONTEND_NAME_RE = /(^|[-_])(client|frontend|front|ui|webapp)([-_]|$)|^(client|frontend|ui)$/i;

const BACKEND_DEPS = new Set([
  'express', 'fastify', 'koa', 'restify', '@nestjs/core', '@nestjs/common',
  'jsonwebtoken', 'passport-jwt', 'mongoose', 'sequelize', 'typeorm', 'prisma',
]);

const FRONTEND_DEPS = new Set([
  'react', 'react-dom', 'vue', '@vue/cli-service', '@angular/core',
  'vite', 'next', 'nuxt', 'svelte',
]);

function isDbImage(image) {
  if (!image || typeof image !== 'string') return false;
  // Strip registry prefix nếu có (vd. "docker.io/library/mongo:5" → "mongo:5")
  const stripped = image.replace(/^.+\//, '');
  return DB_IMAGE_PATTERNS.some(re => re.test(stripped));
}

// Parse 1 entry trong ports[] của compose → container port (string)
//   "3001"               → "3001"
//   "8080:80"            → "80"
//   "127.0.0.1:5000:5000" → "5000"
//   "3001-3010:3001-3010" → null (range, bỏ)
function parseTargetPort(portEntry) {
  if (typeof portEntry !== 'string' && typeof portEntry !== 'number') return null;
  const parts = String(portEntry).split(':');
  if (parts.length > 3) return null;

  let candidate = parts[parts.length - 1];

  // Loại bỏ range "3001-3010"
  if (candidate.includes('-')) return null;
  // Loại bỏ "3001/tcp" suffix
  candidate = candidate.split('/')[0];

  if (!/^\d+$/.test(candidate)) return null;
  return candidate;
}

function safeReadJson(filePath) {
  try {
    return JSON.parse(readFileSync(filePath, 'utf8'));
  } catch {
    return null;
  }
}

function resolveBuildContext(projectRoot, build) {
  const context = typeof build === 'string'
    ? build
    : typeof build?.context === 'string' ? build.context : null;
  return context ? resolve(projectRoot, context) : null;
}

function scoreNodeManifest(root) {
  const pkg = safeReadJson(join(root, 'package.json'));
  if (!pkg) return 0;

  const deps = Object.keys({
    ...(pkg.dependencies ?? {}),
    ...(pkg.devDependencies ?? {}),
  }).map(d => d.toLowerCase());

  const hasBackend = deps.some(d => BACKEND_DEPS.has(d));
  const hasFrontend = deps.some(d => FRONTEND_DEPS.has(d));

  let score = 0;
  if (hasBackend) score += 35;
  if (hasFrontend && !hasBackend) score -= 30;
  return score;
}

function scoreNonNodeManifest(root) {
  let score = 0;
  const hasPython = existsSync(join(root, 'requirements.txt')) || existsSync(join(root, 'pyproject.toml'));
  const hasJava = existsSync(join(root, 'pom.xml')) || existsSync(join(root, 'build.gradle'));
  const hasPhp = existsSync(join(root, 'composer.json'));
  const hasGo = existsSync(join(root, 'go.mod'));
  const hasRuby = existsSync(join(root, 'Gemfile'));

  if (hasPython || hasJava || hasPhp || hasGo || hasRuby) score += 20;
  for (const marker of ['routes', 'controllers', 'app.py', 'main.py', 'manage.py', 'src']) {
    if (existsSync(join(root, marker))) score += 5;
  }
  return score;
}

function scoreService(svc, projectRoot) {
  let score = 0;
  const name = svc.name ?? '';
  const buildContext = resolveBuildContext(projectRoot, svc.build);
  const buildText = typeof svc.build === 'string'
    ? svc.build
    : typeof svc.build?.context === 'string' ? svc.build.context : '';
  const text = `${name} ${buildText} ${svc.image ?? ''}`.toLowerCase();

  if (BACKEND_NAME_RE.test(name)) score += 40;
  if (FRONTEND_NAME_RE.test(name)) score -= 45;
  if (BACKEND_NAME_RE.test(buildText)) score += 20;
  if (FRONTEND_NAME_RE.test(buildText)) score -= 25;
  if (/\b(api|server|backend)\b/.test(text)) score += 10;
  if ((svc.depends_on ?? []).some(dep => DB_SERVICE_RE.test(dep))) score += 10;

  for (const p of svc.ports ?? []) {
    const targetPort = parseTargetPort(p);
    if (['3001', '4000', '5000', '8000', '8080'].includes(targetPort)) score += 5;
  }

  if (buildContext && existsSync(buildContext)) {
    score += scoreNodeManifest(buildContext);
    score += scoreNonNodeManifest(buildContext);
  }

  return score;
}

// Convention docker-compose: network mặc định = <basename>_default
// basename được lowercase và lọc ký tự không hợp lệ
function deriveComposeProjectName(projectRoot) {
  const base = basename(projectRoot)
    .toLowerCase()
    .replace(/[^a-z0-9_-]/g, '');
  return base || 'default';
}

function deriveNetworkName(projectRoot, networkKey = 'default') {
  return `${deriveComposeProjectName(projectRoot)}_${networkKey}`;
}

function resolveServiceNetworkName(containerInfo, svc, projectRoot) {
  const networkKeys = svc.networks?.length ? svc.networks : ['default'];
  const selectedKey = networkKeys[0];
  const detail = (containerInfo.dockerCompose?.networksDetail ?? [])
    .find(network => network.name === selectedKey);

  if (detail?.actualName) return detail.actualName;
  if (detail?.external) return selectedKey;
  return deriveNetworkName(projectRoot, selectedKey);
}

/**
 * @param {object} containerInfo  — kết quả từ collectContainerInfo()
 * @param {string} projectRoot    — đường dẫn target project (để derive network)
 * @returns {object|null}
 */
export function pickTargetService(containerInfo, projectRoot) {
  if (!containerInfo?.hasDockerCompose) {
    return null;
  }

  const detail = containerInfo.dockerCompose?.servicesDetail ?? [];
  if (detail.length === 0) return null;

  // Lọc ứng viên: không phải DB và có port mapping
  const candidates = detail.filter(svc => !isDbImage(svc.image) && svc.ports.length > 0);
  if (candidates.length === 0) return null;

  const scoredCandidates = candidates
    .map((svc, index) => ({ svc, index, score: scoreService(svc, projectRoot) }))
    .sort((a, b) => b.score - a.score || a.index - b.index);

  // Pick service backend/API có điểm cao nhất hợp lệ sau sanitize
  for (const { svc, score } of scoredCandidates) {
    try {
      const serviceName = assertServiceName(svc.name);

      // Tìm container port hợp lệ đầu tiên vì scanner chạy trong compose network
      let port = null;
      for (const p of svc.ports) {
        const targetPort = parseTargetPort(p);
        if (targetPort) { port = targetPort; break; }
      }
      if (!port) continue;
      port = assertPort(port);

      const networkName = assertNetworkName(resolveServiceNetworkName(containerInfo, svc, projectRoot));
      const composeFile = containerInfo.composeFile ?? 'docker-compose.yml';

      return { serviceName, port, networkName, composeFile, serviceScore: score };
    } catch (err) {
      console.warn(`[servicePicker] skip ${svc.name}: ${err.message}`);
    }
  }

  return null;
}
