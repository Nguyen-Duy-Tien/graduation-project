// collectors/apiSurface.js
// 3 collector nhỏ trong một file:
//   1. collectApiSurface()     — đọc OpenAPI/Swagger nếu có (không bắt buộc)
//   2. collectGitDiff()        — git diff → file thay đổi → full|incremental
//   3. collectContainerInfo()  — Dockerfile + docker-compose → image, port, env keys

import { readFileSync, existsSync, readdirSync } from 'fs';
import { join, relative } from 'path';
import { execSync } from 'child_process';
import yaml from 'js-yaml';

// ── 1. collectApiSurface ──────────────────────────────────────────────────────
// Tìm và parse OpenAPI/Swagger file nếu có
// Không bắt buộc — nếu không có thì AI tự suy từ route scan

const SPEC_FILENAMES = [
  'openapi.yaml', 'openapi.yml', 'openapi.json',
  'swagger.yaml', 'swagger.yml', 'swagger.json',
  'api.yaml', 'api.yml', 'api.json',
  'docs/openapi.yaml', 'docs/swagger.yaml',
  'api-docs/openapi.yaml',
];

const COMPOSE_FILENAMES = ['docker-compose.yml', 'docker-compose.yaml', 'compose.yaml', 'compose.yml'];
const COMPOSE_SEARCH_MAX_DEPTH = 4;
const COMPOSE_SKIP_DIRS = new Set([
  'node_modules', 'vendor', '.git', '__pycache__', 'dist', 'build',
  '.venv', 'venv', 'target', '.next', 'out', 'coverage', '.cache',
  'tmp', 'temp',
]);

function toPosixPath(path) {
  return path.replace(/\\/g, '/');
}

function composePathScore(relPath) {
  const depth = relPath.split('/').length - 1;
  let score = depth * 10;

  if (/^deploy\/docker\//i.test(relPath)) score -= 5;
  if (/^docker\//i.test(relPath)) score -= 3;
  return score;
}

function findComposeFile(projectRoot) {
  const matches = [];

  function walk(absDir, relDir, depth) {
    let entries = [];
    try {
      entries = readdirSync(absDir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const relPath = relDir ? `${relDir}/${entry.name}` : entry.name;
      const absPath = join(projectRoot, ...relPath.split('/'));

      if (entry.isFile() && COMPOSE_FILENAMES.includes(entry.name)) {
        matches.push(relPath);
        continue;
      }

      if (
        entry.isDirectory()
        && depth < COMPOSE_SEARCH_MAX_DEPTH
        && !COMPOSE_SKIP_DIRS.has(entry.name)
        && !entry.isSymbolicLink()
      ) {
        walk(absPath, relPath, depth + 1);
      }
    }
  }

  walk(projectRoot, '', 0);
  matches.sort((a, b) => composePathScore(a) - composePathScore(b) || a.localeCompare(b));
  return matches[0] ?? null;
}

function parseOpenApiSpec(content, filename) {
  try {
    return filename.endsWith('.json')
      ? JSON.parse(content)
      : yaml.load(content);
  } catch {
    return null;
  }
}

function extractSpecSummary(spec) {
  if (!spec) return null;

  const endpoints = [];
  const paths = spec.paths ?? {};

  for (const [path, methods] of Object.entries(paths)) {
    for (const [method, op] of Object.entries(methods)) {
      if (!['get','post','put','patch','delete','head','options'].includes(method)) continue;
      endpoints.push({
        method:   method.toUpperCase(),
        path,
        summary:  op.summary ?? '',
        tags:     op.tags ?? [],
        security: op.security ? 'required' : 'none',
        params:   (op.parameters ?? []).map(p => ({
          name: p.name,
          in:   p.in,
          required: p.required ?? false,
          schema: p.schema?.type ?? 'any',
        })),
        requestBodySchema: op.requestBody
          ? extractSchemaKeys(op.requestBody)
          : null,
      });
    }
  }

  return {
    source:      'swagger/openapi',
    title:       spec.info?.title ?? 'Unknown',
    version:     spec.info?.version ?? '',
    totalPaths:  Object.keys(paths).length,
    endpoints,
    components:  Object.keys(spec.components?.schemas ?? {}),
    securitySchemes: Object.keys(spec.components?.securitySchemes ?? {}),
  };
}

function extractSchemaKeys(requestBody) {
  try {
    const content = requestBody.content ?? {};
    const firstMedia = Object.values(content)[0];
    const schema = firstMedia?.schema;
    if (!schema) return null;
    if (schema.properties) return Object.keys(schema.properties);
    if (schema.$ref) return [schema.$ref];
    return null;
  } catch {
    return null;
  }
}

export async function collectApiSurface(projectRoot) {
  for (const fname of SPEC_FILENAMES) {
    const specPath = join(projectRoot, fname);
    if (!existsSync(specPath)) continue;

    const content = readFileSync(specPath, 'utf8');
    const spec    = parseOpenApiSpec(content, fname);
    if (!spec) continue;

    const summary = extractSpecSummary(spec);
    if (!summary) continue;

    return {
      specFound:    true,
      specFile:     fname,
      specSummary:  summary,
    };
  }

  return {
    specFound:    false,
    specFile:     null,
    specSummary:  null,
    note:         'No OpenAPI/Swagger spec found — AI will infer attack surface from source code only',
  };
}

// ── 2. collectGitDiff ─────────────────────────────────────────────────────────
// Chạy git diff để biết file nào thay đổi
// → recommendation: "full" nếu file bảo mật thay đổi, "incremental" nếu không

const SECURITY_SENSITIVE_PATHS = [
  /auth|login|jwt|token|password|permission|role|access/i,
  /upload|file|media|attachment/i,
  /admin|internal|console/i,
  /middleware|guard|interceptor/i,
  /config|env|secret/i,
  /sql|query|orm|model|schema/i,
];

function isSensitiveFile(filePath) {
  return SECURITY_SENSITIVE_PATHS.some(re => re.test(filePath));
}

export async function collectGitDiff(projectRoot) {
  let changedFiles = [];
  let commitHash   = '';
  let gitAvailable = false;

  try {
    // Lấy hash của commit mới nhất
    commitHash = execSync('git rev-parse --short HEAD', {
      cwd:     projectRoot,
      stdio:   ['pipe', 'pipe', 'pipe'],
    }).toString().trim();

    // Diff so với commit trước đó
    const diffOutput = execSync('git diff --name-only HEAD~1 HEAD 2>/dev/null || git diff --name-only --cached', {
      cwd:     projectRoot,
      stdio:   ['pipe', 'pipe', 'pipe'],
    }).toString().trim();

    changedFiles = diffOutput
      ? diffOutput.split('\n').filter(Boolean).map(f => f.trim())
      : [];
    gitAvailable = true;
  } catch {
    // Không có git hoặc không có commit — scan toàn bộ
    gitAvailable = false;
  }

  const sensitiveChanged = changedFiles.filter(isSensitiveFile);
  const recommendation   = !gitAvailable || changedFiles.length === 0 || sensitiveChanged.length > 0
    ? 'full'
    : 'incremental';

  return {
    gitAvailable,
    commitHash,
    changedFiles,
    sensitiveChanged,
    changedFileCount:    changedFiles.length,
    sensitiveFileCount:  sensitiveChanged.length,
    recommendation,
    rationale: recommendation === 'full'
      ? 'Security-sensitive files modified or no git history — run full scan'
      : `Only ${changedFiles.length} non-sensitive files changed — incremental scan sufficient`,
  };
}

// ── 3. collectContainerInfo ───────────────────────────────────────────────────
// Đọc Dockerfile và docker-compose.yml → image list, exposed ports, env keys

function parseDockerfile(content) {
  const lines  = content.split('\n').map(l => l.trim()).filter(Boolean);
  const images = [];
  const ports  = [];
  const envKeys = [];

  for (const line of lines) {
    if (/^FROM\s+/i.test(line)) {
      const img = line.replace(/^FROM\s+/i, '').split(/\s+/)[0];
      images.push(img);
    }
    if (/^EXPOSE\s+/i.test(line)) {
      const p = line.replace(/^EXPOSE\s+/i, '').trim();
      ports.push(...p.split(/\s+/));
    }
    if (/^ENV\s+/i.test(line)) {
      // ENV KEY=value atau ENV KEY value
      const rest = line.replace(/^ENV\s+/i, '');
      const key  = rest.split(/[= ]/)[0];
      if (key) envKeys.push(key);
    }
  }
  return { images, ports, envKeys };
}

function parseDockerCompose(content) {
  let parsed;
  try {
    parsed = yaml.load(content);
  } catch {
    return { services: [], allImages: [], allPorts: [], allEnvKeys: [], networks: [], servicesDetail: [] };
  }

  const services  = Object.keys(parsed?.services ?? {});
  const networks  = Object.keys(parsed?.networks ?? {});
  const networksDetail = Object.entries(parsed?.networks ?? {}).map(([name, cfg]) => ({
    name,
    actualName: typeof cfg?.name === 'string' ? cfg.name : null,
    external: cfg?.external === true || cfg?.external?.external === true,
  }));
  const allImages  = [];
  const allPorts   = [];
  const allEnvKeys = [];
  const servicesDetail = [];

  for (const [name, svc] of Object.entries(parsed?.services ?? {})) {
    if (svc.image) allImages.push(svc.image);

    const ports = [];
    for (const p of svc.ports ?? []) {
      const portStr = typeof p === 'string' ? p : String(p);
      allPorts.push(portStr);
      ports.push(portStr);
    }

    // Environment keys (bỏ values để không lộ secret)
    const envs = svc.environment;
    if (envs) {
      if (Array.isArray(envs)) {
        for (const env of envs) {
          if (typeof env === 'string') {
            allEnvKeys.push(env.split('=')[0]);
          }
        }
      } else if (typeof envs === 'object' && envs !== null) {
        allEnvKeys.push(...Object.keys(envs));
      }
    }

    // Chi tiết service cho service picker (không chứa secret values)
    servicesDetail.push({
      name,
      image:      svc.image ?? null,
      build:      svc.build ?? null,
      ports,
      networks:   Array.isArray(svc.networks)
        ? svc.networks
        : svc.networks && typeof svc.networks === 'object' ? Object.keys(svc.networks) : [],
      depends_on: Array.isArray(svc.depends_on)
        ? svc.depends_on
        : svc.depends_on ? Object.keys(svc.depends_on) : [],
    });
  }

  return { services, allImages, allPorts, allEnvKeys, networks, networksDetail, servicesDetail };
}

export async function collectContainerInfo(projectRoot) {
  const result = {
    hasDockerfile:     false,
    hasDockerCompose:  false,
    dockerfile:        null,
    dockerCompose:     null,
  };

  // Dockerfile
  const dockerfilePath = join(projectRoot, 'Dockerfile');
  if (existsSync(dockerfilePath)) {
    const content = readFileSync(dockerfilePath, 'utf8');
    result.hasDockerfile = true;
    result.dockerfile    = parseDockerfile(content);
  }

  // Docker Compose, including common nested layouts such as deploy/docker/docker-compose.yml
  const composeFile = findComposeFile(projectRoot);
  if (composeFile) {
    const composePath = join(projectRoot, ...composeFile.split('/'));
    if (existsSync(composePath)) {
      const content = readFileSync(composePath, 'utf8');
      result.hasDockerCompose = true;
      result.dockerCompose    = parseDockerCompose(content);
      result.composeFile      = toPosixPath(composeFile);
      result.composeDir       = composeFile.includes('/')
        ? composeFile.split('/').slice(0, -1).join('/')
        : '.';
    }
  }

  return result;
}
