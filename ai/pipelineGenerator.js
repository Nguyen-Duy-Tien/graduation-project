// ai/pipelineGenerator.js
// Đọc context.json + tool_config.json → sinh:
//   - runtime/runtime-info.json        (service info + flags + dirs)
//   - runtime/run-sast.sh              (SAST + SCA tools)
//   - runtime/deploy-target.sh         (docker-compose up hoặc no-op)
//   - runtime/run-dast.sh              (DAST tools, đọc dastSkipped flag)
//   - runtime/teardown.sh              (docker-compose down)
//
// Fallback: nếu tool_config.json missing/xấu → dùng PROFILE_TOOL_MAP[profileKey].
//
// CLI:
//   node ai/pipelineGenerator.js <contextDir> <runtimeDir> [<targetDir>]

import {
  readFileSync, writeFileSync, mkdirSync, existsSync, chmodSync,
} from 'fs';
import { join, resolve, isAbsolute } from 'path';

import { SAST_TOOLS, DAST_TOOLS } from '../tools/index.js';
import { pickTargetService }      from '../runtime/servicePicker.js';
import { shellQuote }             from '../runtime/sanitize.js';
import { PROFILE_TOOL_MAP }       from '../collector/techStack.js';

// ── Helpers ───────────────────────────────────────────────────────────────────

function safeReadJson(path) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    return null;
  }
}

// Convert PROFILE_TOOL_MAP entry → tool_config shape (như buildToolConfig output)
function configFromProfile(profileKey) {
  const profile = PROFILE_TOOL_MAP[profileKey] ?? PROFILE_TOOL_MAP.unknown;
  const active  = new Set(profile.active);
  return {
    _meta:        { generatedBy: 'fallback/PROFILE_TOOL_MAP', profileKey },
    scanStrategy: 'full',
    semgrep: {
      enabled:  active.has('semgrep'),
      rulesets: profile.sast?.rulesets ?? ['p/owasp-top-ten'],
    },
    bandit:  { enabled: active.has('bandit') },
    trivy:   { enabled: active.has('trivy'), targets: ['fs'] },
    zap:     {
      enabled:    active.has('zap'),
      mode:       profile.dast?.mode ?? 'baseline',
      focusPaths: [],
    },
    nuclei:  {
      enabled:      active.has('nuclei'),
      templateTags: [],
      severity:     'medium,high,critical',
    },
    nikto:   { enabled: active.has('nikto') },
  };
}

// Check tool_config.json có hợp lệ tối thiểu không
function isToolConfigValid(cfg) {
  if (!cfg || typeof cfg !== 'object') return false;
  // Phải có ít nhất 1 tool enabled
  return ['semgrep', 'bandit', 'trivy', 'zap', 'nuclei', 'nikto']
    .some(k => cfg[k]?.enabled === true);
}

// ── Script renderers ──────────────────────────────────────────────────────────

const SHEBANG = '#!/usr/bin/env bash\nset -u\n';

function renderSastScript(cfg, projectInfo) {
  const sections = [SHEBANG, 'echo "═══ SAST + SCA ═══"'];
  for (const adapter of SAST_TOOLS) {
    if (!adapter.enabled(cfg, projectInfo)) {
      sections.push(`echo "[SKIP] ${adapter.name} — not enabled"`);
      continue;
    }
    const result = adapter.buildScript(cfg, projectInfo);
    if (result.skipped) {
      sections.push(`echo "[SKIP] ${adapter.name} — ${result.reason}"`);
    } else {
      sections.push(result.script);
    }
  }
  sections.push('echo "═══ SAST done ═══"');
  return sections.join('\n\n') + '\n';
}

function renderDeployScript(runtimeInfo, projectInfo) {
  if (runtimeInfo.dastSkipped) {
    return `${SHEBANG}
echo "[DEPLOY] DAST skipped (${runtimeInfo.skipReason ?? 'no deployable target'}) — nothing to deploy"
exit 0
`;
  }

  const targetDir   = shellQuote(projectInfo.targetDir);
  const composeFile = shellQuote(runtimeInfo.composeFile);
  const service     = shellQuote(runtimeInfo.serviceName);

  return `${SHEBANG}
echo "[DEPLOY] docker-compose up -d (target: ${runtimeInfo.serviceName}:${runtimeInfo.port})"
cd ${targetDir}
docker-compose -f ${composeFile} up -d --build
echo "[DEPLOY] Waiting 15s for services to be ready..."
sleep 15
docker-compose -f ${composeFile} ps ${service} || true
`;
}

function renderDastScript(cfg, projectInfo, runtimeInfo) {
  if (runtimeInfo.dastSkipped) {
    return `${SHEBANG}
echo "[DAST] Skipped — ${runtimeInfo.skipReason ?? 'no deployable target'}"
exit 0
`;
  }

  const sections = [SHEBANG, `echo "═══ DAST — target: ${runtimeInfo.serviceName}:${runtimeInfo.port} ═══"`];
  for (const adapter of DAST_TOOLS) {
    if (!adapter.enabled(cfg, projectInfo)) {
      sections.push(`echo "[SKIP] ${adapter.name} — not enabled"`);
      continue;
    }
    const result = adapter.buildScript(cfg, projectInfo, runtimeInfo);
    if (result.skipped) {
      sections.push(`echo "[SKIP] ${adapter.name} — ${result.reason}"`);
    } else {
      sections.push(result.script);
    }
  }
  sections.push('echo "═══ DAST done ═══"');
  return sections.join('\n\n') + '\n';
}

function renderTeardownScript(runtimeInfo, projectInfo) {
  if (runtimeInfo.dastSkipped) {
    return `${SHEBANG}\necho "[TEARDOWN] Nothing to tear down (DAST was skipped)"\nexit 0\n`;
  }
  const targetDir   = shellQuote(projectInfo.targetDir);
  const composeFile = shellQuote(runtimeInfo.composeFile);
  return `${SHEBANG}
echo "[TEARDOWN] docker-compose down -v"
cd ${targetDir}
docker-compose -f ${composeFile} down -v || true
`;
}

// ── Main ──────────────────────────────────────────────────────────────────────

export function generatePipeline({ contextDir, runtimeDir, targetDir }) {
  const ctxPath = join(contextDir, 'context.json');
  const cfgPath = join(contextDir, 'tool_config.json');

  const context = safeReadJson(ctxPath);
  if (!context) throw new Error(`context.json not found or invalid: ${ctxPath}`);

  let cfg = safeReadJson(cfgPath);
  if (!isToolConfigValid(cfg)) {
    const profileKey = context.techStack?.profileKey ?? 'unknown';
    console.warn(`[pipelineGenerator] tool_config.json missing/invalid — falling back to PROFILE_TOOL_MAP[${profileKey}]`);
    cfg = configFromProfile(profileKey);
  }

  // projectInfo: thông tin về target dùng cho tools
  const resolvedTargetDir = isAbsolute(targetDir) ? targetDir : resolve(targetDir);
  const projectInfo = {
    targetDir:  resolvedTargetDir,
    reportsDir: resolve(contextDir, 'scan-reports'),
    language:   context.techStack?.language ?? 'unknown',
    framework:  context.techStack?.framework ?? 'unknown',
    profileKey: context.techStack?.profileKey ?? 'unknown',
  };

  // runtimeInfo: chọn service từ container info
  const containerInfo = context.containerInfo ?? {};
  const picked = pickTargetService(containerInfo, resolvedTargetDir);
  const runtimeInfo = picked
    ? { ...picked, dastSkipped: false }
    : { dastSkipped: true, skipReason: containerInfo.hasDockerCompose
        ? 'no app service with port mapping (only DB images?)'
        : 'no docker-compose.yml in target' };

  // Đảm bảo runtimeDir và reportsDir tồn tại
  mkdirSync(resolve(runtimeDir), { recursive: true });
  mkdirSync(projectInfo.reportsDir, { recursive: true });

  // Ghi runtime-info.json
  const fullRuntimeInfo = {
    ...runtimeInfo,
    targetDir:    projectInfo.targetDir,
    reportsDir:   projectInfo.reportsDir,
    contextDir:   resolve(contextDir),
    generatedAt:  new Date().toISOString(),
    toolConfigSource: cfg._meta?.generatedBy ?? 'unknown',
    project:      { language: projectInfo.language, framework: projectInfo.framework },
  };
  writeFileSync(join(runtimeDir, 'runtime-info.json'), JSON.stringify(fullRuntimeInfo, null, 2));

  // Render và ghi 4 script
  const files = [
    { name: 'run-sast.sh',     content: renderSastScript(cfg, projectInfo) },
    { name: 'deploy-target.sh', content: renderDeployScript(runtimeInfo, projectInfo) },
    { name: 'run-dast.sh',     content: renderDastScript(cfg, projectInfo, runtimeInfo) },
    { name: 'teardown.sh',     content: renderTeardownScript(runtimeInfo, projectInfo) },
  ];

  for (const f of files) {
    const outPath = join(runtimeDir, f.name);
    writeFileSync(outPath, f.content, 'utf8');
    try { chmodSync(outPath, 0o755); } catch { /* Windows ignore */ }
    console.log(`[OUTPUT] ${f.name} → ${outPath}`);
  }

  console.log(`\n[DONE] DAST: ${runtimeInfo.dastSkipped ? 'SKIPPED — ' + runtimeInfo.skipReason : `${runtimeInfo.serviceName}:${runtimeInfo.port}`}`);
  return fullRuntimeInfo;
}

// ── CLI ───────────────────────────────────────────────────────────────────────

async function main() {
  const args = process.argv.slice(2);
  const contextDir = args[0] ?? './security-context-output';
  const runtimeDir = args[1] ?? './runtime';
  const targetDir  = args[2] ?? process.env.TARGET_PROJECT_DIR ?? process.cwd();

  if (args.includes('--help') || args.includes('-h')) {
    console.log('Usage: node ai/pipelineGenerator.js <contextDir> <runtimeDir> [<targetDir>]');
    console.log('Default contextDir: ./security-context-output');
    console.log('Default runtimeDir: ./runtime');
    console.log('Default targetDir:  $TARGET_PROJECT_DIR or cwd');
    process.exit(0);
  }

  if (!existsSync(contextDir)) {
    console.error(`[FATAL] contextDir not found: ${contextDir}`);
    process.exit(1);
  }

  generatePipeline({ contextDir, runtimeDir, targetDir });
}

import { fileURLToPath } from 'url';

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main().catch(err => { console.error('[FATAL]', err.message); process.exit(1); });
}
