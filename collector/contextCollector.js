// collectors/contextCollector.js
// Entry point duy nhất của Tuần 7
// Gọi Promise.all() chạy 5 collector song song → merge → ghi context.json
//
// Sử dụng CLI:
//   node contextCollector.js /path/to/project
//   node contextCollector.js /path/to/project --output /custom/output/dir
//
// Hoặc import như module:
//   import { collectContext } from './collectors/contextCollector.js'
//   const ctx = await collectContext('/path/to/project')

import { writeFileSync, mkdirSync } from 'fs';
import { join, resolve } from 'path';

import { collectTechStack }     from './techStack.js';
import { collectRoutes }        from './routeScanner.js';
import { collectCodePatterns }  from './codePattern.js';
import { collectSchemas }       from './schemaScanner.js';
import { collectApiSurface, collectGitDiff, collectContainerInfo } from './apiSurface.js';

// ── Merge helper ──────────────────────────────────────────────────────────────

function buildContext(projectRoot, results) {
  const [techStack, routes, codePatterns, schemas, apiSurface, gitDiff, containerInfo] = results;

  // Unified attack surface summary (dùng bởi AI prompt)
  const attackSurfaceSummary = {
    totalEndpoints:      routes.totalEndpoints,
    highRiskEndpoints:   routes.highRiskCount,
    classificationStats: routes.classificationStats,
    dangerousPatterns:   {
      total:       codePatterns.totalFindings,
      bySeverity:  codePatterns.bySeverity,
      categories:  Object.keys(codePatterns.byCategory),
    },
    schemaSummary:       {
      totalModels:          schemas.totalModels,
      sensitiveFieldCount:  schemas.sensitiveFieldCount,
      modelsWithSensitiveFields: schemas.modelsWithSensitiveFields?.length ?? 0,
    },
    hasSwaggerSpec:      apiSurface.specFound,
    scanRecommendation:  gitDiff.recommendation,
    isContainerized:     containerInfo.hasDockerfile || containerInfo.hasDockerCompose,
  };

  return {
    _meta: {
      version:      '1.0.0',
      collectedAt:  new Date().toISOString(),
      projectRoot,
      module:       'context-collector-week7',
    },
    techStack,
    routes,
    codePatterns,
    schemas,
    apiSurface,
    gitDiff,
    containerInfo,
    attackSurfaceSummary,
  };
}

// ── Logger nhẹ (không dùng thư viện ngoài) ───────────────────────────────────

function log(stage, message) {
  const ts = new Date().toISOString().slice(11, 23);
  console.log(`[${ts}] [${stage.padEnd(14)}] ${message}`);
}

function logError(stage, err) {
  console.error(`[ERROR] [${stage}] ${err.message}`);
}

// ── Main collectContext ───────────────────────────────────────────────────────

/**
 * Chạy 5 collector song song và trả về context object hoàn chỉnh.
 * @param {string} projectRoot  — đường dẫn tuyệt đối hoặc tương đối tới project
 * @returns {Promise<object>}   — context object
 */
export async function collectContext(projectRoot) {
  const absRoot = resolve(projectRoot);
  log('INIT', `Project root: ${absRoot}`);

  // Bước 1: thu thập tech stack trước (các collector khác cần kết quả này)
  log('techStack', 'Detecting language and framework...');
  const techStack = await collectTechStack(absRoot).catch(err => {
    logError('techStack', err);
    return { language: 'unknown', framework: 'unknown', features: {}, depFile: null };
  });
  log('techStack', `Detected: ${techStack.language} / ${techStack.framework}`);

  // Bước 2: chạy 5 collector còn lại song song
  log('PARALLEL', 'Running collectors in parallel...');
  const startTime = Date.now();

  const [routes, codePatterns, schemas, apiSurface, gitDiff, containerInfo] = await Promise.all([
    collectRoutes(absRoot, techStack).then(r => {
      log('routeScanner', `Found ${r.totalEndpoints} endpoints (${r.highRiskCount} high-risk)`);
      return r;
    }).catch(err => {
      logError('routeScanner', err);
      return { totalEndpoints: 0, highRiskCount: 0, classificationStats: {}, routes: [], highRiskRoutes: [], filesScanned: 0 };
    }),

    collectCodePatterns(absRoot).then(r => {
      log('codePattern', `Found ${r.totalFindings} dangerous patterns (critical: ${r.bySeverity.critical})`);
      return r;
    }).catch(err => {
      logError('codePattern', err);
      return { totalFindings: 0, bySeverity: {}, byCategory: {}, topFindings: [], filesScanned: 0 };
    }),

    collectSchemas(absRoot).then(r => {
      log('schemaScanner', `Found ${r.totalModels} models (${r.sensitiveFieldCount} sensitive fields)`);
      return r;
    }).catch(err => {
      logError('schemaScanner', err);
      return { totalModels: 0, models: [], modelsWithSensitiveFields: [], sensitiveFieldCount: 0, fieldIndex: {}, filesScanned: 0 };
    }),

    collectApiSurface(absRoot).then(r => {
      log('apiSurface', r.specFound ? `Swagger spec found: ${r.specFile}` : 'No spec — AI will infer');
      return r;
    }).catch(err => {
      logError('apiSurface', err);
      return { specFound: false, specFile: null, specSummary: null };
    }),

    collectGitDiff(absRoot).then(r => {
      log('gitDiff', `${r.changedFileCount} changed files → recommendation: ${r.recommendation}`);
      return r;
    }).catch(err => {
      logError('gitDiff', err);
      return { gitAvailable: false, changedFiles: [], sensitiveChanged: [], recommendation: 'full' };
    }),

    collectContainerInfo(absRoot).then(r => {
      const summary = r.hasDockerCompose
        ? `docker-compose: ${r.dockerCompose?.services?.length ?? 0} services`
        : r.hasDockerfile ? 'Dockerfile found' : 'No container config';
      log('containerInfo', summary);
      return r;
    }).catch(err => {
      logError('containerInfo', err);
      return { hasDockerfile: false, hasDockerCompose: false };
    }),
  ]);

  const elapsed = Date.now() - startTime;
  log('PARALLEL', `All collectors done in ${elapsed}ms`);

  // Bước 3: merge thành context object
  const context = buildContext(absRoot, [techStack, routes, codePatterns, schemas, apiSurface, gitDiff, containerInfo]);

  // Print summary
  const s = context.attackSurfaceSummary;
  console.log('\n' + '═'.repeat(56));
  console.log('  CONTEXT COLLECTION COMPLETE');
  console.log('═'.repeat(56));
  console.log(`  Endpoints found   : ${s.totalEndpoints} (${s.highRiskEndpoints} high-risk)`);
  console.log(`  Dangerous patterns: ${s.dangerousPatterns.total} (critical: ${s.dangerousPatterns.bySeverity?.critical ?? 0})`);
  console.log(`  Sensitive fields  : ${s.schemaSummary.sensitiveFieldCount} in ${s.schemaSummary.modelsWithSensitiveFields} models`);
  console.log(`  Swagger spec      : ${s.hasSwaggerSpec ? 'yes' : 'no — AI will infer'}`);
  console.log(`  Scan strategy     : ${s.scanRecommendation}`);
  console.log(`  Containerized     : ${s.isContainerized}`);
  console.log('═'.repeat(56) + '\n');

  return context;
}

// ── CLI entry point ───────────────────────────────────────────────────────────

async function main() {
  const args        = process.argv.slice(2);
  const projectRoot = args[0] ?? '.';
  const outputIdx   = args.indexOf('--output');
  const outputDir   = outputIdx !== -1 ? args[outputIdx + 1] : join(projectRoot, 'security-context-output');

  if (!projectRoot || args.includes('--help') || args.includes('-h')) {
    console.log('Usage: node contextCollector.js <project-root> [--output <dir>]');
    process.exit(0);
  }

  try {
    const context = await collectContext(projectRoot);

    // Ghi context.json
    mkdirSync(resolve(outputDir), { recursive: true });
    const outPath = join(resolve(outputDir), 'context.json');
    writeFileSync(outPath, JSON.stringify(context, null, 2), 'utf8');
    console.log(`[OUTPUT] context.json written → ${outPath}`);

    // Exit code 0 = thành công
    process.exit(0);
  } catch (err) {
    console.error('[FATAL]', err.message);
    process.exit(1);
  }
}

// Chạy nếu là entry point (ESM equivalent của require.main === module)
import { fileURLToPath } from 'url';

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main();
}
