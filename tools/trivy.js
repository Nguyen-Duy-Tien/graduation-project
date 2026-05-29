// tools/trivy.js
// SCA: quét dependency + container image vulnerabilities.
//
// targets có thể là ['fs'], ['image'], ['config'] hoặc kết hợp.
// Phase 1 chỉ implement 'fs' (quét manifest dependency); 'image'/'config' future.

import { sanitizeTrivyTargets, shellQuote } from '../runtime/sanitize.js';

export const name = 'trivy';

export function enabled(cfg) {
  return Boolean(cfg?.trivy?.enabled);
}

export function buildScript(cfg, projectInfo) {
  const targets = sanitizeTrivyTargets(cfg.trivy?.targets ?? ['fs']);
  if (targets.length === 0) {
    return { skipped: true, reason: 'no valid targets', script: '' };
  }

  const targetDir  = shellQuote(projectInfo.targetDir);
  const reportsDir = shellQuote(projectInfo.reportsDir);

  // Phase 1: chỉ chạy 'fs'. Cảnh báo nếu target khác có trong list.
  const lines = [`echo "[SCA] Trivy — targets: ${targets.join(',')}"`];
  if (targets.includes('fs')) {
    lines.push(`docker run --rm \\
  -v ${targetDir}:/src:ro \\
  -v ${reportsDir}:/out \\
  aquasec/trivy \\
  fs --format json --output /out/trivy-report.json /src || true`);
  }
  // 'image' và 'config' chưa support — log và skip
  for (const t of targets.filter(x => x !== 'fs')) {
    lines.push(`echo "[SCA] Trivy target '${t}' not implemented in Phase 1 — skipped"`);
  }

  return { skipped: false, script: lines.join('\n') };
}
