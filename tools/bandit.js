// tools/bandit.js
// Python SAST. Chỉ enable khi techStack.language === 'python' và cfg.bandit.enabled.

import { shellQuote } from '../runtime/sanitize.js';

export const name = 'bandit';

export function enabled(cfg, projectInfo) {
  if (!cfg?.bandit?.enabled) return false;
  // Tiết kiệm: chỉ chạy bandit nếu thực sự là Python project
  return projectInfo?.language === 'python';
}

export function buildScript(cfg, projectInfo) {
  const targetDir  = shellQuote(projectInfo.targetDir);
  const reportsDir = shellQuote(projectInfo.reportsDir);

  const script = `
echo "[SAST] Bandit — Python static analysis"
docker run --rm \\
  -v ${targetDir}:/src:ro \\
  -v ${reportsDir}:/out \\
  ghcr.io/pycqa/bandit/bandit \\
  bandit -r /src -f json -o /out/bandit-report.json || true
`.trim();

  return { skipped: false, script };
}
