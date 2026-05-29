// tools/semgrep.js
// Adapter cho Semgrep SAST. Sinh đoạn shell cho run-sast.sh.
//
// Chấp nhận: cfg.semgrep = { enabled, rulesets[], extraFlags?, reason }
// Sanitize: rulesets qua sanitizeRulesets, drop entries xấu. Nếu rỗng → disable.

import { sanitizeRulesets, shellQuote } from '../runtime/sanitize.js';

export const name = 'semgrep';

export function enabled(cfg) {
  return Boolean(cfg?.semgrep?.enabled);
}

/**
 * @param {object} cfg          — tool_config.json
 * @param {object} projectInfo  — { targetDir, reportsDir }
 * @returns {{ script: string, skipped: boolean, reason?: string }}
 */
export function buildScript(cfg, projectInfo) {
  const sec = cfg.semgrep ?? {};
  const rulesets = sanitizeRulesets(sec.rulesets);
  if (rulesets.length === 0) {
    return { skipped: true, reason: 'no valid rulesets after sanitize', script: '' };
  }

  const targetDir = shellQuote(projectInfo.targetDir);
  const reportPath = shellQuote(`${projectInfo.reportsDir}/semgrep-report.json`);
  const configFlags = rulesets.map(r => `--config=${shellQuote(r)}`).join(' ');

  // Mount targetDir vào /src trong container, mount reportsDir vào /out
  const reportsMount = shellQuote(projectInfo.reportsDir);

  const script = `
echo "[SAST] Semgrep — rulesets: ${rulesets.join(' ')}"
docker run --rm \\
  -v ${targetDir}:/src:ro \\
  -v ${reportsMount}:/out \\
  returntocorp/semgrep \\
  semgrep scan ${configFlags} --json --output=/out/semgrep-report.json /src || true
`.trim();

  return { skipped: false, script };
}
