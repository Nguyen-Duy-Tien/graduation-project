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
  const configFlags = rulesets.map(r => `--config=${shellQuote(r)}`).join(' ');

  // Mount the superproject for Git submodules so .git/modules remains resolvable in the container.
  const reportsMount = shellQuote(projectInfo.reportsDir);

  const script = `
echo "[SAST] Semgrep — rulesets: ${rulesets.join(' ')}"
SEMGREP_TARGET_DIR=${targetDir}
SEMGREP_MOUNT_SOURCE="$SEMGREP_TARGET_DIR"
SEMGREP_MOUNT_DEST="/src"
SEMGREP_SCAN_PATH="/src"

if command -v git >/dev/null 2>&1; then
  SEMGREP_SUPERPROJECT="$(git -C "$SEMGREP_TARGET_DIR" rev-parse --show-superproject-working-tree 2>/dev/null || true)"
  if [ -n "$SEMGREP_SUPERPROJECT" ] && [ -d "$SEMGREP_SUPERPROJECT" ]; then
    SEMGREP_SUPERPROJECT_REAL="$(cd "$SEMGREP_SUPERPROJECT" && pwd -P)"
    SEMGREP_TARGET_REAL="$(cd "$SEMGREP_TARGET_DIR" && pwd -P)"
    case "$SEMGREP_TARGET_REAL/" in
      "$SEMGREP_SUPERPROJECT_REAL"/*)
        SEMGREP_RELATIVE_TARGET="\${SEMGREP_TARGET_REAL#"$SEMGREP_SUPERPROJECT_REAL"/}"
        SEMGREP_MOUNT_SOURCE="$SEMGREP_SUPERPROJECT_REAL"
        SEMGREP_MOUNT_DEST="/workspace"
        SEMGREP_SCAN_PATH="/workspace/$SEMGREP_RELATIVE_TARGET"
        echo "[SAST] Semgrep detected Git submodule; mounting superproject: $SEMGREP_SUPERPROJECT_REAL"
        ;;
    esac
  fi
fi

docker run --rm \\
  -v "$SEMGREP_MOUNT_SOURCE:$SEMGREP_MOUNT_DEST:ro" \\
  -v ${reportsMount}:/out \\
  returntocorp/semgrep \\
  semgrep scan ${configFlags} --json --output=/out/semgrep-report.json "$SEMGREP_SCAN_PATH" || true
`.trim();

  return { skipped: false, script };
}
