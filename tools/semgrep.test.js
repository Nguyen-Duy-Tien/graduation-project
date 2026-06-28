import test from 'node:test';
import assert from 'node:assert/strict';

import { buildScript } from './semgrep.js';

test('semgrep buildScript mounts Git superproject when target is a submodule', () => {
  const result = buildScript(
    { semgrep: { rulesets: ['p/javascript', 'p/security-audit'] } },
    {
      targetDir: '/var/lib/jenkins/workspace/DevSecOps-AI-Pentest/benchmarks/juice-shop',
      reportsDir: '/var/lib/jenkins/workspace/DevSecOps-AI-Pentest/security-context-output/scan-reports',
    },
  );

  assert.equal(result.skipped, false);
  assert.match(result.script, /git -C "\$SEMGREP_TARGET_DIR" rev-parse --show-superproject-working-tree/);
  assert.match(result.script, /SEMGREP_MOUNT_DEST="\/workspace"/);
  assert.match(result.script, /SEMGREP_SCAN_PATH="\/workspace\/\$SEMGREP_RELATIVE_TARGET"/);
  assert.match(result.script, /semgrep scan --config='p\/javascript' --config='p\/security-audit'/);
});
