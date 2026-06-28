import test from 'node:test';
import assert from 'node:assert/strict';

import { buildScript } from './trivy.js';

test('trivy buildScript mounts a persistent cache directory', () => {
  const result = buildScript(
    { trivy: { targets: ['fs'] } },
    {
      targetDir: '/var/lib/jenkins/workspace/DevSecOps-AI-Pentest/benchmarks/juice-shop',
      reportsDir: '/var/lib/jenkins/workspace/DevSecOps-AI-Pentest/security-context-output/scan-reports',
    },
  );

  assert.equal(result.skipped, false);
  assert.match(result.script, /TRIVY_REPORTS_DIR='\/var\/lib\/jenkins\/workspace\/DevSecOps-AI-Pentest\/security-context-output\/scan-reports'/);
  assert.match(result.script, /TRIVY_CACHE_DIR="\$\(cd "\$TRIVY_REPORTS_DIR\/\.\." && pwd -P\)\/\.trivy-cache"/);
  assert.match(result.script, /-v "\$TRIVY_CACHE_DIR:\/root\/\.cache\/trivy"/);
  assert.match(result.script, /fs --format json --output \/out\/trivy-report\.json \/src/);
});
