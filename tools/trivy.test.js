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
  assert.match(result.script, /-v "\$TRIVY_CACHE_DIR:\/tmp\/trivy-cache"/);
  assert.match(result.script, /--cache-dir \/tmp\/trivy-cache/);
  assert.match(result.script, /fs --format json --output \/out\/trivy-report\.json \/src/);
});

test('trivy buildScript supports image and config targets', () => {
  const result = buildScript(
    { trivy: { targets: ['fs', 'image', 'config'] } },
    {
      targetDir: '/var/lib/jenkins/workspace/DevSecOps-AI-Pentest/benchmarks/juice-shop',
      reportsDir: '/var/lib/jenkins/workspace/DevSecOps-AI-Pentest/security-context-output/scan-reports',
      containerInfo: {
        composeFile: 'compose.yaml',
        hasDockerCompose: true,
        dockerCompose: {
          servicesDetail: [
            { name: 'web', image: 'bkimminich/juice-shop:latest', build: null, ports: ['3000:3000'] },
          ],
        },
      },
    },
    {
      serviceName: 'web',
      composeFile: 'compose.yaml',
      composeProjectName: 'juice-shop',
    },
  );

  assert.equal(result.skipped, false);
  assert.match(result.script, /image --skip-version-check --format json --output \/out\/trivy-image-1\.json 'bkimminich\/juice-shop:latest'/);
  assert.match(result.script, /trivy-image-report\.json/);
  assert.match(result.script, /config --skip-version-check --format json --output \/out\/trivy-config-report\.json \/src/);
  assert.doesNotMatch(result.script, /not implemented/);
});

test('trivy buildScript builds and scans compose build-only service image', () => {
  const result = buildScript(
    { trivy: { targets: ['image'] } },
    {
      targetDir: '/var/lib/jenkins/workspace/demo/examples/sqli',
      reportsDir: '/var/lib/jenkins/workspace/demo/security-context-output/scan-reports',
      containerInfo: {
        composeFile: 'compose.yaml',
        hasDockerCompose: true,
        dockerCompose: {
          servicesDetail: [
            { name: 'web', image: null, build: './web', ports: ['5000:5000'] },
          ],
        },
      },
    },
    {
      serviceName: 'web',
      composeFile: 'compose.yaml',
      composeProjectName: 'sqli',
    },
  );

  assert.equal(result.skipped, false);
  assert.match(result.script, /docker-compose -p 'sqli' -f 'compose\.yaml' build 'web'/);
  assert.match(result.script, /docker-compose -p 'sqli' -f 'compose\.yaml' images -q 'web'/);
  assert.match(result.script, /image --skip-version-check --format json --output \/out\/trivy-image-build-1\.json "\$TRIVY_IMAGE_REF"/);
});
