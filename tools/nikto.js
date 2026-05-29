// tools/nikto.js
// DAST web server scanner. Chỉ enable khi cfg.nikto.enabled (thường cho PHP).

import {
  assertServiceName, assertNetworkName, assertPort, shellQuote,
} from '../runtime/sanitize.js';

export const name = 'nikto';

export function enabled(cfg) {
  return Boolean(cfg?.nikto?.enabled);
}

export function buildScript(cfg, projectInfo, runtimeInfo) {
  if (runtimeInfo?.dastSkipped) {
    return { skipped: true, reason: 'no deployable target', script: '' };
  }

  let service, port, network;
  try {
    service = assertServiceName(runtimeInfo.serviceName);
    port    = assertPort(runtimeInfo.port);
    network = assertNetworkName(runtimeInfo.networkName);
  } catch (err) {
    return { skipped: true, reason: err.message, script: '' };
  }

  const targetUrl  = `http://${service}:${port}/`;
  const reportsDir = shellQuote(projectInfo.reportsDir);

  const script = `
echo "[DAST] Nikto — target: ${targetUrl}"
docker run --rm \\
  --network ${shellQuote(network)} \\
  -v ${reportsDir}:/out \\
  alpine/nikto \\
  -h ${shellQuote(targetUrl)} -Format json -output /out/nikto-report.json || true
`.trim();

  return { skipped: false, script };
}
