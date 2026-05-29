// tools/zap.js
// DAST: OWASP ZAP. Cần runtimeInfo.serviceName + port + networkName để attack.
// Nếu runtimeInfo.dastSkipped → return skipped.

import {
  assertZapMode, assertServiceName, assertNetworkName, assertPort,
  sanitizeFocusPaths, shellQuote,
} from '../runtime/sanitize.js';

export const name = 'zap';

export function enabled(cfg) {
  return Boolean(cfg?.zap?.enabled);
}

export function buildScript(cfg, projectInfo, runtimeInfo) {
  if (runtimeInfo?.dastSkipped) {
    return { skipped: true, reason: 'no deployable target', script: '' };
  }

  let mode, service, port, network;
  try {
    mode    = assertZapMode(cfg.zap?.mode ?? 'baseline');
    service = assertServiceName(runtimeInfo.serviceName);
    port    = assertPort(runtimeInfo.port);
    network = assertNetworkName(runtimeInfo.networkName);
  } catch (err) {
    return { skipped: true, reason: err.message, script: '' };
  }

  const focusPaths = sanitizeFocusPaths(cfg.zap?.focusPaths ?? []);
  const targetUrl  = `http://${service}:${port}${focusPaths[0] ?? '/'}`;
  const reportsDir = shellQuote(projectInfo.reportsDir);

  // Map mode → ZAP script + format flag
  const modeMap = {
    'baseline':  { cmd: 'zap-baseline.py',  extra: '' },
    'api-scan':  { cmd: 'zap-api-scan.py',  extra: '-f openapi' },
    'full-scan': { cmd: 'zap-full-scan.py', extra: '' },
  };
  const { cmd, extra } = modeMap[mode];

  // ZAP container chạy với user 'zap' (UID 1000) → không write được /zap/wrk
  // nếu host dir thuộc UID khác. Chmod 777 trước khi mount.
  const script = `
echo "[DAST] ZAP ${mode} — target: ${targetUrl}"
mkdir -p ${reportsDir}
chmod 777 ${reportsDir}
docker run --rm \\
  --network ${shellQuote(network)} \\
  -v ${reportsDir}:/zap/wrk:rw \\
  ghcr.io/zaproxy/zaproxy:stable \\
  ${cmd} -t ${shellQuote(targetUrl)} ${extra} -J zap-report.json || true
`.trim();

  return { skipped: false, script };
}
