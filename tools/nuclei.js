// tools/nuclei.js
// DAST: nuclei template-based scanner. Cần URL target từ runtimeInfo.

import {
  assertSeverityList, assertServiceName, assertNetworkName, assertPort,
  sanitizeNucleiTags, shellQuote,
} from '../runtime/sanitize.js';

export const name = 'nuclei';

export function enabled(cfg) {
  return Boolean(cfg?.nuclei?.enabled);
}

export function buildScript(cfg, projectInfo, runtimeInfo) {
  if (runtimeInfo?.dastSkipped) {
    return { skipped: true, reason: 'no deployable target', script: '' };
  }

  let severity, service, port, network;
  try {
    severity = assertSeverityList(cfg.nuclei?.severity ?? 'medium,high,critical');
    service  = assertServiceName(runtimeInfo.serviceName);
    port     = assertPort(runtimeInfo.port);
    network  = assertNetworkName(runtimeInfo.networkName);
  } catch (err) {
    return { skipped: true, reason: err.message, script: '' };
  }

  const tags = sanitizeNucleiTags(cfg.nuclei?.templateTags ?? []);
  const tagsArg = tags.length > 0 ? `-tags ${shellQuote(tags.join(','))}` : '';

  const targetUrl  = `http://${service}:${port}/`;
  const reportsDir = shellQuote(projectInfo.reportsDir);

  const script = `
echo "[DAST] Nuclei — severity: ${severity}, tags: ${tags.join(',') || '(default)'}"
docker run --rm \\
  --network ${shellQuote(network)} \\
  -v ${reportsDir}:/out \\
  projectdiscovery/nuclei \\
  -u ${shellQuote(targetUrl)} -s ${shellQuote(severity)} ${tagsArg} \\
  -jsonl -o /out/nuclei-report.jsonl || true
`.trim();

  return { skipped: false, script };
}
