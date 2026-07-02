// tools/trivy.js
// SCA adapter for Trivy. Supports filesystem, container image, and config scans.

import { basename } from 'path';
import {
  assertServiceName,
  sanitizeImageRefs,
  sanitizeTrivyTargets,
  shellQuote,
} from '../runtime/sanitize.js';

export const name = 'trivy';

export function enabled(cfg) {
  return Boolean(cfg?.trivy?.enabled);
}

function unique(items) {
  return [...new Set(items.filter(Boolean))];
}

function deriveComposeProjectName(targetDir) {
  const base = basename(targetDir)
    .toLowerCase()
    .replace(/[^a-z0-9_-]/g, '');
  return base || 'default';
}

function serviceByName(projectInfo, runtimeInfo) {
  const serviceName = runtimeInfo?.serviceName ?? projectInfo?.serviceName;
  if (!serviceName) return null;
  return (projectInfo.containerInfo?.dockerCompose?.servicesDetail ?? [])
    .find(service => service.name === serviceName) ?? null;
}

function collectExplicitImages(cfg, projectInfo, runtimeInfo) {
  const configuredImages = cfg.trivy?.images ?? cfg.trivy?.imageRefs ?? [];
  const selectedService = serviceByName(projectInfo, runtimeInfo);
  const selectedImages = selectedService?.image ? [selectedService.image] : [];

  if (configuredImages.length > 0) {
    return sanitizeImageRefs(configuredImages);
  }

  return sanitizeImageRefs(unique(selectedImages));
}

function collectBuildServices(projectInfo, runtimeInfo) {
  const selectedService = serviceByName(projectInfo, runtimeInfo);
  if (!selectedService?.build) return [];

  try {
    return [assertServiceName(selectedService.name)];
  } catch {
    return [];
  }
}

function buildTrivyCommonSetup(targetDir, reportsDir) {
  return `TRIVY_TARGET_DIR=${targetDir}
TRIVY_REPORTS_DIR=${reportsDir}
TRIVY_CACHE_DIR="$(cd "$TRIVY_REPORTS_DIR/.." && pwd -P)/.trivy-cache"
mkdir -p "$TRIVY_CACHE_DIR" "$TRIVY_REPORTS_DIR"`;
}

function buildFsScript() {
  return `echo "[SCA] Trivy fs"
docker run --rm \\
  -v "$TRIVY_TARGET_DIR:/src:ro" \\
  -v "$TRIVY_REPORTS_DIR:/out" \\
  -v "$TRIVY_CACHE_DIR:/root/.cache/trivy" \\
  aquasec/trivy \\
  fs --format json --output /out/trivy-report.json /src || true`;
}

function buildConfigScript() {
  return `echo "[SCA] Trivy config"
docker run --rm \\
  -v "$TRIVY_TARGET_DIR:/src:ro" \\
  -v "$TRIVY_REPORTS_DIR:/out" \\
  -v "$TRIVY_CACHE_DIR:/root/.cache/trivy" \\
  aquasec/trivy \\
  config --skip-version-check --format json --output /out/trivy-config-report.json /src || true`;
}

function imageScanCommand(imageRef, outputFile) {
  return `docker run --rm "\${TRIVY_DOCKER_SOCKET_ARGS[@]}" \\
  -v "$TRIVY_REPORTS_DIR:/out" \\
  -v "$TRIVY_CACHE_DIR:/root/.cache/trivy" \\
  aquasec/trivy \\
  image --skip-version-check --format json --output /out/${outputFile} ${shellQuote(imageRef)} || true`;
}

function imageScanCommandFromVariable(outputFile) {
  return `docker run --rm "\${TRIVY_DOCKER_SOCKET_ARGS[@]}" \\
  -v "$TRIVY_REPORTS_DIR:/out" \\
  -v "$TRIVY_CACHE_DIR:/root/.cache/trivy" \\
  aquasec/trivy \\
  image --skip-version-check --format json --output /out/${outputFile} "$TRIVY_IMAGE_REF" || true`;
}

function appendImageReportCommand(outputFile) {
  return `if [ -s "$TRIVY_REPORTS_DIR/${outputFile}" ]; then
  if [ "$TRIVY_IMAGE_FIRST" -eq 0 ]; then printf ',\\n' >> "$TRIVY_IMAGE_AGG"; fi
  cat "$TRIVY_REPORTS_DIR/${outputFile}" >> "$TRIVY_IMAGE_AGG"
  TRIVY_IMAGE_FIRST=0
fi`;
}

function buildImageScript(cfg, projectInfo, runtimeInfo) {
  const imageRefs = collectExplicitImages(cfg, projectInfo, runtimeInfo);
  const buildServices = collectBuildServices(projectInfo, runtimeInfo);
  const composeFile = runtimeInfo?.composeFile
    ?? projectInfo.containerInfo?.composeFile
    ?? 'docker-compose.yml';
  const composeProjectName = runtimeInfo?.composeProjectName
    ?? projectInfo.composeProjectName
    ?? deriveComposeProjectName(projectInfo.targetDir);

  if (imageRefs.length === 0 && buildServices.length === 0) {
    return `echo "[SCA] Trivy image skipped - no compose image or build service found"
printf '{"SchemaVersion":2,"ArtifactName":"trivy-image","ArtifactType":"container_image","Results":[]}' > "$TRIVY_REPORTS_DIR/trivy-image-report.json"`;
  }

  const sections = [
    `echo "[SCA] Trivy image"`,
    `TRIVY_IMAGE_AGG="$TRIVY_REPORTS_DIR/trivy-image-report.json"
TRIVY_IMAGE_FIRST=1
printf '{"Reports":[' > "$TRIVY_IMAGE_AGG"
TRIVY_DOCKER_SOCKET_ARGS=()
if [ -S /var/run/docker.sock ]; then
  TRIVY_DOCKER_SOCKET_ARGS=(-v /var/run/docker.sock:/var/run/docker.sock)
fi`,
  ];

  imageRefs.forEach((imageRef, index) => {
    const outputFile = `trivy-image-${index + 1}.json`;
    sections.push(`echo "[SCA] Trivy image ref: ${imageRef}"
${imageScanCommand(imageRef, outputFile)}
${appendImageReportCommand(outputFile)}`);
  });

  buildServices.forEach((serviceName, index) => {
    const outputFile = `trivy-image-build-${index + 1}.json`;
    sections.push(`echo "[SCA] Trivy compose build image: ${serviceName}"
if [ -S /var/run/docker.sock ]; then
  cd "$TRIVY_TARGET_DIR"
  docker-compose -p ${shellQuote(composeProjectName)} -f ${shellQuote(composeFile)} build ${shellQuote(serviceName)} || true
  TRIVY_IMAGE_REF="$(docker-compose -p ${shellQuote(composeProjectName)} -f ${shellQuote(composeFile)} images -q ${shellQuote(serviceName)} 2>/dev/null | head -n 1 || true)"
  if [ -n "$TRIVY_IMAGE_REF" ]; then
    ${imageScanCommandFromVariable(outputFile)}
    ${appendImageReportCommand(outputFile)}
  else
    echo "[SCA] Trivy image skipped for ${serviceName} - docker-compose did not return an image id"
  fi
else
  echo "[SCA] Trivy image skipped for ${serviceName} - /var/run/docker.sock not available"
fi`);
  });

  sections.push(`printf ']}' >> "$TRIVY_IMAGE_AGG"`);
  return sections.join('\n');
}

export function buildScript(cfg, projectInfo, runtimeInfo = null) {
  const targets = sanitizeTrivyTargets(cfg.trivy?.targets ?? ['fs']);
  if (targets.length === 0) {
    return { skipped: true, reason: 'no valid targets', script: '' };
  }

  const targetDir = shellQuote(projectInfo.targetDir);
  const reportsDir = shellQuote(projectInfo.reportsDir);

  const lines = [`echo "[SCA] Trivy - targets: ${targets.join(',')}"`];
  lines.push(buildTrivyCommonSetup(targetDir, reportsDir));

  if (targets.includes('fs')) {
    lines.push(buildFsScript());
  }

  if (targets.includes('image')) {
    lines.push(buildImageScript(cfg, projectInfo, runtimeInfo));
  }

  if (targets.includes('config')) {
    lines.push(buildConfigScript());
  }

  return { skipped: false, script: lines.join('\n') };
}
