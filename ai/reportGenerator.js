// ai/reportGenerator.js
// Chức năng 3 của đề tài: Security Report Generator
//
// Flow:
//   readSemgrep() + readBandit() + readTrivy() + readZap() + readNuclei() + readNikto()
//   → deduplicate() gộp finding trùng
//   → triageWithGemini() (Gemini Call #3) phân loại + risk score + remediation
//   → buildHtml() render security-report.html

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { dirname, join, resolve } from 'path';
import { callGeminiWithRetry, parseJson, logUsage } from './geminiClient.js';

// ── 1. Tool report readers ────────────────────────────────────────────────────

/**
 * Parse Semgrep JSON report.
 * semgrep scan --json → { results: [{ check_id, path, start, end, extra }] }
 */
export function readSemgrep(reportPath) {
  if (!existsSync(reportPath)) return [];
  try {
    const raw = JSON.parse(readFileSync(reportPath, 'utf8'));
    return (raw.results ?? []).map(r => ({
      source:   'semgrep',
      ruleId:   r.check_id ?? '',
      category: mapSemgrepCategory(r.check_id ?? ''),
      severity: mapSemgrepSeverity(r.extra?.severity ?? ''),
      location: `${r.path}:${r.start?.line ?? 0}`,
      file:     r.path ?? '',
      line:     r.start?.line ?? 0,
      message:  r.extra?.message ?? '',
      snippet:  r.extra?.lines ?? '',
      cweId:    r.extra?.metadata?.cwe?.[0] ?? null,
      owasp:    r.extra?.metadata?.owasp?.[0] ?? null,
    }));
  } catch (e) {
    console.warn(`[readSemgrep] Parse error: ${e.message}`);
    return [];
  }
}

/**
 * Parse Bandit JSON report (Python SAST).
 * bandit -r . -f json → { results: [{ test_id, filename, line_number, issue_text, severity }] }
 */
export function readBandit(reportPath) {
  if (!existsSync(reportPath)) return [];
  try {
    const raw = JSON.parse(readFileSync(reportPath, 'utf8'));
    return (raw.results ?? []).map(r => ({
      source:   'bandit',
      ruleId:   r.test_id ?? '',
      category: mapBanditCategory(r.test_id ?? ''),
      severity: (r.issue_severity ?? 'MEDIUM').toLowerCase(),
      location: `${r.filename}:${r.line_number ?? 0}`,
      file:     r.filename ?? '',
      line:     r.line_number ?? 0,
      message:  r.issue_text ?? '',
      snippet:  r.code ?? '',
      cweId:    r.issue_cwe?.id ? `CWE-${r.issue_cwe.id}` : null,
    }));
  } catch (e) {
    console.warn(`[readBandit] Parse error: ${e.message}`);
    return [];
  }
}

/**
 * Parse Trivy JSON report.
 * trivy fs --format json → { Results: [{ Target, Vulnerabilities: [...] }] }
 */
export function readTrivy(reportPath) {
  if (!existsSync(reportPath)) return [];
  try {
    const raw = JSON.parse(readFileSync(reportPath, 'utf8'));
    const findings = [];
    for (const result of raw.Results ?? []) {
      for (const vuln of result.Vulnerabilities ?? []) {
        findings.push({
          source:    'trivy',
          ruleId:    vuln.VulnerabilityID ?? '',
          category:  'dependency',
          severity:  (vuln.Severity ?? 'UNKNOWN').toLowerCase(),
          location:  result.Target ?? '',
          file:      result.Target ?? '',
          line:      0,
          message:   `${vuln.VulnerabilityID}: ${vuln.Title ?? vuln.Description?.slice(0, 120) ?? ''}`,
          snippet:   `${vuln.PkgName}@${vuln.InstalledVersion} → fix: ${vuln.FixedVersion ?? 'no fix available'}`,
          cweId:     null,
          cvssScore: vuln.CVSS?.nvd?.V3Score ?? vuln.CVSS?.nvd?.V2Score ?? null,
        });
      }
    }
    return findings;
  } catch (e) {
    console.warn(`[readTrivy] Parse error: ${e.message}`);
    return [];
  }
}

export function readTrivyExtended(reportPath, options = {}) {
  if (!existsSync(reportPath)) return [];
  try {
    const raw = JSON.parse(readFileSync(reportPath, 'utf8'));
    const reports = Array.isArray(raw.Reports) ? raw.Reports : [raw];
    const findings = [];

    for (const report of reports) {
      const reportTarget = report.ArtifactName ?? report.Metadata?.ImageID ?? '';
      const reportType = options.reportType ?? report.ArtifactType ?? 'filesystem';

      for (const result of report.Results ?? []) {
        for (const vuln of result.Vulnerabilities ?? []) {
          findings.push({
            source:    'trivy',
            ruleId:    vuln.VulnerabilityID ?? '',
            category:  'dependency',
            severity:  (vuln.Severity ?? 'UNKNOWN').toLowerCase(),
            location:  result.Target ?? reportTarget,
            file:      result.Target ?? reportTarget,
            line:      0,
            message:   `${vuln.VulnerabilityID}: ${vuln.Title ?? vuln.Description?.slice(0, 120) ?? ''}`,
            snippet:   `${vuln.PkgName}@${vuln.InstalledVersion} -> fix: ${vuln.FixedVersion ?? 'no fix available'}`,
            cweId:     null,
            cvssScore: vuln.CVSS?.nvd?.V3Score ?? vuln.CVSS?.nvd?.V2Score ?? null,
            artifact:  reportTarget,
            reportType,
          });
        }

        for (const misconfig of result.Misconfigurations ?? []) {
          findings.push({
            source:   'trivy',
            ruleId:   misconfig.ID ?? misconfig.AVDID ?? '',
            category: 'misconfig',
            severity: (misconfig.Severity ?? 'UNKNOWN').toLowerCase(),
            location: result.Target ?? reportTarget,
            file:     result.Target ?? reportTarget,
            line:     misconfig.CauseMetadata?.StartLine ?? 0,
            message:  `${misconfig.ID ?? misconfig.AVDID ?? 'MISCONFIG'}: ${misconfig.Title ?? misconfig.Message ?? ''}`,
            snippet:  [
              misconfig.Message,
              misconfig.Resolution ? `Resolution: ${misconfig.Resolution}` : '',
            ].filter(Boolean).join('\n'),
            cweId:    null,
            owasp:    misconfig.CauseMetadata?.Provider ?? null,
            artifact: reportTarget,
            reportType,
          });
        }

        for (const secret of result.Secrets ?? []) {
          findings.push({
            source:   'trivy',
            ruleId:   secret.RuleID ?? secret.Category ?? 'secret',
            category: 'secret',
            severity: normalizeSeverity(secret.Severity ?? 'high'),
            location: secret.StartLine ? `${result.Target ?? reportTarget}:${secret.StartLine}` : (result.Target ?? reportTarget),
            file:     result.Target ?? reportTarget,
            line:     secret.StartLine ?? 0,
            message:  secret.Title ?? secret.RuleID ?? 'Secret detected',
            snippet:  'Secret value redacted by report parser.',
            cweId:    null,
            artifact: reportTarget,
            reportType,
          });
        }
      }
    }

    return findings;
  } catch (e) {
    console.warn(`[readTrivyExtended] Parse error: ${e.message}`);
    return [];
  }
}

/**
 * Parse ZAP JSON report.
 * ZAP outputs array of sites → each with alerts
 */
export function readZap(reportPath) {
  if (!existsSync(reportPath)) return [];
  try {
    const raw = JSON.parse(readFileSync(reportPath, 'utf8'));
    const findings = [];
    const sites = Array.isArray(raw) ? raw : (raw.site ?? []);

    for (const site of sites) {
      const alerts = site.alerts ?? site.Alert ?? [];
      for (const alert of alerts) {
        const risk = (alert.riskdesc ?? alert.risk ?? '').toLowerCase();
        if (risk.includes('informational') || risk.includes('false')) continue;

        const instances = Array.isArray(alert.instances) && alert.instances.length
          ? alert.instances
          : [alert];

        for (const instance of instances) {
          const url = instance.uri ?? instance.url ?? alert.url ?? site['@name'] ?? '';
          const method = instance.method ?? alert.method ?? '';
          const param = instance.param ?? alert.param ?? '';
          const evidence = instance.evidence ?? alert.evidence ?? '';
          const attack = instance.attack ?? alert.attack ?? '';
          const location = formatRequestLocation({ method, url, param });

          findings.push({
            source:      'zap',
            ruleId:      String(alert.pluginid ?? alert.alertRef ?? ''),
            category:    mapZapCategory(alert.alert ?? alert.name ?? ''),
            severity:    mapZapRisk(alert.riskcode ?? alert.riskdesc ?? ''),
            location,
            url,
            method,
            param,
            evidence,
            attack,
            confidence:  alert.confidence ?? alert.confidencedesc ?? '',
            file:        '',
            line:        0,
            message:     alert.alert ?? alert.name ?? '',
            snippet:     formatZapSnippet({ evidence, attack, param }),
            cweId:       alert.cweid ? `CWE-${alert.cweid}` : null,
            owasp:       alert.wascid ? `WASC-${alert.wascid}` : null,
          });
        }
      }
    }
    return findings;
  } catch (e) {
    console.warn(`[readZap] Parse error: ${e.message}`);
    return [];
  }
}

/**
 * Parse Nuclei JSONL report.
 * nuclei -jsonl -> one JSON object per line.
 */
export function readNuclei(reportPath) {
  if (!existsSync(reportPath)) return [];
  try {
    return readFileSync(reportPath, 'utf8')
      .split(/\r?\n/)
      .map(line => line.trim())
      .filter(Boolean)
      .map(line => JSON.parse(line))
      .map(r => ({
        source:   'nuclei',
        ruleId:   r['template-id'] ?? r.templateID ?? r.id ?? '',
        category: mapNucleiCategory(r),
        severity: normalizeSeverity(r.info?.severity ?? r.severity ?? 'medium'),
        location: r['matched-at'] ?? r.host ?? r.url ?? '',
        file:     '',
        line:     0,
        message:  r.info?.name ?? r.name ?? r['template-id'] ?? 'Nuclei finding',
        snippet:  r['extracted-results']?.length
          ? `Extracted: ${r['extracted-results'].join(', ')}`
          : `Matcher: ${r['matcher-name'] ?? 'N/A'}`,
        cweId:    normalizeCwe(r.info?.classification?.['cwe-id']),
        owasp:    r.info?.classification?.['owasp-top-ten'] ?? null,
      }));
  } catch (e) {
    console.warn(`[readNuclei] Parse error: ${e.message}`);
    return [];
  }
}

/**
 * Parse Nikto JSON report.
 * Nikto JSON varies by version; support vulnerabilities/items arrays.
 */
export function readNikto(reportPath) {
  if (!existsSync(reportPath)) return [];
  try {
    const raw = JSON.parse(readFileSync(reportPath, 'utf8'));
    const hostItems = Array.isArray(raw) ? raw : (raw.hosts ?? raw.vulnerabilities ?? raw.items ?? []);
    const findings = [];

    for (const entry of hostItems) {
      const items = entry.vulnerabilities ?? entry.items ?? (entry.id ? [entry] : []);
      for (const item of items) {
        const msg = item.msg ?? item.message ?? item.description ?? item.name ?? '';
        findings.push({
          source:   'nikto',
          ruleId:   String(item.id ?? item.osvdbid ?? item.pluginid ?? item.references ?? ''),
          category: mapNiktoCategory(msg),
          severity: mapNiktoSeverity(msg),
          location: item.url ?? item.uri ?? entry.ip ?? entry.hostname ?? '',
          file:     '',
          line:     0,
          message:  msg || 'Nikto finding',
          snippet:  item.method ? `Method: ${item.method}` : '',
          cweId:    normalizeCwe(item.cwe),
          owasp:    null,
        });
      }
    }

    return findings;
  } catch (e) {
    console.warn(`[readNikto] Parse error: ${e.message}`);
    return [];
  }
}

export function readManualTests(manualTestsPath) {
  if (!manualTestsPath || !existsSync(manualTestsPath)) return [];
  try {
    const raw = JSON.parse(readFileSync(manualTestsPath, 'utf8'));
    return raw.manual_test_cases ?? raw.test_cases ?? [];
  } catch (e) {
    console.warn(`[readManualTests] Parse error: ${e.message}`);
    return [];
  }
}

// ── 2. Deduplication ──────────────────────────────────────────────────────────

/**
 * Gộp findings trùng lặp theo key: category:ruleId:location
 * Cùng lỗ hổng được phát hiện bởi nhiều tool → gộp lại thành 1
 */
export function deduplicate(allFindings) {
  const groups = new Map();

  for (const f of allFindings) {
    // Normalize location: chỉ dùng phần path, không dùng line number cho ZAP
    const locationKey = f.source === 'zap'
      ? normalizeZapLocationKey(f)
      : f.source === 'nuclei' || f.source === 'nikto'
        ? `${f.location}:${f.ruleId}`
        : `${f.file}:${f.line}`;

    const key = `${f.category}:${f.ruleId}:${locationKey}`;

    if (groups.has(key)) {
      groups.get(key).sources.push(f.source);
      groups.get(key).sourceCount++;
    } else {
      groups.set(key, {
        ...f,
        sources:     [f.source],
        sourceCount: 1,
        dedupKey:    key,
      });
    }
  }

  return [...groups.values()].sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };
    return (order[a.severity] ?? 4) - (order[b.severity] ?? 4);
  });
}

// ── 3. Gemini Call #3: Triage ─────────────────────────────────────────────────

const TRIAGE_SYSTEM = `You are a senior security engineer performing vulnerability triage for a DevSecOps pipeline.

You will receive a list of security findings from automated tools (Semgrep, Bandit, Trivy, ZAP) along with the project context.

Your tasks:
1. Classify each finding: confirmed_vulnerability | likely_vulnerability | needs_manual_review
2. Calculate a risk_score 0-100 based on: severity + exploitability + context relevance
3. Generate specific remediation guidance referencing the exact file/framework
4. Write an executive summary

CRITICAL: Output ONLY valid JSON. No markdown, no explanation.

Output schema:
{
  "executive_summary": {
    "overall_risk": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
    "security_posture_score": 0-100,
    "critical_count": number,
    "high_count": number,
    "medium_count": number,
    "low_count": number,
    "key_findings": ["string"],
    "immediate_actions": ["string"]
  },
  "triaged_findings": [
    {
      "id": "F-001",
      "original_finding": { /* copy of input finding */ },
      "triage_status": "confirmed_vulnerability" | "likely_vulnerability" | "needs_manual_review",
      "triage_reason": "string",
      "risk_score": 0-100,
      "confirmed_by_sources": number,
      "remediation": {
        "summary": "string",
        "code_example": "optional — show correct code pattern",
        "references": ["CWE-xxx", "OWASP A..."]
      }
    }
  ]
}`;

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

/**
 * Gọi Gemini để triage findings.
 * @param {object[]} deduplicatedFindings
 * @param {object}   context               — context.json để AI biết ngữ cảnh
 * @param {object}   options               — { apiKey }
 */
export async function triageWithGemini(deduplicatedFindings, context, options = {}) {
  const CHUNK_SIZE = 30; // Giới hạn 10 lỗi mỗi cụm gửi cho AI
  let allTriagedFindings = [];
  let summaryForReduce = [];

  if (deduplicatedFindings.length === 0) {
    return {
      executive_summary: {
        overall_risk: 'LOW',
        security_posture_score: 100,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        key_findings: ['No scanner findings were available for AI triage.'],
        immediate_actions: [],
      },
      triaged_findings: [],
    };
  }

  console.log(`[AI] Bắt đầu phân mảnh ${deduplicatedFindings.length} lỗi thô để xử lý (Map-Reduce)...`);

  // =========================================================================
  // GIAI ĐOẠN 1 (MAP): CHIA CỤM XỬ LÝ SONG SONG ĐỂ KHÔNG BỊ RÁCH JSON
  // =========================================================================
  for (let i = 0; i < deduplicatedFindings.length; i += CHUNK_SIZE) {
    const chunk = deduplicatedFindings.slice(i, i + CHUNK_SIZE);
    const chunkNum = Math.floor(i / CHUNK_SIZE) + 1;
    const totalChunks = Math.ceil(deduplicatedFindings.length / CHUNK_SIZE);
    console.log(`[AI] --> Triage cụm lỗi số ${chunkNum}/${totalChunks}...`);

    // Rút gọn payload gửi lên để tối ưu token
    const chunkPayload = chunk.map((f, idx) => ({
      id: `F-${String(i + idx + 1).padStart(3, '0')}`,
      source: f.source,
      severity: f.severity,
      category: f.category,
      ruleId: f.ruleId,
      message: f.message,
      location: f.location,
      file: f.file,
      line: f.line,
      url: f.url,
      method: f.method,
      param: f.param,
      evidence: f.evidence?.slice(0, 200),
      snippet: f.snippet?.slice(0, 260)
    }));

    const mapPrompt = `
      You are a precise security triager for a ${context.techStack?.framework ?? 'web'} application.
      Analyze this subset of tool findings:
      ${JSON.stringify(chunkPayload)}

      Output STRICT JSON exactly matching this schema. Keep reasons to 1 sentence and reference the exact file, URL, line, parameter, or evidence when available.
      {
        "results": [
          {
            "id": "F-001",
            "triage_status": "confirmed_vulnerability" | "likely_vulnerability" | "needs_manual_review",
            "triage_reason": "1 short sentence explaining why.",
            "risk_score": 50,
            "remediation_summary": "1 short sentence fixing it."
          }
        ]
      }
    `;

    try {
      const mapResult = await callGeminiWithRetry(mapPrompt, "You are a precise security triager. Output ONLY JSON.", {
        apiKey: options.apiKey,
        temperature: 0.1,
        maxOutputTokens: 8192
      });

      const parsed = parseJson(mapResult.text);

      // Gắn kết quả AI vào dữ liệu gốc để giữ trọn vẹn 100% manh mối log
      chunk.forEach((rawFinding, idx) => {
        const findingId = `F-${String(i + idx + 1).padStart(3, '0')}`;
        const aiVerdict = parsed.results?.find(r => r.id === findingId) || {};

        const triageStatus = ['confirmed_vulnerability', 'likely_vulnerability'].includes(aiVerdict.triage_status)
          ? aiVerdict.triage_status
          : 'needs_manual_review';

        allTriagedFindings.push({
          id: findingId,
          original_finding: rawFinding,
          triage_status: triageStatus,
          triage_reason: aiVerdict.triage_reason || 'AI missing analysis due to context limit.',
          risk_score: aiVerdict.risk_score || 50,
          confirmed_by_sources: rawFinding.sourceCount || 1,
          remediation: {
            summary: aiVerdict.remediation_summary || 'Manual review required.'
          }
        });

        summaryForReduce.push({
          id: findingId,
          severity: rawFinding.severity,
          status: triageStatus
        });
      });
    } catch (e) {
      console.error(`[WARN] Lỗi xử lý JSON ở cụm ${chunkNum}: ${e.message}. Kích hoạt Fallback an toàn.`);
      // Fallback: Giữ nguyên dữ liệu đẩy vào để Pipeline không bị die
      chunk.forEach((rawFinding, idx) => {
        allTriagedFindings.push({
          id: `F-${String(i + idx + 1).padStart(3, '0')}`,
          original_finding: rawFinding,
          triage_status: 'needs_manual_review',
          triage_reason: 'Fallback due to AI parse error.',
          risk_score: 50,
          remediation: { summary: 'Please review manually.' }
        });
      });
    }

    if (chunkNum < totalChunks) {
        console.log(`[WAIT] Xong cụm ${chunkNum}. Nghỉ 15s để chống(429)...`);
        await sleep(15000);
    }
  }

  // =========================================================================
  // GIAI ĐOẠN 2 (REDUCE): ĐÁNH GIÁ NGỮ CẢNH TOÀN CỤC VÀ ĐIỂM POSTURE SCORE
  // =========================================================================
  console.log(`[AI] Giai đoạn 2: Gọi AI đánh giá Executive Summary từ ${summaryForReduce.length} lỗi...`);
  
  const reducePrompt = `
    You are a CISO. Here is a lightweight summary of all triaged findings:
    ${JSON.stringify(summaryForReduce)}

    Calculate the overall security posture and provide an executive summary.
    Output STRICT JSON:
    {
      "executive_summary": {
        "overall_risk": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
        "security_posture_score": 0-100,
        "critical_count": number,
        "high_count": number,
        "medium_count": number,
        "low_count": number,
        "key_findings": ["1 short sentence", "1 short sentence"],
        "immediate_actions": ["1 short sentence"]
      }
    }
  `;

  let finalExecutiveSummary = {};
  try {
    const reduceResult = await callGeminiWithRetry(reducePrompt, "You are an executive security officer.", {
      apiKey: options.apiKey,
      temperature: 0.1
    });
    const parsedReduce = parseJson(reduceResult.text);
    finalExecutiveSummary = parsedReduce.executive_summary || parsedReduce;
  } catch (e) {
    console.error("[WARN] Lỗi Giai đoạn Reduce (Executive Summary):", e.message);
    finalExecutiveSummary = { overall_risk: "UNKNOWN", security_posture_score: 0, critical_count: 0, high_count: 0, medium_count: 0, low_count: 0, key_findings: ["Pipeline fallback executed."] };
  }

  // Trả về đúng cấu trúc mà hàm buildHtml() của Tiến đang mong đợi
  return {
    executive_summary: finalExecutiveSummary,
    triaged_findings: allTriagedFindings
  };
}

// ── 4. HTML Report Builder ────────────────────────────────────────────────────

const SEVERITY_COLORS = {
  critical: '#dc2626',
  high:     '#ea580c',
  medium:   '#d97706',
  low:      '#16a34a',
  unknown:  '#6b7280',
};

const STATUS_BADGE = {
  confirmed_vulnerability: { label: 'Confirmed',    bg: '#fee2e2', color: '#991b1b' },
  likely_vulnerability:    { label: 'Likely',        bg: '#fef3c7', color: '#92400e' },
  needs_manual_review:     { label: 'Review Needed', bg: '#e0f2fe', color: '#075985' },
};

function renderFindingCard(f) {
  const original = f.original_finding ?? {};
  const sev = original.severity ?? 'unknown';
  const sevColor = SEVERITY_COLORS[sev] ?? SEVERITY_COLORS.unknown;
  const badge = STATUS_BADGE[f.triage_status] ?? STATUS_BADGE.needs_manual_review;
  const refs = f.remediation?.references?.join(', ') ?? '';
  const evidence = original.evidence || extractEvidenceFromSnippet(original.snippet);
  const detailRows = [
    ['Vulnerability Location', formatDisplayLocation(original)],
    ['Rule', [original.source, original.ruleId].filter(Boolean).join(' / ')],
    ['Vulnerability Category', original.category],
    ['Parameter', original.param],
    ['Evidence', evidence],
    ['CWE', original.cweId],
    ['OWASP/WASC', original.owasp],
  ].filter(([, value]) => value !== undefined && value !== null && String(value).trim() !== '');

  return `
      <div class="finding" data-severity="${escHtml(sev)}">
        <div class="finding-header">
          <span class="severity-pill" style="background:${sevColor}20;color:${sevColor};border:1px solid ${sevColor}40">
            ${escHtml(String(sev).toUpperCase())}
          </span>
          <span class="status-badge" style="background:${badge.bg};color:${badge.color}">
            ${escHtml(badge.label)}
          </span>
          <strong class="finding-id">${escHtml(f.id ?? '')}</strong>
          <span class="finding-title">${escHtml(formatFindingTitle(f))}</span>
          <span class="risk-score">Risk: ${escHtml(f.risk_score ?? '?')}/100</span>
        </div>
        <div class="finding-body">
          <dl class="finding-details">
            ${detailRows.map(([label, value]) => `
            <div class="detail-row">
              <dt>${escHtml(label)}</dt>
              <dd>${escHtml(value)}</dd>
            </div>`).join('')}
          </dl>
          ${original.snippet ? `<pre class="snippet">${escHtml(original.snippet)}</pre>` : ''}
          <div class="finding-analysis">
            <div class="analysis-box triage-reason">
              <div class="analysis-label">Triage</div>
              <div class="analysis-text">${escHtml(f.triage_reason ?? '')}</div>
            </div>
            <div class="analysis-box remediation">
              <div class="analysis-label">Fix</div>
              <div class="analysis-text">${escHtml(f.remediation?.summary ?? '')}</div>
            </div>
            ${f.remediation?.code_example ? `<pre class="code-example">${escHtml(f.remediation.code_example)}</pre>` : ''}
            ${refs ? `<div class="refs">References: ${escHtml(refs)}</div>` : ''}
          </div>
        </div>
      </div>`;
}

export function buildHtml(triageResult, context, metadata = {}) {
  const summary  = triageResult.executive_summary ?? {};
  const findings = triageResult.triaged_findings ?? [];
  const manualTests = metadata.manualTests ?? [];
  const toolNames = metadata.tools?.length ? metadata.tools : inferToolNames(findings);
  const toolLabel = [...toolNames, 'AI Triage (Gemini 3.0 Flash)'].join(' · ');
  const ts       = new Date().toISOString();
  const project  = `${context.techStack?.language ?? '?'} / ${context.techStack?.framework ?? '?'}`;
  const toolRuns = triageResult.tool_runs ?? metadata.toolRuns ?? [];

  const findingsHtml = findings
    .map(renderFindingCard)
    .join('\n');

  const toolRunsHtml = toolRuns.length ? `
<div class="tool-runs">
  <h2>Tool Run Summary</h2>
  <div class="tool-run-grid">
    ${toolRuns.map(run => `
    <div class="tool-run ${run.exists ? 'tool-run-ok' : 'tool-run-missing'}">
      <strong>${escHtml(run.label ?? run.key)}</strong>
      <span>${run.exists ? `${escHtml(run.findingCount ?? 0)} findings` : `missing ${escHtml(run.file ?? '')}`}</span>
    </div>`).join('')}
  </div>
</div>` : '';

  const manualTestsHtml = manualTests.map(tc => {
    const sev = String(tc.severity ?? 'MEDIUM').toLowerCase();
    const sevColor = SEVERITY_COLORS[sev] ?? SEVERITY_COLORS.medium;
    const evidence = tc.evidence ?? {};
    const evidenceRows = [
      evidence.route ? ['Route evidence', evidence.route] : null,
      evidence.classification?.length ? ['Classification', evidence.classification.join(', ')] : null,
      evidence.middleware?.length ? ['Middleware', evidence.middleware.join(', ')] : null,
      evidence.risk_signals?.length ? ['Risk signals', evidence.risk_signals.join(', ')] : null,
      evidence.schema_fields?.length ? ['Schema fields', evidence.schema_fields.join(', ')] : null,
    ].filter(Boolean);
    const steps = (tc.steps ?? []).map(step => `
      <li>
        <strong>Step ${escHtml(step.step ?? '')}:</strong> ${escHtml(step.action ?? step)}
        ${step.http_request ? `<pre class="snippet">${escHtml(step.http_request)}</pre>` : ''}
        ${step.expected_if_vulnerable ? `<div class="triage-reason"><strong>Vulnerable if:</strong> ${escHtml(step.expected_if_vulnerable)}</div>` : ''}
      </li>
    `).join('');

    return `
    <div class="finding manual-test">
      <div class="finding-header">
        <span class="severity-pill" style="background:${sevColor}20;color:${sevColor};border:1px solid ${sevColor}40">
          ${escHtml(tc.severity ?? 'MEDIUM')}
        </span>
        <strong class="finding-id">${escHtml(tc.id ?? '')}</strong>
        <span class="finding-title">${escHtml(tc.vulnerability_type ?? 'Manual Test')} - ${escHtml(tc.target_endpoint ?? '')}</span>
      </div>
      <div class="finding-body">
        ${tc.why_generated ? `<div class="analysis-box evidence-box"><div class="analysis-label">Why Generated</div><div class="analysis-text">${escHtml(tc.why_generated)}</div></div>` : ''}
        ${evidenceRows.length ? `
        <dl class="finding-details manual-evidence">
          ${evidenceRows.map(([label, value]) => `
          <div class="detail-row">
            <dt>${escHtml(label)}</dt>
            <dd>${escHtml(value)}</dd>
          </div>`).join('')}
        </dl>` : ''}
        ${tc.preconditions?.length ? `<div class="meta-row"><span>Preconditions: ${escHtml(tc.preconditions.join('; '))}</span></div>` : ''}
        <ol class="manual-steps">${steps}</ol>
        ${tc.confirmed_vulnerable_indicator ? `<div class="triage-reason"><strong>Confirm:</strong> ${escHtml(tc.confirmed_vulnerable_indicator)}</div>` : ''}
        ${tc.remediation_hint ? `<div class="remediation"><strong>Fix hint:</strong> ${escHtml(tc.remediation_hint)}</div>` : ''}
      </div>
    </div>`;
  }).join('\n');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Report — ${escHtml(project)}</title>
<style>
  :root {
    --c-bg: #0f172a; --c-surface: #1e293b; --c-border: #334155;
    --c-text: #e2e8f0; --c-muted: #94a3b8; --c-accent: #38bdf8;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--c-bg); color: var(--c-text); font-family: 'Segoe UI', system-ui, sans-serif; padding: 2rem; }
  h1 { font-size: 1.5rem; font-weight: 700; color: var(--c-accent); margin-bottom: 0.25rem; }
  .meta { color: var(--c-muted); font-size: 0.85rem; margin-bottom: 2rem; }
  .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
  .stat-card { background: var(--c-surface); border: 1px solid var(--c-border); border-radius: 8px; padding: 1rem; text-align: center; }
  .stat-number { font-size: 2rem; font-weight: 700; }
  .stat-label  { font-size: 0.75rem; color: var(--c-muted); margin-top: 0.25rem; text-transform: uppercase; letter-spacing: 0.05em; }
  .key-findings { background: var(--c-surface); border: 1px solid var(--c-border); border-radius: 8px; padding: 1.25rem; margin-bottom: 2rem; }
  .key-findings h2 { font-size: 1rem; margin-bottom: 0.75rem; color: var(--c-accent); }
  .key-findings li { font-size: 0.9rem; color: var(--c-muted); margin-bottom: 0.35rem; list-style: none; padding-left: 1.25rem; position: relative; }
  .key-findings li::before { content: '→'; position: absolute; left: 0; color: var(--c-accent); }
  .tool-runs { background: var(--c-surface); border: 1px solid var(--c-border); border-radius: 8px; padding: 1rem; margin-bottom: 2rem; }
  .tool-runs h2 { font-size: 1rem; margin-bottom: 0.75rem; color: var(--c-accent); }
  .tool-run-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 0.6rem; }
  .tool-run { border: 1px solid var(--c-border); border-radius: 6px; padding: 0.65rem 0.75rem; display: flex; flex-direction: column; gap: 0.25rem; }
  .tool-run span { color: var(--c-muted); font-size: 0.8rem; }
  .tool-run-missing { opacity: 0.7; }
  .manual-steps { padding-left: 1.25rem; color: var(--c-muted); font-size: 0.86rem; }
  .manual-steps li { margin-bottom: 0.75rem; }
  h2.section-title { font-size: 1rem; font-weight: 600; margin: 2rem 0 1rem; border-bottom: 1px solid var(--c-border); padding-bottom: 0.5rem; }
  .findings-list { display: flex; flex-direction: column; gap: 2.25rem; }
  .finding { background: var(--c-surface); border: 1px solid var(--c-border); border-left: 4px solid var(--c-accent); border-radius: 8px; overflow: hidden; box-shadow: 0 14px 28px rgba(0,0,0,0.22); }
  .finding-header { display: grid; grid-template-columns: auto auto auto minmax(0, 1fr) auto; align-items: center; gap: 0.65rem; padding: 0.9rem 1rem; background: rgba(255,255,255,0.03); border-bottom: 1px solid var(--c-border); }
  .severity-pill, .status-badge { font-size: 0.7rem; font-weight: 600; padding: 0.2rem 0.5rem; border-radius: 4px; text-transform: uppercase; letter-spacing: 0.04em; }
  .risk-score { font-size: 0.75rem; color: var(--c-muted); white-space: nowrap; }
  .finding-id { font-size: 0.8rem; color: var(--c-muted); }
  .finding-title { font-size: 0.95rem; min-width: 0; overflow-wrap: anywhere; }
  .finding-body { padding: 1.1rem; }
  .finding-details { display: grid; gap: 0.45rem; margin-bottom: 1rem; padding-bottom: 1rem; border-bottom: 1px solid var(--c-border); }
  .detail-row { display: grid; grid-template-columns: 7.5rem minmax(0, 1fr); gap: 0.75rem; font-size: 0.82rem; line-height: 1.45; }
  .detail-row dt { color: var(--c-muted); font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em; }
  .detail-row dd { color: var(--c-text); overflow-wrap: anywhere; }
  .meta-row { display: flex; flex-wrap: wrap; gap: 1rem; font-size: 0.8rem; color: var(--c-muted); margin-bottom: 0.75rem; }
  .snippet, .code-example { background: #0a1628; border: 1px solid var(--c-border); border-radius: 4px; padding: 0.6rem; font-size: 0.78rem; overflow-x: auto; color: #a5f3fc; margin: 0.5rem 0; white-space: pre-wrap; word-break: break-all; }
  .finding-analysis { display: grid; gap: 0.8rem; margin-top: 1rem; padding-top: 1rem; border-top: 1px solid var(--c-border); }
  .analysis-box { border-radius: 6px; padding: 0.85rem 0.95rem; font-size: 0.86rem; line-height: 1.55; }
  .analysis-label { font-size: 0.72rem; font-weight: 800; text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 0.35rem; }
  .analysis-text { color: var(--c-text); overflow-wrap: anywhere; }
  .evidence-box { background: rgba(56,189,248,0.08); border: 1px solid rgba(56,189,248,0.22); color: var(--c-text); margin-bottom: 0.9rem; }
  .manual-evidence { margin-bottom: 0.9rem; }
  .triage-reason { background: rgba(251,191,36,0.09); border: 1px solid rgba(251,191,36,0.28); color: #fbbf24; }
  .remediation { background: rgba(134,239,172,0.08); border: 1px solid rgba(134,239,172,0.24); color: #86efac; }
  .refs { font-size: 0.78rem; color: var(--c-muted); margin-top: 0.4rem; }
  @media (max-width: 760px) {
    body { padding: 1rem; }
    .finding-header { grid-template-columns: auto auto auto; }
    .finding-title, .risk-score { grid-column: 1 / -1; }
    .detail-row { grid-template-columns: 1fr; gap: 0.15rem; }
  }
  footer { margin-top: 3rem; text-align: center; font-size: 0.75rem; color: var(--c-muted); }
</style>
</head>
<body>
<h1>🔐 Security Report</h1>
<div class="meta">
  Project: <strong>${escHtml(project)}</strong> &nbsp;·&nbsp;
  Generated: ${ts} &nbsp;·&nbsp;
  Tools: ${escHtml(toolLabel)}
</div>

<div class="summary-grid">
  <div class="stat-card">
    <div class="stat-number" style="color:${SEVERITY_COLORS.critical}">${summary.critical_count ?? 0}</div>
    <div class="stat-label">Critical</div>
  </div>
  <div class="stat-card">
    <div class="stat-number" style="color:${SEVERITY_COLORS.high}">${summary.high_count ?? 0}</div>
    <div class="stat-label">High</div>
  </div>
  <div class="stat-card">
    <div class="stat-number" style="color:${SEVERITY_COLORS.medium}">${summary.medium_count ?? 0}</div>
    <div class="stat-label">Medium</div>
  </div>
  <div class="stat-card">
    <div class="stat-number" style="color:${SEVERITY_COLORS.low}">${summary.low_count ?? 0}</div>
    <div class="stat-label">Low</div>
  </div>
  <div class="stat-card">
    <div class="stat-number" style="color:var(--c-accent)">${summary.security_posture_score ?? '?'}</div>
    <div class="stat-label">Posture Score</div>
  </div>
  <div class="stat-card">
    <div class="stat-number" style="color:${
      summary.overall_risk === 'CRITICAL' ? SEVERITY_COLORS.critical
      : summary.overall_risk === 'HIGH'   ? SEVERITY_COLORS.high
      : summary.overall_risk === 'MEDIUM' ? SEVERITY_COLORS.medium
      : SEVERITY_COLORS.low}">${summary.overall_risk ?? '?'}</div>
    <div class="stat-label">Overall Risk</div>
  </div>
</div>

<div class="key-findings">
  <h2>Key Findings</h2>
  <ul>${(summary.key_findings ?? []).map(k => `<li>${escHtml(k)}</li>`).join('')}</ul>
  ${summary.immediate_actions?.length ? `
  <h2 style="margin-top:0.75rem">Immediate Actions</h2>
  <ul>${summary.immediate_actions.map(a => `<li>${escHtml(a)}</li>`).join('')}</ul>` : ''}
</div>

${toolRunsHtml}

${manualTestsHtml ? `
<h2 class="section-title">Manual Testing Checklist</h2>
${manualTestsHtml}` : ''}

<h2 class="section-title">Vulnerability Findings</h2>
${findingsHtml ? `<div class="findings-list">${findingsHtml}</div>` : '<p style="color:var(--c-muted)">No confirmed findings.</p>'}

<footer>Generated by AI-assisted DevSecOps Pipeline · Gemini 3.0 Flash · ${ts}</footer>
</body>
</html>`;
}

function escHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function formatRequestLocation({ method = '', url = '', param = '' }) {
  return [
    method ? String(method).toUpperCase() : '',
    url,
    param ? `param=${param}` : '',
  ].filter(Boolean).join(' ');
}

function formatZapSnippet({ evidence = '', attack = '', param = '' }) {
  const parts = [
    evidence ? `Evidence: ${evidence}` : '',
    attack ? `Attack: ${attack}` : '',
    param ? `Parameter: ${param}` : '',
  ].filter(Boolean);
  return parts.length ? parts.join('\n') : 'Evidence: N/A';
}

function normalizeZapLocationKey(f) {
  const url = f.url || f.location || '';
  let path = url;
  try {
    path = new URL(url.startsWith('http') ? url : `http://x${url}`).pathname.replace(/\/$/, '') || '/';
  } catch {
    path = String(url).replace(/[?#].*$/, '').replace(/\/$/, '') || '/';
  }

  const method = String(f.method ?? '').toUpperCase();
  const param = String(f.param ?? '');
  const evidence = String(f.evidence ?? '').slice(0, 120);
  return `${method}:${path}:${param}:${evidence}`;
}

function formatDisplayLocation(f) {
  if (f.file) {
    return f.line ? `${f.file}:${f.line}` : f.file;
  }
  return f.location || f.url || '';
}

function formatFindingTitle(f) {
  const original = f.original_finding ?? {};
  const base = original.message || original.ruleId || 'Security finding';
  const where = original.param
    ? `param ${original.param}`
    : original.line
      ? `line ${original.line}`
      : original.url || original.location || '';
  return where ? `${base} - ${where}` : base;
}

function extractEvidenceFromSnippet(snippet) {
  const text = String(snippet ?? '');
  const match = text.match(/^Evidence:\s*(.+)$/mi);
  return match?.[1]?.trim() ?? '';
}

function inferToolNames(findings) {
  const labels = {
    semgrep: 'Semgrep',
    bandit:  'Bandit',
    trivy:   'Trivy',
    zap:     'ZAP',
    nuclei:  'Nuclei',
    nikto:   'Nikto',
  };
  const names = new Set();
  for (const finding of findings ?? []) {
    const source = finding.original_finding?.source ?? finding.source;
    if (labels[source]) names.add(labels[source]);
  }
  return [...names];
}

function normalizeTriageSummary(triageResult) {
  const findings = triageResult.triaged_findings ?? [];
  const counts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };

  for (const finding of findings) {
    const severity = normalizeSeverity(finding.original_finding?.severity ?? 'unknown');
    counts[severity] = (counts[severity] ?? 0) + 1;
  }

  return {
    ...triageResult,
    executive_summary: {
      ...(triageResult.executive_summary ?? {}),
      critical_count: counts.critical,
      high_count: counts.high,
      medium_count: counts.medium,
      low_count: counts.low,
      finding_count: findings.length,
    },
  };
}

// ── Category/severity mappers ─────────────────────────────────────────────────

function mapSemgrepCategory(ruleId) {
  const id = ruleId.toLowerCase();
  if (id.includes('injection') || id.includes('sqli')) return 'sqli';
  if (id.includes('jwt') || id.includes('auth'))        return 'jwt';
  if (id.includes('xss'))                               return 'xss';
  if (id.includes('ssrf'))                              return 'ssrf';
  if (id.includes('path') || id.includes('traversal'))  return 'path_traversal';
  if (id.includes('secret') || id.includes('key'))      return 'secret';
  return 'general';
}

function mapSemgrepSeverity(s) {
  const m = { ERROR: 'critical', WARNING: 'high', INFO: 'medium' };
  return m[s.toUpperCase()] ?? 'medium';
}

function mapBanditCategory(testId) {
  const id = testId.toLowerCase();
  if (id.includes('sql'))    return 'sqli';
  if (id.includes('exec'))   return 'rce';
  if (id.includes('crypto')) return 'crypto';
  if (id.includes('hash'))   return 'crypto';
  if (id.startsWith('b10'))  return 'injection';
  return 'general';
}

function mapZapCategory(alertName) {
  const n = alertName.toLowerCase();
  if (n.includes('sql'))                           return 'sqli';
  if (n.includes('xss') || n.includes('script'))  return 'xss';
  if (n.includes('csrf'))                          return 'csrf';
  if (n.includes('path') || n.includes('traversal')) return 'path_traversal';
  if (n.includes('header') || n.includes('cors')) return 'misconfig';
  if (n.includes('auth') || n.includes('session')) return 'auth';
  return 'general';
}

function mapZapRisk(riskVal) {
  const v = String(riskVal).toLowerCase();
  if (v === '3' || v.includes('high'))   return 'high';
  if (v === '2' || v.includes('medium')) return 'medium';
  if (v === '1' || v.includes('low'))    return 'low';
  if (v === '0' || v.includes('info'))   return 'low';
  return 'medium';
}

function normalizeSeverity(s) {
  const v = String(s ?? '').toLowerCase();
  if (['critical', 'high', 'medium', 'low'].includes(v)) return v;
  if (v.includes('critical')) return 'critical';
  if (v.includes('high')) return 'high';
  if (v.includes('medium')) return 'medium';
  if (v.includes('low') || v.includes('info')) return 'low';
  return 'medium';
}

function normalizeCwe(cwe) {
  if (!cwe) return null;
  const value = Array.isArray(cwe) ? cwe[0] : cwe;
  const text = String(value);
  if (/^CWE-\d+$/i.test(text)) return text.toUpperCase();
  const match = text.match(/\d+/);
  return match ? `CWE-${match[0]}` : null;
}

function mapNucleiCategory(finding) {
  const tags = [
    ...(finding.info?.tags ? String(finding.info.tags).split(',') : []),
    finding['template-id'] ?? '',
    finding.info?.name ?? '',
  ].join(' ').toLowerCase();

  if (tags.includes('sqli') || tags.includes('sql')) return 'sqli';
  if (tags.includes('xss')) return 'xss';
  if (tags.includes('ssrf')) return 'ssrf';
  if (tags.includes('jwt') || tags.includes('auth')) return 'auth';
  if (tags.includes('file') || tags.includes('upload')) return 'file_upload';
  if (tags.includes('exposure') || tags.includes('exposed') || tags.includes('disclosure')) return 'info_leak';
  if (tags.includes('misconfig') || tags.includes('config')) return 'misconfig';
  if (tags.includes('cve')) return 'dependency';
  return 'general';
}

function mapNiktoCategory(message) {
  const msg = String(message ?? '').toLowerCase();
  if (msg.includes('xss') || msg.includes('script')) return 'xss';
  if (msg.includes('sql')) return 'sqli';
  if (msg.includes('header') || msg.includes('cors') || msg.includes('cookie')) return 'misconfig';
  if (msg.includes('directory') || msg.includes('file') || msg.includes('disclosure')) return 'info_leak';
  if (msg.includes('auth') || msg.includes('login')) return 'auth';
  return 'general';
}

function mapNiktoSeverity(message) {
  const msg = String(message ?? '').toLowerCase();
  if (msg.includes('critical') || msg.includes('remote command') || msg.includes('rce')) return 'critical';
  if (msg.includes('vulnerab') || msg.includes('xss') || msg.includes('sql') || msg.includes('disclosure')) return 'high';
  if (msg.includes('header') || msg.includes('cookie') || msg.includes('default')) return 'medium';
  return 'low';
}

// ── CLI runner (Stage 8 trong Jenkinsfile) ────────────────────────────────────

async function main() {
  const args        = process.argv.slice(2);
  const reportsDir  = args[0] ?? './scan-reports';
  const contextPath = args[1] ?? './security-context-output/context.json';
  const outputDir   = args[2] ?? './final-report';
  const apiKey      = process.env.GEMINI_API_KEY;

  if (!apiKey) {
    console.error('[ERROR] GEMINI_API_KEY not set');
    process.exit(1);
  }

  console.log('[INFO] Reading scan reports...');
  const reportSpecs = [
    { key: 'semgrep', label: 'Semgrep', file: 'semgrep-report.json', reader: readSemgrep },
    { key: 'bandit',  label: 'Bandit',  file: 'bandit-report.json',  reader: readBandit },
    { key: 'trivy',   label: 'Trivy FS',     file: 'trivy-report.json',        reader: readTrivyExtended },
    { key: 'trivy-image', label: 'Trivy Image',  file: 'trivy-image-report.json',  reader: (path) => readTrivyExtended(path, { reportType: 'container_image' }) },
    { key: 'trivy-config', label: 'Trivy Config', file: 'trivy-config-report.json', reader: (path) => readTrivyExtended(path, { reportType: 'config' }) },
    { key: 'zap',     label: 'ZAP',     file: 'zap-report.json',     reader: readZap },
    { key: 'nuclei',  label: 'Nuclei',  file: 'nuclei-report.jsonl', reader: readNuclei },
    { key: 'nikto',   label: 'Nikto',   file: 'nikto-report.json',   reader: readNikto },
  ];

  const reportRuns = reportSpecs.map(spec => {
    const path = join(reportsDir, spec.file);
    const exists = existsSync(path);
    const findings = exists ? spec.reader(path) : [];
    return { ...spec, path, exists, findingCount: findings.length, findings };
  });

  const allFindings = reportRuns.flatMap(run => run.findings);
  const toolsForReport = reportRuns
    .filter(run => run.exists)
    .map(run => run.label);
  const toolRunSummary = reportRuns.map(({ key, label, file, exists, findingCount }) => ({
    key,
    label,
    file,
    exists,
    findingCount,
  }));
  console.log(`[INFO] Total raw findings: ${allFindings.length}`);

  const deduped = deduplicate(allFindings);
  console.log(`[INFO] After deduplication: ${deduped.length} unique findings`);

  const context = JSON.parse(readFileSync(resolve(contextPath), 'utf8'));
  const triaged = normalizeTriageSummary(await triageWithGemini(deduped, context, { apiKey }));
  triaged.tool_runs = toolRunSummary;
  triaged.scan_summary = {
    raw_finding_count: allFindings.length,
    deduplicated_finding_count: deduped.length,
    triaged_finding_count: triaged.triaged_findings?.length ?? 0,
  };
  const manualTests = readManualTests(join(dirname(resolve(contextPath)), 'manual_tests.json'));

  mkdirSync(resolve(outputDir), { recursive: true });

  // HTML report
  const html = buildHtml(triaged, context, { manualTests, tools: toolsForReport });
  writeFileSync(join(resolve(outputDir), 'security-report.html'), html, 'utf8');
  console.log(`[OUTPUT] security-report.html → ${join(outputDir, 'security-report.html')}`);

  // JSON report (untuk integrasi lanjut)
  writeFileSync(join(resolve(outputDir), 'security-report.json'), JSON.stringify(triaged, null, 2), 'utf8');
  console.log(`[OUTPUT] security-report.json → ${join(outputDir, 'security-report.json')}`);

  const s = triaged.executive_summary;
  console.log(`\n[DONE] Risk: ${s?.overall_risk} | Posture: ${s?.security_posture_score}/100 | Critical: ${s?.critical_count} | High: ${s?.high_count} | Medium: ${s?.medium_count} | Low: ${s?.low_count}`);
}

import { fileURLToPath } from 'url';

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main().catch(err => { console.error('[FATAL]', err.message); process.exit(1); });
}
