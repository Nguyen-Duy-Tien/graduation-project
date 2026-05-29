// ai/reportGenerator.js
// Chức năng 3 của đề tài: Security Report Generator
//
// Flow:
//   readSemgrep() + readBandit() + readTrivy() + readZap()
//   → deduplicate() gộp finding trùng
//   → triageWithGemini() (Gemini Call #3) phân loại + risk score + remediation
//   → buildHtml() render security-report.html

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join, resolve } from 'path';
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

        findings.push({
          source:   'zap',
          ruleId:   String(alert.pluginid ?? alert.alertRef ?? ''),
          category: mapZapCategory(alert.alert ?? alert.name ?? ''),
          severity: mapZapRisk(alert.riskcode ?? alert.riskdesc ?? ''),
          location: alert.instances?.[0]?.uri ?? alert.url ?? site['@name'] ?? '',
          file:     '',
          line:     0,
          message:  alert.alert ?? alert.name ?? '',
          snippet:  `Evidence: ${alert.instances?.[0]?.evidence ?? alert.evidence ?? 'N/A'}`,
          cweId:    alert.cweid ? `CWE-${alert.cweid}` : null,
          owasp:    alert.wascid ? `WASC-${alert.wascid}` : null,
        });
      }
    }
    return findings;
  } catch (e) {
    console.warn(`[readZap] Parse error: ${e.message}`);
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
      ? new URL(f.location.startsWith('http') ? f.location : 'http://x' + f.location).pathname.replace(/\/$/, '')
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
1. Classify each finding: confirmed_vulnerability | likely_vulnerability | needs_manual_review | false_positive
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
    "key_findings": ["string"],
    "immediate_actions": ["string"]
  },
  "triaged_findings": [
    {
      "id": "F-001",
      "original_finding": { /* copy of input finding */ },
      "triage_status": "confirmed_vulnerability" | "likely_vulnerability" | "needs_manual_review" | "false_positive",
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

/**
 * Gọi Gemini để triage findings.
 * @param {object[]} deduplicatedFindings
 * @param {object}   context               — context.json để AI biết ngữ cảnh
 * @param {object}   options               — { apiKey }
 */
export async function triageWithGemini(deduplicatedFindings, context, options = {}) {
  const CHUNK_SIZE = 10; // Giới hạn 10 lỗi mỗi cụm gửi cho AI
  let allTriagedFindings = [];
  let summaryForReduce = [];

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
      ruleId: f.ruleId,
      message: f.message,
      location: f.location,
      snippet: f.snippet?.slice(0, 200)
    }));

    const mapPrompt = `
      You are a precise security triager for a ${context.techStack?.framework ?? 'web'} application.
      Analyze this subset of tool findings:
      ${JSON.stringify(chunkPayload)}

      Output STRICT JSON exactly matching this schema. Keep reasons to 1 sentence.
      {
        "results": [
          {
            "id": "F-001",
            "triage_status": "confirmed_vulnerability" | "likely_vulnerability" | "needs_manual_review" | "false_positive",
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

        allTriagedFindings.push({
          id: findingId,
          original_finding: rawFinding,
          triage_status: aiVerdict.triage_status || 'needs_manual_review',
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
          status: aiVerdict.triage_status || 'needs_manual_review'
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
    finalExecutiveSummary = { overall_risk: "UNKNOWN", security_posture_score: 0, critical_count: 0, high_count: 0, medium_count: 0, key_findings: ["Pipeline fallback executed."] };
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
  false_positive:          { label: 'False Positive', bg: '#f0fdf4', color: '#166534' },
};

export function buildHtml(triageResult, context, metadata = {}) {
  const summary  = triageResult.executive_summary ?? {};
  const findings = triageResult.triaged_findings ?? [];
  const ts       = new Date().toISOString();
  const project  = `${context.techStack?.language ?? '?'} / ${context.techStack?.framework ?? '?'}`;

  const findingsHtml = findings
    .filter(f => f.triage_status !== 'false_positive')
    .map(f => {
      const sev   = f.original_finding?.severity ?? 'unknown';
      const badge = STATUS_BADGE[f.triage_status] ?? STATUS_BADGE.needs_manual_review;
      const refs  = f.remediation?.references?.join(', ') ?? '';
      return `
      <div class="finding" data-severity="${sev}">
        <div class="finding-header">
          <span class="severity-pill" style="background:${SEVERITY_COLORS[sev]}20;color:${SEVERITY_COLORS[sev]};border:1px solid ${SEVERITY_COLORS[sev]}40">
            ${sev.toUpperCase()}
          </span>
          <span class="status-badge" style="background:${badge.bg};color:${badge.color}">
            ${badge.label}
          </span>
          <span class="risk-score">Risk: ${f.risk_score ?? '?'}/100</span>
          <strong class="finding-id">${f.id}</strong>
          <span class="finding-title">${escHtml(f.original_finding?.message ?? '')}</span>
        </div>
        <div class="finding-body">
          <div class="meta-row">
            <span>📁 ${escHtml(f.original_finding?.location ?? '')}</span>
            <span>🔧 ${escHtml(f.original_finding?.source ?? '')}</span>
            ${f.original_finding?.cweId ? `<span>🏷️ ${escHtml(f.original_finding.cweId)}</span>` : ''}
          </div>
          ${f.original_finding?.snippet ? `<pre class="snippet">${escHtml(f.original_finding.snippet)}</pre>` : ''}
          <div class="triage-reason"><strong>Triage:</strong> ${escHtml(f.triage_reason ?? '')}</div>
          <div class="remediation">
            <strong>Fix:</strong> ${escHtml(f.remediation?.summary ?? '')}
            ${f.remediation?.code_example ? `<pre class="code-example">${escHtml(f.remediation.code_example)}</pre>` : ''}
            ${refs ? `<div class="refs">References: ${escHtml(refs)}</div>` : ''}
          </div>
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
  h2.section-title { font-size: 1rem; font-weight: 600; margin: 2rem 0 1rem; border-bottom: 1px solid var(--c-border); padding-bottom: 0.5rem; }
  .finding { background: var(--c-surface); border: 1px solid var(--c-border); border-radius: 8px; margin-bottom: 1rem; overflow: hidden; }
  .finding-header { display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem; padding: 0.75rem 1rem; background: rgba(255,255,255,0.02); border-bottom: 1px solid var(--c-border); }
  .severity-pill, .status-badge { font-size: 0.7rem; font-weight: 600; padding: 0.2rem 0.5rem; border-radius: 4px; text-transform: uppercase; letter-spacing: 0.04em; }
  .risk-score { font-size: 0.75rem; color: var(--c-muted); margin-left: auto; }
  .finding-id { font-size: 0.8rem; color: var(--c-muted); }
  .finding-title { font-size: 0.9rem; flex: 1; min-width: 200px; }
  .finding-body { padding: 1rem; }
  .meta-row { display: flex; flex-wrap: wrap; gap: 1rem; font-size: 0.8rem; color: var(--c-muted); margin-bottom: 0.75rem; }
  .snippet, .code-example { background: #0a1628; border: 1px solid var(--c-border); border-radius: 4px; padding: 0.6rem; font-size: 0.78rem; overflow-x: auto; color: #a5f3fc; margin: 0.5rem 0; white-space: pre-wrap; word-break: break-all; }
  .triage-reason { font-size: 0.85rem; color: #fbbf24; margin-bottom: 0.5rem; }
  .remediation { font-size: 0.85rem; color: #86efac; }
  .refs { font-size: 0.78rem; color: var(--c-muted); margin-top: 0.4rem; }
  footer { margin-top: 3rem; text-align: center; font-size: 0.75rem; color: var(--c-muted); }
</style>
</head>
<body>
<h1>🔐 Security Report</h1>
<div class="meta">
  Project: <strong>${escHtml(project)}</strong> &nbsp;·&nbsp;
  Generated: ${ts} &nbsp;·&nbsp;
  Tools: Semgrep · Bandit · Trivy · ZAP · AI Triage (Gemini 3.0 Flash)
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

<h2 class="section-title">Vulnerability Findings</h2>
${findingsHtml || '<p style="color:var(--c-muted)">No confirmed findings.</p>'}

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
  const allFindings = [
    ...readSemgrep(join(reportsDir, 'semgrep-report.json')),
    ...readBandit(join(reportsDir, 'bandit-report.json')),
    ...readTrivy(join(reportsDir, 'trivy-report.json')),
    ...readZap(join(reportsDir, 'zap-report.json')),
  ];
  console.log(`[INFO] Total raw findings: ${allFindings.length}`);

  const deduped = deduplicate(allFindings);
  console.log(`[INFO] After deduplication: ${deduped.length} unique findings`);

  const context = JSON.parse(readFileSync(resolve(contextPath), 'utf8'));
  const triaged = await triageWithGemini(deduped, context, { apiKey });

  mkdirSync(resolve(outputDir), { recursive: true });

  // HTML report
  const html = buildHtml(triaged, context);
  writeFileSync(join(resolve(outputDir), 'security-report.html'), html, 'utf8');
  console.log(`[OUTPUT] security-report.html → ${join(outputDir, 'security-report.html')}`);

  // JSON report (untuk integrasi lanjut)
  writeFileSync(join(resolve(outputDir), 'security-report.json'), JSON.stringify(triaged, null, 2), 'utf8');
  console.log(`[OUTPUT] security-report.json → ${join(outputDir, 'security-report.json')}`);

  const s = triaged.executive_summary;
  console.log(`\n[DONE] Risk: ${s?.overall_risk} | Posture: ${s?.security_posture_score}/100 | Critical: ${s?.critical_count} | High: ${s?.high_count}`);
}

import { fileURLToPath } from 'url';

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main().catch(err => { console.error('[FATAL]', err.message); process.exit(1); });
}
