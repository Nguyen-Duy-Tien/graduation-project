// ai/geminiClient.js
// Wrapper thuần gọi Gemini 2.0 Flash API
// Dùng fetch native (Node.js ≥ 18) — không cần SDK
//
// Exports:
//   callGemini(prompt, systemInstruction, options)
//   callGeminiWithRetry(prompt, systemInstruction, options)  ← tự retry 3 lần
//   parseJson(rawText)                                        ← strip fences + parse

const GEMINI_ENDPOINT = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-3.0-flash:generateContent';

// Retry config
const MAX_RETRIES    = 5; // Tăng lên 5 lần thử
const RETRY_DELAYS   = [10000, 30000, 60000, 90000, 120000];
const RETRYABLE_CODES = new Set([429, 500, 502, 503, 504]);

// ── Safety filter override ────────────────────────────────────────────────────
// Pentest content (sql injection, jwt bypass, xss...) bị Gemini block mặc định
// Cần tắt toàn bộ 4 category để nhận response đầy đủ
const SAFETY_SETTINGS_OFF = [
  { category: 'HARM_CATEGORY_HARASSMENT',        threshold: 'BLOCK_NONE' },
  { category: 'HARM_CATEGORY_HATE_SPEECH',       threshold: 'BLOCK_NONE' },
  { category: 'HARM_CATEGORY_SEXUALLY_EXPLICIT', threshold: 'BLOCK_NONE' },
  { category: 'HARM_CATEGORY_DANGEROUS_CONTENT', threshold: 'BLOCK_NONE' },
];

// ── Core request builder ──────────────────────────────────────────────────────

function buildRequestBody(prompt, systemInstruction, options = {}) {
  const body = {
    // JSON mode native → response luôn là JSON hợp lệ
    generationConfig: {
      temperature:      options.temperature     ?? 0.15,
      topP:             options.topP            ?? 0.95,
      topK:             options.topK            ?? 40,
      maxOutputTokens:  options.maxOutputTokens ?? 8192,
      responseMimeType: 'application/json',
    },
    safetySettings: SAFETY_SETTINGS_OFF,
    contents: [
      {
        role:  'user',
        parts: [{ text: prompt }],
      },
    ],
  };

  if (systemInstruction) {
    body.systemInstruction = {
      role:  'user',
      parts: [{ text: systemInstruction }],
    };
  }

  return body;
}

// ── Single call ───────────────────────────────────────────────────────────────

/**
 * Gọi Gemini API một lần.
 * @param {string} prompt
 * @param {string|null} systemInstruction
 * @param {object} options   — { temperature, maxOutputTokens, ... }
 * @returns {Promise<{text: string, usageMetadata: object, finishReason: string}>}
 */
export async function callGemini(prompt, systemInstruction = null, options = {}) {
  const apiKey = options.apiKey ?? process.env.GEMINI_API_KEY;
  if (!apiKey) throw new Error('GEMINI_API_KEY not set');

  const url      = `${GEMINI_ENDPOINT}?key=${apiKey}`;
  const bodyJson = JSON.stringify(buildRequestBody(prompt, systemInstruction, options));

  const response = await fetch(url, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    bodyJson,
  });

  if (!response.ok) {
    const errText = await response.text().catch(() => '');
    const error   = new Error(`Gemini API error ${response.status}: ${errText.slice(0, 200)}`);
    error.status  = response.status;
    throw error;
  }

  const data = await response.json();

  // Kiểm tra finish reason
  const candidate    = data.candidates?.[0];
  const finishReason = candidate?.finishReason ?? 'UNKNOWN';

  if (finishReason === 'SAFETY') {
    throw new Error('Gemini blocked response due to safety filters (safety settings may not have applied)');
  }
  if (finishReason === 'MAX_TOKENS') {
    console.warn('[GEMINI] Response truncated due to MAX_TOKENS — consider reducing context size');
  }

  const text = candidate?.content?.parts
    ?.map(p => p.text ?? '')
    .join('') ?? '';

  return {
    text,
    finishReason,
    usageMetadata: data.usageMetadata ?? {},
  };
}

// ── Retry wrapper ─────────────────────────────────────────────────────────────

/**
 * Gọi Gemini với auto-retry tối đa 3 lần khi gặp 429/500/503.
 * @param {string} prompt
 * @param {string|null} systemInstruction
 * @param {object} options
 * @returns {Promise<{text: string, usageMetadata: object, finishReason: string}>}
 */
export async function callGeminiWithRetry(prompt, systemInstruction = null, options = {}) {
  let lastError;

  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    try {
      const result = await callGemini(prompt, systemInstruction, options);
      if (attempt > 0) {
        console.log(`[GEMINI] Succeeded on attempt ${attempt + 1}`);
      }
      return result;
    } catch (err) {
      lastError = err;
      const status = err.status ?? 0;

      if (!RETRYABLE_CODES.has(status)) {
        // Non-retryable error (4xx khác 429) — fail immediately
        throw err;
      }

      if (attempt < MAX_RETRIES - 1) {
        const delay = RETRY_DELAYS[attempt];
        console.warn(`[GEMINI] Attempt ${attempt + 1} failed (${status}) — retrying in ${delay}ms...`);
        await new Promise(r => setTimeout(r, delay));
      }
    }
  }

  throw new Error(`Gemini API failed after ${MAX_RETRIES} attempts: ${lastError?.message}`);
}

// ── JSON parser ───────────────────────────────────────────────────────────────

/**
 * Strip markdown fences và parse JSON từ Gemini response text.
 * Dù đã dùng responseMimeType=application/json, đôi khi model vẫn bọc trong fences.
 * @param {string} rawText
 * @returns {object}
 */
export function parseJson(rawText) {
  if (!rawText || typeof rawText !== 'string') {
    throw new Error('parseJson: empty or non-string input');
  }

  let cleaned = rawText.trim();

  // Strip ```json ... ``` hoặc ``` ... ```
  cleaned = cleaned.replace(/^```(?:json)?\s*\n?/i, '').replace(/\n?```\s*$/i, '').trim();

  // Strip leading/trailing text nếu JSON bắt đầu với { hoặc [
  const jsonStart = cleaned.search(/[{[]/);
  const jsonEnd   = Math.max(cleaned.lastIndexOf('}'), cleaned.lastIndexOf(']'));

  if (jsonStart > 0) cleaned = cleaned.slice(jsonStart);
  if (jsonEnd > 0 && jsonEnd < cleaned.length - 1) {
    cleaned = cleaned.slice(0, jsonEnd + 1);
  }

  try {
    return JSON.parse(cleaned);
  } catch (err) {
    throw new Error(`parseJson failed: ${err.message}\nRaw (first 300 chars): ${rawText.slice(0, 300)}`);
  }
}

// ── Usage logging helper ──────────────────────────────────────────────────────

export function logUsage(callName, usageMetadata) {
  const { promptTokenCount = 0, candidatesTokenCount = 0, totalTokenCount = 0 } = usageMetadata;
  console.log(`[GEMINI] ${callName} | in: ${promptTokenCount} | out: ${candidatesTokenCount} | total: ${totalTokenCount} tokens`);
}
