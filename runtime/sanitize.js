// runtime/sanitize.js
// Whitelist regex cho mọi giá trị động trước khi nội suy vào shell command.
//
// Hai chế độ xử lý:
//   - assertX(value)        → throw nếu sai (single-value: mode, port, service, network)
//   - sanitizeArrayX(items) → drop entry sai, log warning (multi-value: rulesets, tags, paths)
//
// Lý do: với array, một entry xấu không nên kill toàn pipeline — chỉ disable tool nếu
// array rỗng sau khi sanitize. Với single-value, sai = không có cách dùng → fail-fast.

// ── Whitelist patterns ────────────────────────────────────────────────────────

const PATTERNS = {
  ruleset:      /^p\/[a-z0-9][a-z0-9-]{1,60}$/,
  nucleiTag:    /^[a-z0-9][a-z0-9_-]{0,40}$/,
  severityList: /^(low|medium|high|critical)(,(low|medium|high|critical))*$/,
  zapMode:      /^(baseline|api-scan|full-scan)$/,
  serviceName:  /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$/,
  networkName:  /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$/,
  port:         /^[1-9][0-9]{0,4}$/,
  focusPath:    /^\/[a-zA-Z0-9_\-/.~%]{0,200}$/,
  trivyTarget:  /^(fs|image|config)$/,
  imageRef:     /^(?:[a-z0-9][a-z0-9.-]*(?::[1-9][0-9]{0,4})?\/)?[a-z0-9][a-z0-9._/-]{0,200}(?::[\w.-]{1,128})?(?:@sha256:[a-f0-9]{64})?$/,
};

// ── Single-value asserters (throw on fail) ────────────────────────────────────

function makeAsserter(label, regex, extraCheck) {
  return function assert(value) {
    if (typeof value !== 'string') {
      throw new Error(`[sanitize] ${label}: expected string, got ${typeof value}`);
    }
    if (!regex.test(value)) {
      throw new Error(`[sanitize] ${label}: invalid value "${truncate(value)}" (does not match ${regex})`);
    }
    if (extraCheck) extraCheck(value);
    return value;
  };
}

export const assertRuleset      = makeAsserter('ruleset',      PATTERNS.ruleset);
export const assertNucleiTag    = makeAsserter('nucleiTag',    PATTERNS.nucleiTag);
export const assertSeverityList = makeAsserter('severityList', PATTERNS.severityList);
export const assertZapMode      = makeAsserter('zapMode',      PATTERNS.zapMode);
export const assertServiceName  = makeAsserter('serviceName',  PATTERNS.serviceName);
export const assertNetworkName  = makeAsserter('networkName',  PATTERNS.networkName);
export const assertFocusPath    = makeAsserter('focusPath',    PATTERNS.focusPath);
export const assertTrivyTarget  = makeAsserter('trivyTarget',  PATTERNS.trivyTarget);
export const assertImageRef     = makeAsserter('imageRef',     PATTERNS.imageRef);

export const assertPort = makeAsserter('port', PATTERNS.port, (v) => {
  const n = Number(v);
  if (n < 1 || n > 65535) throw new Error(`[sanitize] port: ${n} out of range 1–65535`);
});

// ── Array sanitizers (drop invalid entries) ───────────────────────────────────

function makeArraySanitizer(label, regex) {
  return function sanitize(items) {
    if (!Array.isArray(items)) return [];
    const kept = [];
    for (const item of items) {
      if (typeof item === 'string' && regex.test(item)) {
        kept.push(item);
      } else {
        console.warn(`[sanitize] ${label}: dropped "${truncate(String(item))}"`);
      }
    }
    return kept;
  };
}

export const sanitizeRulesets    = makeArraySanitizer('rulesets',    PATTERNS.ruleset);
export const sanitizeNucleiTags  = makeArraySanitizer('nucleiTags',  PATTERNS.nucleiTag);
export const sanitizeFocusPaths  = makeArraySanitizer('focusPaths',  PATTERNS.focusPath);
export const sanitizeTrivyTargets = makeArraySanitizer('trivyTargets', PATTERNS.trivyTarget);
export const sanitizeImageRefs = makeArraySanitizer('imageRefs', PATTERNS.imageRef);

// ── Shell quote (single-quote escape, POSIX-safe) ─────────────────────────────
// Dùng cho path có space/Unicode (vd. "E:\đồ án tốt nghiệp\")

export function shellQuote(str) {
  if (typeof str !== 'string') throw new Error('[sanitize] shellQuote: expected string');
  return `'${str.replace(/'/g, `'\\''`)}'`;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function truncate(s, n = 80) {
  return s.length > n ? s.slice(0, n) + '…' : s;
}
