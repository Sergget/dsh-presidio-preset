/**
 * Host half of dsh-pii-guard-terms.
 *
 * The browser half (settings page) needs a tiny JSON API to list and persist
 * the custom terms the PII guard must redact. We keep the terms in the very
 * file the Python redaction service reads as its custom rule source, so a term
 * saved in the UI reaches the redaction pipeline within the rule reload
 * interval (CustomRuleSet.refresh, one second by default) instead of living
 * in a config blob nothing consumes.
 *
 * Route shape follows the harness conventions:
 *   GET  /api/dsh-pii-guard/terms        -> list terms
 *   POST /api/dsh-pii-guard/terms/save   -> replace the term list
 *   GET  /api/dsh-pii-guard/settings     -> read guard runtime settings (P0/P1)
 *   POST /api/dsh-pii-guard/settings/save -> write guard runtime settings
 *
 * The host server matches routes by pathname only, so the paths above are
 * absolute; the browser half builds the same absolute URLs.
 *
 * Runtime settings live in .pii_presidio_store/guard-settings.json — the same
 * single source of truth the guard plugin reads on every event, so a change
 * made here takes effect on the next tool call without restarting DSH.
 */
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

export const name = 'dsh-pii-guard-terms';
export const inject = [];

const API_LIST = '/api/dsh-pii-guard/terms';
const API_SAVE = '/api/dsh-pii-guard/terms/save';
const API_SETTINGS = '/api/dsh-pii-guard/settings';
const API_SETTINGS_SAVE = '/api/dsh-pii-guard/settings/save';
const API_PRESET = '/api/dsh-pii-guard/preset';
const API_PRESET_SAVE = '/api/dsh-pii-guard/preset/save';

/**
 * Repository root. Overridable so the bundle stays portable: an env var (same
 * `PII_GUARD_REPO` the guard plugin honours) or the bundle config `repo` wins,
 * and only then does the build-time default apply. Every derived path below —
 * including the one `warnIfPathDrift` resolves preset-relative paths against —
 * follows this value, so moving the checkout moves the whole config surface.
 */
// FIX-1: 默认兜底不再写死作者路径，改为从 import.meta.url 推断仓库候选。
//   本插件位于 <root>/plugins/dsh-pii-guard-terms/lib/index.js；从 lib 目录向上三级
//   才是 root（lib -> dsh-pii-guard-terms -> plugins -> root）。部署态 root 是 DSH_HOME
//   （无 presidio_pii/server.py），仓库态则是仓库根（含 presidio_pii/server.py）。
//   用该哨兵文件区分：命中则返回仓库根；否则返回空串并由调用方告警要求显式配置。
function inferRepoFromModule() {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    const candidate = resolve(here, '..', '..', '..');
    return existsSync(resolve(candidate, 'presidio_pii', 'server.py'))
      ? candidate.replace(/\\/g, '/').replace(/\/+$/, '')
      : '';
  } catch {
    return '';
  }
}
const DEFAULT_REPO = inferRepoFromModule();
function resolveRepo(rawConfig) {
  const fromConfig = typeof rawConfig?.repo === 'string' ? rawConfig.repo.trim() : '';
  const fromEnv = typeof process.env.PII_GUARD_REPO === 'string' ? process.env.PII_GUARD_REPO.trim() : '';
  const resolved = (fromConfig || fromEnv || DEFAULT_REPO).replace(/\\/g, '/').replace(/\/+$/, '');
  if (!resolved) {
    console.error('[dsh-pii-guard-terms] 无法确定仓库根：请配置 bundle config.repo 或环境变量 PII_GUARD_REPO（默认推断失败，插件部署在 DSH_HOME 时无法自动定位仓库）。');
  }
  return resolved;
}
const DEFAULT_TERMS_FILE = '/.pii_presidio_store/user_terms_rules.json';
const DEFAULT_SETTINGS_FILE = '/.pii_presidio_store/guard-settings.json';
const DEFAULT_PRESET_FILE = '/.agent-presets/presidio-pii/preset.json';
const DEFAULT_MAX_TERMS = 500;
const DEFAULT_MAX_TERM_LENGTH = 200;
const MAX_BODY_BYTES = 64 * 1024;

const ENTITY_TYPE = 'USER_TERM';
const PLACEHOLDER_NAME = 'user-term-placeholder';
/** A pattern that can never match; used to represent an empty term list. */
const NEVER_MATCH = '(?!)';
/** Control characters are never allowed inside a term. */
const CONTROL_CHARS = /[\u0000-\u001F\u007F]/;

/** Defaults mirror the guard plugin's ENV_FALLBACK; env wins when no file field exists. */
const SETTINGS_DEFAULTS = {
  displayMode: (['full', 'mask', 'off'].includes(String(process.env.PII_GUARD_DISPLAY ?? 'full').toLowerCase())
    ? String(process.env.PII_GUARD_DISPLAY ?? 'full').toLowerCase() : 'full'),
  failOpen: (process.env.PII_GUARD_FAIL_OPEN ?? '').toLowerCase() === '1',
  shellDisabled: (process.env.PII_GUARD_SHELL ?? '').toLowerCase() === 'off',
  shellAllowlist: process.env.PII_GUARD_SHELL_ALLOWLIST ?? '',
};
const SETTINGS_KEYS = ['displayMode', 'failOpen', 'shellDisabled', 'shellAllowlist'];

/** Escape a literal so Python's re treats it as plain text. */
function escapeLiteral(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, (ch) => `\\${ch}`);
}

function writeJson(res, status, payload) {
  res.statusCode = status;
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.setHeader('cache-control', 'no-store');
  res.setHeader('referrer-policy', 'no-referrer');
  res.setHeader('x-content-type-options', 'nosniff');
  res.end(JSON.stringify(payload));
}

function isLoopbackRequest(req) {
  const address = req?.socket?.remoteAddress ?? '';
  if (!address) return false;
  return address === '::1' || address === '127.0.0.1' || address.startsWith('127.')
    || address === '::ffff:127.0.0.1';
}

/**
 * The exact DSH browser-session cookie name for a host: `dsh-auth-` +
 * base64url(sha256(authority)), where authority is the URL-normalised host
 * (see dsh-client-connection/lib/index.js cookieName/requestAudience). Matching
 * the real name — instead of accepting any non-empty Cookie — stops a forged
 * `Cookie: foo=1` header from faking a same-origin proof. The cookie value's
 * HMAC signature is verified by the harness' own authenticate(); here we only
 * require the correctly-named cookie to be present as same-origin evidence.
 */
function sessionCookieName(host) {
  try {
    const authority = new URL(`http://${host}`).host;
    const digest = createHash('sha256').update(authority).digest();
    const encoded = digest.toString('base64').replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
    return `dsh-auth-${encoded}`;
  } catch {
    return null;
  }
}

function hasSessionCookie(req) {
  const headers = req?.headers ?? {};
  const host = typeof headers.host === 'string' ? headers.host : '';
  const cookie = headers.cookie;
  if (!host || typeof cookie !== 'string' || cookie.length === 0) return false;
  const name = sessionCookieName(host);
  if (!name) return false;
  for (const segment of cookie.split(';')) {
    const at = segment.indexOf('=');
    if (at === -1) continue;
    if (segment.slice(0, at).trim() !== name) continue;
    if (segment.slice(at + 1).trim().length > 0) return true;
  }
  return false;
}

/**
 * Same-origin proof. A browser fetch from the settings page carries
 * `Sec-Fetch-Site: same-origin` (or an Origin header); the desktop shell
 * forwards requests without those headers but keeps the host session cookie.
 */
function hasSameOriginProof(req) {
  const headers = req?.headers ?? {};
  const site = typeof headers['sec-fetch-site'] === 'string' ? headers['sec-fetch-site'] : '';
  if (site === 'cross-site') return false;
  const origin = typeof headers.origin === 'string' ? headers.origin : '';
  if (origin) {
    try {
      const parsed = new URL(origin);
      return typeof headers.host === 'string' && parsed.host === headers.host;
    } catch {
      return false;
    }
  }
  if (site === 'same-origin' || site === 'none') return true;
  return hasSessionCookie(req);
}

/** Loopback + method + same-origin proof, in that order. */
function guard(req, res, method) {
  const headers = req?.headers ?? {};
  if (typeof headers.host !== 'string' || headers.host.length === 0) {
    writeJson(res, 400, { error: 'missing host header' });
    return false;
  }
  if (!isLoopbackRequest(req)) {
    writeJson(res, 403, { error: 'forbidden: loopback-only' });
    return false;
  }
  const actual = String(req?.method ?? '').toUpperCase();
  if (actual !== method) {
    writeJson(res, 405, { error: `method not allowed: ${actual}` });
    return false;
  }
  if (!hasSameOriginProof(req)) {
    writeJson(res, 403, { error: 'forbidden: missing same-origin proof' });
    return false;
  }
  return true;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error('request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

/**
 * Normalize the term list coming from the browser. Terms are plain literal
 * strings; anything that could smuggle a regex or break the rule file is
 * rejected instead of being silently reinterpreted.
 */
function normalizeTerms(input, config) {
  if (!Array.isArray(input)) throw new Error('terms must be an array');
  const seen = new Set();
  const out = [];
  for (const raw of input) {
    if (typeof raw !== 'string') throw new Error('each term must be a string');
    const term = raw.trim();
    if (!term) continue;
    if (term.length > config.maxTermLength) {
      throw new Error(`term too long: ${term.length} > ${config.maxTermLength}`);
    }
    if (CONTROL_CHARS.test(term)) {
      throw new Error('term contains control characters');
    }
    if (seen.has(term)) continue;
    seen.add(term);
    out.push(term);
    if (out.length > config.maxTerms) {
      throw new Error(`too many terms: limit is ${config.maxTerms}`);
    }
  }
  return out;
}

/** Read the terms back out of the rule file (the rule file is the source of truth). */
function readTerms(termsFile) {
  if (!existsSync(termsFile)) return [];
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(termsFile, 'utf8'));
  } catch {
    return [];
  }
  if (!Array.isArray(parsed)) return [];
  const seen = new Set();
  const out = [];
  let unrecognized = 0;
  for (const row of parsed) {
    if (!row || typeof row !== 'object') continue;
    if (row.entity_type !== ENTITY_TYPE) continue;
    if (row.name === PLACEHOLDER_NAME) continue; // never-matching sentinel, not a term
    const term = typeof row.term === 'string' ? row.term : '';
    if (!term || seen.has(term)) continue;
    seen.add(term);
    out.push(term);
  }
  // S3: rows written by hand may lack the custom `term` key. Unescape the
  // `pattern` back to the literal term so a manual edit shows up in the list
  // instead of being silently wiped by the next save. Only safe escapes the
  // UI itself produces (escapeLiteral) are reversed; anything else counts as
  // unrecognized and is reported, never auto-adopted.
  for (const row of parsed) {
    if (!row || typeof row !== 'object') continue;
    if (row.entity_type !== ENTITY_TYPE) continue;
    if (row.name === PLACEHOLDER_NAME) continue;
    if (typeof row.term === 'string' && row.term) continue; // already handled above
    const pattern = typeof row.pattern === 'string' ? row.pattern : '';
    if (!pattern) continue;
    const literal = unescapeLiteral(pattern);
    if (literal === null || literal === '' || seen.has(literal)) {
      unrecognized += 1;
      continue;
    }
    seen.add(literal);
    out.push(literal);
  }
  if (unrecognized > 0) {
    console.error(`[dsh-pii-guard-terms] readTerms: ${unrecognized} USER_TERM rule(s) could not be mapped back to a literal term (real regex patterns). They are preserved verbatim on the next save but cannot be edited via the UI.`);
  }
  return out;
}

/**
 * S3: rows that must survive a UI save untouched — USER_TERM rules with no
 * usable `term` key whose pattern is not a UI-written literal (real regexes).
 * writeTerms re-appends them verbatim so a hand-maintained rule is never lost.
 */
function unrecognizedRuleRows(termsFile) {
  if (!existsSync(termsFile)) return [];
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(termsFile, 'utf8'));
  } catch {
    return [];
  }
  if (!Array.isArray(parsed)) return [];
  const adopted = new Set(readTerms(termsFile));
  const kept = [];
  for (const row of parsed) {
    if (!row || typeof row !== 'object') continue;
    if (row.entity_type !== ENTITY_TYPE || row.name === PLACEHOLDER_NAME) continue;
    if (typeof row.term === 'string' && row.term) continue;
    const literal = typeof row.pattern === 'string' ? unescapeLiteral(row.pattern) : null;
    if (literal !== null && literal !== '' && adopted.has(literal)) continue;
    kept.push(row);
  }
  return kept;
}

/**
 * S3: inverse of escapeLiteral for patterns the UI itself wrote. Returns null
 * when the pattern contains anything beyond plain text + the exact escapes
 * escapeLiteral emits (regex syntax, unknown escapes, quantifiers), so a
 * hand-written real regex is never misread as a literal term.
 */
function unescapeLiteral(pattern) {
  if (pattern.length === 0) return '';
  let out = '';
  for (let i = 0; i < pattern.length; i += 1) {
    const ch = pattern[i];
    if (ch === '\\') {
      const next = pattern[i + 1];
      // escapeLiteral only ever emits `\<x>` escapes for [.*+?^${}()|[\]\\]
      if (next !== undefined && /^[.*+?^${}()|[\]\\]$/.test(next)) {
        out += next;
        i += 1;
        continue;
      }
      return null; // \d, \b, \uXXXX... -> a real regex, not a literal
    }
    // Any bare regex metacharacter means this pattern is not a plain literal.
    if (/[.*+?^${}()|[\]]/.test(ch)) return null;
    out += ch;
  }
  return out;
}

/**
 * Write the term list as custom rules.
 *
 * The empty list is written as a single never-matching rule on purpose: the
 * rule loader keeps the previous rule set when a reload yields zero rules,
 * so an empty array would silently keep redacting the old terms.
 */
function writeTerms(termsFile, terms, preserveRows) {
  const rules = terms.map((term, index) => ({
    name: `user-term-${String(index + 1).padStart(4, '0')}`,
    entity_type: ENTITY_TYPE,
    pattern: escapeLiteral(term),
    score: 0.95,
    priority: 0,
    term,
  }));
  const payload = (rules.length > 0 || (preserveRows?.length ?? 0) > 0)
    ? [...rules, ...(preserveRows ?? [])]
    : [{
      name: PLACEHOLDER_NAME,
      entity_type: ENTITY_TYPE,
      pattern: NEVER_MATCH,
      score: 0,
      priority: 0,
      term: '',
    }];
  mkdirSync(dirname(termsFile), { recursive: true });
  const tmp = `${termsFile}.tmp`;
  writeFileSync(tmp, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
  renameSync(tmp, termsFile);
  return rules.length;
}

/** Read the runtime guard settings (P0/P1); the file is the single source of truth. */
/**
 * Preset-level knobs the guard consumes: which entity types stay enabled and
 * which whitelist file protects terms from redaction. Kept in preset.json
 * (not guard-settings.json) because the Python engine reads them from there;
 * the hook hot-reloads on preset mtime change, so a save here takes effect on
 * the next call without restarting DSH.
 */
const PRESET_DEFAULT_ENTITY_TYPES = [
  'ID_NUMBER', 'PHONE_NUMBER', 'EMAIL_ADDRESS', 'CREDIT_CODE', 'BANK_CARD',
  'PASSPORT', 'LICENSE_PLATE', 'IP_ADDRESS', 'MAC_ADDRESS', 'PERSON',
  'LOCATION', 'ORGANIZATION', 'JOB_TITLE',
];

function readPreset(presetFile) {
  let data = {};
  try {
    if (existsSync(presetFile)) {
      const parsed = JSON.parse(readFileSync(presetFile, 'utf8'));
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) data = parsed;
    }
  } catch {
    data = {};
  }
  const types = Array.isArray(data.entity_types) ? data.entity_types : PRESET_DEFAULT_ENTITY_TYPES;
  return {
    entityTypes: types.filter((t) => typeof t === 'string' && t.trim()).map((t) => t.trim()),
    whitelistPath: typeof data.config?.whitelist_path === 'string' ? data.config.whitelist_path : '',
    knownEntityTypes: PRESET_DEFAULT_ENTITY_TYPES,
    file: presetFile,
  };
}

/** Validate + write only the two preset knobs; every other field is preserved verbatim. */
function writePreset(presetFile, patch) {
  let data = {};
  try {
    if (existsSync(presetFile)) {
      const parsed = JSON.parse(readFileSync(presetFile, 'utf8'));
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) data = parsed;
    }
  } catch {
    throw new Error('preset.json is not valid JSON; fix or delete it before saving');
  }
  if (Object.hasOwn(patch, 'entityTypes')) {
    if (!Array.isArray(patch.entityTypes)) throw new Error('entityTypes must be an array');
    const allowed = new Set(PRESET_DEFAULT_ENTITY_TYPES);
    for (const raw of patch.entityTypes) {
      if (typeof raw !== 'string') throw new Error('entityTypes entries must be strings');
      if (!allowed.has(raw)) throw new Error(`unknown entity type: ${raw}`);
    }
    // 去重保序; 空数组是合法值, 表示"全部启用"（与 Python 侧语义一致）
    data.entity_types = [...new Set(patch.entityTypes)];
  }
  if (Object.hasOwn(patch, 'whitelistPath')) {
    const raw = patch.whitelistPath;
    if (raw !== null && typeof raw !== 'string') throw new Error('whitelistPath must be a string or null');
    const value = typeof raw === 'string' ? raw.trim() : '';
    if (value.length > 1024) throw new Error('whitelistPath too long (max 1024 chars)');
    if (value && CONTROL_CHARS.test(value)) throw new Error('whitelistPath contains control characters');
    if (value && !/^[A-Za-z]:[\\/]/.test(value) && !value.startsWith('/') && !value.startsWith('.')) {
      throw new Error('whitelistPath must be absolute or start with ./ or ../');
    }
    data.config = { ...(data.config && typeof data.config === 'object' ? data.config : {}) };
    data.config.whitelist_path = value || null;
  }
  mkdirSync(dirname(presetFile), { recursive: true });
  const tmp = `${presetFile}.tmp`;
  writeFileSync(tmp, `${JSON.stringify(data, null, 2)}\n`, 'utf8');
  renameSync(tmp, presetFile);
  return readPreset(presetFile);
}

function readSettings(settingsFile) {
  let disk = {};
  try {
    if (existsSync(settingsFile)) {
      const parsed = JSON.parse(readFileSync(settingsFile, 'utf8'));
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) disk = parsed;
    }
  } catch {
    disk = {};
  }
  const out = {};
  for (const key of SETTINGS_KEYS) {
    out[key] = Object.hasOwn(disk, key) ? disk[key] : SETTINGS_DEFAULTS[key];
  }
  return out;
}

/** Normalise + validate a settings payload; unknown keys are dropped. */
/**
 * Reject regex sources whose shape invites catastrophic backtracking (ReDoS).
 * The allowlist runs synchronously inside the tool post-execute hook, so a
 * regex like `(a+)+$` would freeze the whole agent loop with no way to
 * interrupt it.
 *
 * A fragile "regex that matches regex" (the old impl) missed `{m,n}` and
 * nested groups — `(a{1,})+$`, `((a+))+$`, `(?:a{1,})+$` all slipped through.
 * Instead we parse the source into a group tree and reject two shapes:
 *   1. nested repetition — a repeat-quantified group whose body itself
 *      contains a repeat quantifier (`(a+)+`, `(a{2,}){3,}`, `((a+))+`)
 *   2. quantified alternation with overlapping branches (`(a|a)+`, `(a|aa)+`)
 * Escapes and character classes are skipped so `\(` / `[(+)]` never trip it,
 * and harmless common patterns like `^(get|set)\s` stay accepted.
 */
export function hasNestedQuantifier(source) {
  const n = source.length;
  let i = 0;

  // Read one repetition quantifier at i, advancing past it. Return its max
  // repeat count: Infinity for * + {n,}; null when there is no quantifier.
  // '?' (0..1) is not a repetition on its own, so it reports 1.
  function readQuant() {
    if (i >= n) return null;
    const ch = source[i];
    if (ch === '*' || ch === '+' || ch === '?') {
      i += 1;
      if (source[i] === '?' || source[i] === '+') i += 1; // lazy / possessive
      return ch === '?' ? 1 : Infinity;
    }
    if (ch === '{') {
      const m = /^\{(\d+)(,(\d*))?\}/.exec(source.slice(i));
      if (!m) return null;
      i += m[0].length;
      const min = parseInt(m[1], 10);
      let max;
      if (m[2] === undefined) max = min;            // {n}
      else if (m[3] === '') max = Infinity;          // {n,}
      else max = parseInt(m[3], 10);                 // {n,m}
      if (source[i] === '?' || source[i] === '+') i += 1;
      return Math.max(min, max);
    }
    return null;
  }

  // Parse a group body. Returns:
  //   fatal       — nested repetition / overlapped quantified alternation found
  //   repeatIn    — any descendant atom is repeat-quantified (max > 1)
  //   branchTexts — literal prefixes of each alternation branch (for overlap)
  function parseBody(inGroup) {
    let fatal = false;
    let repeatIn = false;
    const branchTexts = [''];
    let active = 0;

    while (i < n) {
      const ch = source[i];
      if (ch === '\\') { i += 2; branchTexts[active] += '\\'; continue; }
      if (ch === '[') {
        i += 1;
        if (source[i] === '^') i += 1;
        if (source[i] === ']') i += 1;
        while (i < n && source[i] !== ']') { if (source[i] === '\\') i += 1; i += 1; }
        if (source[i] === ']') i += 1;
        const q = readQuant();
        if (q !== null && q > 1) repeatIn = true;
        branchTexts[active] += '©'; // class placeholder, never a literal letter
        continue;
      }
      if (ch === '(') {
        i += 1;
        // consume group prefix: (?: (?= (?! (?<= (?<! (?<name>
        if (source[i] === '?') {
          if (['?:', '?=', '?!'].includes(source.slice(i, i + 2))) i += 2;
          else if (['?<=', '?<!'].includes(source.slice(i, i + 3))) i += 3;
          else if (source[i + 1] === '<') {
            const gt = source.indexOf('>', i);
            if (gt !== -1 && gt - i < 64) i = gt + 1;
            else i += 1;
          } else i += 1;
        }
        const child = parseBody(true);
        if (source[i] === ')') i += 1;
        const q = readQuant();
        if (q !== null && q > 1) {
          if (child.repeatIn) fatal = true; // nested repetition
          if (child.branchTexts.length > 1 && overlap(child.branchTexts)) fatal = true;
          repeatIn = true;
        }
        if (child.repeatIn) repeatIn = true;
        if (child.fatal) fatal = true;
        continue;
      }
      if (ch === ')') {
        if (inGroup) { i += 1; return { fatal, repeatIn, branchTexts }; }
        i += 1; // stray ')'
        continue;
      }
      if (ch === '|') { branchTexts.push(''); active = branchTexts.length - 1; i += 1; continue; }
      // ordinary literal atom
      i += 1;
      const q = readQuant();
      if (q !== null && q > 1) repeatIn = true;
      branchTexts[active] += ch;
    }
    return { fatal, repeatIn, branchTexts };
  }

  // Two branches overlap when one is a prefix of the other or they are equal.
  // Only literal prefixes are compared; placeholders/groups don't count, so
  // safe patterns like ^(get|set)\s are left alone.
  function overlap(texts) {
    const keys = texts.filter((s) => s.length > 0 && !s.includes('\\'));
    for (let a = 0; a < keys.length; a += 1) {
      for (let b = a + 1; b < keys.length; b += 1) {
        if (keys[a] === keys[b] || keys[a].startsWith(keys[b]) || keys[b].startsWith(keys[a])) return true;
      }
    }
    return false;
  }

  return parseBody(false).fatal;
}

function normalizeSettings(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new Error('settings must be an object');
  }
  const out = {};
  if (Object.hasOwn(input, 'displayMode')) {
    const mode = String(input.displayMode ?? '').toLowerCase();
    if (!['full', 'mask', 'off'].includes(mode)) throw new Error('displayMode must be full|mask|off');
    out.displayMode = mode;
  }
  if (Object.hasOwn(input, 'failOpen')) out.failOpen = Boolean(input.failOpen);
  if (Object.hasOwn(input, 'shellDisabled')) out.shellDisabled = Boolean(input.shellDisabled);
  if (Object.hasOwn(input, 'shellAllowlist')) {
    const src = String(input.shellAllowlist ?? '');
    if (src.length > 512) throw new Error('shellAllowlist too long (max 512 chars)');
    try {
      if (src) new RegExp(src);
    } catch (error) {
      throw new Error(`shellAllowlist is not a valid regex: ${error instanceof Error ? error.message : String(error)}`);
    }
    if (src && hasNestedQuantifier(src)) {
      throw new Error('shellAllowlist rejected: nested quantifiers can freeze the agent loop (ReDoS)');
    }
    out.shellAllowlist = src;
  }
  return out;
}

function writeSettings(settingsFile, original, patch) {
  const merged = { ...original, ...patch };
  const out = {};
  for (const key of SETTINGS_KEYS) out[key] = merged[key];
  mkdirSync(dirname(settingsFile), { recursive: true });
  const tmp = `${settingsFile}.tmp`;
  writeFileSync(tmp, `${JSON.stringify(out, null, 2)}\n`, 'utf8');
  renameSync(tmp, settingsFile);
  return out;
}

/** Compare paths case-/separator-insensitively (S2: UI termsFile vs preset custom_rules_path). */
function samePath(a, b) {
  const norm = (p) => String(p ?? '').replace(/\\/g, '/').replace(/\/+$/, '').toLowerCase();
  return norm(a) !== '' && norm(a) === norm(b);
}

/**
 * S2 guard: the terms file the UI writes must be the same file the Python
 * redaction engine loads via preset.json's config.custom_rules_path. A drift
 * means saved terms silently stop taking effect, so surface it loudly at boot.
 */
function warnIfPathDrift(termsFile, presetFile, repo) {
  try {
    if (!existsSync(presetFile)) return;
    const preset = JSON.parse(readFileSync(presetFile, 'utf8'));
    const crp = preset?.config?.custom_rules_path;
    if (typeof crp !== 'string' || crp.trim() === '') return;
    const resolved = resolve(repo, crp.trim());
    if (!samePath(termsFile, resolved)) {
      console.error(`[dsh-pii-guard-terms] PATH DRIFT: UI termsFile=${termsFile} but preset custom_rules_path resolves to ${resolved}. Terms saved in the UI will NOT reach the redaction engine. Align these paths.`);
    }
  } catch {
    // A malformed preset is reported by the harness; never break the host here.
  }
}

function handleList(req, res, termsFile, config) {
  if (!guard(req, res, 'GET')) return;
  let terms = [];
  try {
    terms = readTerms(termsFile);
  } catch {
    terms = [];
  }
  writeJson(res, 200, {
    ok: true,
    terms,
    file: termsFile,
    maxTerms: config.maxTerms,
    maxTermLength: config.maxTermLength,
  });
}

async function handleSave(req, res, termsFile, config) {
  if (!guard(req, res, 'POST')) return;
  let terms;
  try {
    const raw = await readBody(req);
    const body = raw ? JSON.parse(raw) : {};
    terms = normalizeTerms(body?.terms, config);
  } catch (error) {
    writeJson(res, 400, {
      error: error instanceof Error ? error.message : String(error),
    });
    return;
  }
  try {
    // S3: hand-written USER_TERM rules without a usable `term` key survive a
    // UI save verbatim instead of being wiped.
    const count = writeTerms(termsFile, terms, unrecognizedRuleRows(termsFile));
    writeJson(res, 200, { ok: true, count, terms, file: termsFile });
  } catch (error) {
    writeJson(res, 500, {
      error: error instanceof Error ? error.message : String(error),
    });
  }
}

async function handleSettingsGet(req, res, settingsFile) {
  if (!guard(req, res, 'GET')) return;
  try {
    writeJson(res, 200, { ok: true, settings: readSettings(settingsFile), file: settingsFile });
  } catch (error) {
    writeJson(res, 500, { error: error instanceof Error ? error.message : String(error) });
  }
}

async function handleSettingsSave(req, res, settingsFile) {
  if (!guard(req, res, 'POST')) return;
  let patch;
  try {
    const raw = await readBody(req);
    const body = raw ? JSON.parse(raw) : {};
    patch = normalizeSettings(body?.settings ?? body);
  } catch (error) {
    writeJson(res, 400, { error: error instanceof Error ? error.message : String(error) });
    return;
  }
  try {
    const current = readSettings(settingsFile);
    const out = writeSettings(settingsFile, current, patch);
    writeJson(res, 200, { ok: true, settings: out, file: settingsFile });
  } catch (error) {
    writeJson(res, 500, { error: error instanceof Error ? error.message : String(error) });
  }
}

function handlePresetGet(req, res, presetFile) {
  if (!guard(req, res, 'GET')) return;
  try {
    writeJson(res, 200, { ok: true, preset: readPreset(presetFile) });
  } catch (error) {
    writeJson(res, 500, { error: error instanceof Error ? error.message : String(error) });
  }
}

async function handlePresetSave(req, res, presetFile) {
  if (!guard(req, res, 'POST')) return;
  let patch;
  try {
    const raw = await readBody(req);
    const body = raw ? JSON.parse(raw) : {};
    const source = body?.preset ?? body;
    if (!source || typeof source !== 'object' || Array.isArray(source)) {
      throw new Error('preset patch must be an object');
    }
    patch = {};
    if (Object.hasOwn(source, 'entityTypes')) patch.entityTypes = source.entityTypes;
    if (Object.hasOwn(source, 'whitelistPath')) patch.whitelistPath = source.whitelistPath;
  } catch (error) {
    writeJson(res, 400, { error: error instanceof Error ? error.message : String(error) });
    return;
  }
  try {
    const preset = writePreset(presetFile, patch);
    writeJson(res, 200, { ok: true, preset });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    // 校验类失败是调用方的问题（400），文件不可写才是 500
    const status = /not valid JSON|must be|unknown entity type|too long|control characters/.test(message) ? 400 : 500;
    writeJson(res, status, { error: message });
  }
}

export function apply(ctx, rawConfig) {
  const repo = resolveRepo(rawConfig);
  const config = {
    repo,
    termsFile: (rawConfig?.termsFile ?? process.env.PII_GUARD_TERMS_FILE ?? repo + DEFAULT_TERMS_FILE),
    maxTerms: Number(rawConfig?.maxTerms ?? DEFAULT_MAX_TERMS),
    maxTermLength: Number(rawConfig?.maxTermLength ?? DEFAULT_MAX_TERM_LENGTH),
    settingsFile: (rawConfig?.settingsFile ?? process.env.PII_GUARD_SETTINGS_FILE ?? repo + DEFAULT_SETTINGS_FILE),
    presetFile: (rawConfig?.presetFile ?? process.env.PII_DSH_PRESET ?? repo + DEFAULT_PRESET_FILE),
  };

  // Create the rule file up front so the Python side can resolve the path on
  // its very first engine construction.
  try {
    if (!existsSync(config.termsFile)) writeTerms(config.termsFile, []);
  } catch {
    // A missing file is reported through the API, not by breaking the host.
  }

  // S2: fail loudly if the UI's terms file and the engine's custom-rules file
  // are not the same path — otherwise UI edits silently stop taking effect.
  warnIfPathDrift(config.termsFile, config.presetFile, config.repo);

  ctx.inject(['webServer'], (webCtx) => {
    webCtx.effect(() => {
      const server = webCtx.webServer;
      const disposers = [
        server.register({
          kind: 'exact',
          path: API_LIST,
          handler: (req, res) => handleList(req, res, config.termsFile, config),
        }),
        server.register({
          kind: 'exact',
          path: API_SAVE,
          handler: (req, res) => handleSave(req, res, config.termsFile, config),
        }),
        server.register({
          kind: 'exact',
          path: API_SETTINGS,
          handler: (req, res) => handleSettingsGet(req, res, config.settingsFile),
        }),
        server.register({
          kind: 'exact',
          path: API_SETTINGS_SAVE,
          handler: (req, res) => handleSettingsSave(req, res, config.settingsFile),
        }),
        server.register({
          kind: 'exact',
          path: API_PRESET,
          handler: (req, res) => handlePresetGet(req, res, config.presetFile),
        }),
        server.register({
          kind: 'exact',
          path: API_PRESET_SAVE,
          handler: (req, res) => handlePresetSave(req, res, config.presetFile),
        }),
      ];
      return () => {
        for (const dispose of disposers) {
          try {
            dispose();
          } catch {
            // Disposal must never break the host teardown.
          }
        }
      };
    }, 'dsh-pii-guard-terms: terms api');
  });
}
