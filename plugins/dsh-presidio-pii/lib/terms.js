/**
 * Host half of dsh-presidio-pii (terms, runtime settings, and preset config API).
 *
 * Route shape follows harness conventions:
 *   GET  /api/dsh-pii-guard/terms         -> list terms
 *   POST /api/dsh-pii-guard/terms/save    -> replace the term list
 *   GET  /api/dsh-pii-guard/settings      -> read guard runtime settings
 *   POST /api/dsh-pii-guard/settings/save -> write guard runtime settings
 *   GET  /api/dsh-pii-guard/preset        -> read preset entity types & whitelist
 *   POST /api/dsh-pii-guard/preset/save   -> update preset entity types & whitelist
 */
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { ensureDefaultPreset, resolveDataPaths } from './paths.mjs';
import { hasNestedQuantifier } from './regex-safety.mjs';

export const name = 'dsh-presidio-pii-terms';
export const inject = [];

const API_LIST = '/api/dsh-pii-guard/terms';
const API_SAVE = '/api/dsh-pii-guard/terms/save';
const API_SETTINGS = '/api/dsh-pii-guard/settings';
const API_SETTINGS_SAVE = '/api/dsh-pii-guard/settings/save';
const API_PRESET = '/api/dsh-pii-guard/preset';
const API_PRESET_SAVE = '/api/dsh-pii-guard/preset/save';

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

/** Escape a literal so regex engines treat it as plain text. */
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
  const cookieName = sessionCookieName(host);
  if (!cookieName) return false;
  for (const segment of cookie.split(';')) {
    const at = segment.indexOf('=');
    if (at === -1) continue;
    if (segment.slice(0, at).trim() !== cookieName) continue;
    if (segment.slice(at + 1).trim().length > 0) return true;
  }
  return false;
}

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
  return new Promise((resolveBody, reject) => {
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
    req.on('end', () => resolveBody(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

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
    if (row.name === PLACEHOLDER_NAME) continue;
    const term = typeof row.term === 'string' ? row.term : '';
    if (!term || seen.has(term)) continue;
    seen.add(term);
    out.push(term);
  }
  for (const row of parsed) {
    if (!row || typeof row !== 'object') continue;
    if (row.entity_type !== ENTITY_TYPE) continue;
    if (row.name === PLACEHOLDER_NAME) continue;
    if (typeof row.term === 'string' && row.term) continue;
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
    console.error(`[dsh-presidio-pii] readTerms: ${unrecognized} USER_TERM rule(s) could not be mapped back to a literal term (real regex patterns). They are preserved verbatim on the next save but cannot be edited via the UI.`);
  }
  return out;
}

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

function unescapeLiteral(pattern) {
  if (pattern.length === 0) return '';
  let out = '';
  for (let i = 0; i < pattern.length; i += 1) {
    const ch = pattern[i];
    if (ch === '\\') {
      const next = pattern[i + 1];
      if (next !== undefined && /^[.*+?^${}()|[\]\\]$/.test(next)) {
        out += next;
        i += 1;
        continue;
      }
      return null;
    }
    if (/[.*+?^${}()|[\]]/.test(ch)) return null;
    out += ch;
  }
  return out;
}

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

const PRESET_DEFAULT_ENTITY_TYPES = [
  'ID_NUMBER', 'PHONE_NUMBER', 'EMAIL_ADDRESS', 'CREDIT_CODE', 'BANK_CARD',
  'PASSPORT', 'LICENSE_PLATE', 'IP_ADDRESS', 'MAC_ADDRESS', 'PERSON',
  'LOCATION', 'ORGANIZATION', 'JOB_TITLE',
  'AGE', 'BIRTH_DATE', 'GENDER', 'ETHNICITY', 'EDUCATION', 'IM_ACCOUNT', 'EMPLOYEE_ID',
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

function samePath(a, b) {
  const norm = (p) => String(p ?? '').replace(/\\/g, '/').replace(/\/+$/, '').toLowerCase();
  return norm(a) !== '' && norm(a) === norm(b);
}

function warnIfPathDrift(termsFile, presetFile, dataDir, repo) {
  try {
    if (!existsSync(presetFile)) return;
    const preset = JSON.parse(readFileSync(presetFile, 'utf8'));
    const crp = preset?.config?.custom_rules_path;
    if (typeof crp !== 'string' || crp.trim() === '') return;
    const raw = crp.trim();
    const candidates = isAbsolute(raw)
      ? [raw]
      : [
          resolve(dirname(presetFile), raw),
          ...(dataDir ? [resolve(dataDir, raw)] : []),
          ...(repo ? [resolve(repo, raw)] : []),
        ];
    if (!candidates.some((c) => samePath(termsFile, c))) {
      console.error(`[dsh-presidio-pii] PATH DRIFT: UI termsFile=${termsFile} but preset custom_rules_path resolves to ${candidates[0]}. Terms saved in the UI will NOT reach the redaction engine. Align these paths.`);
    }
  } catch {
    // Non-fatal
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
    const status = /not valid JSON|must be|unknown entity type|too long|control characters/.test(message) ? 400 : 500;
    writeJson(res, status, { error: message });
  }
}

export function apply(ctx, rawConfig) {
  const paths = resolveDataPaths(rawConfig);
  const config = {
    repo: paths.repo,
    dataDir: paths.dataDir,
    termsFile: paths.termsFile,
    maxTerms: Number(rawConfig?.maxTerms ?? DEFAULT_MAX_TERMS),
    maxTermLength: Number(rawConfig?.maxTermLength ?? DEFAULT_MAX_TERM_LENGTH),
    settingsFile: paths.settingsFile,
    presetFile: paths.presetFile,
  };

  ensureDefaultPreset(config.presetFile, paths.mode);

  try {
    if (!existsSync(config.termsFile)) writeTerms(config.termsFile, []);
  } catch {
    // Non-fatal
  }

  warnIfPathDrift(config.termsFile, config.presetFile, config.dataDir, config.repo);

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
            // Non-fatal
          }
        }
      };
    }, 'dsh-presidio-pii: terms api');
  });
}
