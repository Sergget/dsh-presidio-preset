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
 *
 * The host server matches routes by pathname only, so the paths above are
 * absolute; the browser half builds the same absolute URLs.
 */
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

export const name = 'dsh-pii-guard-terms';
export const inject = [];

const API_LIST = '/api/dsh-pii-guard/terms';
const API_SAVE = '/api/dsh-pii-guard/terms/save';

const DEFAULT_TERMS_FILE = 'E:/Code/dsh-presidio-preset/.pii_presidio_store/user_terms_rules.json';
const DEFAULT_MAX_TERMS = 500;
const DEFAULT_MAX_TERM_LENGTH = 200;
const MAX_BODY_BYTES = 64 * 1024;

const ENTITY_TYPE = 'USER_TERM';
const PLACEHOLDER_NAME = 'user-term-placeholder';
/** A pattern that can never match; used to represent an empty term list. */
const NEVER_MATCH = '(?!)';
/** Control characters are never allowed inside a term. */
const CONTROL_CHARS = /[\u0000-\u001F\u007F]/;

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
 * Same-origin proof. A browser fetch from the settings page carries
 * `Sec-Fetch-Site: same-origin` (or an Origin header); the desktop shell
 * forwards requests without those headers but keeps the host cookie.
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
  const cookie = headers.cookie;
  return typeof cookie === 'string' && cookie.length > 0;
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
  for (const row of parsed) {
    if (!row || typeof row !== 'object') continue;
    if (row.entity_type !== ENTITY_TYPE) continue;
    const term = typeof row.term === 'string' ? row.term : '';
    if (!term || seen.has(term)) continue;
    seen.add(term);
    out.push(term);
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
function writeTerms(termsFile, terms) {
  const rules = terms.map((term, index) => ({
    name: `user-term-${String(index + 1).padStart(4, '0')}`,
    entity_type: ENTITY_TYPE,
    pattern: escapeLiteral(term),
    score: 0.95,
    priority: 0,
    term,
  }));
  const payload = rules.length > 0
    ? rules
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
    const count = writeTerms(termsFile, terms);
    writeJson(res, 200, { ok: true, count, terms, file: termsFile });
  } catch (error) {
    writeJson(res, 500, {
      error: error instanceof Error ? error.message : String(error),
    });
  }
}

export function apply(ctx, rawConfig) {
  const config = {
    termsFile: (rawConfig?.termsFile ?? process.env.PII_GUARD_TERMS_FILE ?? DEFAULT_TERMS_FILE),
    maxTerms: Number(rawConfig?.maxTerms ?? DEFAULT_MAX_TERMS),
    maxTermLength: Number(rawConfig?.maxTermLength ?? DEFAULT_MAX_TERM_LENGTH),
  };

  // Create the rule file up front so the Python side can resolve the path on
  // its very first engine construction.
  try {
    if (!existsSync(config.termsFile)) writeTerms(config.termsFile, []);
  } catch {
    // A missing file is reported through the API, not by breaking the host.
  }

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
