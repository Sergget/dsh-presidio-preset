// 会话映射 + HMAC 日志指纹 + 配置加载，逐字对齐 presidio_pii/hooks.py。
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { Engine } from './engine.mjs';
import { SessionRegistry } from './db.mjs';
import { JsonlJournal } from './journal.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_REPO = path.resolve(HERE, '..');
const DEFAULT_DB = path.join(DEFAULT_REPO, '.pii_presidio_store', 'sessions.db');
const DEFAULT_LOG = path.join(DEFAULT_REPO, '.pii_presidio_store', 'hook_log.jsonl');
const DEFAULT_PRESET = path.join(DEFAULT_REPO, '.agent-presets', 'presidio-pii', 'preset.json');
const DEFAULT_MAX_BYTES = 10 * 1024 * 1024;

function warn(msg) { console.error(`[pii] ${msg}`); }

class PresetUnreadable extends Error {}

function env(name) { return process.env[name]; }
function envOr(name, fallback) { const v = env(name); return v === undefined ? fallback : v; }

// ---- 配置读取 ----
function presetFile() { return envOr('PII_DSH_PRESET', DEFAULT_PRESET); }

function presetConfig(strict = false) {
  const fp = presetFile();
  if (!fs.existsSync(fp)) return {};
  let data;
  try {
    data = JSON.parse(fs.readFileSync(fp, 'utf8').replace(/^\uFEFF/, ''));
  } catch (ex) {
    if (strict) throw new PresetUnreadable(`${fp}: ${ex.message}`);
    warn(`preset 配置读取失败 (${fp}): ${ex.message}`);
    return {};
  }
  return (data && typeof data.config === 'object' && data.config !== null) ? data.config : {};
}

function presetPath(key, strict = false) {
  const value = presetConfig(strict)[key];
  if (!value) return null;
  if (path.isAbsolute(value)) return value;
  const candidates = [path.join(DEFAULT_REPO, value), path.join(path.dirname(presetFile()), value)];
  return candidates.find((c) => fs.existsSync(c)) || candidates[0];
}

function dbPath() { return env('PII_DSH_DB_PATH') || presetPath('db_path') || DEFAULT_DB; }
function whitelistFile(strict = false) { return env('PII_DSH_WHITELIST') || presetPath('whitelist_path', strict); }
const BUILTIN_RULES_DIR = 'rule_libraries';

// 内置规则库：仓库 rule_libraries/*.json 始终与用户规则一起加载。
// 生产事故回归：此前只加载 preset 的 custom_rules_path，扩展字段库（AGE 等 7 类）
// 缺席 → 引擎判为"未知实体类型"并静默剔除，Phase 0 字段在生产环境等于没做。
function builtinRuleLibraries(repoDir = DEFAULT_REPO) {
  try {
    const dir = path.join(repoDir, BUILTIN_RULES_DIR);
    if (!fs.existsSync(dir)) return [];
    return fs.readdirSync(dir)
      .filter((f) => f.toLowerCase().endsWith('.json'))
      .sort()
      .map((f) => path.join(dir, f));
  } catch (ex) {
    warn(`内置规则库枚举失败，仅使用用户规则: ${ex.message}`);
    return [];
  }
}

// 返回分号分隔的多路径（CustomRuleSet 支持 [;,] 分隔并逐文件做热更新签名）
function customRulesSpec() {
  const explicit = env('PII_DSH_CUSTOM_RULES') || presetPath('custom_rules_path');
  const parts = builtinRuleLibraries();
  if (explicit) parts.push(explicit);
  return parts.length ? parts.join(';') : null;
}

function parseInterval(raw, fallback = 1.0) {
  if (raw == null) return fallback;
  if (typeof raw === 'boolean') return raw ? fallback : 0.0;
  if (typeof raw === 'number') return Math.max(0, Number(raw));
  const text = String(raw).trim().toLowerCase();
  if (!text) return fallback;
  if (['0', 'off', 'false', 'no', 'none'].includes(text)) return 0.0;
  const n = Number(text);
  if (Number.isFinite(n)) return Math.max(0, n);
  warn(`无法解析规则热更新间隔 ${JSON.stringify(raw)}, 使用默认 ${fallback}s`);
  return fallback;
}

function rulesReloadInterval() {
  let raw = env('PII_DSH_RULES_RELOAD');
  if (raw === undefined) raw = presetConfig().rules_reload_interval;
  return parseInterval(raw);
}

function whitelist(strict = false) {
  const raw = whitelistFile(strict);
  if (!raw || !fs.existsSync(raw)) return [];
  let text;
  try {
    text = fs.readFileSync(raw, 'utf8').replace(/^\uFEFF/, '');
  } catch (ex) {
    if (strict) throw new PresetUnreadable(`白名单文件 ${raw}: ${ex.message}`);
    warn(`白名单文件读取失败 (${raw}): ${ex.message}`);
    return [];
  }
  return text.split(/\r?\n/).map((ln) => ln.trim()).filter((ln) => ln && !ln.startsWith('#'));
}

function entityTypes() {
  let raw = env('PII_DSH_ENTITY_TYPES');
  if (raw === undefined) {
    const fp = presetFile();
    if (fs.existsSync(fp)) {
      let data;
      try {
        data = JSON.parse(fs.readFileSync(fp, 'utf8').replace(/^\uFEFF/, ''));
      } catch (ex) {
        throw new PresetUnreadable(`${fp}: ${ex.message}`);
      }
      raw = data?.entity_types;
    }
  }
  if (!raw) return [];
  if (typeof raw === 'string') raw = raw.replace(/;/g, ',').split(',');
  if (!Array.isArray(raw)) return [];
  return raw.map((t) => String(t).trim()).filter(Boolean);
}

function presetSignature() {
  try {
    const st = fs.statSync(presetFile());
    return `${st.mtimeNs ?? st.mtimeMs}|${st.size}`;
  } catch { return null; }
}

// ---- 指纹 ----
export function sessionId(cid) {
  if (cid) return crypto.createHash('sha1').update(cid, 'utf8').digest('hex').slice(0, 12);
  const today = new Date().toISOString().slice(0, 10); // 等价 date.today().isoformat()
  return 'daily-' + crypto.createHash('sha1').update(today, 'utf8').digest('hex').slice(0, 8);
}

function idFingerprint(value) {
  if (!value) return null;
  return crypto.createHash('sha1').update(value, 'utf8').digest('hex').slice(0, 12);
}

let HMAC_KEY = null;
function hmacKey() {
  if (HMAC_KEY) return HMAC_KEY;
  const e = env('PII_DSH_LOG_HMAC_KEY');
  if (e) { HMAC_KEY = Buffer.from(e, 'utf8'); return HMAC_KEY; }
  const keyFile = path.join(path.dirname(dbPath()), 'journal_hmac.key');
  try {
    const data = fs.readFileSync(keyFile);
    if (data.length) { HMAC_KEY = data; return HMAC_KEY; }
  } catch { /* 文件不存在，走生成 */ }
  const secret = crypto.randomBytes(32);
  try {
    fs.mkdirSync(path.dirname(keyFile), { recursive: true });
    fs.writeFileSync(keyFile, secret, { mode: 0o600 });
  } catch (ex) {
    warn(`无法写入日志密钥 (${keyFile}): ${ex.message}`);
  }
  HMAC_KEY = secret;
  return HMAC_KEY;
}

export function fingerprint(text) {
  return crypto.createHmac('sha256', hmacKey()).update(text, 'utf8').digest('hex').slice(0, 16);
}

export function maskValue(value, etype) {
  const v = String(value);
  if (etype === 'EMAIL_ADDRESS' && v.includes('@')) {
    const at = v.indexOf('@');
    return `${v.slice(0, 1)}***@${v.slice(at + 1)}`;
  }
  if (v.length <= 4) return `${v.slice(0, 1)}${'*'.repeat(Math.max(0, v.length - 1))}`;
  return `${v.slice(0, 2)}${'*'.repeat(Math.max(0, v.length - 4))}${v.slice(-2)}`;
}

function entityCounts(placeholders) {
  const counts = {};
  for (const ph of Object.keys(placeholders)) {
    const parts = ph.replace(/^⟦|⟧$/g, '').split(':');
    const ptype = parts[1];
    if (ptype) counts[ptype] = (counts[ptype] || 0) + 1;
  }
  return counts;
}

// ---- 单例引擎 ----
let ENGINE = null;
let PRESET_SIG = null;
let JOURNAL = null;

export function getEngine(cfg) {
  if (!ENGINE) {
    let types;
    try { types = entityTypes(); }
    catch (ex) { warn(`preset 实体类型读取失败, 暂时启用全部类型: ${ex.message}`); types = []; }
    ENGINE = new Engine({
      repoDir: DEFAULT_REPO,
      dbPath: dbPath(),
      whitelist: whitelist(),
      customRules: customRulesSpec(),
      rulesCheckInterval: rulesReloadInterval(),
      entityTypes: types,
      ...(cfg || {}),
    });
    PRESET_SIG = presetSignature();
  } else {
    const sig = presetSignature();
    if (sig !== PRESET_SIG) {
      PRESET_SIG = sig;
      try { ENGINE.setEntityTypes(entityTypes()); }
      catch (ex) { warn(`preset 实体类型热更新失败, 保留旧值: ${ex.message}`); }
      try { ENGINE.setWhitelist(whitelist(true)); }
      catch (ex) { warn(`preset 白名单热更新失败, 保留旧值: ${ex.message}`); }
    }
  }
  return ENGINE;
}

export function getJournal() {
  if (JOURNAL === null) {
    const raw = envOr('PII_DSH_LOG_PATH', DEFAULT_LOG);
    let max = DEFAULT_MAX_BYTES;
    const rawMax = (env('PII_DSH_LOG_MAX_BYTES') || '').trim();
    if (rawMax) {
      const n = Number(rawMax);
      max = Number.isInteger(n) ? Math.max(0, n) : (warn(`无法解析日志上限 ${JSON.stringify(rawMax)}, 使用默认 ${DEFAULT_MAX_BYTES}`), DEFAULT_MAX_BYTES);
    }
    JOURNAL = raw === '0' ? null : new JsonlJournal(raw, max);
  }
  return JOURNAL;
}

export function resetSingleton() {
  ENGINE = null; JOURNAL = null; HMAC_KEY = null; PRESET_SIG = null;
}

// ---- before / after ----
export function beforeLlm(prompt, cid = null, docId = 'prompt') {
  const engine = getEngine();
  const sid = sessionId(cid);
  const rd = engine.redact(prompt, sid, docId);
  const journal = getJournal();
  if (journal) {
    journal.record('before_llm', {
      conv_sha1: idFingerprint(cid),
      session_id: sid,
      doc_sha1: idFingerprint(docId),
      n_replaced: rd.n_replaced,
      entities: rd.entity_counts,
      redacted_sha256: fingerprint(rd.text),
      chars: String(prompt).length,
    });
  }
  return rd.text;
}

export function afterLlm(response, cid = null, docId = 'prompt') {
  const engine = getEngine();
  const sid = sessionId(cid);
  const rs = engine.restore(response, sid, docId);
  const stats = { n_restored: Object.keys(rs.restored).length, n_unrestored: Object.keys(rs.unrestored).length };
  const journal = getJournal();
  if (journal) {
    journal.record('after_llm', {
      conv_sha1: idFingerprint(cid),
      session_id: sid,
      doc_sha1: idFingerprint(docId),
      n_restored: stats.n_restored,
      n_unrestored: stats.n_unrestored,
      entities: entityCounts(rs.restored),
      response_sha256: fingerprint(response),
      chars: String(response).length,
    });
  }
  return { text: rs.text, stats };
}
