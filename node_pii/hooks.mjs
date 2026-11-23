// 会话映射 + HMAC 日志指纹 + 配置加载，逐字对齐 presidio_pii/hooks.py。
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { Engine } from './engine.mjs';
import { SessionRegistry } from './db.mjs';
import { JsonlJournal } from './journal.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = path.resolve(HERE, '..');

// 布局判定用 package.json 的包名做正向标记（不依赖"某个目录恰好不存在"这种副作用）：
// bundle 布局下 PKG_ROOT 就是包根，带 package.json；仓库检出布局下 PKG_ROOT 是仓库根，没有 package.json。
function detectBundleLayout() {
  try {
    const pkgFile = path.join(PKG_ROOT, 'package.json');
    if (!fs.existsSync(pkgFile)) return false;
    const pkg = JSON.parse(fs.readFileSync(pkgFile, 'utf8').replace(/^\uFEFF/, ''));
    return Boolean(pkg && pkg.name === 'dsh-presidio-pii');
  } catch {
    return false;
  }
}
const IS_BUNDLE_LAYOUT = detectBundleLayout();
const DEFAULT_MAX_BYTES = 10 * 1024 * 1024;
const BUILTIN_RULES_DIR = 'rule_libraries';

function warn(msg) { console.error(`[pii] ${msg}`); }

class PresetUnreadable extends Error {}

function env(name) { return process.env[name]; }
function envOr(name, fallback) { const v = env(name); return v === undefined ? fallback : v; }

function resolveDshHome() {
  const fromEnv = (env('DSH_HOME') || '').trim();
  return fromEnv ? path.resolve(fromEnv) : path.join(os.homedir(), '.dsh');
}

function defaultRepoDir(cfg) {
  const fromCfg = typeof cfg?.repoDir === 'string' && cfg.repoDir.trim() ? path.resolve(cfg.repoDir.trim()) : '';
  const fromEnv = (env('PII_GUARD_REPO') || '').trim();
  if (fromCfg) return fromCfg;
  if (fromEnv) return path.resolve(fromEnv);
  return PKG_ROOT;
}

function defaultDataDir(cfg) {
  const fromCfgData = typeof cfg?.dataDir === 'string' && cfg.dataDir.trim() ? path.resolve(cfg.dataDir.trim()) : '';
  if (fromCfgData) return fromCfgData;
  const fromEnvData = (env('PII_GUARD_DATA_DIR') || '').trim();
  if (fromEnvData) return path.resolve(fromEnvData);
  const fromCfgRepo = typeof cfg?.repoDir === 'string' && cfg.repoDir.trim() ? path.resolve(cfg.repoDir.trim()) : '';
  if (fromCfgRepo) return path.join(fromCfgRepo, '.pii_presidio_store');
  const fromEnvRepo = (env('PII_GUARD_REPO') || '').trim();
  if (fromEnvRepo) return path.join(path.resolve(fromEnvRepo), '.pii_presidio_store');
  if (IS_BUNDLE_LAYOUT) {
    return path.join(resolveDshHome(), 'data', 'presidio-pii');
  }
  return path.join(PKG_ROOT, '.pii_presidio_store');
}

// ---- 配置读取 ----
function presetFile(cfg) {
  if (typeof cfg?.presetPath === 'string' && cfg.presetPath.trim()) return path.resolve(cfg.presetPath.trim());
  const fromEnv = env('PII_DSH_PRESET');
  if (fromEnv !== undefined) return fromEnv;
  if (IS_BUNDLE_LAYOUT && !cfg?.repoDir && !(env('PII_GUARD_REPO') || '').trim()) {
    const dataPreset = path.join(defaultDataDir(cfg), 'preset.json');
    if (fs.existsSync(dataPreset)) return dataPreset;
    const bundledDefault = path.join(PKG_ROOT, 'defaults', 'preset.json');
    if (fs.existsSync(bundledDefault)) return bundledDefault;
    return dataPreset;
  }
  return path.join(defaultRepoDir(cfg), '.agent-presets', 'presidio-pii', 'preset.json');
}

function presetConfig(strict = false, cfg = null) {
  const fp = presetFile(cfg);
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

function presetPath(key, strict = false, cfg = null) {
  const value = presetConfig(strict, cfg)[key];
  if (!value) return null;
  if (path.isAbsolute(value)) return value;
  const dataDir = defaultDataDir(cfg);
  const repoDir = defaultRepoDir(cfg);
  const pFile = presetFile(cfg);
  const candidates = [
    path.join(path.dirname(pFile), value),
    path.join(dataDir, value),
    path.join(repoDir, value),
    path.join(PKG_ROOT, value),
  ];
  return candidates.find((c) => fs.existsSync(c)) || candidates[0];
}

function dbPath(cfg = null) {
  if (typeof cfg?.dbPath === 'string' && cfg.dbPath.trim()) return cfg.dbPath.trim();
  return env('PII_DSH_DB_PATH') || presetPath('db_path', false, cfg) || path.join(defaultDataDir(cfg), 'sessions.db');
}

function whitelistFile(strict = false, cfg = null) {
  return env('PII_DSH_WHITELIST') || presetPath('whitelist_path', strict, cfg);
}

// 内置规则库：rule_libraries/*.json 始终与用户规则一起加载。
// 生产事故回归：此前只加载 preset 的 custom_rules_path，扩展字段库（AGE 等 7 类）
// 缺席 → 引擎判为"未知实体类型"并静默剔除，Phase 0 字段在生产环境等于没做。
function builtinRuleLibraries(repoDir = PKG_ROOT) {
  try {
    const candidates = [
      path.join(repoDir, BUILTIN_RULES_DIR),
      path.join(PKG_ROOT, BUILTIN_RULES_DIR),
    ];
    const dir = candidates.find((d) => fs.existsSync(d));
    if (!dir) return [];
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
function customRulesSpec(cfg = null) {
  const explicit = env('PII_DSH_CUSTOM_RULES') || presetPath('custom_rules_path', false, cfg);
  const parts = builtinRuleLibraries(defaultRepoDir(cfg));
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

function rulesReloadInterval(cfg = null) {
  let raw = env('PII_DSH_RULES_RELOAD');
  if (raw === undefined) raw = presetConfig(false, cfg).rules_reload_interval;
  return parseInterval(raw);
}

function whitelist(strict = false, cfg = null) {
  const raw = whitelistFile(strict, cfg);
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

function entityTypes(cfg = null) {
  let raw = env('PII_DSH_ENTITY_TYPES');
  if (raw === undefined) {
    const fp = presetFile(cfg);
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

function presetSignature(cfg = null) {
  try {
    const st = fs.statSync(presetFile(cfg));
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
function hmacKey(cfg = null) {
  if (HMAC_KEY) return HMAC_KEY;
  const e = env('PII_DSH_LOG_HMAC_KEY');
  if (e) { HMAC_KEY = Buffer.from(e, 'utf8'); return HMAC_KEY; }
  const keyFile = path.join(path.dirname(dbPath(cfg)), 'journal_hmac.key');
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
let ENGINE_CFG = null;
let PRESET_SIG = null;
let JOURNAL = null;

export function getEngine(cfg) {
  if (!ENGINE) {
    ENGINE_CFG = cfg || null;
    let types;
    try { types = entityTypes(ENGINE_CFG); }
    catch (ex) { warn(`preset 实体类型读取失败, 暂时启用全部类型: ${ex.message}`); types = []; }
    ENGINE = new Engine({
      repoDir: defaultRepoDir(ENGINE_CFG),
      dbPath: dbPath(ENGINE_CFG),
      whitelist: whitelist(false, ENGINE_CFG),
      customRules: customRulesSpec(ENGINE_CFG),
      rulesCheckInterval: rulesReloadInterval(ENGINE_CFG),
      entityTypes: types,
      ...(cfg || {}),
    });
    PRESET_SIG = presetSignature(ENGINE_CFG);
  } else {
    const activeCfg = cfg || ENGINE_CFG;
    const sig = presetSignature(activeCfg);
    if (sig !== PRESET_SIG) {
      PRESET_SIG = sig;
      try { ENGINE.setEntityTypes(entityTypes(activeCfg)); }
      catch (ex) { warn(`preset 实体类型热更新失败, 保留旧值: ${ex.message}`); }
      try { ENGINE.setWhitelist(whitelist(true, activeCfg)); }
      catch (ex) { warn(`preset 白名单热更新失败, 保留旧值: ${ex.message}`); }
    }
  }
  return ENGINE;
}

export function getJournal() {
  if (JOURNAL === null) {
    const defaultLog = path.join(defaultDataDir(ENGINE_CFG), 'hook_log.jsonl');
    const raw = envOr('PII_DSH_LOG_PATH', defaultLog);
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
  ENGINE = null; ENGINE_CFG = null; JOURNAL = null; HMAC_KEY = null; PRESET_SIG = null;
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
