import { existsSync, copyFileSync, mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
export const PKG_ROOT = resolve(HERE, '..');
export const DEFAULT_PRESET_TEMPLATE = join(PKG_ROOT, 'defaults', 'preset.json');

export function normalizeSlash(p) {
  return String(p ?? '').replace(/\\/g, '/').replace(/\/+$/, '');
}

export function resolveDshHomeDir() {
  const fromEnv = typeof process.env.DSH_HOME === 'string' ? process.env.DSH_HOME.trim() : '';
  return fromEnv ? resolve(fromEnv) : join(homedir(), '.dsh');
}

export function resolvePkgRoot() {
  if (existsSync(join(PKG_ROOT, 'node_pii', 'server.mjs'))) {
    return PKG_ROOT;
  }
  const legacyRepo = resolve(PKG_ROOT, '..', '..');
  if (existsSync(join(legacyRepo, 'node_pii', 'server.mjs'))) {
    return legacyRepo;
  }
  return PKG_ROOT;
}

function detectRepoCheckoutRoot() {
  const candidate = resolve(PKG_ROOT, '..', '..');
  const hasRepoMarkers = existsSync(join(candidate, 'node_pii', 'server.mjs'))
    && (existsSync(join(candidate, '.pii_presidio_store'))
      || existsSync(join(candidate, '.agent-presets', 'presidio-pii', 'preset.json')));
  return hasRepoMarkers ? candidate : '';
}

/**
 * Resolve all runtime data paths for the unified plugin without hardcoded machine paths.
 *
 * Precedence:
 *   1. explicit config.dataDir (or env PII_GUARD_DATA_DIR) -> <dataDir>/{...}
 *   2. explicit config.repo    (or env PII_GUARD_REPO)    -> <repo>/.pii_presidio_store/{...}
 *   3. repository checkout fallback (only when DSH_HOME is unset)
 *   4. $DSH_HOME/data/presidio-pii (or ~/.dsh/data/presidio-pii)
 */
export function resolveDataPaths(rawConfig = {}) {
  const cfg = rawConfig && typeof rawConfig === 'object' ? rawConfig : {};
  const cfgDataDir = typeof cfg.dataDir === 'string' && cfg.dataDir.trim() ? resolve(cfg.dataDir.trim()) : '';
  const cfgRepo = typeof cfg.repo === 'string' && cfg.repo.trim() ? resolve(cfg.repo.trim()) : '';
  const envDataDir = typeof process.env.PII_GUARD_DATA_DIR === 'string' && process.env.PII_GUARD_DATA_DIR.trim()
    ? resolve(process.env.PII_GUARD_DATA_DIR.trim()) : '';
  const envRepo = typeof process.env.PII_GUARD_REPO === 'string' && process.env.PII_GUARD_REPO.trim()
    ? resolve(process.env.PII_GUARD_REPO.trim()) : '';

  const hasDshHome = typeof process.env.DSH_HOME === 'string' && process.env.DSH_HOME.trim().length > 0;
  let mode = 'dataDir';
  let repo = '';
  let dataDir = '';

  if (cfgDataDir || envDataDir) {
    mode = 'dataDir';
    dataDir = cfgDataDir || envDataDir;
    repo = cfgRepo || envRepo;
  } else if (cfgRepo || envRepo) {
    mode = 'repo';
    repo = cfgRepo || envRepo;
    dataDir = join(repo, '.pii_presidio_store');
  } else if (!hasDshHome) {
    const detectedRepo = detectRepoCheckoutRoot();
    if (detectedRepo) {
      mode = 'repo';
      repo = detectedRepo;
      dataDir = join(repo, '.pii_presidio_store');
    } else {
      mode = 'dataDir';
      dataDir = join(resolveDshHomeDir(), 'data', 'presidio-pii');
    }
  } else {
    mode = 'dataDir';
    dataDir = join(resolveDshHomeDir(), 'data', 'presidio-pii');
  }

  const pickStr = (val) => (typeof val === 'string' && val.trim() ? val.trim() : '');
  const termsFile = pickStr(cfg.termsFile) || pickStr(process.env.PII_GUARD_TERMS_FILE) || join(dataDir, 'user_terms_rules.json');
  const settingsFile = pickStr(cfg.settingsFile) || pickStr(process.env.PII_GUARD_SETTINGS_FILE) || join(dataDir, 'guard-settings.json');
  const defaultPreset = mode === 'repo' && repo
    ? join(repo, '.agent-presets', 'presidio-pii', 'preset.json')
    : join(dataDir, 'preset.json');
  const presetFile = pickStr(cfg.presetFile) || pickStr(cfg.preset) || pickStr(process.env.PII_DSH_PRESET) || defaultPreset;
  const dbFile = pickStr(cfg.dbFile) || pickStr(process.env.PII_DSH_DB_PATH) || join(dataDir, 'sessions.db');
  const logFile = pickStr(cfg.logFile) || pickStr(process.env.PII_DSH_LOG_PATH) || join(dataDir, 'hook_log.jsonl');

  const pkgRoot = resolvePkgRoot();
  const serverFile = join(pkgRoot, 'node_pii', 'server.mjs');
  const hooksFile = join(pkgRoot, 'node_pii', 'hooks.mjs');

  return {
    mode,
    pkgRoot,
    repo,
    dataDir,
    termsFile,
    settingsFile,
    presetFile,
    dbFile,
    logFile,
    serverFile,
    hooksFile,
  };
}

/** Seed preset.json from defaults/preset.json when running in dataDir mode and target does not exist yet. */
export function ensureDefaultPreset(presetFile, mode) {
  if (mode !== 'dataDir' || !presetFile || existsSync(presetFile)) return;
  if (!existsSync(DEFAULT_PRESET_TEMPLATE)) return;
  try {
    mkdirSync(dirname(presetFile), { recursive: true });
    copyFileSync(DEFAULT_PRESET_TEMPLATE, presetFile);
  } catch {
    // Non-fatal: callers handle missing preset cleanly.
  }
}
