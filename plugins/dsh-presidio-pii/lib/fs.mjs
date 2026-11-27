// Safe FS tool surface for dsh-presidio-pii: read_redacted / write_raw / restore / ls
import { readFileSync, writeFileSync, readdirSync, statSync, mkdirSync, existsSync } from 'node:fs';
import { dirname, basename, resolve as resolvePath, isAbsolute } from 'node:path';
import { pathToFileURL } from 'node:url';
import { ensureDefaultPreset, resolveDataPaths } from './paths.mjs';

// ---- 显示模式（与 guard.js 同口径）----
// restore 是「只读展示」工具，其输出直接面向用户，必须遵守 guard-settings.json
// 的 displayMode：mask 时打码显示（显示侧不放完整明文），full 才返回原文。
// write_raw 的落盘还原不受影响——落盘永远是明文（write_raw 自行走 restoreImpl）。
let ACTIVE_SETTINGS_FILE = null;
let _dispCfg = { sig: '', mode: null };

function coerceDisplayMode(v) {
  const s = String(v ?? '').toLowerCase();
  return ['full', 'mask', 'off'].includes(s) ? s : 'full';
}

function displayMode() {
  if (!ACTIVE_SETTINGS_FILE) return 'full';
  let sig = '';
  try {
    if (existsSync(ACTIVE_SETTINGS_FILE)) {
      const st = statSync(ACTIVE_SETTINGS_FILE);
      sig = `${st.mtimeMs}:${st.size}`;
    }
  } catch { sig = ''; }
  if (_dispCfg.mode !== null && sig === _dispCfg.sig) return _dispCfg.mode;
  let mode = coerceDisplayMode(process.env.PII_GUARD_DISPLAY ?? 'full');
  if (sig) {
    try {
      const parsed = JSON.parse(readFileSync(ACTIVE_SETTINGS_FILE, 'utf8'));
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)
          && Object.hasOwn(parsed, 'displayMode')) {
        mode = coerceDisplayMode(parsed.displayMode);
      }
    } catch { /* keep env fallback */ }
  }
  _dispCfg = { sig, mode };
  return mode;
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

function phType(ph) {
  return ph.replace(/^⟦/, '').replace(/⟧$/, '').split(':')[1];
}

export const MAX_READ_CHARS = 200_000;
export const MAX_WRITE_CHARS = 500_000;
export const MAX_LS_ENTRIES = 500;

export function sanitizePath(p) {
  if (typeof p !== 'string' || p.length === 0) return '<unknown>';
  return basename(p);
}

export function safeError(err, op) {
  const msg = err && typeof err.message === 'string' ? err.message : String(err);
  return { error: `${op} failed: ${stripDirs(msg)}`, displayPath: '<redacted>' };
}

function stripDirs(text) {
  return text.replace(/([A-Za-z]:)?[\\/][^\s'"]*/g, (seg) => sanitizePath(seg));
}

let redactImpl = (text) => text;
let restoreImpl = (text) => text;

export function setRedact(fn) {
  if (typeof fn === 'function') redactImpl = fn;
}
export function setRestore(fn) {
  if (typeof fn === 'function') restoreImpl = fn;
}
export function resetImpls() {
  redactImpl = (text) => text;
  restoreImpl = (text) => text;
}

/** 测试辅助：设置/清除显示模式配置文件路径。 */
export function setDisplaySettingsFile(file) {
  ACTIVE_SETTINGS_FILE = file ?? null;
  _dispCfg = { sig: '', mode: null };
}

function pickPath(args) {
  return args?.path ?? args?.file ?? args?.file_path ?? args?.dir ?? args?.directory;
}

function resolveTarget(ctx, args) {
  const raw = pickPath(args);
  if (typeof raw !== 'string' || raw.trim().length === 0) {
    throw new Error('path is required');
  }
  if (isAbsolute(raw)) return raw;
  const cwd = ctx?.cwd ?? process.cwd();
  return resolvePath(cwd, raw);
}

export async function readRedacted(ctx, args) {
  let target;
  try {
    target = resolveTarget(ctx, args);
  } catch (err) {
    return safeError(err, 'read_redacted');
  }
  try {
    let text = readFileSync(target, 'utf8');
    const totalLength = text.length;
    let truncated = false;
    if (text.length > MAX_READ_CHARS) {
      text = text.slice(0, MAX_READ_CHARS);
      truncated = true;
    }
    const redacted = await redactImpl(text);
    return {
      text: typeof redacted === 'string' ? redacted : (redacted?.redacted ?? ''),
      displayPath: sanitizePath(target),
      truncated,
      totalLength,
    };
  } catch (err) {
    return safeError(err, 'read_redacted');
  }
}

const PH_SRC_RE = /⟦PII:[A-Z_]+:\d+⟧/g;

function countPlaceholders(text) {
  return (text.match(PH_SRC_RE) || []).length;
}

export async function writeRaw(ctx, args) {
  let target;
  try {
    target = resolveTarget(ctx, args);
  } catch (err) {
    return safeError(err, 'write_raw');
  }
  const text = args?.text ?? args?.content;
  if (typeof text !== 'string') {
    return { error: 'write_raw: text is required', displayPath: '<redacted>' };
  }
  try {
    let out = text;
    let truncated = false;
    if (out.length > MAX_WRITE_CHARS) {
      out = out.slice(0, MAX_WRITE_CHARS);
      truncated = true;
    }
    // 关键修复：绝不让 ⟦PII:TYPE:NNNN⟧ 占位符字面落盘。
    // 与 guard 对 write/edit 的 restoreArgs 同口径：检测到占位符时先走还原；
    // 还原后仍有残留（映射缺失）则拒绝写入并回显残留占位符，宁可失败也不静默污染文件。
    let restoredCount = 0;
    let rejectedPlaceholders = [];
    if (PH_SRC_RE.test(out)) {
      PH_SRC_RE.lastIndex = 0;
      let restoredText;
      try {
        const rr = await restoreImpl(out);
        restoredText = typeof rr === 'string' ? rr : (rr?.text ?? out);
      } catch (err) {
        return safeError(err, 'write_raw (placeholder restore)');
      }
      if (typeof restoredText === 'string' && restoredText !== out) {
        restoredCount = countPlaceholders(out);
        out = restoredText;
      }
      const remaining = countPlaceholders(out);
      if (remaining > 0) {
        rejectedPlaceholders = [...new Set(out.match(PH_SRC_RE) || [])].slice(0, 10);
        return {
          error: 'write_raw: text still contains ' + remaining
            + ' unrestored PII placeholder(s) after restore; refusing to write. '
            + 'Rewrite the text so no ⟦PII:TYPE:NNNN⟧ markers remain, or verify the placeholders exist in the current session mapping. '
            + 'Rejected placeholders: ' + rejectedPlaceholders.join(', '),
          displayPath: sanitizePath(target),
        };
      }
    }
    PH_SRC_RE.lastIndex = 0;
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, out, 'utf8');
    // 写后读回自检：确认磁盘上的内容确实不含占位符且长度一致（UTF-8）。
    let verify = { verified: true };
    try {
      const writtenBack = readFileSync(target, 'utf8');
      if (writtenBack.length !== out.length || writtenBack !== out) {
        verify = { verified: false, reason: 'written bytes differ from requested text' };
      } else if (countPlaceholders(writtenBack) > 0) {
        verify = { verified: false, reason: 'file contains PII placeholders after write' };
      }
    } catch {
      verify = { verified: false, reason: 'read-back failed' };
    }
    return {
      displayPath: sanitizePath(target),
      written: out.length,
      totalLength: text.length,
      truncated,
      placeholdersRestored: restoredCount,
      ...verify,
    };
  } catch (err) {
    return safeError(err, 'write_raw');
  }
}

export async function restoreText(ctx, args) {
  const text = args?.text ?? args?.content;
  if (typeof text !== 'string') {
    return { error: 'restore: text is required', displayPath: '<redacted>' };
  }
  try {
    const restored = await restoreImpl(text);
    let out = typeof restored === 'string' ? restored : (restored?.text ?? '');
    // 显示模式修复：restore 的结果只面向用户展示，必须遵守 displayMode。
    // mask 时按「原文里的占位符」逐个替换为打码值——不能在还原后的文本上替换
    // （占位符已被还原成原文，找不到锚点会泄露完整 PII）。
    if (displayMode() === 'mask' && PH_SRC_RE.test(text)) {
      PH_SRC_RE.lastIndex = 0;
      const maskMap = (restored && typeof restored === 'object' && restored.restored)
        ? restored.restored
        : null;
      out = text.replace(PH_SRC_RE, (ph) => {
        const orig = maskMap ? maskMap[ph] : undefined;
        // 有映射则打码；无映射的占位符保持原样（不泄漏原文）
        return orig !== undefined && orig !== null ? maskValue(orig, phType(ph)) : ph;
      });
    }
    PH_SRC_RE.lastIndex = 0;
    // 语义修复：restore 只用于最终交付展示。若结果仍含占位符（映射缺失或被
    // 重新登记），必须显式告知，避免把占位符版本当明文写回文件。
    const placeholdersLeft = countPlaceholders(out);
    const warning = placeholdersLeft > 0
      ? 'RESTORE-ONLY-FOR-DISPLAY: ' + placeholdersLeft
        + ' placeholder(s) could NOT be restored (no mapping in this session). '
        + 'Do NOT write this text to a file via write_raw with placeholders still in it — '
        + 'quote the placeholders verbatim or re-read the source with read_redacted.'
      : undefined;
    return {
      text: out,
      displayPath: '<redacted>',
      ...(warning ? { warning } : {}),
    };
  } catch (err) {
    return safeError(err, 'restore');
  }
}

export async function listDir(ctx, args) {
  let target;
  try {
    target = resolveTarget(ctx, args ?? {});
  } catch (err) {
    return safeError(err, 'ls');
  }
  try {
    const st = statSync(target);
    if (!st.isDirectory()) {
      return { error: 'ls: not a directory', displayPath: sanitizePath(target) };
    }
    const entries = readdirSync(target, { withFileTypes: true });
    const totalEntries = entries.length;
    const rows = entries.slice(0, MAX_LS_ENTRIES).map((e) => ({
      name: e.name,
      isDirectory: e.isDirectory(),
      isFile: e.isFile(),
    }));
    return {
      displayPath: sanitizePath(target),
      entries: rows,
      count: rows.length,
      totalEntries,
      truncated: totalEntries > MAX_LS_ENTRIES,
    };
  } catch (err) {
    return safeError(err, 'ls');
  }
}

export const name = 'pii-guard-fs';
export const inject = ['tools'];

const byName = {
  read_redacted: readRedacted,
  write_raw: writeRaw,
  restore: restoreText,
  ls: listDir,
};

function toolDefinition(toolName, description, parameters) {
  return {
    name: toolName,
    description,
    parameters,
    output: {
      schema: { type: 'object', additionalProperties: true },
      render: (_args, value) => [
        { type: 'text', text: typeof value === 'string' ? value : JSON.stringify(value, null, 2) },
      ],
    },
    async execute(args, exec) {
      return byName[toolName](exec?.ctx ?? exec, args ?? {});
    },
  };
}

export const TOOL_DEFS = [
  toolDefinition(
    'read_redacted',
    '读取文本文件并返回 PII 脱敏后的内容（敏感值以 ⟦PII:TYPE:NNNN⟧ 占位符呈现）。这是本 preset 唯一的读取入口。',
    {
      type: 'object',
      additionalProperties: false,
      properties: {
        path: { type: 'string', description: '要读取的文件路径（绝对路径或相对当前工作目录）。' },
      },
      required: ['path'],
    },
  ),
  toolDefinition(
    'write_raw',
    '把文本写入文件（只写明文，绝不写 ⟦PII:TYPE:NNNN⟧ 占位符）。若 text 中含占位符，会先自动尝试还原成明文；仍有无法还原的占位符时将拒绝写入并报错——此时请改用 read_redacted 重新读取源文件，基于其返回的脱敏文本编辑后再写。写入后会读回校验，verified=false 表示写盘异常。',
    {
      type: 'object',
      additionalProperties: false,
      properties: {
        path: { type: 'string', description: '目标文件路径。' },
        text: { type: 'string', description: '要写入的完整文本内容。' },
      },
      required: ['path', 'text'],
    },
  ),
  toolDefinition(
    'restore',
    '把文本中的 ⟦PII:TYPE:NNNN⟧ 占位符还原成原始敏感值。只读展示工具：仅供最终交付给用户查看，不得用于生成写回文件的内容（write_raw 会自行处理还原，且拒绝写入含占位符的文本）。若返回带 warning，表示有占位符无映射、无法还原。',
    {
      type: 'object',
      additionalProperties: false,
      properties: {
        text: { type: 'string', description: '含占位符的文本。' },
      },
      required: ['text'],
    },
  ),
  toolDefinition(
    'ls',
    '列出目录条目（只返回文件名，不含目录结构）。超过 500 条会截断并回报 truncated=true。',
    {
      type: 'object',
      additionalProperties: false,
      properties: {
        path: { type: 'string', description: '目录路径，默认当前工作目录。' },
      },
    },
  ),
];

let enginePromise;
async function engineFor(paths) {
  if (enginePromise !== undefined) return enginePromise;
  enginePromise = (async () => {
    const mod = await import(pathToFileURL(paths.hooksFile).href);
    const engine = mod.getEngine({
      repoDir: paths.repo || paths.pkgRoot,
      dataDir: paths.dataDir,
      dbPath: paths.dbFile,
      presetPath: paths.presetFile,
    });
    const sid = mod.sessionId('pii-guard-' + process.pid);
    return { engine, sid };
  })();
  return enginePromise;
}
export function resetEngine() {
  enginePromise = undefined;
}

export async function apply(ctx, config = {}) {
  const paths = resolveDataPaths(config);
  ensureDefaultPreset(paths.presetFile, paths.mode);
  ACTIVE_SETTINGS_FILE = paths.settingsFile;
  _dispCfg = { sig: '', mode: null };
  try {
    const { engine, sid } = await engineFor(paths);
    setRedact(async (text) => {
      const r = await engine.redact(text, sid, 'svc');
      return r?.redacted ?? r?.text ?? '';
    });
    setRestore(async (text) => {
      const r = await engine.restore(text, sid, 'svc');
      // 返回增强对象：text 供 writeRaw 落盘明文，restored 供 restoreText
      // 在 mask 显示模式下按占位符打码。
      return {
        text: r?.text ?? r?.restored ?? '',
        restored: r?.restored ?? {},
      };
    });
  } catch (err) {
    setRedact(async () => {
      throw new Error(`PII engine unavailable: ${err?.message ?? String(err)}`);
    });
    setRestore(async () => {
      throw new Error(`PII engine unavailable: ${err?.message ?? String(err)}`);
    });
  }
  for (const def of TOOL_DEFS) ctx.tools.register(def);
}

export function createGuardFsTools({ redact, restore } = {}) {
  if (redact) setRedact(redact);
  if (restore) setRestore(restore);
  return { read_redacted: readRedacted, write_raw: writeRaw, restore: restoreText, ls: listDir };
}
// 注意：不要加 `export default apply`。DSH 插件加载器的 unwrapExports 遇到
// default export 会把模块主值当作 service class / apply 形态处理，模块级
// `inject`/`name` 导出被丢弃 → Cordis 判定本插件未声明 inject，
// apply 里访问 ctx.tools 抛 `cannot get property "tools" without inject`
// （2026-11-24 preset 加载失败的根因）。guard.js 只有命名导出，故未报错。
