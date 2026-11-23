// Safe FS tool surface for dsh-presidio-pii: read_redacted / write_raw / restore / ls
import { readFileSync, writeFileSync, readdirSync, statSync, mkdirSync } from 'node:fs';
import { dirname, basename, resolve as resolvePath, isAbsolute } from 'node:path';
import { pathToFileURL } from 'node:url';
import { ensureDefaultPreset, resolveDataPaths } from './paths.mjs';

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
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, out, 'utf8');
    return {
      displayPath: sanitizePath(target),
      written: out.length,
      totalLength: text.length,
      truncated,
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
    return {
      text: typeof restored === 'string' ? restored : (restored?.text ?? ''),
      displayPath: '<redacted>',
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
    '把文本写入文件。用于把 restore 还原后的原文落盘；长度超过上限会截断并回报 truncated=true。',
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
    '把文本中的 ⟦PII:TYPE:NNNN⟧ 占位符还原成原始敏感值。只在最终交付给用户时使用。',
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
  try {
    const { engine, sid } = await engineFor(paths);
    setRedact(async (text) => {
      const r = await engine.redact(text, sid, 'svc');
      return r?.redacted ?? r?.text ?? '';
    });
    setRestore(async (text) => {
      const r = await engine.restore(text, sid, 'svc');
      return r?.text ?? r?.restored ?? '';
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

export default apply;
