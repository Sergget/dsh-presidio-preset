// Phase 1.1 四件套插件：read_redacted / write_raw / restore / ls
//
// 用途：presidio-pii 最小预设的**唯一**文件访问面。预设不再挂
// tool-bash / tool-pwsh / tool-fs / tool-fs-search / tool-todo / tool-web，
// 模型只能通过这里读（读到的是占位符）和写（写的是还原后的原文）。
//
// 设计约束（对应 docs/RESEARCH-pii-protection.md Phase 1 + D3）：
//   1. 自限长：宿主 spill-local/spill-policy 预设管不到，工具自己截断，
//      永不返回 spill locator，防止超长结果绕过脱敏落盘。
//   2. D3 抹 displayPath：所有返回值/错误只保留 basename，绝不回传真实
//      目录结构（否则模型能从路径里反推用户名、项目名等 PII）。
//   3. 零 DSH 包依赖：只用 node 内置模块 + ctx 注入，与
//      dsh-pii-guard / dsh-pii-guard-terms 的既有风格一致。
//   4. redact/restore 可注入：默认走 node_pii 进程内引擎，测试用
//      setRedact / setRestore 打桩。

import { readFileSync, writeFileSync, readdirSync, statSync, mkdirSync } from 'node:fs';
import { join, dirname, basename, resolve as resolvePath, isAbsolute } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

// ── 限长常量（防 spill 触发）───────────────────────────────────────────────
export const MAX_READ_CHARS = 200_000;
export const MAX_WRITE_CHARS = 500_000;
export const MAX_LS_ENTRIES = 500;

// ── D3：抹除 displayPath ──────────────────────────────────────────────────
export function sanitizePath(p) {
  if (typeof p !== 'string' || p.length === 0) return '<unknown>';
  return basename(p);
}

export function safeError(err, op) {
  const msg = err && typeof err.message === 'string' ? err.message : String(err);
  // 错误消息里可能带绝对路径，统一抹成 basename 形态
  return { error: `${op} failed: ${stripDirs(msg)}`, displayPath: '<redacted>' };
}

/** 把错误文本里的路径片段压成 basename，避免目录结构泄漏。 */
function stripDirs(text) {
  return text.replace(/([A-Za-z]:)?[\\/][^\s'"]*/g, (seg) => sanitizePath(seg));
}

// ── redact / restore 注入点 ───────────────────────────────────────────────
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

// ── read_redacted ─────────────────────────────────────────────────────────
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

// ── write_raw ─────────────────────────────────────────────────────────────
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

// ── restore ───────────────────────────────────────────────────────────────
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

// ── ls ────────────────────────────────────────────────────────────────────
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
    let rows = entries.slice(0, MAX_LS_ENTRIES).map((e) => ({
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

// ── Cordis 插件表面 ───────────────────────────────────────────────────────
export const name = 'pii-guard-fs';
// 只依赖 tools 服务；不依赖 fs（自带 node:fs），不依赖 sandbox。
export const inject = ['tools'];

const byName = {
  read_redacted: readRedacted,
  write_raw: writeRaw,
  restore: restoreText,
  ls: listDir,
};

/** 手搓 Cordis 工具定义：本部署的插件无法 import @deepseek-ai/dsh-tools。 */
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

// ── repo / preset 解析 ────────────────────────────────────────────────────
export function inferRepo(explicit) {
  if (typeof explicit === 'string' && explicit.length > 0) return explicit;
  const fromEnv = process.env.PII_GUARD_REPO;
  if (typeof fromEnv === 'string' && fromEnv.length > 0) return fromEnv;
  try {
    // <repo>/plugins/dsh-pii-guard-fs/lib/index.mjs → 上三级
    return resolvePath(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
  } catch {
    return undefined;
  }
}

/** 进程内引擎单例（node_pii/hooks.mjs），与 guard 共用同一 preset/db。 */
let enginePromise;
async function engineFor(repo, presetPath) {
  if (enginePromise !== undefined) return enginePromise;
  enginePromise = (async () => {
    if (repo === undefined) throw new Error('cannot locate repository root: set config.repo or PII_GUARD_REPO');
    const mod = await import(pathToFileURL(join(repo, 'node_pii', 'hooks.mjs')).href);
    return mod.getEngine({ repoDir: repo, presetPath });
  })();
  return enginePromise;
}
export function resetEngine() {
  enginePromise = undefined;
}

export async function apply(ctx, config = {}) {
  const repo = inferRepo(config?.repo);
  const presetPath = config?.preset;
  try {
    const engine = await engineFor(repo, presetPath);
    setRedact(async (text) => {
      const r = await engine.redact(text);
      return r?.redacted ?? r?.text ?? '';
    });
    setRestore(async (text) => {
      const r = await engine.restore(text);
      return r?.text ?? r?.restored ?? '';
    });
  } catch (err) {
    // fail-closed：拿不到引擎时绝不直通原文，让工具直接报错
    setRedact(async () => {
      throw new Error(`PII engine unavailable: ${err?.message ?? String(err)}`);
    });
    setRestore(async () => {
      throw new Error(`PII engine unavailable: ${err?.message ?? String(err)}`);
    });
  }
  for (const def of TOOL_DEFS) ctx.tools.register(def);
}

/** 测试用：拿到 4 个裸函数（不经过 Cordis）。 */
export function createGuardFsTools({ redact, restore } = {}) {
  if (redact) setRedact(redact);
  if (restore) setRestore(restore);
  return { read_redacted: readRedacted, write_raw: writeRaw, restore: restoreText, ls: listDir };
}

export default apply;
