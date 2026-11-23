// dsh-presidio-pii runtime guard plugin (tools/post-execute, agent/created, agent/pre-step, agent/assistant-stream)
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { appendFileSync, existsSync, mkdirSync, readFileSync, statSync } from "node:fs";
import { createHash, randomUUID } from "node:crypto";
import { dirname } from "node:path";
import { ensureDefaultPreset, resolveDataPaths } from "./paths.mjs";
import { hasNestedQuantifier } from "./regex-safety.mjs";

const SHELL_TOOLS = new Set(["pwsh", "bash"]);
const JOB_TOOLS = new Set(["job_output", "job_list"]);
const SHELL_GUARDED = new Set([...SHELL_TOOLS, ...JOB_TOOLS]);
const SKIP_TOOLS = new Set(["job_kill", "read_image"]);
const WRITE_TOOLS = new Set(["write", "edit", "apply_patch", "str_replace_editor"]);
const WRITE_TEXT_KEYS = new Set([
  "content", "new_string", "old_string", "new_str", "old_str",
  "text", "patch", "file_text", "newText", "oldText",
]);
const MAX_JOB_BYTES = 256_000;
const TRUNC_MARK = "\n[pii-guard] output truncated to 256000 bytes before redaction";
const BLOCK_MARK = "[pii-guard] PII redaction service unavailable; tool result blocked (fail-closed). Retry, or set PII_GUARD_FAIL_OPEN=1 for troubleshooting.";

const NODE_BIN = process.env.PII_GUARD_NODE ?? process.env.PII_GUARD_PY ?? process.execPath;

let INITIAL_PATHS = resolveDataPaths(null);
let PKG_ROOT = INITIAL_PATHS.pkgRoot;
let REPO = INITIAL_PATHS.repo || INITIAL_PATHS.pkgRoot;
let DATA_DIR = INITIAL_PATHS.dataDir;
let SERVER = INITIAL_PATHS.serverFile;
let HOOK_LOG = INITIAL_PATHS.logFile;
let GUARD_SETTINGS_FILE = INITIAL_PATHS.settingsFile;
let PRESET_FILE = INITIAL_PATHS.presetFile;
let DB_FILE = INITIAL_PATHS.dbFile;

const SID = "pii-guard-" + process.pid;
const CALL_TIMEOUT_MS = 30_000;
const PH_FULL = /⟦PII:[A-Z_]+:\d+⟧/g;
const PH_TAIL = /⟦(?:PII:[A-Z_]+(?::\d*)?)?$/;

function coerceDisplayMode(v) {
  const s = String(v ?? "").toLowerCase();
  return ["full", "mask", "off"].includes(s) ? s : "full";
}
function coerceShellDisabled(v) {
  if (v === true) return true;
  if (v === false || v === null || v === undefined) return false;
  return ["off", "1", "true", "disabled"].includes(String(v).toLowerCase());
}

const ENV_FALLBACK = {
  displayMode: coerceDisplayMode(process.env.PII_GUARD_DISPLAY ?? "full"),
  failOpen: (process.env.PII_GUARD_FAIL_OPEN ?? "").toLowerCase() === "1",
  shellDisabled: (process.env.PII_GUARD_SHELL ?? "").toLowerCase() === "off",
  shellAllowlist: process.env.PII_GUARD_SHELL_ALLOWLIST ?? "",
};

let _cfg = { sig: "", values: null, allowlist: null, allowlistSrc: null };

function readSettings() {
  let sig = "";
  try {
    if (existsSync(GUARD_SETTINGS_FILE)) {
      const st = statSync(GUARD_SETTINGS_FILE);
      sig = `${st.mtimeMs}:${st.size}`;
    }
  } catch { sig = ""; }
  if (_cfg.values && sig === _cfg.sig) return _cfg.values;
  let disk = {};
  if (sig) {
    try {
      const parsed = JSON.parse(readFileSync(GUARD_SETTINGS_FILE, "utf8"));
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) disk = parsed;
    } catch { disk = {}; }
  }
  const pick = (key) => (Object.hasOwn(disk, key) ? disk[key] : ENV_FALLBACK[key]);
  const values = {
    displayMode: coerceDisplayMode(pick("displayMode")),
    failOpen: Boolean(pick("failOpen")),
    shellDisabled: coerceShellDisabled(pick("shellDisabled")),
    shellAllowlist: String(pick("shellAllowlist") ?? ""),
  };
  _cfg = { sig, values, allowlist: null, allowlistSrc: null };
  return values;
}

function displayMode() { return readSettings().displayMode; }
function isFailOpen() { return readSettings().failOpen; }
function isShellDisabled() { return readSettings().shellDisabled; }

function getAllowlist() {
  const cfg = readSettings();
  if (_cfg.allowlistSrc === cfg.shellAllowlist) return _cfg.allowlist;
  let re = null;
  if (cfg.shellAllowlist) {
    if (hasNestedQuantifier(cfg.shellAllowlist)) {
      // Same shape the settings UI rejects; checked here too because this file
      // can be edited by hand or overridden via PII_GUARD_SHELL_ALLOWLIST.
      console.error("[pii-guard] PII_GUARD_SHELL_ALLOWLIST rejected: nested quantifiers can freeze the agent loop (ReDoS), ignored");
    } else {
      try {
        re = new RegExp(cfg.shellAllowlist);
      } catch (err) {
        console.error(`[pii-guard] invalid PII_GUARD_SHELL_ALLOWLIST, ignored: ${err?.message ?? err}`);
      }
    }
  }
  _cfg.allowlistSrc = cfg.shellAllowlist;
  _cfg.allowlist = re;
  return re;
}

const name = "pii-guard";
const inject = ["tools"];

const PLACEHOLDER_NOTICE_TEXT = [
  "[pii-guard] 工具结果中出现的 ⟦PII:TYPE:NNNN⟧ 是数据脱敏占位符，不是普通文本。使用规则：",
  "1) 引用工具结果时必须逐字符保留占位符原样（包括 ⟦ 与 ⟧），不要转写、缩写、改格式或拆分；",
  "2) 不要猜测占位符代表的内容，也不要为其编造替代文本；",
  "3) 直接展示给用户时保持原样——界面会自动把占位符还原为原始信息。",
].join("\n");
const noticedAgents = new WeakSet();
function placeholderNotice() {
  return {
    role: "user",
    id: "pii-notice-" + randomUUID(),
    content: [{ type: "text", text: PLACEHOLDER_NOTICE_TEXT }],
    source: { kind: "pii-guard", form: "notice", summary: "PII 占位符使用规则" },
  };
}

const PATH_SEP = /[\\/]/;

function isPathFragment(text, value) {
  if (typeof value !== "string" || value === "") return false;
  if (PATH_SEP.test(value)) return true;
  let idx = text.indexOf(value);
  while (idx !== -1) {
    const before = idx > 0 ? text[idx - 1] : "";
    const after = idx + value.length < text.length ? text[idx + value.length] : "";
    if ((before && PATH_SEP.test(before)) || (after && PATH_SEP.test(after))) return true;
    idx = text.indexOf(value, idx + value.length);
  }
  return false;
}

async function redactExempted(text, exec, redactFn) {
  const fn = redactFn ?? redact;
  const msg = await fn(text);
  if (exec && SHELL_GUARDED.has(exec.name) && msg?.map) {
    for (const [ph, val] of Object.entries(msg.map)) {
      if (!ph.includes("ORGANIZATION")) continue;
      if (!isPathFragment(text, val)) continue;
      msg.redacted = msg.redacted.replaceAll(ph, val);
      delete msg.map[ph];
    }
  }
  return msg || { redacted: text, map: {} };
}

let svc = null;
let seq = 0;

function retireService(handle) {
  if (svc === handle) svc = null;
  try { handle.proc.kill(); } catch { /* already dead */ }
}

function buildServerEnv() {
  const env = { ...process.env };
  if (DATA_DIR) env.PII_GUARD_DATA_DIR = DATA_DIR;
  if (DB_FILE) env.PII_DSH_DB_PATH = DB_FILE;
  if (HOOK_LOG) env.PII_DSH_LOG_PATH = HOOK_LOG;
  if (PRESET_FILE) env.PII_DSH_PRESET = PRESET_FILE;
  if (REPO) env.PII_GUARD_REPO = REPO;
  return env;
}

function ensureService() {
  if (svc) return svc;
  try {
    if (DATA_DIR) mkdirSync(DATA_DIR, { recursive: true });
  } catch { /* non-fatal */ }
  const handle = { proc: null, pending: new Map(), rl: null };
  const proc = spawn(NODE_BIN, [SERVER], {
    cwd: PKG_ROOT,
    env: buildServerEnv(),
    stdio: ["pipe", "pipe", "inherit"],
  });
  handle.proc = proc;
  svc = handle;
  const rl = createInterface({ input: proc.stdout });
  handle.rl = rl;
  rl.on("line", (line) => {
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      return;
    }
    const waiter = handle.pending.get(msg.id);
    if (waiter) {
      handle.pending.delete(msg.id);
      waiter(msg);
    }
  });
  const die = (error) => {
    for (const waiter of handle.pending.values()) waiter({ error });
    handle.pending.clear();
    if (svc === handle) svc = null;
  };
  proc.on("exit", () => die("pii server exited"));
  proc.on("error", (err) => die(`pii server spawn failed: ${err?.code ?? err?.message ?? err}`));
  return handle;
}

function callServerOn(handle, payload, pick, project) {
  if (!handle) return Promise.reject(new Error("pii server unavailable"));
  const id = "g" + (++seq);
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      handle.pending.delete(id);
      reject(new Error("pii server timeout"));
    }, CALL_TIMEOUT_MS);
    handle.pending.set(id, (msg) => {
      clearTimeout(timer);
      if (msg.error) reject(new Error(msg.error));
      else if (typeof pick(msg) !== "string") reject(new Error("pii server bad response"));
      else resolve(project ? project(msg) : pick(msg));
    });
    try {
      handle.proc.stdin.write(JSON.stringify({ ...payload, id, sid: SID }) + "\n");
    } catch (err) {
      handle.pending.delete(id);
      clearTimeout(timer);
      reject(err);
    }
  });
}

function redact(text) {
  return callServerWithRetry({ text, mode: "full" }, (msg) => msg.redacted, (msg) => msg);
}

function restoreText(text) {
  return callServerWithRetry({ op: "restore", text, mode: "full" }, (msg) => msg.restored);
}

const CALL_MAX_ATTEMPTS = 3;
const CALL_RETRY_BASE_MS = 150;
const RECOVERABLE = /unavailable|spawn failed|exited|timeout/i;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function callServerWithRetry(payload, pick, project) {
  let lastErr = null;
  let failedHandle = null;
  for (let attempt = 1; attempt <= CALL_MAX_ATTEMPTS; attempt += 1) {
    try {
      const handle = ensureService();
      failedHandle = handle;
      return await callServerOn(handle, payload, pick, project);
    } catch (err) {
      lastErr = err;
      const recoverable = RECOVERABLE.test(String(err?.message ?? err));
      if (!recoverable || attempt === CALL_MAX_ATTEMPTS) break;
      if (failedHandle) retireService(failedHandle);
      await sleep(CALL_RETRY_BASE_MS * attempt);
    }
  }
  throw lastErr ?? new Error("pii server unavailable");
}

async function restoreArgs(args, restoreFn) {
  let changed = false;
  const failed = [];
  async function walk(value, key) {
    if (typeof value === "string") {
      if (key && WRITE_TEXT_KEYS.has(key) && value.includes("⟦PII:")) {
        try {
          const restored = await restoreFn(value);
          if (restored !== value) changed = true;
          return restored;
        } catch (err) {
          failed.push(`${key}: ${err?.message ?? err}`);
          return value;
        }
      }
      return value;
    }
    if (Array.isArray(value)) {
      const out = [];
      for (const item of value) out.push(await walk(item, key));
      return out;
    }
    if (value && typeof value === "object") {
      const out = {};
      for (const [k, v] of Object.entries(value)) out[k] = await walk(v, k);
      return out;
    }
    return value;
  }
  const out = await walk(args, null);
  return { args: out, changed, failed };
}

function redactValueLeaves(value, pairs) {
  function mapString(s) {
    let out = s;
    for (const [ph, orig] of pairs) {
      if (orig && out.includes(orig)) out = out.split(orig).join(ph);
    }
    return out;
  }
  function walk(v) {
    if (typeof v === "string") return mapString(v);
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === "object") {
      const out = {};
      for (const [k, val] of Object.entries(v)) out[k] = walk(val);
      return out;
    }
    return v;
  }
  return walk(value);
}

// 有界缓存：两者都按"最近写入"淘汰，避免长会话无限增长。
// phMap 被淘汰后占位符退化为原样显示（不泄漏原文），displayBufs 按 session
// 淘汰后该会话的扣尾缓冲丢失（仅可能少显示半截占位符，同样不泄漏）。
const PH_CACHE_LIMIT = 20_000;
const DISPLAY_BUF_LIMIT = 200;
const phMap = new Map();
const displayBufs = new Map();

function cacheSet(map, key, value, limit) {
  map.delete(key); // 重新插入以刷新淘汰顺序
  map.set(key, value);
  while (map.size > limit) {
    const oldest = map.keys().next();
    if (oldest.done) break;
    map.delete(oldest.value);
  }
}

function splitDisplayable(acc) {
  const m = PH_TAIL.exec(acc);
  const hold = m ? m[0] : "";
  const head = hold ? acc.slice(0, acc.length - hold.length) : acc;
  const shown = head.replace(PH_FULL, (ph) => phMap.get(ph) ?? ph);
  return { shown, hold };
}

const pendingRestores = new Set();
let restoreImpl = restoreText;
function scheduleRestore(ph) {
  if (pendingRestores.has(ph)) return;
  pendingRestores.add(ph);
  restoreImpl(ph).then((restored) => {
    if (restored && restored !== ph) {
      cacheSet(phMap, ph, displayMode() === "mask" ? displayValue(ph, restored) : restored, PH_CACHE_LIMIT);
    }
  }).catch(() => {
    // keep placeholder on restore failure
  }).finally(() => {
    pendingRestores.delete(ph);
  });
}

function displayValue(ph, orig) {
  if (displayMode() !== "mask") return orig;
  const etype = ph.replace(/^⟦PII:/, "").replace(/:\d+⟧$/, "");
  if (etype === "EMAIL_ADDRESS" && orig.includes("@")) {
    const at = orig.indexOf("@");
    const head = orig.slice(0, 1) || "*";
    return `${head}***@${orig.slice(at + 1)}`;
  }
  if (orig.length <= 4) return orig.slice(0, 1) + "*".repeat(orig.length - 1);
  return orig.slice(0, 2) + "*".repeat(orig.length - 4) + orig.slice(-2);
}

function isText(s) {
  if (s.length === 0) return true;
  const n = Math.min(s.length, 8192);
  let nul = 0, bad = 0;
  for (let i = 0; i < n; i++) {
    const c = s.charCodeAt(i);
    if (c === 0) { nul++; continue; }
    if (c < 32 && c !== 9 && c !== 10 && c !== 13 && c !== 27) bad++;
  }
  return nul / n <= 0.01 && bad / n <= 0.3;
}

function truncateBytes(s, limit) {
  if (Buffer.byteLength(s, "utf8") <= limit) return { text: s, truncated: false };
  let cut = Buffer.from(s, "utf8").subarray(0, limit).toString("utf8");
  if (cut.endsWith("\uFFFD")) cut = cut.slice(0, -1);
  return { text: cut, truncated: true };
}

function auditShellBypass(exec, reason) {
  try {
    const cmd = String(exec?.args?.command ?? "");
    const cmdSha1 = createHash("sha1").update(cmd).digest("hex").slice(0, 8);
    const rec = {
      ts: Math.round(Date.now()) / 1000,
      iso: new Date().toISOString(),
      event: "shell_bypass",
      tool: exec?.name,
      reason,
      cmd_sha1: cmdSha1,
      bytes: cmd.length,
    };
    mkdirSync(dirname(HOOK_LOG), { recursive: true });
    appendFileSync(HOOK_LOG, JSON.stringify(rec) + "\n", "utf8");
  } catch {
    // audit failure must not block bypass
  }
}

const ALLOWLIST_MAX_CMD = 4096;

function shellBypassReason(exec) {
  if (isShellDisabled()) return "env";
  const allowlist = getAllowlist();
  const cmd = exec?.args?.command;
  if (allowlist && typeof cmd === "string" && cmd.length <= ALLOWLIST_MAX_CMD && allowlist.test(cmd)) {
    return "allowlist";
  }
  return null;
}

function configurePaths(config) {
  const paths = resolveDataPaths(config);
  PKG_ROOT = paths.pkgRoot;
  REPO = paths.repo || paths.pkgRoot;
  DATA_DIR = paths.dataDir;
  SERVER = paths.serverFile;
  HOOK_LOG = paths.logFile;
  GUARD_SETTINGS_FILE = paths.settingsFile;
  PRESET_FILE = paths.presetFile;
  DB_FILE = paths.dbFile;
  ensureDefaultPreset(PRESET_FILE, paths.mode);
  _cfg = { sig: "", values: null, allowlist: null, allowlistSrc: null };
}

export async function apply(ctx, options = {}) {
  configurePaths(options);
  const deps = options ?? {};
  const redactFn = deps.redact ?? redact;
  const restoreFn = deps.restore ?? restoreText;
  restoreImpl = restoreFn;

  ctx.on(
    "tools/post-execute",
    async (exec, result, next) => {
      const decision = await next();
      if (SKIP_TOOLS.has(exec.name)) return decision;
      if (result?.isError && !SHELL_GUARDED.has(exec.name)) return decision;
      if (decision?.kind === "block") return decision;
      if (SHELL_GUARDED.has(exec.name)) {
        const bypass = shellBypassReason(exec);
        if (bypass) {
          auditShellBypass(exec, bypass);
          return decision;
        }
      }
      if (decision !== undefined && Object.hasOwn(decision, "value")) {
        console.error("[pii-guard] post-execute value replacement present, blocking result");
        return {
          kind: "block",
          feedback: [{ type: "text", text: "[pii-guard] a downstream policy replaced this tool's canonical value; result blocked to avoid leaking unredacted content." }],
        };
      }
      const source = decision?.content ?? result?.content;
      if (!Array.isArray(source) || !source.some((b) => b?.type === "text" && typeof b.text === "string")) return decision;
      try {
        const content = [];
        if (source.some((b) => b?.type === "text" && typeof b.text === "string" && isText(b.text) && (b.text.includes("\ufffd") || b.text.includes("\u0000")))) {
          content.push({ type: "text", text: "\n[pii-guard] 检测到输出含有乱码（编码错乱），这可能导致模型无法正确识别内容。请改用安全读取工具或确认文件为 UTF-8 编码。" });
        }
        if (SHELL_GUARDED.has(exec.name)) {
          const cmd = String(exec?.args?.command ?? "");
          if (/\.(docx|xlsx|pptx|doc|xls|ppt)\b/i.test(cmd)) {
            content.push({ type: "text", text: "\n[pii-guard] 警告：shell 命令直接引用了 office 二进制文档。这是乱码与脱敏绕过的主要来源——请改用 `read` 工具读取（自带脱敏），或先用 `python -X utf8` + python-docx/openpyxl 转出 Markdown/文本后再读。详见 docs/WORKFLOW-GUIDE.md。" });
          }
        }
        const pairs = [];
        for (const block of source) {
          if (block?.type !== "text" || typeof block.text !== "string") {
            content.push(block);
            continue;
          }
          let text = block.text;
          let truncated = false;
          if (JOB_TOOLS.has(exec.name)) {
            const t = truncateBytes(text, MAX_JOB_BYTES);
            text = t.text;
            truncated = t.truncated;
          }
          if (SHELL_GUARDED.has(exec.name) && !isText(text)) {
            content.push({
              ...block,
              text: text + "\n[pii-guard] non-text output, redaction skipped",
            });
            continue;
          }
          const msg = await redactExempted(text, exec, redactFn);
          if (msg.map && typeof msg.map === "object") {
            for (const [ph, val] of Object.entries(msg.map)) {
              cacheSet(phMap, ph, displayValue(ph, val), PH_CACHE_LIMIT);
              if (typeof val === "string" && val) pairs.push([ph, val]);
            }
          }
          content.push({ ...block, text: msg.redacted + (truncated ? TRUNC_MARK : "") });
        }
        if (pairs.length > 0
            && result?.meta !== undefined
            && result?.value !== undefined
            && !result?.isError
            && !SHELL_GUARDED.has(exec.name)
            && decision?.content === undefined) {
          pairs.sort((a, b) => b[1].length - a[1].length);
          const out = {
            kind: "accept",
            value: redactValueLeaves(result.value, pairs),
          };
          if (exec.agent && !noticedAgents.has(exec.agent)) {
            noticedAgents.add(exec.agent);
            out.additionalContexts = [placeholderNotice(),
              ...(decision?.additionalContexts ?? [])];
          } else if (decision?.additionalContexts !== undefined) {
            out.additionalContexts = decision.additionalContexts;
          }
          return out;
        }
        if (pairs.length > 0 && exec.agent && !noticedAgents.has(exec.agent)) {
          noticedAgents.add(exec.agent);
          return {
            ...decision,
            kind: "accept",
            content,
            additionalContexts: [placeholderNotice(),
              ...(decision?.additionalContexts ?? [])],
          };
        }
        return {
          ...decision,
          kind: "accept",
          content,
          ...(decision?.additionalContexts !== undefined
            ? { additionalContexts: decision.additionalContexts }
            : {}),
        };
      } catch (err) {
        console.error(`[pii-guard] redact failed, blocking result: ${err?.message ?? err}`);
        if (isFailOpen()) {
          console.error("[pii-guard] failOpen=true → passthrough (TROUBLESHOOTING ONLY)");
          return decision;
        }
        return {
          kind: "block",
          feedback: [{ type: "text", text: BLOCK_MARK }],
          ...(decision?.additionalContexts !== undefined
            ? { additionalContexts: decision.additionalContexts }
            : {}),
        };
      }
    },
    { prepend: true },
  );

  ctx.on("agent/created", ({ agent }) => {
    const actx = agent?.ctx;
    if (!actx || typeof actx.tools?.register !== "function") return;
    const disposers = [];
    for (const toolName of WRITE_TOOLS) {
      const original = ctx.tools?.get?.(toolName);
      if (!original || typeof original.execute !== "function") continue;
      try {
        disposers.push(actx.tools.register({
          ...original,
          execute: async (args, exec) => {
            const { args: safeArgs, failed } = await restoreArgs(args, restoreFn);
            if (failed.length) {
              throw new Error(`[pii-guard] placeholder restore failed: ${failed.join("; ")}`);
            }
            return original.execute(safeArgs, exec);
          },
        }));
      } catch (err) {
        console.error(`[pii-guard] failed to shadow ${toolName}: ${err?.message ?? err}`);
      }
    }
    try {
      disposers.push(actx.tools.restrict({ deny: ["read_image"] }));
    } catch (err) {
      console.error(`[pii-guard] read_image restrict skipped: ${err?.message ?? err}`);
    }
    if (disposers.length) {
      const dispose = () => { for (const d of disposers) { try { d(); } catch { /* noop */ } } };
      actx.effect(() => dispose);
    }
  }, { global: true });

  ctx.on("agent/pre-step", async (payload, next) => {
    const decision = await next();
    try {
      const raw = JSON.stringify(payload?.messages ?? []);
      const phones = (raw.match(/(?<!\d)1[3-9]\d{9}(?!\d)/g) ?? []).length;
      const ids = (raw.match(/(?<!\d)\d{17}[\dXx](?!\d)/g) ?? []).length;
      if (phones || ids) {
        console.error(`[pii-guard] pre-step WARN: incoming messages contain ${phones} phone-like and ${ids} id-like literals (not redacted; user-pasted text is outside the tool-result guard)`);
      }
    } catch { /* non-fatal */ }
    return decision;
  }, { global: true });

  ctx.on(
    "agent/assistant-stream",
    ({ agent, frame }) => {
      try {
        if (displayMode() === "off") {
          // 切到 off 时丢弃扣尾缓冲：留着会在切回 full 后把旧前缀拼到新流开头。
          displayBufs.delete(agent?.session?.id);
          return;
        }
        if (frame.type === "start") {
          const b = displayBufs.get(agent?.session?.id);
          if (b) b.pending = "";
          return;
        }
        if (frame.type === "end") {
          const sid = agent?.session?.id;
          const b = displayBufs.get(sid);
          if (b && b.pending) {
            const tail = b.pending.replace(PH_FULL, (ph) => phMap.get(ph) ?? ph);
            frame.chunk = { type: "text-delta", index: Number.MAX_SAFE_INTEGER, text: tail };
            b.pending = "";
          }
          // 流结束即释放该会话的扣尾缓冲，避免长会话按 session 无限累积。
          displayBufs.delete(sid);
          return;
        }
        if (frame.type !== "chunk" || frame.chunk?.type !== "text-delta"
            || typeof frame.chunk.text !== "string") return;
        if (!frame.chunk.text.includes("⟦") && !frame.chunk.text.includes("PII")) {
          const b = displayBufs.get(agent?.session?.id);
          if (!b || !b.pending) return;
        }
        const b = displayBufs.get(agent?.session?.id) ?? { pending: "" };
        cacheSet(displayBufs, agent?.session?.id, b, DISPLAY_BUF_LIMIT);
        const acc = b.pending + frame.chunk.text;
        acc.replace(PH_FULL, (ph) => {
          if (!phMap.has(ph)) scheduleRestore(ph);
          return ph;
        });
        const { shown, hold } = splitDisplayable(acc);
        b.pending = hold;
        frame.chunk = { ...frame.chunk, text: shown };
      } catch (err) {
        console.error(`[pii-guard] display rewrite failed: ${err?.message ?? err}`);
      }
    },
    { prepend: true, global: true },
  );
}

export { name, inject };
