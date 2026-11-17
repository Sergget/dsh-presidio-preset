// dsh-pii-guard — PII 工具拦截守护插件（方案 A 实体）
//
// 挂载方式（preset plugins 内）:
//   - id: pii-guard
//     name: 'file:///E:/Code/dsh_home/plugins/dsh-pii-guard/lib/index.js'
//
// 接缝：tools/post-execute（waterfall，签名 (exec, result, next)）
//   dsh-tools 的 tools/execute 拿到的是 deepFreeze 后的 canonical 结果，
//   且 normalizeDispatchResult 会丢弃 wrapper 的 content、按 result.value 重渲染。
//   因此原地改写 content[].text 必然 TypeError → 降级透传（明文泄漏）。
//   tools/post-execute 返回 { kind:"accept", content } 会被 markCanonical 采纳，
//   是唯一可靠的“改文本”接缝（dsh-tool-fs-search 自身也用它做溢写裁剪）。
//
// 行为:
//   - 默认对**所有**工具的文本型结果脱敏（黑名单 SKIP_TOOLS 除外），覆盖 read/grep/
//     pwsh/job_*/web_fetch/MCP/PTC 等通道；不再靠逐个枚举工具名，新增工具自动在守卫内
//   - shell/后台任务的 isError 结果（spawn 失败、abort）同样脱敏；其它工具的 isError 维持透传
//   - pwsh 与后台任务非文本输出（NUL>1% 或不可打印>30%）→ 不脱敏，追加标记行说明
//   - job_output / job_list 单块超过 256,000 字节 → 先截断再脱敏，末尾追加截断标记
//   - 写入侧（agent 级 scoped shadow）: 在 agent.ctx 上注册 write/edit 同名 wrapper，
//     把模型参数里的占位符**还原回原文**再交给原实现，避免把 ⟦PII:...⟧ 写坏用户文件；
//     tool/call 落盘的仍是占位符版参数，还原只发生在宿主进程内
//   - read_image 在 PII 预设内隐藏（图片内文字无法脱敏），用 ctx.tools.restrict 实现
//   - agent/pre-step 兜底扫描：只告警，不改写消息（与 session log/KV cache 脱节，不做主防线）
//   - shell 逃生开关（仅配置层，模型不可关，命中写审计 shell_bypass）:
//       PII_GUARD_SHELL=off            整个进程不拦 shell/后台任务（启动时读取，重启生效）
//       PII_GUARD_SHELL_ALLOWLIST=正则  仅对 pwsh 命令字符串生效
//   - 部署覆盖: PII_GUARD_PY=<python 解释器>、PII_GUARD_REPO=<仓库根>；allowlist 正则非法时忽略并告警
//   - 显示侧还原（方案 B, 门禁 #4）: 订阅 agent/assistant-stream（prepend+global, 先于
//     session-controller 折叠器), 把助手文本流里的占位符还原/打码后进 GUI。
//     只改显示流, 不改会话存储与模型上下文（持久化发生在 live.push() 内部, 早于 emit）。
//       PII_GUARD_DISPLAY=full          显示完整原值（默认）
//       PII_GUARD_DISPLAY=mask          打码显示: Python 端完成, 原文不过 Node
//       PII_GUARD_DISPLAY=off           关闭显示还原（回到纯占位符）
//   - **fail-closed**: Python 服务异常（spawn 失败/退出/超时/坏响应）→ 返回
//     {kind:"block"} 阻断该工具调用，绝不放行明文。可用 PII_GUARD_FAIL_OPEN=1 显式回退
//     到旧的降级透传语义（仅限排障，默认关闭）。
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { appendFileSync } from "node:fs";
import { createHash, randomUUID } from "node:crypto";

const SHELL_TOOLS = new Set(["pwsh", "bash"]);
const JOB_TOOLS = new Set(["job_output", "job_list"]);
const SHELL_GUARDED = new Set([...SHELL_TOOLS, ...JOB_TOOLS]);
// 黑名单：只有这些工具的结果不扫描。默认全拦，新增工具自动在守卫内。
// job_kill 只回状态文本；read_image 是二进制图片（在 PII 预设里直接 restrict 隐藏）。
const SKIP_TOOLS = new Set(["job_kill", "read_image"]);
// 写入侧要包一层的工具：模型手里只有占位符，落盘前必须还原回原文。
const WRITE_TOOLS = new Set(["write", "edit", "apply_patch", "str_replace_editor"]);
// 这些参数键承载用户文本内容，需要还原占位符；路径等键不动。
const WRITE_TEXT_KEYS = new Set([
  "content", "new_string", "old_string", "new_str", "old_str",
  "text", "patch", "file_text", "newText", "oldText",
]);
const MAX_JOB_BYTES = 256_000;
const TRUNC_MARK = "\n[pii-guard] output truncated to 256000 bytes before redaction";
const BLOCK_MARK = "[pii-guard] PII redaction service unavailable; tool result blocked (fail-closed). Retry, or set PII_GUARD_FAIL_OPEN=1 for troubleshooting.";
const FAIL_OPEN = (process.env.PII_GUARD_FAIL_OPEN ?? "").toLowerCase() === "1";
const PY = process.env.PII_GUARD_PY ?? "python";
// 仓库位置可用 PII_GUARD_REPO 覆盖（默认本机开发路径），便于换机器/目录部署
const REPO = process.env.PII_GUARD_REPO ?? "E:/Code/dsh-presidio-preset";
const SERVER = REPO + "/presidio_pii/server.py";
const HOOK_LOG = REPO + "/.pii_presidio_store/hook_log.jsonl";
const SID = "pii-guard-" + process.pid;
const CALL_TIMEOUT_MS = 30_000;
// 显示侧还原模式: full=完整原值(默认) / mask=打码(Python 端) / off=关闭
const DISPLAY_MODE = (["full", "mask", "off"].includes(
  (process.env.PII_GUARD_DISPLAY ?? "full").toLowerCase())
) ? (process.env.PII_GUARD_DISPLAY ?? "full").toLowerCase() : "full";
// 占位符完整形态与「疑似前缀」（可能被 chunk 边界截断的尾部）
const PH_FULL = /⟦PII:[A-Z_]+:\d+⟧/g;
const PH_TAIL = /⟦(?:PII:[A-Z_]+(?::\d*)?)?$/;
const SHELL_DISABLED = (process.env.PII_GUARD_SHELL ?? "").toLowerCase() === "off";
let SHELL_ALLOWLIST = null;
if (process.env.PII_GUARD_SHELL_ALLOWLIST) {
  try {
    SHELL_ALLOWLIST = new RegExp(process.env.PII_GUARD_SHELL_ALLOWLIST);
  } catch (err) {
    // 配置写错时按“不放行”处理, 避免静默关闭 shell 拦截
    console.error(`[pii-guard] invalid PII_GUARD_SHELL_ALLOWLIST, ignored: ${err?.message ?? err}`);
  }
}
const name = "pii-guard";
const inject = ["tools"];

// 占位符守护提示（症状②防源头）：工具结果被脱敏后，模型手里是 ⟦PII:...⟧ 占位符。
// 若模型在自己的回答里转写/改写占位符（漏字、换格式），显示层与写入层的还原都会失效，
// 且终态 assistant 消息固化后回放路径无法再修（内核无终态事件可拦，取证见 2026-11-17）。
// 因此在 agent 首次产生脱敏映射时，向下一步模型上下文注入一条 notice，明确占位符契约。
// 每个代理只注入一次（per-agent，不影响 KV cache 稳定性）。
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

// 路径/参数脱敏豁免：在 Shell 类工具的输出中，跳过 ORGANIZATION 类型的脱敏。
const isLikelyPath = (text) => (text.includes("/") || text.includes("\\")) && !text.split(/[\s\n]+/).some(w => w.length > 50);

async function redactExempted(text, exec, redactFn) {
  const fn = redactFn ?? redact;
  const msg = await fn(text);
  if (exec && SHELL_GUARDED.has(exec.name) && isLikelyPath(text)) {
    if (msg.map) {
      for (const [ph, val] of Object.entries(msg.map)) {
        if (ph.includes("ORGANIZATION")) {
          msg.redacted = msg.redacted.replace(ph, val);
          delete msg.map[ph];
        }
      }
    }
  }
  // 确保返回 msg 结构符合后续预期
  return msg || { redacted: text, map: {} };
}

let svc = null;
let seq = 0;
const pending = new Map();

function ensureService() {
  if (svc) return svc;
  svc = spawn(PY, [SERVER], {
    cwd: REPO,
    stdio: ["pipe", "pipe", "inherit"],
  });
  const rl = createInterface({ input: svc.stdout });
  rl.on("line", (line) => {
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      return;
    }
    const waiter = pending.get(msg.id);
    if (waiter) {
      pending.delete(msg.id);
      waiter(msg);
    }
  });
  svc.on("exit", () => {
    for (const waiter of pending.values()) waiter({ error: "pii server exited" });
    pending.clear();
    svc = null;
  });
  // spawn 失败（如 PATH 里没有 python）必须兜住: 否则 Node 的未处理 error 事件会终止宿主进程
  svc.on("error", (err) => {
    for (const waiter of pending.values()) {
      waiter({ error: `pii server spawn failed: ${err?.code ?? err?.message ?? err}` });
    }
    pending.clear();
    svc = null;
  });
  return svc;
}

function callServer(payload, pick, project) {
  const p = ensureService();
  if (!p) return Promise.reject(new Error("pii server unavailable"));
  const id = "g" + (++seq);
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new Error("pii server timeout"));
    }, CALL_TIMEOUT_MS);
    pending.set(id, (msg) => {
      clearTimeout(timer);
      if (msg.error) reject(new Error(msg.error));
      else if (typeof pick(msg) !== "string") reject(new Error("pii server bad response"));
      else resolve(project ? project(msg) : pick(msg));
    });
    try {
      p.stdin.write(JSON.stringify({ ...payload, id, sid: SID }) + "\n");
    } catch (err) {
      pending.delete(id);
      clearTimeout(timer);
      reject(err);
    }
  });
}

// 一次 IPC：脱敏（含增量 map，供显示侧还原）+ 还原（写入侧用）。
// 显式 mode=full：msg.map 必须是「占位符 → 原文」，value 重渲染要用它做反向替换；
// 显示侧的 mask 由 Node 侧 PII_GUARD_DISPLAY 控制，不能让服务端改这份映射的值。
// deps.redact 注入的 mock 只用于 post-execute；写入侧一律走真实 restore IPC。
function redact(text) {
  return callServer({ text, mode: "full" }, (msg) => msg.redacted, (msg) => msg);
}

// 写入侧：把占位符还原回原文（server.py 的 op=restore, mode=full）。
// 原文只在宿主 Node 进程内停留一瞬并直接传给原工具实现，不进模型上下文、不回显。
function restoreText(text) {
  return callServer({ op: "restore", text, mode: "full" }, (msg) => msg.restored);
}

// 递归还原参数对象里的文本内容；返回 { args, changed, failed }。
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

// 把 canonical value 里的原文字符串按 [占位符, 原文] 对反向替换成占位符。
// result / result.value 在 pipeline 里已被 deepFreeze，必须整体新建对象，不能原地改。
// pairs 需按「原文」长度降序：先替换长实体，避免 "张伟" 被更短的 "张" 先切坏。
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

// ---- 显示侧还原（方案 B）----
// redact 响应顺带下发增量映射 { 占位符 → 显示值 }（mask 模式下 Python 端直接给打码值，
// 原文不过 Node）。assistant-stream 是 emit 型事件（fire-and-forget），监听器必须
// 同步返回，因此用本地缓存做同步替换；跨 chunk 分裂的占位符用「扣尾补头」：
// 尾部疑似不完整前缀扣住不发，等后续 chunk 拼全后替换（chunk.index 顺序到达）。
const phMap = new Map(); // 占位符 → 显示值
const displayBufs = new Map(); // agent.session.id → { pending: 扣住的尾部前缀 }

function displayMode() {
  return DISPLAY_MODE;
}

// 替换累计文本中的完整占位符; 返回 (可显示文本, 扣住的尾部前缀)
function splitDisplayable(acc) {
  const m = PH_TAIL.exec(acc);
  const hold = m ? m[0] : "";
  const head = hold ? acc.slice(0, acc.length - hold.length) : acc;
  const shown = head.replace(PH_FULL, (ph) => phMap.get(ph) ?? ph);
  return { shown, hold };
}

// 显示侧映射值与 value 重渲染需要的是两份不同的东西：
//   - value 重渲染：占位符 → 原文（把 canonical value 里的原文换成占位符）
//   - 显示侧 phMap：占位符 → 显示值（mask 模式是打码串，绝不能是原文）
// 因此 redact 请求恒为 mode=full（服务端下发原文），mask 在 Node 侧按
// server.py:_mask_value 同口径复刻，保证 PII_GUARD_DISPLAY=mask 语义不变。
function displayValue(ph, orig) {
  if (DISPLAY_MODE !== "mask") return orig;
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

// 按字节截断并按 UTF-8 字符边界回退, 避免半个字符造成乱码
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
    appendFileSync(HOOK_LOG, JSON.stringify(rec) + "\n", "utf8");
  } catch {
    // 审计失败不阻塞放行
  }
}

function shellBypassReason(exec) {
  if (SHELL_DISABLED) return "env";
  const cmd = exec?.args?.command;
  if (SHELL_ALLOWLIST && typeof cmd === "string" && SHELL_ALLOWLIST.test(cmd)) return "allowlist";
  return null;
}

// apply(ctx, deps?) — deps.redact / deps.restore 可注入（单元测试用 mock，生产用默认 IPC 版）
export async function apply(ctx, deps = {}) {
  const redactFn = deps.redact ?? redact;
  const restoreFn = deps.restore ?? restoreText;
  // prepend: 最外层，先于其它 post-execute 监听器取到最终 content，兜住它们的改写
  ctx.on(
    "tools/post-execute",
    async (exec, result, next) => {
      const decision = await next();
      if (SKIP_TOOLS.has(exec.name)) return decision;
      // 错误文本常带路径/文件名: shell 与后台任务的 isError 也要脱敏;
      // 其它工具的错误结果维持原有透传, 避免改变既有错误分类语义
      if (result?.isError && !SHELL_GUARDED.has(exec.name)) return decision;
      if (decision?.kind === "block") return decision;
      if (SHELL_GUARDED.has(exec.name)) {
        const bypass = shellBypassReason(exec);
        if (bypass) {
          auditShellBypass(exec, bypass);
          return decision;
        }
      }
      // 下游若按 value 替换，content 会由该 value 重渲染，此处无法改写其渲染结果。
      // 不能静默放行：阻断并说明原因，避免原文从重渲染路径漏出。
      if (decision !== undefined && Object.hasOwn(decision, "value")) {
        console.error("[pii-guard] post-execute value replacement present, blocking result");
        return {
          kind: "block",
          feedback: [{ type: "text", text: "[pii-guard] a downstream policy replaced this tool's canonical value; result blocked to avoid leaking unredacted content." }],
        };
      }
      const source = decision?.content ?? result?.content;
      // 没有文本型 content 就无需脱敏（纯结构化/二进制结果）
      if (!Array.isArray(source) || !source.some((b) => b?.type === "text" && typeof b.text === "string")) return decision;
      try {
        const content = [];
        // 乱码/编码纠错提示（仅对正常文本——非文本输出由 non-text 标记另行说明）
        if (source.some((b) => b?.type === "text" && typeof b.text === "string" && isText(b.text) && (b.text.includes("\ufffd") || b.text.includes("\u0000")))) {
          content.push({ type: "text", text: "\n[pii-guard] 检测到输出含有乱码（GBK/UTF-8 编码错乱），这可能导致模型无法正确识别内容。建议改用 `read` 工具，或使用 `python -X utf8` 运行脚本。" });
        }
        // office 二进制命令级强约束：pwsh/bash 命令里直接引用 docx/xlsx/pptx 时告警
        if (SHELL_GUARDED.has(exec.name)) {
          const cmd = String(exec?.args?.command ?? "");
          if (/\.(docx|xlsx|pptx|doc|xls|ppt)\b/i.test(cmd)) {
            content.push({ type: "text", text: "\n[pii-guard] 警告：shell 命令直接引用了 office 二进制文档。这是乱码与脱敏绕过的主要来源——请改用 `read` 工具读取（自带脱敏），或先用 `python -X utf8` + python-docx/openpyxl 转出 Markdown/文本后再读。详见 docs/WORKFLOW-GUIDE.md。" });
          }
        }
        const pairs = []; // [占位符, 原文]：本次脱敏得到的映射，用于同源改 canonical value
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
              phMap.set(ph, displayValue(ph, val));  // 显示侧还原（mask 语义在 Node 侧）
              if (typeof val === "string" && val) pairs.push([ph, val]);
            }
          }
          content.push({ ...block, text: msg.redacted + (truncated ? TRUNC_MARK : "") });
        }
        // 问题 A：新版 read/grep 的 meta.lines（GUI 卡片 + session log）由
        // presentationMeta(value) 从 canonical value 派生；post-execute 只改 content
        // 碰不到 meta。返回 {kind:"accept", value} 让 pipeline 用脱敏后的 value
        // 重跑 render + presentationMeta（公开契约 pipeline.js:686-694 / :710-739），
        // content 与 meta 一起变脱敏。仅在有 meta + 有 value + 命中 PII +
        // 下游未改 content 时启用；绝不与 content 同时返回（:684 会抛 TypeError）。
        // shell/job 排除在外，保留 TRUNC_MARK / 非文本标记等装饰。
        if (pairs.length > 0
            && result?.meta !== undefined
            && result?.value !== undefined
            && !result?.isError
            && !SHELL_GUARDED.has(exec.name)
            && decision?.content === undefined) {
          pairs.sort((a, b) => b[1].length - a[1].length); // 长实体优先，避免 "张" 切坏 "张伟"
          const out = {
            kind: "accept",
            value: redactValueLeaves(result.value, pairs),
          };
          // 症状②防源头：本代理首次产生映射时，向下一步注入占位符使用规则。
          if (exec.agent && !noticedAgents.has(exec.agent)) {
            noticedAgents.add(exec.agent);
            out.additionalContexts = [placeholderNotice(),
              ...(decision?.additionalContexts ?? [])];
          } else if (decision?.additionalContexts !== undefined) {
            out.additionalContexts = decision.additionalContexts;
          }
          return out;
        }
        // content 路径（无 meta/value 的工具）同样注入（首次产生映射时）。
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
        // fail-closed: 服务异常时阻断结果，绝不放行明文。
        console.error(`[pii-guard] redact failed, blocking result: ${err?.message ?? err}`);
        if (FAIL_OPEN) {
          console.error("[pii-guard] PII_GUARD_FAIL_OPEN=1 → passthrough (TROUBLESHOOTING ONLY)");
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

  // ---- 写入侧：agent 级同名 scoped shadow ----
  // 读侧已把模型手里的文本变成占位符；写入时若不还原，⟦PII:...⟧ 会被写进用户文件。
  // 官方范式（@deepseek-ai/dsh-experimental-liveshare/lib/index.js:7603-7617）：
  //   ctx.on("agent/created") → agent.ctx.tools.register({...deployment, execute})
  //   → agent.ctx.effect(() => dispose)。nearer registration shadows global。
  // tool/call 落盘的仍是模型给出的占位符版参数；还原只发生在宿主进程内。
  ctx.on("agent/created", ({ agent }) => {
    const actx = agent?.ctx;
    if (!actx || typeof actx.tools?.register !== "function") return;
    const disposers = [];
    for (const toolName of WRITE_TOOLS) {
      // 用全局 ctx 取原 definition，避免拿到本插件自己注册的 wrapper。
      const original = ctx.tools?.get?.(toolName);
      if (!original || typeof original.execute !== "function") continue;
      try {
        disposers.push(actx.tools.register({
          ...original,
          execute: async (args, exec) => {
            const { args: safeArgs, failed } = await restoreArgs(args, restoreFn);
            if (failed.length) {
              // 还原失败不能把占位符写进文件：直接抛错，让工具调用失败而非静默写坏。
              throw new Error(`[pii-guard] placeholder restore failed: ${failed.join("; ")}`);
            }
            return original.execute(safeArgs, exec);
          },
        }));
      } catch (err) {
        console.error(`[pii-guard] failed to shadow ${toolName}: ${err?.message ?? err}`);
      }
    }
    // read_image：图片内文字无法脱敏，直接在 PII 预设内隐藏该工具。
    try {
      disposers.push(actx.tools.restrict({ deny: ["read_image"] }));
    } catch (err) {
      // 该工具不存在时 restrict 会抛 unknown name，忽略即可。
      console.error(`[pii-guard] read_image restrict skipped: ${err?.message ?? err}`);
    }
    if (disposers.length) {
      const dispose = () => { for (const d of disposers) { try { d(); } catch { /* noop */ } } };
      actx.effect(() => dispose);
    }
  }, { global: true });

  // ---- 兜底扫描：agent/pre-step 只告警，不改写消息 ----
  // 覆盖用户直接粘贴进输入框的文本、@ 引用、附件等不经过 tool result 的入口。
  // 不改 decision.messages：该机制与 session log / KV cache 脱节，只做可观测告警。
  ctx.on("agent/pre-step", async (payload, next) => {
    const decision = await next();
    try {
      const raw = JSON.stringify(payload?.messages ?? []);
      // 粗筛：裸 11 位手机号 / 18 位身份证 / 常见中文姓名+号码组合。
      // 只统计数量，不把原文写进日志。
      const phones = (raw.match(/(?<!\d)1[3-9]\d{9}(?!\d)/g) ?? []).length;
      const ids = (raw.match(/(?<!\d)\d{17}[\dXx](?!\d)/g) ?? []).length;
      if (phones || ids) {
        console.error(`[pii-guard] pre-step WARN: incoming messages contain ${phones} phone-like and ${ids} id-like literals (not redacted; user-pasted text is outside the tool-result guard)`);
      }
    } catch { /* 告警失败不影响 step */ }
    return decision;
  }, { global: true });

  // 显示侧还原（方案 B）: 助手流经 GUI 前, 同步替换占位符为映射值（full=原值 / mask=打码）。
  // 持久化在 live.push() 内部完成（早于本事件），此处改写只影响显示流与重连基线，
  // 不改会话存储、不进模型上下文。prepend 保证先于 session-controller 折叠器执行。
  if (DISPLAY_MODE !== "off") {
    ctx.on(
      "agent/assistant-stream",
      ({ agent, frame }) => {
        try {
          if (frame.type === "start") {
            const b = displayBufs.get(agent?.session?.id);
            if (b) b.pending = ""; // 新流开始: 清掉上一流的扣尾
            return;
          }
          if (frame.type === "end") {
            // 流结束: 扣尾若仍是完整占位符则替换, 否则原样放行
            const b = displayBufs.get(agent?.session?.id);
            if (b && b.pending) {
              const tail = b.pending.replace(PH_FULL, (ph) => phMap.get(ph) ?? ph);
              frame.chunk = { type: "text-delta", index: Number.MAX_SAFE_INTEGER, text: tail };
              b.pending = "";
            }
            return;
          }
          if (frame.type !== "chunk" || frame.chunk?.type !== "text-delta"
              || typeof frame.chunk.text !== "string") return;
          if (!frame.chunk.text.includes("⟦") && !frame.chunk.text.includes("PII")) {
            // 快路径: 无占位符迹象且无扣尾 → 原样放行
            const b = displayBufs.get(agent?.session?.id);
            if (!b || !b.pending) return;
          }
          // 扣尾补头: pending + 本帧 delta 合并重新切分, 原地改写 text（对象为通知副本）
          const b = displayBufs.get(agent?.session?.id) ?? { pending: "" };
          displayBufs.set(agent?.session?.id, b);
          const acc = b.pending + frame.chunk.text;
          const { shown, hold } = splitDisplayable(acc);
          b.pending = hold;
          frame.chunk = { ...frame.chunk, text: shown };
        } catch (err) {
          // 显示还原失败不阻塞流: 原样透传（GUI 显示占位符）
          console.error(`[pii-guard] display rewrite failed: ${err?.message ?? err}`);
        }
      },
      { prepend: true, global: true },
    );
  }
}

export { name, inject };
