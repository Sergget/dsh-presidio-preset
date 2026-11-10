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
//   - read / grep / pwsh / job_output / job_list 命中 → 返回改写后的 content（脱敏）
//   - shell/后台任务的 isError 结果（spawn 失败、abort）同样脱敏；read/grep 的 isError 维持透传
//   - pwsh 与后台任务非文本输出（NUL>1% 或不可打印>30%）→ 不脱敏，追加标记行说明
//   - job_output / job_list 单块超过 256,000 字节 → 先截断再脱敏，末尾追加截断标记
//   - shell 逃生开关（仅配置层，模型不可关，命中写审计 shell_bypass）:
//       PII_GUARD_SHELL=off            整个进程不拦 shell/后台任务（启动时读取，重启生效）
//       PII_GUARD_SHELL_ALLOWLIST=正则  仅对 pwsh 命令字符串生效
//   - 其它工具（含 job_kill）→ 原样放行
//   - 部署覆盖: PII_GUARD_PY=<python 解释器>、PII_GUARD_REPO=<仓库根>；allowlist 正则非法时忽略并告警
//   - 显示侧还原（方案 B, 门禁 #4）: 订阅 agent/assistant-stream（prepend+global, 先于
//     session-controller 折叠器), 把助手文本流里的占位符还原/打码后进 GUI。
//     只改显示流, 不改会话存储与模型上下文（持久化发生在 live.push() 内部, 早于 emit）。
//       PII_GUARD_DISPLAY=full          显示完整原值（默认）
//       PII_GUARD_DISPLAY=mask          打码显示: Python 端完成, 原文不过 Node
//       PII_GUARD_DISPLAY=off           关闭显示还原（回到纯占位符）
//   - Python 服务异常（含 spawn 失败/退出/超时）→ 降级透传（宁可放行不全挂死），stderr 告警
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { appendFileSync } from "node:fs";
import { createHash } from "node:crypto";

const SHELL_TOOLS = new Set(["pwsh"]);
const JOB_TOOLS = new Set(["job_output", "job_list"]);
const SHELL_GUARDED = new Set([...SHELL_TOOLS, ...JOB_TOOLS]);
const GUARDED_TOOLS = new Set(["read", "grep", ...SHELL_GUARDED]);
const MAX_JOB_BYTES = 256_000;
const TRUNC_MARK = "\n[pii-guard] output truncated to 256000 bytes before redaction";
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

function redact(text) {
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
      else if (typeof msg.redacted !== "string") reject(new Error("pii server bad response"));
      else resolve(msg);
    });
    try {
      p.stdin.write(JSON.stringify({ id, text, sid: SID }) + "\n");
    } catch (err) {
      pending.delete(id);
      clearTimeout(timer);
      reject(err);
    }
  });
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

// apply(ctx, deps?) — deps.redact 可注入（单元测试用 mock，生产用默认 IPC 版）
export async function apply(ctx, deps = {}) {
  const redactFn = deps.redact ?? redact;
  // prepend: 最外层，先于其它 post-execute 监听器取到最终 content，兜住它们的改写
  ctx.on(
    "tools/post-execute",
    async (exec, result, next) => {
      const decision = await next();
      if (!GUARDED_TOOLS.has(exec.name)) return decision;
      // 错误文本常带路径/文件名: shell 与后台任务的 isError 也要脱敏;
      // read/grep 的错误结果维持原有透传, 避免改变既有错误分类语义
      if (result?.isError && !SHELL_GUARDED.has(exec.name)) return decision;
      if (decision?.kind === "block") return decision;
      if (SHELL_GUARDED.has(exec.name)) {
        const bypass = shellBypassReason(exec);
        if (bypass) {
          auditShellBypass(exec, bypass);
          return decision;
        }
      }
      // 下游若按 value 替换，content 会由该 value 重渲染，此处无法改写其渲染结果
      if (decision !== undefined && Object.hasOwn(decision, "value")) {
        console.error("[pii-guard] post-execute value replacement present, skip redaction");
        return decision;
      }
      const source = decision?.content ?? result?.content;
      if (!Array.isArray(source)) return decision;
      try {
        const content = [];
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
          const msg = await redactFn(text);
          if (msg.map && typeof msg.map === "object") {
            for (const [ph, val] of Object.entries(msg.map)) phMap.set(ph, val);
          }
          content.push({ ...block, text: msg.redacted + (truncated ? TRUNC_MARK : "") });
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
        // 降级透传: 宁可放行不全挂死, stderr 告警
        console.error(`[pii-guard] redact failed, passthrough: ${err?.message ?? err}`);
        return decision;
      }
    },
    { prepend: true },
  );

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
