// 插件行为冒烟测试（node 运行；由 tools/release_gate.py #5 调用）。
// 用法: node tests/js/plugin_jobs.mjs <plugin index.js 路径>
//
// 覆盖 P2 后台任务拦截（job_output/job_list 脱敏、256 KB 截断、job_kill 放行）与
// P3 isError 脱敏（shell/后台任务脱敏、read 维持透传），顺带回归 pwsh 非文本标记，
// 以及 Python 服务 spawn 失败时的降级透传（不得崩溃宿主进程）。
import { copyFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const pluginPath = process.argv[2];
if (!pluginPath) {
  console.error("用法: node tests/js/plugin_jobs.mjs <plugin index.js>");
  process.exit(2);
}

// 插件源码是 ESM 语法但目录里没有 package.json type=module, 复制成 .mjs 再加载
const tmp = mkdtempSync(join(tmpdir(), "pii-plugin-"));
const copy = join(tmp, "plugin.mjs");
copyFileSync(pluginPath, copy);

// 默认 redact 走 spawn；指向不存在的解释器用于验证 spawn 失败时降级而非崩溃
process.env.PII_GUARD_PY = "pii-guard-no-such-python-xyz";
// 非法 allowlist 正则: 必须在加载时忽略，而不是抛错导致整个插件失效
process.env.PII_GUARD_SHELL_ALLOWLIST = "(";

const { apply } = await import(pathToFileURL(copy).href);
rmSync(tmp, { recursive: true, force: true });

const handlers = {}; // event-name -> listener (tools/post-execute + agent/assistant-stream)
await apply({ on: (evt, fn) => { handlers[evt] = fn; } }, {
  // 模拟引擎: 只替换固定实体, 其余原样返回
  redact: async (t) => ({
    redacted: t.replaceAll("张伟", "⟦PII:PERSON:0001⟧")
                  .replaceAll("13800138000", "⟦PII:PHONE_NUMBER:0002⟧"),
  }),
});

const handler = (exec, result, next) => handlers["tools/post-execute"](exec, result, next);

const cases = [];
function check(name, cond, detail = "") {
  cases.push({ name, cond, detail });
}

async function runTool(tool, text, opts = {}) {
  const block = { type: "text", text };
  const decision = { kind: "accept", content: [block] };
  const res = await handler(
    { name: tool, args: opts.args ?? {} },
    { content: [block], ...(opts.isError ? { isError: true } : {}) },
    async () => decision,
  );
  return res;
}

// 1. job_output: 脱敏
{
  const res = await runTool("job_output", "ongoing: 张伟 13800138000\n");
  const out = res.content[0].text;
  check("job_output 脱敏", !out.includes("张伟") && !out.includes("13800138000")
        && out.includes("⟦PII:PERSON:") && out.includes("⟦PII:PHONE_NUMBER:"), out);
}

// 2. job_list: 命令/描述回显脱敏
{
  const res = await runTool("job_list", "id=1 command=Get-Content .\\张伟.txt 13800138000\n");
  const out = res.content[0].text;
  check("job_list 脱敏", !out.includes("张伟") && !out.includes("13800138000"), out);
}

// 3. job_output: 超过 256 KB 先截断再脱敏, 末尾有标记
{
  const big = "A".repeat(300000) + "张伟";
  const res = await runTool("job_output", big);
  const out = res.content[0].text;
  const mark = "\n[pii-guard] output truncated to 256000 bytes before redaction";
  check("job_output 截断", out.includes(mark) && !out.includes("张伟"), String(out.length));
  const body = out.slice(0, out.indexOf(mark));
  check("job_output 截断上限", byteLength(body) <= 256000, String(byteLength(body)));
}

// 4. 无 PII 的 job_output: 逐字节不变
{
  const text = "job done, exit=0, elapsed=12.3s\n";
  const res = await runTool("job_output", text);
  check("job_output 无 PII 不变", res.content[0].text === text, res.content[0].text);
}

// 5. job_kill: 不拦截
{
  const text = "killed job 张伟 13800138000";
  const res = await runTool("job_kill", text);
  check("job_kill 放行", res.content[0].text === text, res.content[0].text);
}

// 6. pwsh 非文本: 追加标记且不改原文
{
  const text = "a\u0000b\u0000c";
  const res = await runTool("pwsh", text);
  const out = res.content[0].text;
  check("pwsh 非文本标记", out === text + "\n[pii-guard] non-text output, redaction skipped", out);
}

// 7. read 仍拦截
{
  const res = await runTool("read", "张伟 13800138000");
  check("read 仍拦截", !res.content[0].text.includes("张伟"), res.content[0].text);
}

// 8. pwsh isError: 错误文本脱敏（P3）
{
  const res = await runTool("pwsh", "spawn failed: 张伟 13800138000", { isError: true });
  const out = res.content[0].text;
  check("pwsh isError 脱敏", !out.includes("张伟") && !out.includes("13800138000")
        && out.includes("⟦PII:PERSON:"), out);
}

// 9. job_output isError: 同样脱敏
{
  const res = await runTool("job_output", "job aborted for 张伟", { isError: true });
  check("job_output isError 脱敏", !res.content[0].text.includes("张伟"),
        res.content[0].text);
}

// 10. read isError: 维持透传（不改既有语义）
{
  const text = "read failed: 张伟";
  const res = await runTool("read", text, { isError: true });
  check("read isError 透传", res.content[0].text === text, res.content[0].text);
}

// 11. 服务进程 spawn 失败: 不得崩溃宿主, 降级为原样透传
{
  let handler2 = null;
  await apply({ on: (evt, fn) => { if (evt === "tools/post-execute") handler2 = fn; } });  // 用默认 redact（会去 spawn 不存在的解释器）
  const text = "read failed: 张伟 13800138000";
  const block = { type: "text", text };
  const res = await handler2({ name: "read", args: {} },
                             { content: [block] },
                             async () => ({ kind: "accept", content: [block] }));
  check("spawn 失败降级透传", res.content[0].text === text, res.content[0].text);
}

// 12. 非法 allowlist 正则: 插件仍加载且 shell 照常拦截（不得静默放行）
{
  const res = await runTool("pwsh", "Write-Output 张伟 13800138000");
  const out = res.content[0].text;
  check("非法 allowlist 不放行", !out.includes("张伟") && !out.includes("13800138000"), out);
}

function byteLength(s) {
  return Buffer.byteLength(s, "utf8");
}

let failed = 0;
for (const c of cases) {
  console.log(`${c.cond ? "PASS" : "FAIL"}  ${c.name}${c.cond ? "" : "  ← " + c.detail}`);
  if (!c.cond) failed++;
}
console.log(failed === 0 ? "[result] ALL PASS" : `[result] ${failed} FAILED`);
process.exit(failed === 0 ? 0 : 1);
