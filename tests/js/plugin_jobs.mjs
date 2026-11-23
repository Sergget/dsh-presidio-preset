// 插件行为冒烟测试（node 运行；由 tools/release_gate.py #5 调用）。
// 用法: node tests/js/plugin_jobs.mjs <plugin index.js 路径>
//
// 覆盖 P2 后台任务拦截（job_output/job_list 脱敏、256 KB 截断、job_kill 放行）、
// P3 isError 脱敏（shell/后台任务脱敏、非 shell 工具维持透传）、pwsh 非文本标记，
// 以及 v0.2 新语义：默认全工具扫描、value 替换阻断、fail-closed 阻断、
// 写入侧 wrapper 还原占位符、read_image 在 agent 作用域隐藏、pre-step 只告警。
import { pathToFileURL } from "node:url";

const pluginPath = process.argv[2];
if (!pluginPath) {
  console.error("用法: node tests/js/plugin_jobs.mjs <plugin index.js>");
  process.exit(2);
}

// 默认 redact/restore 走 spawn；指向不存在的解释器用于验证 fail-closed 而非崩溃
process.env.PII_GUARD_PY = "pii-guard-no-such-python-xyz";
// 非法 allowlist 正则: 必须在加载时忽略，而不是抛错导致整个插件失效
process.env.PII_GUARD_SHELL_ALLOWLIST = "(";

// 插件目录自带 package.json type=module，可直接以真实路径加载，无需复制成 .mjs。
const { apply } = await import(pathToFileURL(pluginPath).href);

const handlers = {}; // event-name -> listener
const mockCtx = {
  on: (evt, fn) => { handlers[evt] = fn; },
  tools: {
    get: (name) => mockDefinitions[name],
  },
};
// 模拟原工具 definition + 记录 execute 实际收到的参数
const mockDefinitions = {};
const executeCalls = [];
for (const n of ["write", "edit", "apply_patch", "str_replace_editor"]) {
  mockDefinitions[n] = {
    name: n,
    description: "mock",
    parameters: {},
    output: { schema: { type: "object" }, render: () => [] },
    execute: async (args) => { executeCalls.push({ name: n, args }); return { ok: true }; },
  };
}

const deps = {
  // 与 server.py 默认 full 模式对齐：map = { 占位符 → 原文 }，
  // 供 post-execute 把 canonical value / meta 派生源一并脱敏。
  redact: async (t) => {
    const map = {};
    let redacted = t;
    if (t.includes("张伟")) {
      map["⟦PII:PERSON:0001⟧"] = "张伟";
      redacted = redacted.replaceAll("张伟", "⟦PII:PERSON:0001⟧");
    }
    if (t.includes("13800138000")) {
      map["⟦PII:PHONE_NUMBER:0002⟧"] = "13800138000";
      redacted = redacted.replaceAll("13800138000", "⟦PII:PHONE_NUMBER:0002⟧");
    }
    return { redacted, map };
  },
  restore: async (t) => t.replaceAll("⟦PII:PERSON:0001⟧", "张伟")
                         .replaceAll("⟦PII:PHONE_NUMBER:0002⟧", "13800138000"),
};
await apply(mockCtx, deps);

const handler = (exec, result, next) => handlers["tools/post-execute"](exec, result, next);

const cases = [];
function check(name, cond, detail = "") {
  cases.push({ name, cond, detail });
}

async function runTool(tool, text, opts = {}) {
  const block = { type: "text", text };
  // 真实 pipeline 的默认 next() 只返回 { kind: "accept" }（不带 content），
  // content 从 result 取；这样 value 重渲染分支才能触发。
  const decision = { kind: "accept" };
  let res = await handler(
    { name: tool, args: opts.args ?? {} },
    { content: [block],
      ...(opts.meta !== undefined ? { meta: opts.meta } : {}),
      ...(opts.value !== undefined ? { value: opts.value } : {}),
      ...(opts.isError ? { isError: true } : {}) },
    async () => decision,
  );
  // 模拟 pipeline.js:696-700：accept 且未给 content/value 时，沿用 result.content。
  // value 重渲染分支必须保持「无 content」，故带 value 时不合并。
  if (res && res.kind === "accept"
      && !Object.hasOwn(res, "content") && !Object.hasOwn(res, "value")) {
    res = { ...res, content: [block] };
  }
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

// 5. job_kill: 黑名单放行
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

// 8. 默认全工具扫描：任意新工具（如 web_fetch / MCP）的文本结果也脱敏
{
  const res = await runTool("mcp__some_server__read_file", "张伟 13800138000");
  const out = res.content[0].text;
  check("默认全工具扫描", !out.includes("张伟") && !out.includes("13800138000"), out);
}

// 9. pwsh isError: 错误文本脱敏（P3）
{
  const res = await runTool("pwsh", "spawn failed: 张伟 13800138000", { isError: true });
  const out = res.content[0].text;
  check("pwsh isError 脱敏", !out.includes("张伟") && !out.includes("13800138000")
        && out.includes("⟦PII:PERSON:"), out);
}

// 10. job_output isError: 同样脱敏
{
  const res = await runTool("job_output", "job aborted for 张伟", { isError: true });
  check("job_output isError 脱敏", !res.content[0].text.includes("张伟"),
        res.content[0].text);
}

// 11. read isError: 维持透传（不改既有语义）
{
  const text = "read failed: 张伟";
  const res = await runTool("read", text, { isError: true });
  check("read isError 透传", res.content[0].text === text, res.content[0].text);
}

// 12. 服务进程 spawn 失败: fail-closed 阻断（绝不放行明文），且宿主不崩溃
{
  let handler2 = null;
  await apply({ on: (evt, fn) => { if (evt === "tools/post-execute") handler2 = fn; } });  // 默认 redact → spawn 失败
  const text = "read failed: 张伟 13800138000";
  const block = { type: "text", text };
  const res = await handler2({ name: "read", args: {} },
                             { content: [block] },
                             async () => ({ kind: "accept", content: [block] }));
  check("spawn 失败 fail-closed 阻断",
        res.kind === "block" && JSON.stringify(res.feedback).includes("[pii-guard]")
        && !JSON.stringify(res).includes("张伟") && !JSON.stringify(res).includes("13800138000"),
        JSON.stringify(res));
}

// 13. 下游 value 替换: 阻断而不是静默放行（原文可能经重渲染漏出）
{
  const block = { type: "text", text: "张伟 13800138000" };
  const res = await handler({ name: "read", args: {} }, { content: [block] },
                            async () => ({ kind: "accept", value: { raw: "张伟" } }));
  check("value 替换阻断", res.kind === "block" && !JSON.stringify(res).includes("13800138000"),
        JSON.stringify(res));
}

// 13b. 有 meta 的 read 结果：改 canonical value 让 pipeline 重渲染 content 与
// meta.lines，堵住 GUI 卡片 / session log 里的原文（问题 A）
{
  const text = "张伟 13800138000";
  const value = {
    path: "E:/vault/张伟.md",
    offset: 1,
    lines: [{ number: 1, text }],
    totalLines: 1,
  };
  const res = await runTool("read", text, {
    meta: { path: value.path, offset: 1, lines: value.lines, totalLines: 1 },
    value,
  });
  const flat = JSON.stringify(res);
  check("meta 工具走 value 重渲染",
        res.kind === "accept" && res.value !== undefined
        && !Object.hasOwn(res, "content")
        && res.value.lines[0].text.includes("⟦PII:PERSON:")
        && res.value.path.includes("⟦PII:PERSON:")
        && !flat.includes("张伟") && !flat.includes("13800138000"),
        flat);
}

// 13c. 无 PII 时不替换 value（零 schema 风险），仍走原 content 路径
{
  const text = "job done, exit=0, elapsed=12.3s\n";
  const value = { path: "E:/a.md", offset: 1,
                  lines: [{ number: 1, text }], totalLines: 1 };
  const res = await runTool("read", text, {
    meta: { path: value.path, offset: 1, lines: value.lines, totalLines: 1 },
    value,
  });
  check("无 PII 不替换 value",
        res.content?.[0]?.text === text && res.value === undefined,
        JSON.stringify(res));
}

// 13d. shell/job 即使带 meta 也不走 value 路径（保留 TRUNC_MARK / 非文本标记装饰）
{
  const res = await runTool("pwsh", "张伟 13800138000",
                            { meta: { cwd: "E:/x" }, value: { cwd: "张伟" } });
  check("shell 不走 value 重渲染",
        res.content?.[0]?.text.includes("⟦PII:PERSON:") && res.value === undefined,
        JSON.stringify(res));
}

// 14. 非法 allowlist 正则: 插件仍加载且 shell 照常拦截（不得静默放行）
{
  const res = await runTool("pwsh", "Write-Output 张伟 13800138000");
  const out = res.content[0].text;
  check("非法 allowlist 不放行", !out.includes("张伟") && !out.includes("13800138000"), out);
}

// 15. 写入侧 scoped shadow: agent/created 后 write/edit 的占位符被还原再交给原实现
{
  const registered = [];
  const restricted = [];
  const effects = [];
  const agentCtx = {
    tools: {
      register: (def) => { registered.push(def); return () => {}; },
      restrict: (f) => { restricted.push(f); return () => {}; },
    },
    effect: (fn) => { effects.push(fn); },
  };
  await handlers["agent/created"]({ agent: { ctx: agentCtx } });
  check("写入侧注册 write/edit wrapper",
        registered.filter((d) => ["write", "edit"].includes(d.name)).length === 2,
        registered.map((d) => d.name).join(","));
  check("read_image 被 restrict 隐藏",
        restricted.some((f) => Array.isArray(f.deny) && f.deny.includes("read_image")),
        JSON.stringify(restricted));
  check("wrapper 注册挂到 agent.ctx.effect", effects.length === 1, String(effects.length));

  const writeDef = registered.find((d) => d.name === "write");
  await writeDef.execute(
    { file_path: "E:/tmp/a.md", content: "联系人 ⟦PII:PERSON:0001⟧ 电话 ⟦PII:PHONE_NUMBER:0002⟧" },
    {},
  );
  const got = executeCalls.at(-1);
  check("write 占位符已还原为原文",
        got?.name === "write" && got.args.content === "联系人 张伟 电话 13800138000"
        && !got.args.content.includes("⟦PII:"),
        JSON.stringify(got));

  const editDef = registered.find((d) => d.name === "edit");
  await editDef.execute(
    { file_path: "E:/tmp/a.md", old_string: "张伟", new_string: "⟦PII:PERSON:0001⟧ 13800138000" },
    {},
  );
  const got2 = executeCalls.at(-1);
  check("edit new_string 占位符已还原",
        got2?.name === "edit" && got2.args.new_string === "张伟 13800138000"
        && got2.args.old_string === "张伟",
        JSON.stringify(got2));
}

// 16. pre-step 兜底: 只告警，返回原 decision、不改 messages
{
  const nextDecision = { kind: "proceed", messages: ["用户消息"] };
  const origWarn = console.error;
  let warned = "";
  console.error = (s) => { warned += String(s); };
  let res;
  try {
    res = await handlers["agent/pre-step"](
      { messages: [{ content: "联系人 张伟 13800138000" }] },
      async () => nextDecision,
    );
  } finally {
    console.error = origWarn;
  }
  check("pre-step 只告警不改写",
        res === nextDecision && warned.includes("[pii-guard] pre-step WARN"),
        JSON.stringify(res) + " | " + warned);
}

// 17-19. 占位符守护提示（症状②防源头）：首次产生映射的 agent 收到 additionalContexts notice
{
  const agentA = { ctx: {} };
  const agentB = { ctx: {} };
  // 17. 首次：value 路径（read 含 meta/value 且非 shell），映射产生 → additionalContexts 含 notice
  const res1 = await handler(
    { name: "read", args: {}, agent: agentA },
    { content: [{ type: "text", text: "张伟 13800138000" }], meta: { lines: [] }, value: { a: "张伟 13800138000" } },
    async () => ({ kind: "accept", map: { "⟦PII:PERSON:1⟧": "张伟", "⟦PII:PHONE_NUMBER:1⟧": "13800138000" } }),
  );
  check("首次映射注入 notice（value 路径）",
        Array.isArray(res1.additionalContexts) && res1.additionalContexts.length === 1
        && res1.additionalContexts[0].source?.kind === "pii-guard"
        && res1.additionalContexts[0].source?.form === "notice"
        && res1.additionalContexts[0].content?.[0]?.text.includes("⟦PII:"),
        JSON.stringify(res1.additionalContexts ?? null));
  check("notice 仍是 value 重渲染且不带 content",
        Object.hasOwn(res1, "value") && !Object.hasOwn(res1, "content")
        && JSON.stringify(res1.value ?? null).includes("⟦PII:PERSON:"),
        JSON.stringify(res1.value ?? null));
  // 18. 同一 agent 第二次：不再注入
  const res2 = await handler(
    { name: "job_output", args: {}, agent: agentA },
    { content: [{ type: "text", text: "张伟再次出现" }] },
    async () => ({ kind: "accept" }),
  );
  check("同 agent 第二次不重复注入",
        res2.additionalContexts === undefined && res2.content?.[0]?.text.includes("⟦PII:PERSON:"),
        JSON.stringify(res2.additionalContexts ?? null));
  // 19. 另一个 agent：各自注入一次
  const res3 = await handler(
    { name: "job_output", args: {}, agent: agentB },
    { content: [{ type: "text", text: "张伟 in B" }] },
    async () => ({ kind: "accept" }),
  );
  check("不同 agent 各自注入一次",
        Array.isArray(res3.additionalContexts) && res3.additionalContexts.length === 1
        && res3.additionalContexts[0].source?.kind === "pii-guard",
        JSON.stringify(res3.additionalContexts ?? null));
  // 19b. 无映射的工具结果不注入
  const res4 = await handler(
    { name: "job_output", args: {}, agent: { ctx: {} } },
    { content: [{ type: "text", text: "干净文本 no pii" }] },
    async () => ({ kind: "accept" }),
  );
  check("无映射不注入 notice",
        res4.additionalContexts === undefined && res4.content?.[0]?.text === "干净文本 no pii",
        JSON.stringify(res4.additionalContexts ?? null));
}


// 20. office 命令级告警：pwsh 命令引用 docx 时追加 WORKFLOW-GUIDE 提示
{
  const res = await runTool("pwsh", "plain output", { args: { command: "python parse.py report.docx" } });
  const out = res.content.map(b => b.text || "").join("\n");
  check("office 命令告警注入",
        out.includes("office") && out.includes("WORKFLOW-GUIDE"), out);
  const res2 = await runTool("pwsh", "plain output 2", { args: { command: "Get-Date" } });
  const out2 = res2.content.map(b => b.text || "").join("\n");
  check("非 office 命令不告警",
        !out2.includes("WORKFLOW-GUIDE"), out2);
}

// 21. shell 路径豁免要逐个实体判定：目录片段里的机构名放行，正文里的机构名仍脱敏。
{
  const shellDeps = {
    redact: async (t) => {
      const map = {};
      let redacted = t;
      if (t.includes("某某科技")) {
        map["⟦PII:ORGANIZATION:0001⟧"] = "某某科技";
        redacted = redacted.replaceAll("某某科技", "⟦PII:ORGANIZATION:0001⟧");
      }
      if (t.includes("乙乙咨询")) {
        map["⟦PII:ORGANIZATION:0002⟧"] = "乙乙咨询";
        redacted = redacted.replaceAll("乙乙咨询", "⟦PII:ORGANIZATION:0002⟧");
      }
      return { redacted, map };
    },
    restore: async (t) => t,
  };
  const localHandlers = {};
  await apply({ on: (evt, fn) => { localHandlers[evt] = fn; } }, shellDeps);
  const res = await localHandlers["tools/post-execute"](
    { name: "pwsh", args: { command: "Get-ChildItem" }, agent: { ctx: {} } },
    { content: [{ type: "text", text: "E:/data/某某科技/报告.txt 由乙乙咨询出具" }] },
    async () => ({ kind: "accept" }),
  );
  const out = res.content.map((b) => b.text || "").join("\n");
  // 路径片段里的机构名还原为原文，正文里的仍保留占位符
  check("路径中的机构名豁免脱敏", out.includes("某某科技"), out);
  check("正文中的机构名仍脱敏", out.includes("⟦PII:ORGANIZATION:0002⟧") && !out.includes("乙乙咨询"), out);
}

function byteLength(s) {
  return Buffer.byteLength(s, "utf8");
}

// 22. S2 回归：guard 侧也必须拒绝嵌套量词的 allowlist（设置面板之外的第二道闸）。
// 手改 guard-settings.json 或设 PII_GUARD_SHELL_ALLOWLIST 都会绕过 UI 校验，
// 所以 guard 读到这里时必须自己再拦一次，否则 (a+)+ 这类模式会冻结 agent loop。
{
  const { mkdirSync, mkdtempSync, writeFileSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const rejectRoot = mkdtempSync(join(tmpdir(), "pii-redos-"));
  const rejectStore = join(rejectRoot, ".pii_presidio_store");
  mkdirSync(rejectStore, { recursive: true });
  writeFileSync(
    join(rejectStore, "guard-settings.json"),
    JSON.stringify({ shellAllowlist: "^(a+)+$", shellDisabled: false }),
    "utf8",
  );
  const { apply: applyReject } = await import(pathToFileURL(pluginPath).href + `?redos=${Date.now()}`);
  const rejectHandlers = {};
  await applyReject(
    { on: (evt, fn) => { rejectHandlers[evt] = fn; } },
    {
      repo: rejectRoot.replaceAll("\\", "/"),
      redact: async (t) => ({ redacted: t.replaceAll("张伟", "⟦PII:PERSON:0001⟧"),
                              map: { "⟦PII:PERSON:0001⟧": "张伟" } }),
      restore: async (t) => t,
    },
  );
  // 命中 allowlist 会直接放行（原文透传）；被拒则走脱敏链，人名被替换成占位符。
  const res = await rejectHandlers["tools/post-execute"](
    { name: "pwsh", args: { command: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }, agent: { ctx: {} } },
    { content: [{ type: "text", text: "张伟" }] },
    async () => ({ kind: "accept" }),
  );
  const out = (res.content ?? []).map((b) => b.text || "").join("\n");
  check("嵌套量词 allowlist 被 guard 拒绝（不放行）", !out.includes("张伟") && out.includes("⟦PII:PERSON:"), out);
  rmSync(rejectRoot, { recursive: true, force: true });
}

let failed = 0;
for (const c of cases) {
  console.log(`${c.cond ? "PASS" : "FAIL"}  ${c.name}${c.cond ? "" : "  ← " + c.detail}`);
  if (!c.cond) failed++;
}
console.log(failed === 0 ? "[result] ALL PASS" : `[result] ${failed} FAILED`);
process.exit(failed === 0 ? 0 : 1);
