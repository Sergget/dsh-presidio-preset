// pii-guard 单元验证（mock redact，不依赖 spawn——沙箱内 spawn 管道被禁）。
// 真实 IPC 链路由 Step1 管道测试 + Step5 端到端覆盖。
// 运行: node tools/test-pii-guard.mjs   退出码 0=PASS 1=FAIL
// FIX-1: 从脚本位置推断仓库根（tools -> ..），不再写死安装态绝对路径。
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const GUARD = join(REPO, "plugins", "dsh-presidio-pii", "lib", "guard.js");
const { apply } = await import(pathToFileURL(GUARD).href);

// 当前 guard 的脱敏监听器注册在 tools/post-execute，签名 (exec, result, next)。
const handlers = [];
const mockCtx = {
  on(event, fn) {
    if (event === "tools/post-execute") handlers.push(fn);
  },
};

// mock redact: 模拟 Python 服务返回（与 presidio_pii/server.py 协议一致）
const mockRedact = async (text) => ({
  id: "mock",
  redacted: text
    .replaceAll("范志强", "⟦PII:PERSON:0001⟧")
    .replaceAll("13800138000", "⟦PII:PHONE_NUMBER:0001⟧"),
  n: 2,
});

await apply(mockCtx, { redact: mockRedact });
const guard = handlers[0];
if (typeof guard !== "function") {
  console.error("FAIL: expected a tools/post-execute handler, got", typeof guard);
  process.exit(1);
}

// post-execute 三参签名：next() 返回 decision，脱敏基于 decision.content ?? result.content。
const call = (exec, result) => guard(exec, result, async () => result);

// 用例1: read → mock 脱敏生效
const fakeResult = {
  content: [{
    type: "text",
    text: "# 研究方法\n\n范志强，姚志刚，谭俊杰\n\n手机 13800138000",
  }],
};
const r1 = await call({ name: "read", args: {} }, fakeResult);
const t1 = r1.content[0].text;
const pass1 = !t1.includes("范志强") && !t1.includes("13800138000")
  && t1.includes("⟦PII:PERSON:0001⟧") && t1.includes("⟦PII:PHONE_NUMBER:0001⟧");
console.log(`[case1 read-redacted] PASS=${pass1}`);

// 用例2: 守卫名单内的 pwsh → 现行语义为默认全拦，应被脱敏
const raw = { content: [{ type: "text", text: "范志强 raw" }] };
const r2 = await call({ name: "pwsh", args: { command: "echo hi" } }, raw);
console.log(`[case2 pwsh-redacted] PASS=${r2.content[0].text.includes("⟦PII:PERSON:0001⟧")}`);

// 用例3: isError 结果 → 原样返回不处理（read 非 shell 守卫，错误维持透传）
const errRes = { isError: true, content: [{ type: "text", text: "范志强" }] };
const r3 = await call({ name: "read", args: {} }, errRes);
console.log(`[case3 isError] PASS=${r3.content[0].text === "范志强"}`);

// 用例4: grep（守卫集合内第二工具）
const r4 = await call({ name: "grep", args: {} }, fakeResult);
console.log(`[case4 grep-redacted] PASS=${r4.content[0].text.includes("⟦PII:PERSON:0001⟧")}`);

process.exit(pass1 ? 0 : 1);
