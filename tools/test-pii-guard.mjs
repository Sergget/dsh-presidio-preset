// pii-guard 单元验证（mock redact，不依赖 spawn——沙箱内 spawn 管道被禁）。
// 真实 IPC 链路由 Step1 管道测试 + Step5 端到端覆盖。
// 运行: node tools/test-pii-guard.mjs   退出码 0=PASS 1=FAIL
import { apply } from "file:///E:/Code/dsh_home/plugins/dsh-pii-guard/lib/index.js";

const handlers = [];
const mockCtx = {
  on(event, fn) {
    if (event === "tools/execute") handlers.push(fn);
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
if (handlers.length !== 1) {
  console.error("FAIL: expected 1 tools/execute handler, got", handlers.length);
  process.exit(1);
}
const guard = handlers[0];

// 用例1: read → mock 脱敏生效
const fakeNext = async () => ({
  content: [{
    type: "text",
    text: "# 研究方法\n\n范志强，姚志刚，谭俊杰\n\n手机 13800138000",
  }],
});
const r1 = await guard({ name: "read", args: {} }, fakeNext);
const t1 = r1.content[0].text;
const pass1 = !t1.includes("范志强") && !t1.includes("13800138000")
  && t1.includes("⟦PII:PERSON:0001⟧") && t1.includes("⟦PII:PHONE_NUMBER:0001⟧");
console.log(`[case1 read-redacted] PASS=${pass1}`);

// 用例2: 非守卫工具（pwsh）→ 原样透传
const raw = { content: [{ type: "text", text: "范志强 raw" }] };
const r2 = await guard({ name: "pwsh", args: {} }, async () => raw);
console.log(`[case2 passthrough] PASS=${r2.content[0].text === "范志强 raw"}`);

// 用例3: isError 结果 → 原样返回不处理
const errRes = { isError: true, content: [{ type: "text", text: "范志强" }] };
const r3 = await guard({ name: "read", args: {} }, async () => errRes);
console.log(`[case3 isError] PASS=${r3.content[0].text === "范志强"}`);

// 用例4: grep（守卫集合内第二工具）
const r4 = await guard({ name: "grep", args: {} }, fakeNext);
console.log(`[case4 grep-redacted] PASS=${r4.content[0].text.includes("⟦PII:PERSON:0001⟧")}`);

process.exit(pass1 ? 0 : 1);
