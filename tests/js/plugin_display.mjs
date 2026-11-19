// 显示侧还原（方案 B）冒烟: agent/assistant-stream 监听器的同步替换逻辑。
// 不依赖 Python 服务: 直接注入 phMap（模拟 redact 响应下发的增量映射）。
// 覆盖: 完整占位符替换、跨 chunk 分裂（扣尾补头）、end 兜底、无 PII 快路径、
//       off 模式动态开关（通过 guard-settings.json 即时切换，无需重启）。
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const pluginPath = process.argv[2];
if (!pluginPath) {
  console.error("用法: node tests/js/plugin_display.mjs <plugin index.js>");
  process.exit(2);
}
process.env.PII_GUARD_PY = "pii-guard-no-such-python-xyz"; // 不走真实服务
process.env.PII_GUARD_DISPLAY = "full";

// 把仓库根指到临时目录，这样 guard-settings.json 可隔离地写入/切换。
const repoTmp = mkdtempSync(join(tmpdir(), "pii-display-repo-"));
const storeDir = join(repoTmp, ".pii_presidio_store");
mkdirSync(storeDir, { recursive: true });
const settingsFile = join(storeDir, "guard-settings.json");
process.env.PII_GUARD_REPO = repoTmp.replaceAll("\\", "/");

const tmp = mkdtempSync(join(tmpdir(), "pii-display-"));
const copy = join(tmp, "plugin.mjs");
copyFileSync(pluginPath, copy);
const { apply } = await import(pathToFileURL(copy).href);
rmSync(tmp, { recursive: true, force: true });

// 进程重启后 phMap 为空，但映射仍保存在 SQLite；显示侧应通过同一 restore IPC
// 按会话恢复，而不是把其他会话的映射混进来。用 mock 隔离验证接缝与缓存行为。
const persistent = {
  sid: "pii-guard-42",
  restoreCalls: [],
};
const handlers = {};
await apply({ on: (evt, fn) => { handlers[evt] = fn; } }, {
  restore: async (text) => {
    persistent.restoreCalls.push({ text });
    if (text.includes(PH(1))) return text.replace(PH(1), "持久化姓名");
    return text;
  },
});
const stream = handlers["agent/assistant-stream"];
if (!stream) { console.error("FAIL  agent/assistant-stream listener not registered"); process.exit(1); }

const agent = { session: { id: "s1" } };
const chunk = (text, index) => ({ type: "chunk", attemptId: "a1", revision: 1, index, time: 0, chunk: { type: "text-delta", index, text } });

let failed = 0;
function check(name, cond, detail = "") {
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${cond ? "" : "  ← " + detail}`);
  if (!cond) failed++;
}

// 注入映射（模拟 redact 响应的 map 下发）; 用占位符文本本身构造, 不含 PII
const PH = (n) => `\u27E6PII:PERSON:${String(n).padStart(4, "0")}\u27E7`;
// 通过触发一次假 redact 调用来填 phMap 不可行（服务不存在），直接测内部行为:
// 无映射且 restore 也查不到时占位符原样透传（不崩溃、不吞字符）。
{
  const f = chunk(`hello ${PH(9)} world`, 0);
  stream({ agent, frame: f });
  check("无映射时占位符原样透传（服务失败 fail-safe）", f.chunk.text === `hello ${PH(9)} world`, f.chunk.text);
}

// 跨 chunk 分裂: 占位符被切成 3 段, 前缀扣住, 拼全后整体透传（仍无映射, 原样）
{
  const parts = ["前缀⟦PII:", "PERSON:00", "42⟧后缀"];
  let acc = "";
  const outs = parts.map((t, i) => {
    const f = chunk(t, i);
    stream({ agent, frame: f });
    acc = f.chunk.text; // 每帧改写后的可见文本
    return acc;
  });
  const total = outs.join("");
  check("分裂占位符不丢字符", total === parts.join(""), total);
  check("分裂后无残留扣尾", !total.includes("⟦PII:PERSON:0042⟧⟦") && !/\u27E6$/.test(total), total);
}

// end 帧: 扣尾兜底（前缀扣住到 end 仍不完整 → 原样放行）
{
  const f1 = chunk("尾部孤立前缀 ⟦PII:PE", 0);
  stream({ agent, frame: f1 });
  const heldVisible = f1.chunk.text; // 前缀应被扣住: 可见文本不应含完整孤立前缀之外的泄漏
  check("扣尾被缓冲不外泄", !heldVisible.includes("PII:PE"), `visible=${JSON.stringify(heldVisible)}`);
  const f2 = { type: "end", attemptId: "a1", revision: 2, index: 1, outcome: { kind: "committed", eventType: "assistant/message", seq: 1 } };
  stream({ agent, frame: f2 });
  const flushed = f2.chunk?.text === "\u27E6PII:PE";
  check("end 兜底放行扣尾", flushed, `flushed=${JSON.stringify(f2.chunk?.text)}`);
}

// 新流 start: 清扣尾（上一流的 pending 不泄漏到下一流）
{
  const f1 = chunk("abc ⟦PII:PE", 0);
  stream({ agent, frame: f1 });
  const fStart = { type: "start", attemptId: "a2", revision: 3, turn: 1, step: 1 };
  stream({ agent, frame: fStart });
  const f2 = chunk("xyz", 0);
  stream({ agent, frame: f2 });
  check("start 清扣尾且新流文本干净", f2.chunk.text === "xyz", f2.chunk.text);
}

// off 模式动态开关: 写入 guard-settings.json(displayMode=off) 后，下一个事件即生效。
// full 模式下孤立前缀 "⟦PII:PE" 会被扣尾（可见文本不含 PII:PE）；
// off 模式下 handler 首行 return，frame 不改写，"PII:PE" 原样可见。
{
  writeFileSync(settingsFile, JSON.stringify({ displayMode: "off" }), "utf8");
  const agentOff = { session: { id: "s-off" } };
  const f = chunk("off 模式前缀 ⟦PII:PE", 0);
  stream({ agent: agentOff, frame: f });
  check("off 模式即时生效（不扣尾、原样透传）", f.chunk.text.includes("PII:PE"), `visible=${JSON.stringify(f.chunk.text)}`);

  // 再切回 full，验证即时恢复（同一插件实例，无需重启）
  writeFileSync(settingsFile, JSON.stringify({ displayMode: "full" }), "utf8");
  const agentFull = { session: { id: "s-full-again" } };
  const f2 = chunk("full 模式前缀 ⟦PII:PE", 0);
  stream({ agent: agentFull, frame: f2 });
  check("切回 full 即时恢复（扣尾）", !f2.chunk.text.includes("PII:PE"), `visible=${JSON.stringify(f2.chunk.text)}`);
}

// 进程重启恢复：phMap 为空时，通过 restore IPC 从 SQLite 按会话恢复并回填缓存。
{
  const agentNew = { session: { id: "s-restart" } };
  const f = chunk(`联系人 ${PH(1)}`, 0);
  stream({ agent: agentNew, frame: f });
  // 异步恢复在下一拍完成
  await new Promise((r) => setTimeout(r, 50));
  const f2 = chunk(`联系人 ${PH(1)}`, 1);
  stream({ agent: agentNew, frame: f2 });
  check("重启后从 SQLite 恢复映射", f2.chunk.text === "联系人 持久化姓名", f2.chunk.text);
  check("restore 被调用", persistent.restoreCalls.length > 0, JSON.stringify(persistent.restoreCalls));
}

// 缓存命中后不再重复 IPC：同一占位符第二次出现直接用缓存。
{
  const before = persistent.restoreCalls.length;
  const agentCache = { session: { id: "s-cache" } };
  const f = chunk(`联系人 ${PH(1)}`, 0);
  stream({ agent: agentCache, frame: f });
  await new Promise((r) => setTimeout(r, 50));
  const f2 = chunk(`联系人 ${PH(1)}`, 1);
  stream({ agent: agentCache, frame: f2 });
  const after = persistent.restoreCalls.length;
  check("缓存命中不重复 IPC", after - before <= 1, `before=${before} after=${after}`);
}

// S3 回归：config.repo 必须覆盖 env PII_GUARD_REPO（与 terms 的 resolveRepo 对齐）。
// 重新加载一份插件模块（独立实例），只传 config.repo 指向第二个临时仓库，
// env 仍指向 repoTmp；若 guard 仍只认 env，就会读错文件、off 模式不生效。
{
  const repo2 = mkdtempSync(join(tmpdir(), "pii-s3-repo-"));
  const store2 = join(repo2, ".pii_presidio_store");
  mkdirSync(store2, { recursive: true });
  const settings2 = join(store2, "guard-settings.json");
  writeFileSync(settings2, JSON.stringify({ displayMode: "off" }), "utf8");

  const copy2 = join(mkdtempSync(join(tmpdir(), "pii-s3-plugin-")), "plugin.mjs");
  copyFileSync(pluginPath, copy2);
  const { apply: apply2 } = await import(pathToFileURL(copy2).href + `?s3=${Date.now()}`);
  const handlers2 = {};
  await apply2({ on: (evt, fn) => { handlers2[evt] = fn; } }, {
    repo: repo2.replaceAll("\\", "/"),
    restore: async (t) => t,
  });
  const stream2 = handlers2["agent/assistant-stream"];
  const f = chunk("S3 前缀 ⟦PII:PE", 0);
  stream2({ agent: { session: { id: "s-s3" } }, frame: f });
  check("S3 config.repo 覆盖 env（guard 读新路径 off 设置）", f.chunk.text.includes("PII:PE"), `visible=${JSON.stringify(f.chunk.text)}`);
  rmSync(repo2, { recursive: true, force: true });
}

rmSync(repoTmp, { recursive: true, force: true });
process.exit(failed ? 1 : 0);
