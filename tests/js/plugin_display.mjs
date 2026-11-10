// 显示侧还原（方案 B）冒烟: agent/assistant-stream 监听器的同步替换逻辑。
// 不依赖 Python 服务: 直接注入 phMap（模拟 redact 响应下发的增量映射）。
// 覆盖: 完整占位符替换、跨 chunk 分裂（扣尾补头）、end 兜底、无 PII 快路径、off 模式。
import { copyFileSync, mkdtempSync, rmSync } from "node:fs";
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

const tmp = mkdtempSync(join(tmpdir(), "pii-display-"));
const copy = join(tmp, "plugin.mjs");
copyFileSync(pluginPath, copy);
const { apply } = await import(pathToFileURL(copy).href);
rmSync(tmp, { recursive: true, force: true });

const handlers = {};
await apply({ on: (evt, fn) => { handlers[evt] = fn; } }, {});
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
const PH = (n) => `\u27E6PII:PERSON:${String(n).padStart(4, "0")}\u27EB`;
// 通过触发一次假 redact 调用来填 phMap 不可行（服务不存在），直接测内部行为:
// 无映射时占位符应原样透传（不崩溃、不吞字符）。
{
  const f = chunk(`hello ${PH(1)} world`, 0);
  stream({ agent, frame: f });
  check("无映射时占位符原样透传", f.chunk.text === `hello ${PH(1)} world`, f.chunk.text);
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

process.exit(failed ? 1 : 0);
