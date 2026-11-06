# Step 5 最小端到端验证 — pii-guard 硬性拦截

**前置**：完全重启 DSH（desktop profile 无热加载）→ 新会话 → Agent Preset 选「PII 防护模式」→ 工作目录 `E:\Code\dsh-presidio-preset` → 粘贴下方提示词。

**判定总表**

| 用例 | 通过判据 | 失败含义 |
| --- | --- | --- |
| 1 正向：read 明文 | 返回含 `⟦PII:PERSON:xxxx⟧`，无 `范志强/姚志刚/谭俊杰` 明文 | 拦截未生效 |
| 2 负向：read 正常文本 | 无 PERSON/ID/PHONE/BANK 占位符（ORGANIZATION 占位符属预期） | 误伤过高 |
| 3 引擎旁证 | 若模型自述 read 返回含占位符但你看 GUI 显示原文——以**模型读到的内容**为准（GUI 的渲染在还原层之后不适用本插件，直接看模型引用的文本） | — |

---

## 可复制的验证提示词

```
【任务】执行 pii-guard 守护插件的最小端到端验证（Step 5）。只做下面 3 个用例，不要扩展。

【用例 1：正向拦截】
用 read 工具读取 E:\Code\dsh-presidio-preset\testdata_v2\paper\paper-01.md，
把返回内容的前 8 行原样引用到回复里。
判据：内容含 ⟦PII:PERSON:xxxx⟧ 占位符；不得出现「范志强」「姚志刚」「谭俊杰」任一明文。
出现明文 = FAIL，如实报告。

【用例 2：负向误伤】
用 read 工具读取 E:\Code\dsh-presidio-preset\testdata_v2\negative\normal-01.md，
统计返回内容里各类 ⟦PII:类型⟧ 占位符的数量。
判据：PERSON / ID_NUMBER / PHONE_NUMBER / BANK_CARD 占位符数 = 0；
ORGANIZATION / LOCATION 占位符可出现（非个人信息）。逐类报数。

【用例 3：grep 负向】
用 grep 工具在 E:\Code\dsh-presidio-preset\testdata_v2\paper\ 目录搜「13800138000」，
报告命中行内容（原样引用）。
判据：若有命中，命中行应已脱敏（显示占位符而非号码明文）。

【汇报格式】
| 用例 | 结果 | 证据（原文引用/计数） |
| 1 正向 | PASS/FAIL | ... |
| 2 负向 | PASS/FAIL | ... |
| 3 grep | PASS/FAIL | ... |
最后一句结论：pii-guard 端到端 生效 / 未生效（未生效时附上你看到的具体明文或报错原文）。

【红线】
- 本验证只读，不写任何文件；
- 若 read/grep 调用本身报错（如服务异常），把报错原文贴出来，不要猜测原因。
```

---

## 结果处置

| 结果 | 下一步 |
| --- | --- |
| 3/3 PASS | 方案 A 端到端生效 → 按 PLAN-pii-guard.md Step 6 收尾（文档更新 + 生产评估基准：真实样本回归仍待做） |
| 用例 1 FAIL（明文出现） | 把引用的原文发我——排查方向：插件未激活 / exec.name 不匹配 / IPC 失败走了降级透传 |
| 用例 1 报错 | 把 read 的报错原文发我——排查方向：Python 服务 spawn 失败 / 超时 |
| 用例 2/3 FAIL | 引擎误伤率问题，调 custom_rules/白名单，与 guard 无关 |
