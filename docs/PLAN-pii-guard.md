# 方案 A：PII 工具拦截守护插件 — 实施计划

> 目标：把 preset 的「脱敏」从**提示词级自律**升级为**循环内硬性流程**——模型通过
> `read`/`grep` 等工具读到的文件内容，在进入上下文**之前**被自动脱敏，模型无感、
> 不可跳过。

## 一、可行性证据（已用 asar 源码逐行核实）

| 关键机制 | 证据来源 | 结论 |
| --- | --- | --- |
| `tools/execute` 是 wrapper 接缝 | `@deepseek-ai/dsh-tool-call-timeout-policy/lib/index.js:116` | `ctx.on("tools/execute", async (exec, next) => {...})` 可拦截每个工具调用，`await next()` 返回模型可见结果，可改写后 `return` |
| 插件注入工具注册表 | 同上 `index.js:84` | `const inject = ["tools"]` 声明依赖 |
| read 结果可改写结构 | `@deepseek-ai/dsh-tool-fs/lib/index.js:356-377` | 模型可见结果是 `content: [{type:"text", text}]` 数组，`text` 即文件正文 |
| 本地插件挂载方式 | `profiles/desktop/cordis.patch.yml` 中 `auto-review-fix` 行 | `name: 'file:///E:/Code/dsh_home/plugins/<name>/lib/index.js'` 本机已有先例 |

**结论**：方案 A 技术上完全可行，机制与 timeout-policy 同源，比它还简单（timeout 改
signal，我们改 result 文本）。

## 二、架构设计

```
模型调用 read(file_path)
        │
        ▼
tools/execute 事件（本插件 ctx.on 拦截）
        │
        ├─ 非目标工具(read/grep) → await next() 原样放行
        │
        └─ 目标工具 → await next() 拿原始结果
              │
              ▼
        提取 result.content[].text
              │
              ▼
        调用常驻 Python 脱敏引擎 redact_text()
              │
              ▼
        改写 content[].text 为脱敏文本
              │
              ▼
        return（模型只看到脱敏文本）
```

### 关键设计决策

1. **常驻 Python 子进程（stdio JSON-RPC）**，不是每次 spawn：
   - 起因：`import presidio_pii.engine` 实测 5.3s（jieba 词典加载）。
   - 设计：插件启动时 spawn 一个 Python 服务进程，词表加载一次，之后每次 read 走
     stdin/stdout 的 JSON 请求，单次 <100ms。
   - 复用：优先 `presidio_pii` 现有的 `engine` 与 `hooks` API，不新造识别逻辑。

2. **拦截面 = read + grep**（`tool-fs` 与 `tool-fs-search`），**不含 pwsh**：
   - pwsh 输出是任意命令产物，无法可靠剥离「文件内容 vs 命令噪声」。
   - pwsh 是本方案的**已知旁路**：模型可 `cat` 明文。计划 Step 5 单独处理（见风险节），
     第一步先守住最常用的 read/grep 通道。

3. **会话级映射表**：脱敏时把「占位符 ↔ 原文」写入映射库（复用现有 SQLite/session
   机制），使后续 restore 可逆。

## 三、实施步骤与逐步验证

### Step 1 — Python 脱敏服务（常驻进程）
- 产出：`presidio_pii/server.py`，实现 `--stdio` 模式：
  读一行 JSON `{"id": "r1", "text": "...", "sid": "s"}` → 回一行
  `{"id": "r1", "redacted": "...", "n": 3}`。
- **验证**：`echo '{"text":"张伟的身份证110101199003077890"}' | python presidio_pii/server.py`
  返回 `redacted` 含 `⟦PII:PERSON⟧`，且原文不复现。exit 判定输出 JSON 合法。

### Step 2 — 插件骨架（Node）
- 产出：`E:\Code\dsh_home\plugins\dsh-pii-guard\lib\index.js`，仿 timeout-policy：
  `inject=["tools"]` + `apply(ctx) { ctx.on("tools/execute", ...) }`。
- 先做**透传版**：拦截 read/grep，打印工具名与 content 长度后原样放行（不改写）。
- **验证**：挂载后（Step 4 一起验），读任意文件，插件日志出现该工具调用，文件内容
  仍正常（透传未破坏）。

### Step 3 — 接入 Python 服务 + 改写 result
- 产出：插件启动时 spawn Python 服务，read/grep 结果经 IPC 脱敏后改写 `content[].text`。
- **验证单元级**：用 Node 直接 require 插件（mock ctx），喂一个含明文的假 result，
  断言返回的 text 已脱敏、占位符可被映射表还原。

### Step 4 — 挂载到 preset + 组合验证
- 产出：在 `bundle/cordis.patch.yml` 的 plugins 里加一行：
  ```yaml
  - id: pii-guard
    name: 'file:///E:/Code/dsh_home/plugins/dsh-pii-guard/lib/index.js'
  ```
- **验证**：`dsh --profile web --dump-config` exit 0，含 `pii-guard` 行；无 schema 报错。

### Step 5 — 端到端硬性验证（核心）
- 重启 DSH 后，在 PII 防护模式下让 agent 读 `testdata_v2/paper/paper-01.md`
  （明文含 范志强/姚志刚/谭俊杰）。
- **验收判据**：read 返回内容里**不再出现**明文人名/号码，而是 `⟦PII:PERSON:0001⟧`
  占位符；`restore` 后还原。若明文仍在 → 失败，回退排查。
- **负向验证**：尝试 `grep 姚志刚`，命中结果同样被脱敏。

### Step 6 — 文档与提交
- 更新 SKILL.md/test-guide.md：把「自律工作流」的边界说明改为「read/grep 已硬性
  拦截；pwsh 仍是旁路」，诚实标注剩余边界。
- 提交全部改动 + 部署同步。

## 四、风险与回退

| 风险 | 影响 | 缓解 / 回退 |
| --- | --- | --- |
| **pwsh 旁路未被拦截** | 模型可 `cat` 明文 | Step 5 后若需彻底，再上方案 B（disable pwsh + 受限 shell），本计划不做 |
| Python 服务崩溃/挂起 | read 全挂 | 插件对 IPC 加超时；服务异常时**降级透传**（宁可放行不全挂死），并写 stderr 告警 |
| 脱敏误伤（把代码/正常文本当 PII） | 模型看到占位符而非原文 | 只对 read/grep 的文本型 content 处理；白名单可配置；误伤率由 eval 回归把关 |
| 多会话并发共享 Python 服务 | 串行排队 | 服务用简单队列；量小够用 |
| 插件影响非 PII 会话 | 干扰标准模式 | 插件只在 `presidio-pii` preset 的 plugins 列表里，其它 preset 不挂 |

## 五、验收清单（Done 的定义）

- [ ] `presidio_pii/server.py` 单进程 JSON 回显脱敏，复现原文=0
- [ ] `dsh-pii-guard/lib/index.js` 透传版在组合中无报错
- [ ] 改写版单元测试：喂明文假 result → 返回脱敏 + 可还原
- [ ] `dsh --profile web --dump-config` 含 pii-guard 行，exit 0
- [ ] **端到端**：PII 模式 read `paper-01.md` 返回占位符，无明文；restore 复原
- [ ] 负向：`grep 明文人名` 同样被脱敏
- [ ] 文档更新 + git 提交，无密钥/凭据/明文 PII 入库

## 六、未覆盖（明确不在本期）

- pwsh 输出的脱敏（方案 B 范畴）
- 图片/二进制内容的 OCR 脱敏
- 网关侧（llm-worker 前）脱敏