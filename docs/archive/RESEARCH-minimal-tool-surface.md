> **【已归档 2026-11-18】** 本文已合并进 docs/RESEARCH-pii-protection.md（研究总纲），
> 此处仅作历史留存。新文档统一了问题编号（`R-xx` / `T-xx` / `F-xx`），
> 附录 B 提供旧编号对照表。**请以新文档为准，本文不再更新。**
> 保留本文件的目的：完整保留当时的推演过程与逐行源码取证，便于追溯结论来源。

---
# 研究报告：极简工具面 + 工具级钉死脱敏/还原

> 研究对象：「像 dsh 极简模式那样只暴露最少量的工具（bash、read_redacted、write_raw、restore 等），
> 直接在工具级钉死脱敏和还原规则，通过强语言约束不得使用 bash 获取文件内容；
> 支持读取、写入的格式有限也可接受，可用 md 做中转、其他工具如 write_docx（参照事先给的模板）还原 docx」
>
> 结论日期：2026-11-18　核实基线：dsh `0.2.2-rc.1`（`@deepseek-ai/*` 全量 workspace 包）
> 本文所有断言都带可核对的源码行号或 README 原文。凡标「未验证」的，是本文没跑到实测的。

---

## 0. 结论摘要

**一句话**：这条路**走得通一半**，但不是用户设想的那一半——真正管用的不是「强语言约束禁止 bash 读」，而是**根本不给 bash**；
「工具级钉死还原」已经是成熟工程范式，「工具级钉死脱敏」在 DSH 现有接缝上有**三条必然漏路**（isError 通道、PTC canonical value、spill 落盘），见 §4。

1. **「只暴露最少工具」✅ 完全可行**，且官方有两套现成机制：
   配置级（`tool-fs` 的 `read` / `write` / `edit` / `readImage` / `applyPatch` 五个独立开关，`dsh-tool-fs/lib/index.js:1967-1989`）
   + 运行期（`agent.ctx.tools.restrict({ allow | deny })`，`dsh-tools/lib/index.js:453-467`）。
   但要写成一行 JS 插件，**不是 yml 里能配出来的**。
2. **「工具级钉死还原」✅ 可行，且仓库已经有生产级实现**：`agent/created` → `agent.ctx.tools.register({...original, execute})` 做 scoped shadow，
   `plugins/dsh-pii-guard/lib/index.js:618-659` 已经在跑。照抄即可。
3. **「工具级钉死脱敏」⚠️ 只能钉住成功结果的一半**。`tools/post-execute` 能替换成功结果的 `content`/`value`
   （`pipeline.js:673-701`），但**不能替换 `isError` 结果**（`:687`），而 `fs` 层 **57 处错误里有 39 处**把 `displayPath` 拼进文本
   （`dsh-fs-local/lib/index.js` 全文件统计，18 处不含路径）。→ **文件名里含真实姓名时，错误通道必然明文泄漏**，这不是概率问题。
4. **「强语言约束不得用 bash 获取文件内容」❌ 作为安全边界不成立**。三重证据：
   Windows 沙箱**只管写不管读**（`dsh-sandbox-windows-acl/README.md`：「confines child-process **writes and deletes**」、
   「**Reads are unrestricted on Windows**」）；`dsh-bash-sandbox/README.md`：「The modes govern file effects only — **network stays unrestricted**」；
   而且**本仓库自己已经论证过白名单/约束不可靠**——`docs/DECISION-shell-redaction.md` §0.2 原文：
   「白名单只能算弱化版，命令拼接/别名/`& {}` 很容易绕过，安全收益低」。
5. **正确解法是删除，不是约束**：如果这个预设的商品是「处理含 PII 的文档」，那它**根本不需要 shell**。
   不留 bash，「禁止 bash 读文件」这条做不到的约束就自动消失了。代价是跑不了测试/编译/git——对纯文档处理场景代价为零。
   这是本报告最强的建议（见 §6 Phase 1）。
6. **「md 中转 + write_docx 按模板还原」⚠️ 需求内部自相矛盾**：`md` 中转之后，段内混合格式（run 级样式）已经丢了，
   再「按模板还原」只能还原**版式骨架**，还原不了**原有文字样式**。`presidio_pii/documents.py:295-302` 的
   `_set_docx_paragraph` 注释原文已经写明这一点：「最小实现: 重写首个 run, 其余 run 清空 (**丢失段内混合格式**)」。
   这条必须由产品拍板：到底是「还原原样式」还是「套模板样式」。
7. **PTC 路线会静默击穿现有方案**：`dsh-tool-executor-ptc/lib/index.js:514-521` 返回给程序的是 `result.value`（canonical value），
   `post-execute` 改 `content` 对程序内拿到的值**无效**。当前 `presidio-pii` 预设挂了 `workflow-ptc` 但**没挂** `dsh-tool-executor-ptc`；
   一旦有人补上这一行，`dsh-pii-guard` 的 post-execute 脱敏就会变成「只在 UI 上看着脱敏了」。
8. **好消息一条**：`web_fetch` 只允许 `http:`/`https:`（`dsh-web-fetch-http/lib/index.js:30` 原文
   `if (url.protocol !== "http:" && url.protocol !== "https:") throw new WebError(...)`），所以 `file://` 这条读通道是堵死的，
   不用担心 agent 用 `web_fetch` 读本地文件。

---

## 1. 需求拆解：五条断言不是一回事

用户这句话里有五个独立主张，风险等级和可行性完全不同，必须拆开判：

| # | 断言 | 性质 | 本报告判定 |
|---|---|---|---|
| A1 | 只暴露最少量工具 | 工具面裁剪 | ✅ 可行（两套官方机制，需写插件） |
| A2 | 工具级钉死脱敏 | 结果侧拦截 | ⚠️ 部分可行（isError 与 canonical value 两处漏） |
| A3 | 工具级钉死还原 | 参数/写盘侧改写 | ✅ 可行（已有生产范式） |
| A4 | 强语言约束禁止 bash 读文件 | **策略承诺** | ❌ 不可作为安全边界 |
| A5 | md 中转 + write_docx 按模板还原 | 格式折衷 | ⚠️ 有条件可行，但与「还原」语义冲突 |

**A4 单独拎出来说**：A1/A2/A3/A5 都是「做多少算多少」的工程问题，A4 是**安全承诺**问题。
把 A4 写进验收契约，等于给用户一个「用语言约束挡住了文件读取」的虚假保证——一旦事后要写事故复盘，
这是最伤的一类。所以本报告对 A4 的结论是**不能写进契约**，要么实现成「无 shell」，要么明说「有 shell 就有读取能力，我们不承诺拦截」。

---

## 2. DSH 极简模式的真实形状（源码级）

用户说「像 dsh 极简模式那样」。先把极简模式是什么钉死，免得对错靶子。

`.../@deepseek-ai/dsh-sdk-minimal/cordis.patch.yml`（179 行）——注释第 1-3 行原文：
> 「Standalone minimal SDK application. Unlike the ordinary SDK profile, this bundle does not layer over dsh-base: this insert is the complete Cordis tree.」

它的工具面：

| 行号 | 挂载 | 关键配置 |
|---|---|---|
| :44-50 | `dsh-tool-fs` | `{ read: false, readImage: true, write: false, edit: false }` |
| :82-86 | `dsh-terminal-bash` | POSIX，`timeoutMs: 300000`，`disabled: platform === 'win32'` |
| :88-93 | `dsh-terminal-bash` | `shellDialect: pwsh`，`timeoutMs: 300000`，`disabled: platform !== 'win32'` |
| :144-157 | `dsh-tool-bash-persistent` | 持久 bash |
| :158-170 | `dsh-tool-pwsh-persistent` | 持久 pwsh，description 里明写「You don't have access to the internet via this tool.」 |
| :70-74 | `dsh-sandbox-policy` | `mode: danger-full-access` |
| :113-118 | `dsh-system-prompt` | `includeHarnessIdentity: false`、`includeRuntimeContext: false` |
| :172-176 | `dsh-session-persistence-jsonl` | `compression: none`（= 明文 JSONL） |
| :121-124 | `dsh-tools` + `dsh-tool-executor-native` | **native 执行器，没有 PTC** |

**读出来的三个事实**：

1. **极简模式的「极简」= 关掉 fs 读写 + 砍掉 web/subagent/todo/skill/jobs，但 shell 全留（含持久 shell）。**
   它不是「PII 安全模式」，是「给 SWE 用的精简编码启动器」。用户想借它的**形状**，但不能借它的**安全假设**——
   它把 shell 全留、沙箱设 `danger-full-access`，恰恰是因为它不做 PII 防护。
2. **极简模式本身没有任何脱敏能力**，`tool-fs` 的 `read` 关掉只是「没有结构化读通道」，shell 一样能 `cat`。
3. **极简模式用 native 执行器**，所以不踩 §4.2 的 PTC 坑。当前 `presidio-pii` 预设也是 native，但挂了 `workflow-ptc`。

### 2.1 一个更关键的立体事实：`dsh-base` 是所有预设的公共底座

这一条决定了「工具面到底能不能真的收窄」，前面几节都没提到。

`.../@deepseek-ai/dsh-base/cordis.patch.yml`（20962B）文件头第 1 行注释原文：
> 「The shared dsh core: model access, tools, durable sessions, and safety defaults for **every dsh --profile surface**」

它**已经挂了**下面这些行（`dsh-base` 是 profile 级底座，不是 preset 级）：

| 行号 | 挂载 | 关键配置 / 与本方案的关系 |
|---|---|---|
| :296-297 | `tool-fs` | `config: { applyPatch: false }` —— **`read`/`write`/`edit` 三开关仍是默认 true**。但 note：Web 面已在 `:506-507` 把整行 host 侧 disable，所以真正生效的是下面 2.1.1 的结论 |
| :302-303 | `tool-fs-search` | `config: { sampleOverCapGlobResults: false }` —— 同上，Web 面 `:509-510` 已 disable |
| :411-412 | `spill-local` | spill 落盘的是原文，且 `retrievalHint` 教模型去读 |
| :414-415 | `spill-policy` | 管何时 spill |
| :138-139 | `session-persistence-jsonl` | `config: { root: dshHomePath('sessions') }`，会话 JSONL（`compression` 默认 `zstd`，非加密） |
| :292-294 | `fs-observation-policy` | **`disabled: true`** —— 读前强制（read-before-write）默认是关的；本方案如果要复用它的 `FS_NOT_OBSERVED` 语义，得自己打开 |
| :501-502 | `tool-executor-native` | 当前生效的执行器 |
| :504-506 | `tool-executor-ptc` + `disabled: true` | **默认关闭**，所以 §4.2 的 PTC 破口当前不触发 |

`dsh-web-app/cordis.patch.yml` 第 1-2 行注释确认了覆盖语义：
> 「The dsh-web-app bundle patch: the browser surface over the dsh-base layer. **Applied after dsh-base's insert; rows here override base rows by id**」

#### 2.1.1 但 base 不是全部——Web 面已经把「agent 平面」腾空了

只看 `dsh-base` 会得出错误结论。`dsh-web-app/cordis.patch.yml`（22879B）`:467-476` 有一段注释是决定性的：

> 「the agent plane moves behind agent presets … Every row below composes what ONE agent contributes to the host registries: its tools, its prompt sections, its delegation backends. **The base keeps them for the TUI**, which is single-session and composes its agent process-wide; **the Web surface disables them here and lets each session mount a preset instead.**
> Disabling rather than deleting is deliberate: the base is shared, and a row absent from a surface overlay would silently reappear the day someone reorders the composition.」

**Web 面实际 `disabled: true` 的 22 行**（这些行在 Web 下不生效，完全由预设的 `plugins` 数组决定）：
`tool-plugin-manager`(:484)｜`tool-bash`(:487)｜`tool-pwsh`(:490)｜`tool-jobs`(:503)｜`tool-fs`(:506)｜`tool-fs-search`(:509)｜`skill-filesystem`(:521)｜`tool-skill`(:524)｜`command-goal`(:530)｜`tool-goal`(:533)｜`plan-mode`(:536)｜`compaction-basic`(:546)｜`command-compact`(:549)｜`tool-result-pruner`(:552)｜`tool-subagent-control`(:562)｜`tool-subagent`(:565)｜`tool-subagent-fork`(:568)｜`workflow-ptc`(:571)｜`tool-workflow`(:574)｜`agent-instructions`(:577)｜`tool-todo`(:580)｜`tool-web`(:583)

**留在 host 平面、预设管不到的行**（在 web-app 层 ABSENT，即未被覆盖、继续生效）：
`spill-local`｜`spill-policy`｜`session-persistence-jsonl`｜`tool-executor-native`｜`tool-bash-persistent`｜`tool-pwsh-persistent`

（`present` 与 `tool-ask-user` 在 base 和 web-app 层都 ABSENT —— 它们由预设自己的 `plugins` 数组挂载，属 agent 平面，归预设管。本仓库 `$DSH_HOME/cordis.patch.yml:399-411` 与 `bundle/cordis.patch.yml` 里确实这两行都在。）

`dsh-agent-preset/lib/index.js` 全文 898B，`Config = z.object({ id, name, description, order, plugins })` —— **预设只是「一组 child plugin entry」，没有 `disabled` 语义**，也不拥有 host 平面。这从机制上印证了上面的划分。

**三条推论（修订版，与初稿不同）**：

1. **对「agent 平面」的行，预设数组就是权威**：`tool-fs` / `tool-fs-search` / `tool-bash` / `tool-pwsh` / `tool-web` / `tool-todo` 这些在 Web 下已被 host 禁掉，**预设里不写 = 不存在**。所以「删掉 bash」「删掉 grep」在自己的预设里就是**删一行**，不需要写 `disabled: true`。（初稿写「必须覆盖 base 行」，是错的。）
2. **对 host 平面的行，预设无能为力**：`spill-local` / `spill-policy` / `session-persistence-jsonl` 在任何预设下都生效。要动它们只能改 **profile / home 层 patch**（`$DSH_HOME/cordis.patch.yml`，本机 21763B / 421 行）或另起 profile。
3. **想彻底不受 base 影响**，唯一干净路径是「另起一个 profile」（像极简 SDK 那样不 layer over base），代价是丢掉 base 的模型接入、会话、压缩等全部能力，等于自建一个 DSH。**不建议**。

→ 因此 P0-5 的正确说法是：**`grep` 可以靠「不写进预设」删掉；`spill` 和 `session JSONL` 删不掉，只能靠 profile 层或接受。**

`.../@deepseek-ai/dsh-web-app/presets/` 下有四个官方预设可直接参考形状：
`cordis.patch.yml`(7434B)、`minimal.patch.yml`(3724B)、`ptc.patch.yml`(6963B)、`standard.patch.yml`(6858B)。
`minimal.patch.yml`（78 行 / 3724B）里 `tool-fs` 一行就是 `{ read: false, readImage: true, write: false, edit: false }` ——
**这就是「极简模式」在 Web 侧的最小实现，我们可以照抄这个形状，但把 `readImage` 也设为 false。**

---

## 3. 逐条判定

### 3.1 A1 只暴露最少量工具 —— ✅ 可行

**两条路径，都要写代码或写配置，不能靠提示词。**

**(a) 配置级：`dsh-tool-fs` 五个独立开关。**
`dsh-tool-fs/lib/index.js:1967-1989` `apply(ctx, config)` 逐字：

```js
assertPositiveInteger("readLimit", resolved.readLimit);
assertPositiveInteger("readMaxLineLength", resolved.readMaxLineLength);
assertPositiveInteger("readMaxBytes", resolved.readMaxBytes);
assertPositiveInteger("readStreamMinSize", resolved.readStreamMinSize);
if (resolved.read) applyReadTool(ctx, { limit, maxLineLength, maxBytes, streamMinSize });
if (resolved.readImage) ctx.inject(["attachments"], (imageCtx) => { applyReadImageTool(imageCtx); });
if (resolved.write || resolved.edit || resolved.applyPatch) {
  const sandbox = new FsSandboxController(ctx);
  if (resolved.write) applyWriteTool(ctx, sandbox);
  if (resolved.edit) applyEditTool(ctx, sandbox);
  if (resolved.applyPatch) applyApplyPatchTool(ctx, sandbox);
}
```

README 原文：「All keys are optional. The `read`, `readImage`, `write`, and `edit` switches default to `true`;
set a switch to `false` to omit that tool and its guidance. ... All five tools may be disabled.」

→ 我们需要的组合是 `{ read: false, readImage: false, write: false, edit: false, applyPatch: false }`，
**一行 yml 就能做到**，这是整个方案里最便宜的一步。

**(b) 运行期：`agent.ctx.tools.restrict({ allow | deny })`。**
`dsh-tools/lib/index.js:453-467`：

- `:455` 无 scope 直接抛：「tools.restrict() requires a scoped context (agent.ctx): a context-global restriction would mask every agent」
- `:458` 空 filter 直接抛：「tools.restrict({}) is a no-op」
- `:463` **不能命名 `run_code`**（PTC 传输名是保留字，只能 restrict 底层工具）
- `:464-466` 未知工具名抛错并列出全部已知名（→ **组合变化会让插件启动失败**，见 P1-4）
- `:467` 返回 disposer，「restriction lifts when disposed」

README 原文：「applies an allow or deny mask to the global tools one agent inherits; masks intersect, scoped registrations stay visible」
+「restrictions that hide tools remove their entire schema cost for that agent」+「Registration, disposal, or scoped restriction may invalidate reuse from the first changed schema token.」

→ **`restrict` 是 A1 的兜底手段**：就算某个包硬要注册 `grep`，也能在 agent scope 里 deny 掉。

**(c) 自建工具的写法已验证可行。**
`dsh-tool-present/lib/index.js:19+` 与 `E:\Code\dsh_home\.agent-presets\liangshen\tool-activate.mjs`（176 行）是两份可直接抄的完整样例：
`defineTool({ name, description, parameters, output: { schema, render }, execute(args, exec) })` + `ctx.tools.register(...)`，
`when({ agent, modelSelection, signal })` 返回 false 时**连 schema 都不发**。

yml 里挂本地 JS 插件的写法（`liangshen/agent.cordis.yml:161-177` 实测）：
```yaml
- id: minimal-prompt
  name: ./minimal-prompt.mjs
  config: { ... }
```
→ 不需要发 npm 包，`name: ./xxx.mjs` 相对路径即可。

### 3.2 A2 工具级钉死脱敏 —— ⚠️ 只能钉住一半

`tools/post-execute` 的确切能力（`pipeline.js:662-701`）：

| 能做什么 | 源码 |
|---|---|
| 替换成功结果的 `content` | `:696-700` `{...result, ...decision.content !== void 0 ? { content: decision.content } : {}}` |
| 替换成功结果的 `value`（触发重新渲染） | `:686-695` `createSuccessResult(exec, tool, decision.value)` |
| 把结果转成 `isError` + 反馈文本（block） | `:675-683` |
| **同时给 content 和 value** | ❌ `:684` `throw new TypeError("...cannot replace both value and content")` |
| **替换 `isError` 结果的 value** | ❌ `:687` `if (result.isError) throw new TypeError("tools/post-execute cannot replace the value of a failed result")` |
| **替换 `isError` 结果的 content** | ❌ `:744-746` `if (result.isError) return this.markCanonical(exec, { isError: true, error: result.error })` 原样返回 |

**→ 全是成功结果的能力，错误结果完全透明。**

**这条漏路的现实触发面有多大？** `dsh-fs-local/lib/index.js` 里一共 **57 处 `new FsError(`**，其中 **39 处**把路径拼进 message：

```
:193  cannot resolve "${displayPath}": a parent path segment is not a directory
:202  cannot resolve "${displayPath}": parent traversal crosses a missing directory
:283  cannot list "${displayPath}": permission denied
:284  cannot list "${displayPath}": ${errorMessage(error)}
:309  cannot list "${target.displayPath}": not found
:310  cannot list "${target.displayPath}": not a directory
:343  cannot ${verb} "${displayPath}": invalid UTF-8 text
:371  cannot ${verb} "${target.displayPath}": not found
:373  cannot ${verb} "${target.displayPath}": not a regular file
:387  cannot read "${target.displayPath}": binary file
:403  cannot read "${target.displayPath}": ${info.size} bytes exceeds the ${maxBytes}-byte limit
:414  cannot read "${target.displayPath}": content exceeds the ${maxBytes}-byte limit
:473  cannot read "${target.displayPath}": binary file        （第二条二进制判定路径）
:502  cannot write "${displayPath}": ${errorMessage(metadataError)}
:505  cannot write "${displayPath}": not a regular file
:506  cannot overwrite existing "${displayPath}" without reading it first
:508  cannot overwrite existing "${displayPath}" without reading it first
:509  cannot write "${displayPath}": ${errorMessage(error)}
:514  cannot write "${path}": permission denied
:515  cannot write "${path}": ${errorMessage(error)}
```

另外 18 处不含路径（`:129 :143 :184 :419 :451 :484 :493 :601 :743 :834 :836 :856 :858 :867 :868 :870 :970 :985`），
例如 `:184`「file_path must be a non-empty string」、`:419`「read aborted」、`:493`「temp cleanup failed …」。
→ **39/57 ≈ 68% 的 fs 错误是带路径的**，不是「个别例外」。

文件名里带真实姓名的场景（`张三-劳动合同-2026.docx`、`李四诊断报告.pdf`）在国内办公环境**是常态而非例外**。
模型调 `read_redacted("张三-劳动合同.docx")` → 文件不存在/是二进制/超限 → 错误文本原样进上下文 → **脱敏形同虚设**。

**缓解路径（三条，按成本排）**：
1. **在自建工具内部 catch 所有 fs 异常，把路径从 message 里抹掉再抛出**——因为自建工具的 `execute` 抛出的 Error 是我们自己构造的。
   这条最便宜，且**必须做**。
2. 对 `restrict` 掉的工具不必管（根本没注册）。
3. 对必须保留的第三方工具（`present`、`job_output` 等），靠 `pii-guard` 的 post-execute 兜；但它们的 isError 兜不住，
   只好在 `pii-guard` 里加一条**「非 SHELL_GUARDED 的 isError 一律 block 成通用文本」**的开关——这是可选的强策略，
   代价是模型拿不到真实报错、排障变难。

### 3.3 A3 工具级钉死还原 —— ✅ 可行，已有生产范式

`plugins/dsh-pii-guard/lib/index.js:619-622` 的注释原文（这就是答案）：

> 「读侧已把模型手里的文本变成占位符；写入时若不还原，`⟦PII:...⟧` 会被写进用户文件。
> 官方范式（`@deepseek-ai/dsh-experimental-liveshare/lib/index.js:7603-7617`）：
> `ctx.on("agent/created")` → `agent.ctx.tools.register({...deployment, execute})` → `agent.ctx.effect(() => dispose)`。
> **nearer registration shadows global**。tool/call 落盘的仍是模型给出的占位符版参数；还原只发生在宿主进程内。」

实现骨架：
```js
ctx.on("agent/created", ({ agent }) => {
  const actx = agent?.ctx;
  for (const toolName of WRITE_TOOLS) {
    const original = ctx.tools?.get?.(toolName);   // ← 用全局 ctx 取原始定义，避免取到自己的 wrapper
    disposers.push(actx.tools.register({
      ...original,
      execute: async (args, exec) => {
        const { args: safeArgs, failed } = await restoreArgs(args, restoreFn);
        if (failed.length) throw new Error(`[pii-guard] placeholder restore failed: ${failed.join("; ")}`);
        return original.execute(safeArgs, exec);
      },
    }));
  }
  actx.effect(() => { for (const d of disposers) d(); });
}, { global: true });
```

**三个已踩过的坑（文档化，别重踩）**：
- `:583` 必须用**全局** `ctx.tools.get()` 取原始定义，用 `actx` 会取到自己注册的 wrapper → 无限递归。
- `:609` `restoreArgs` 失败时必须 **throw**（fail-closed），不能静默传原参数（那样会把占位符写进用户文件）。
- **tool/call 落盘的是占位符版参数**（注释原文）→ 审计日志里看不到真实写入内容（见 P1-9）。

### 3.4 A4 强语言约束禁止 bash 读文件 —— ❌ 不可作为安全边界

三重证据，全部是项目内或官方文档的原文：

**(a) Windows 沙箱不管读。**
`dsh-sandbox-windows-acl/README.md` Summary 原文：
> 「On Windows, this package confines child-process **writes and deletes** to the workspace and a private temporary directory...」
> 「Choose a different mechanism when the child must also be **read-confined or network-restricted**: `WRITE_RESTRICTED` intersects write accesses only, so pair this backend with a read-side policy or an AppContainer capability token for stronger confinement.」

`dsh-pwsh-sandbox/README.md` Known Limitations 第一条原文：
> 「**Reads are unrestricted on Windows** — the ACL runner restricts writes only」

`dsh-bash-sandbox/README.md` 原文：
> 「The modes govern file effects only — **network stays unrestricted** and process visibility is backend-specific.」

→ 沙箱三层文档一致：**没有任何一层承诺读隔离**。想靠 `mode: read-only` 挡住 `Get-Content` 是无效的。

**(b) 本仓库自己已经否定过白名单。**
`docs/DECISION-shell-redaction.md` §0.2 原文：
> 「推荐默认全量拦截 `pwsh` 的模型可见文本（stdout + `[stderr]` 段 + 状态标记），而不是"只认读文件命令"的白名单
> —— 白名单只能算弱化版，**命令拼接/别名/`& {}` 很容易绕过，安全收益低**。」

这段话是上一次决策留下的，针对的正是「用规则判断哪些命令算读文件」。用户现在提的「强语言约束」是同一个思路的更进一步弱化版（从正则判断退化成自然语言要求），
**结论只会更差**。

**(c) prompt 级约束的失效模式是已知的**：长上下文漂移、模型为完成任务自利推理（「我需要看这个文件才能修 bug」）、
外部内容注入（读到的网页/文档里写「忽略之前的指令」）。
而且现有工程里**没有任何「模型读了文件」的审计**：`dsh-pwsh-local` 只把 stdout/stderr 拼成文本，不解析命令语义；
`plugins/dsh-pii-guard/lib/index.js:443-456` 的 `shell_bypass` 只记 `{ts, iso, event, tool, reason, cmd_sha1, bytes}`（**命令只存 sha1 前 8 位，不存原文**），
`shellBypassReason`（`:466-474`）只有两个来源：`isShellDisabled()` → `"env"`、allowlist 正则命中 → `"allowlist"`。
**它记录的是「这次要不要脱敏」，不是「模型读了什么」**。所以连「事后发现有人违规」的能力都没有。

**→ 结论：A4 不能写进验收契约。要么实现成「无 shell」，要么在 README 里明写「有 shell 就有读取能力」。**

### 3.5 A5 md 中转 + write_docx 按模板还原 —— ⚠️ 需求内部矛盾

**先说能力边界（本机实测 + 官方 SKILL 原文）**：

| 能力 | 状态 | 证据 |
|---|---|---|
| `python-docx` | ✅ 1.2.0 可用 | 本机 `python -c "import docx"` |
| `openpyxl` | ✅ 可用 | 同上 |
| `docxtpl`（模板填充） | ❌ **ImportError** | 本机实测 |
| DSH 原生 `write_docx` 工具 | ❌ 不存在 | 只有 `dsh-skill-office` 的 6 个技能，走 `python-docx` + shell |
| 分页/渲染 | ❌ 不支持 | `office-docx/SKILL.md` 原文「**python-docx does not paginate or render documents.**」 |

`dsh-skill-office/README.md` 原文：「Authoring instructions do not resolve renderer paths; loading operation instructions validates existing interpreter and CLI files without preparing engines. **Bash or PowerShell owns approvals, sandboxing, cancellation, and output management.**」
→ 官方设计就是「skill 教怎么写脚本 + shell 执行」，**没有 `write_docx` 这种原生工具**。要 `write_docx` 只能自建。

**再说那个矛盾**——「md 中转」和「按模板还原」是互斥的：

`presidio_pii/documents.py:295-302` 当前实现：
```python
def _set_docx_paragraph(p, text: str) -> None:
    """最小实现: 重写首个 run, 其余 run 清空 (丢失段内混合格式)。"""
    if p.runs:
        p.runs[0].text = text
        for r in p.runs[1:]:
            r.text = ""
    else:
        p.add_run(text)
```
`office-docx/SKILL.md` 原文：「**Update the relevant runs; assigning paragraph `.text` destroys run formatting.**」

→ 现状（保留原 docx、只换文本单元）**已经会丢段内混合格式**。如果再加一层 `docx → md → docx`，
丢的就不止是 run 级样式，还有：批注（comments.xml）、修订（revisions）、内容控件、域代码、SmartArt、
图片锚定、页眉页脚的分节继承、表格合并单元格语义、公式（OMML）。

`documents.py:321-347` 的 `_docx_units` 已经在尽力捞（段落 / 表格递归 / 页眉页脚 / 文本框 `w:txbxContent` / 批注部件），
说明维护者知道「docx 不是纯文本容器」。

**所以必须由产品拍板二选一**：
- **路线 α「保原文样式」**：不做 md 中转。读 docx → 抽文本单元 → 脱敏 → **写回原 docx 的同一单元**（= 现有 `read_units`/`write_units` 路径）。样式 100% 保留，但模型看到的是脱敏后的纯文本，不能重排结构。
- **路线 β「套模板」**：模型写 md → 用模板的样式定义生成新 docx（模板里的占位符替换或样式继承）。可以重排结构、可以用模板统一版式，**但原文档的文字级样式全部丢失**。

**这两条不能同时要。** 用户说「参照事先给的模板还原」= 路线 β；但同时说「还原 docx」= 路线 α 的语义。报告按 β 设计（因为 α 已经有实现，不需要研究），并在 §7 列为待拍板项。

---

## 4. 六条硬否定（红队自攻击结果）

以下是「表面上能做，实际做不到」的五处。每一条都对着一条具体的源码路径。

### 4.1 硬否定一：isError 通道不可脱敏

见 §3.2。`pipeline.js:687` + `:744-746` + fs 层 57 处错误里 39 处带路径。
**后果**：文件名即 PII 时必然泄漏。**缓解**：自建工具内部 catch + 抹路径（必做），第三方工具加「isError 全 block」强策略（可选）。

### 4.2 硬否定二：PTC `run_code` 下 post-execute 对程序无效

`dsh-tool-executor-ptc/lib/index.js:512-521` 逐字：
```js
const outcome = await new Promise((resolve, reject) => {
  let parked;
  const settle = (result) => {
    resolve(result.isError ? { isError: true, message: result.error.message }
                          : { isError: false, value: result.value });   // ← 给程序的是 value
```
`dsh-tools/README.md` Known Limitations 原文：
> 「**Canonical values belong to execution**… Replacing or redacting that content does not remove the canonical value available to a programmatic caller; **a policy that must deny that access must block execution or replace the value**.」

**后果**：一旦启用 PTC，`dsh-pii-guard` 的 post-execute 只改了 `content`（= UI 与 Session 里看着脱敏了），
而程序内 `await tools.read(...)` 拿到的是**原文**，模型可以 `console.log` 出来或再拼进 `write`。
**这是最危险的一条，因为它是静默的**——现有测试、现有门禁、现有 UI 全部正常，看起来一切安好。

**当前状态**：`presidio-pii` 预设挂了 `workflow-ptc`（`:188-189`）但**没有挂** `dsh-tool-executor-ptc`（grep `ptc` 只命中 workflow 行），
所以现在是 native 执行器，暂时安全。**但这是一颗定时炸弹**——任何人为了用 `run_code` 加一行就会踩。

**缓解**：在预设 yml 里加注释锁死（「本预设禁止挂 `dsh-tool-executor-ptc`，理由见 docs/RESEARCH-minimal-tool-surface.md §4.2」），
并把这条写进门禁（`tools/release_gate.py` 加一条断言：预设 yml 里不得出现 `dsh-tool-executor-ptc`）。

### 4.3 硬否定三：读通道不止 read 一个

| 通道 | 是否读原文 | 关掉的方式 |
|---|---|---|
| `read` | ✅ | `tool-fs` `read: false` |
| `grep` | ✅ 返回 `Line N: <preview>` | **整包不写 `tool-fs-search`**（无单工具开关）；Web 面已在 `dsh-web-app/cordis.patch.yml:509-510` 把它 host 侧 disabled，所以预设不写就真的没有 |
| `glob` | ⚠️ 只返回路径（路径本身可能含 PII） | 同上 |
| `spill` 文件 | ✅ **就是原文** | 无法关；`retrievalHint` 还主动教模型去读（原文：「Use read with offset/limit, or grep this path to search within it.」） |
| session JSONL | ✅ **明文落盘** | `compression: zstd` 只是压缩，不是加密 |
| `web_fetch` | ❌ 已堵死（只允许 http/https） | — |
| `bash`/`pwsh` | ✅ | **只能不挂** |

`dsh-tool-fs-search/README.md` 原文：「Routine budgets stay out of the model-facing schema: a model that needs surrounding context reads the matched file with `read`」
→ 这句话反过来就是：**`grep` 本身就是读取工具**，它自己就能吐出匹配行内容（`grepMaxLineBytes: 2000`）。

**后果**：只关 `read` 而留 `grep` = 掩耳盗铃。`DECISION-shell-redaction.md` §0.5 已承认「溢出文件（spill）内容为原文，只能靠 read 通道守卫」，
而现在 read 通道被我们关掉了，spill 就成了裸奔的原文。

**缓解**：`tool-fs-search` 整包不写进预设即可（Web 面 host 侧已 disabled，见 §2.1.1）；再自建 `grep_redacted`（返回前跑脱敏）+ spill 路径在自建工具里抹掉。**注意 `spill-local` / `spill-policy` 属 host 平面，预设删不掉**（§2.1.1 推论 2）。

### 4.4 硬否定四：用户粘贴的文本在工具级守卫之外

`plugins/dsh-pii-guard/lib/index.js:661-663` 注释原文：
> 「不改 decision.messages：该机制与 session log / KV cache 脱节，只做可观测告警」

代码只做计数告警：`console.error("[pii-guard] pre-step WARN: ... (not redacted; user-pasted text is outside the tool-result guard)")`。

**后果**：工具级方案只覆盖「工具结果 → 模型」这条边，**覆盖不了「用户 → 模型」这条边**。
用户把身份证号贴进对话框，agent 照样进 LLM 上下文。而这条边恰恰是最常见的 PII 入口。

**缓解**：这条只能靠 `agent/pre-step` 改写（现有实现故意不改，理由是与 session log / KV cache 脱节）。
真正的解法是**在 Web 客户端提交前脱敏**（客户端侧），或者在 `agent/pre-step` 做改写并接受 KV cache 全失效的代价。
**无论哪种，都超出「工具级钉死」的范围**，必须在报告里说清楚。

### 4.5 硬否定五：占位符是可被模型伪造的字符串

`presidio_pii/engine.py:243`：
```python
ph = f"{PH_OPEN}PII:{ptype}:{counters[ptype]:04d}{PH_CLOSE}"   # ⟦PII:PERSON:0001⟧
```
`restore()`（`engine.py:266-294`）只扫文本中**出现**的占位符。

→ 模型可以手写 `⟦PII:PERSON:0001⟧`（它从上下文里见过这个字符串）。`restore` 会把它替换成对应的真实姓名。

**这是泄露吗？** 严格说不是——模型从没见过原文，它没法凭空造出它不知道的信息。
**但这是语义错位**：模型可以把占位符挪到不该出现的位置，导致「张伟的身份证号」被写进「李四」那一行。
在自动生成的合同/报表里，这比漏脱敏更隐蔽——数字都对得上，只是张冠李戴。

**缓解**：
- 写入路径的还原继续做（必须做，否则占位符进用户文件）；
- 但**还原后要做一次校验**：占位符的出现位置是否与读侧一致（同一文档内位置一致才放行）。
  代价是这套机制要维护「占位符 ↔ 位置」的对应关系，而现有 `Counter` 是按 entity_type 全局递增的
  （`counters[ptype] += 1`，跨文档共享），**做不到文档内隔离**。这是设计级改动，列为 Phase 3。

### 4.6 硬否定六：spill 会把原文写进磁盘，而且两个 prepend 监听器的顺序不稳定

`dsh-spill-policy/lib/index.js:237-255`（`{ prepend: true }`）：
```js
ctx.on("tools/post-execute", async (exec, result, next) => {
  const decision = await next();
  if (decision.kind !== "accept" || Object.hasOwn(decision, "value") || exec.name === "read") return decision;
  const content = decision.content ?? result.content;
  ...
  const retained = await bound(exec, content, exec.name, exec.callId, ...);
  return { kind: "accept", content: retained, ... };
}, { prepend: true });
```

**三个问题叠在一起**：

1. **`:239` 的 `exec.name === "read"` 是名字级豁免** —— `read` 的巨大结果永不被 spill。而 Phase 1 正好把 `read` 换成自建 `read_redacted`（名字不同）→ **自建工具的大结果会被 spill 成原文文件**。要么自建工具自己限长（推荐），要么改名蹭豁免（不推荐，语义欺骗）。
2. **spill 通知直接教模型去读原文**（`dsh-spill-policy/README.md` 原文）：
   > `(Omitted N bytes. Full formatted result stored at: /…/session-…/…-web_fetch.txt. Use read with offset/limit, or grep this path to search within it.)`
3. **两者都 `{ prepend: true }`，谁在外层由注册顺序决定**。`cordis/lib/index.js:919-929` `const method = options.prepend ? "unshift" : "push";` —— 后注册的 unshift 到最前、成为最外层。
   - 若 **spill-policy 在外层**：它拿到的是 pii-guard 已经脱敏过的 content → spill 到磁盘的是**占位符版**（安全）。
   - 若 **pii-guard 在外层**：spill-policy 先把**原文**写盘，pii-guard 再脱敏 content → **磁盘上是原文，模型手里是占位符**（最坏的组合：看起来安全，实际落盘泄露）。

**后果**：这不只是「顺序可能不对」，而是**没有任何代码或测试在保证这个顺序**。
`pii-guard` 的注释（`plugins/dsh-pii-guard/lib/index.js:481`，对应注册在 `:615`）写「prepend: 最外层，先于其它 post-execute 监听器取到最终 content」，
但 `spill-policy` 也是 prepend，两者的相对顺序取决于插件加载次序（yml 里谁在前）。

**缓解（Phase 1 必做）**：
- 自建工具**自己限长**，让结果永远落在 `spill-policy` 的 `maxInlineTokens`（默认 12500）以内 → 从源头不产生 spill 文件；
- 加一条**门禁断言**：在真实会话里构造一个超长结果，断言磁盘 `spill` 目录里出现的是占位符而不是原文；
- 若必须用 spill，把 `spill-policy` 在 yml 里排在 `pii-guard` **之前**，让 pii-guard 成为外层（但这是隐式契约，必须写注释 + 门禁锁定）。

---

## 5. 潜在问题清单

分级标准：**P0** = 不解决就是「假安全」（用户以为安全实际不安全）；**P1** = 功能不完整或体验受损；**P2** = 打磨项。

### P0（7 条）

| ID | 问题 | 证据 | 缓解 |
|---|---|---|---|
| P0-1 | 「禁止 bash 读文件」不可实现，沙箱层不承诺读隔离 | `dsh-sandbox-windows-acl/README.md`、`dsh-pwsh-sandbox/README.md`、`dsh-bash-sandbox/README.md` 三层一致 | **删除 bash**（Phase 1）或用 AppContainer 级改造（成本极高） |
| P0-2 | 本仓库已论证「白名单/约束判断」安全收益低，用户方案是它的更弱版本 | `docs/DECISION-shell-redaction.md` §0.2 原文 | 明确告知，不写进契约 |
| P0-3 | `isError` 结果不可脱敏，而 fs 层 **57 处错误中 39 处**内嵌 `displayPath` | `pipeline.js:687`、`:744-746`；`dsh-fs-local/lib/index.js` 的 39 处完整行号见 §8 | 自建工具内部 catch + 抹路径（必做）；第三方工具可选强 block |
| P0-4 | PTC `run_code` 给程序的是 canonical value，post-execute 对程序无效 | `tool-executor-ptc/lib/index.js:514-521`；`dsh-tools/README.md` canonical value 限制 | 预设禁止挂 `dsh-tool-executor-ptc`，并加门禁断言 |
| P0-5 | 读通道多元：`grep` / `spill` / session JSONL 全是原文 | `tool-fs-search/README.md`、`spill-local/README.md`、`session-persistence-jsonl/README.md`（`compression: none` 明文） | **分两类**：`grep` 属 agent 平面（web-app 层 `:509` 已 disabled），预设里**不写就没了**；`spill-local`/`spill-policy`/`session-persistence-jsonl` 属 host 平面，预设管不到，只能改 `$DSH_HOME/cordis.patch.yml` 或接受（见 §2.1.1） |
| P0-6 | 用户粘贴文本在工具级守卫之外 | `plugins/dsh-pii-guard/lib/index.js:661-677` 注释原文「不改 decision.messages：该机制与 session log / KV cache 脱节，只做可观测告警」 | 文档明写此缺口；客户端侧脱敏（超出本方案范围） |
| P0-7 | **spill 落盘原文 + 两个 prepend 监听器的相对顺序无保证**：`spill-policy` 与 `pii-guard` 都 `{ prepend: true }`，谁在外层由注册顺序决定；若 pii-guard 在外层，spill-policy 会先把**原文**写盘再被脱敏 | `dsh-spill-policy/lib/index.js:237-255`（`:239` 的 `exec.name === "read"` 姓名级豁免）、`cordis/lib/index.js:919-929`（`unshift`）、`dsh-spill-policy/README.md` 的 spill 通知原文 | 自建工具**自己限长**（不产生 spill）；加门禁：构造超长结果后断言 spill 目录里是占位符不是原文；yml 里把 `spill-policy` 排在 `pii-guard` 之前（见 §4.6） |

### P1（11 条）

| ID | 问题 | 证据 | 缓解 |
|---|---|---|---|
| P1-1 | `restrict` 是运行期 API，不能配在 yml 里 | `dsh-tools/lib/index.js:453-467` | 写一个 JS 插件在 `agent/created` 时 restrict |
| P1-2 | `restrict` 命名未知工具直接抛错，组合一变插件启动失败 | `:464-466` | 包一层 try/catch + 白名单校验已知名 |
| P1-3 | `restrict` 不能命名 `run_code`（保留传输名） | `:463` | 只能 restrict 底层工具 |
| P1-4 | `restrict` 变更会 invalidate KV cache | `dsh-tools/README.md` 原文 | 尽量在预设期一次性定好，别在会话中途改 |
| P1-5 | `tool-fs-search` 无单工具开关（只能整包取舍）；好在其行在 web-app 层已被 disabled，预设不写即无 grep | `tool-fs-search/README.md` 配置表只有 `sampleOverCapGlobResults` 等；`dsh-web-app/cordis.patch.yml:509-510` | 预设里**不写** `tool-fs-search` 即可；如需 grep 能力，自建 `grep_redacted` 走脱敏通道 |
| P1-6 | `spill` 的 `retrievalHint` 主动教模型去读原文 | `spill-local/README.md` 原文 | 自建工具里抹掉 locator / hint |
| P1-7 | 会话 JSONL 明文（默认 zstd 也非加密） | `session-persistence-jsonl/README.md` | 文档明写；或改 `compression: none` + 存到受限目录（但 shell 仍可读） |
| P1-8 | `failOpen` 开关存在，极简模式若打开就变成「无保护工具面」 | `plugins/dsh-pii-guard/lib/index.js:93`（读 env）、`:128`（`isFailOpen`）、`:603`（`failOpen=true → passthrough (TROUBLESHOOTING ONLY)`） | 极简预设里**禁止** `PII_GUARD_FAIL_OPEN=1`，加门禁断言 |
| P1-9 | 写入侧 tool/call 落盘的是占位符版参数 → 审计看不出真实写入内容 | `plugins/dsh-pii-guard/lib/index.js:618-659` 注释原文 | 增加「写入时把 ph→type 记录下来」的审计事件，只记类型不记原文 |
| P1-10 | 占位符编号跨文档共享（`counters` 全局递增），跨文档同号可能撞 | `engine.py:243` | 批量处理时必须 `commit=False` 后整批 commit（已有约定），或改为文档内计数 |
| P1-11 | docx `md` 中转丢段内格式，与「按模板还原」冲突 | `documents.py:295-302` 注释、`office-docx/SKILL.md` 原文 | 产品拍板路线 α / β（§7） |

### P2（8 条）

| ID | 问题 | 证据 | 缓解 |
|---|---|---|---|
| P2-1 | `docxtpl` 本机不可用，模板占位符填充需自研 | 本机 ImportError | 自研（用 `python-docx` 遍历 + run 级替换）或加依赖 |
| P2-2 | 中日韩文字需显式 `w:eastAsia` 字体，否则中文字体可能回退 | `office-docx/SKILL.md` 原文 | 生成器里统一设 eastAsia |
| P2-3 | python-docx 不分页不渲染，页数/目录无法预知 | `office-docx/SKILL.md` 原文 | 明写限制；需要渲染时走 `office-render` |
| P2-4 | md 中转丢批注/修订/内容控件/域代码/公式 | `documents.py:321-347` 已在捞 textbox/comments，说明这些是真实格式 | 路线 β 时明写「不保留」 |
| P2-5 | 自建工具的正则无超时，用户自定义规则可 ReDoS | 参考 Presidio `REGEX_TIMEOUT_SECONDS` 默认 60s 且有超时只 warn | 加超时 + 指标 |
| P2-6 | `restrict` deny 掉 `read_image` 会导致附件图无法看（现有 pii-guard 已这么做） | `pii-guard/lib/index.js` 注释「图片内文字无法脱敏，直接在 PII 预设内隐藏该工具」 | 保持现状，文档明写 |
| P2-7 | `present` 工具暴露源文件路径（可能含 PII） | `office-docx/SKILL.md`「It exposes the current source file without copying or preserving its bytes」 | 文件名在写入前就应改成占位符名 |
| P2-8 | 持久 shell 的 description 里写着「You don't have access to the internet via this tool.」这类误导性文案 | `sdk-minimal/cordis.patch.yml:166` | 自建工具描述要写准确 |

**统计：P0 = 7，P1 = 11，P2 = 8，合计 26 条。**

---

## 6. 三阶段落地方案

### Phase 1（1–2 天）：「删掉 bash」版最小 PII 预设

**核心动作是删除，不是建设。** 目标工具面**只有 5 个**：

| 工具 | 作用 | 实现 |
|---|---|---|
| `read_redacted(file_path, offset?, limit?)` | 读文件 → 脱敏 → 返回占位符版文本 | 自建：`ctx.fs.resolve` + `ctx.fs.readText` + `engine.redact` |
| `write_raw(file_path, content)` | 把占位符版内容还原成原文写入 | 自建：`engine.restore` + `ctx.fs.resolve` + `ctx.fs.writeText` |
| `restore(text)` | 把模型手里的占位符文本还原（给用户看/贴出去） | 自建：`engine.restore` |
| `ls(path)` | 列目录（**只返回脱敏后的文件名**） | 自建：`ctx.fs.resolve` + `ctx.fs.listDir` + 文件名脱敏 |
| `present(files)` | 交付文件给用户 | 复用现有 |

`ctx.fs` 的方法名已在类型定义里逐个核实（`dsh-fs/lib/types/index.d.ts`）：
`resolve(path, opts?)`(:110)｜`stat(target, signal?)`(:154)｜`lstat`(:169)｜`readText(target, signal?)`(:178)｜
`streamText`(:188)｜`readBytes`(:199)｜`readByteRange`(:213)｜**`listDir(target, signal?)`(:224)**（不是 `list`）｜
`writeText(target, content, expected?, signal?, sandboxPolicy?)`(:237)｜`editText`(:251)｜`patchText`(:267)｜`deleteFile`(:282)｜`moveFile`(:301)。
→ **Phase 1 的 API 面已确认可用，无需改 DSH 源码。**

不挂的东西：`tool-fs`（全关）、`tool-fs-search`、`tool-bash`、`tool-pwsh`、`tool-jobs`、`tool-web`、`tool-subagent`、
`workflow-ptc`、`tool-executor-ptc`、`read_image`。

⚠️ **注意「不挂」的写法要分两类**（详见 §2.1.1）：

- **agent 平面**（`tool-fs` / `tool-fs-search` / `tool-bash` / `tool-pwsh` / `tool-jobs` / `tool-web` / `tool-subagent` / `workflow-ptc`）：
  Web 面已把这些行在 host 侧 `disabled: true`（`dsh-web-app/cordis.patch.yml:484-584` 共 22 行）。**预设里不写就没挂**，这是 Phase 1 最省事的一步。
- **host 平面**（`spill-local` / `spill-policy` / `session-persistence-jsonl` / `tool-executor-native`）：
  预设的 `plugins` 数组**管不到**。要动只能在 `$DSH_HOME/cordis.patch.yml`（本机 21763B / 421 行）改，或接受它们存在。
  → Phase 1 的应对是「接受 + 在自建工具里绕开」：自建工具**自己限长**（避免触发 spill），并且不把 spill locator 回给模型。

**Phase 1 的验收契约（6 条硬指标）**：
1. 会话里**不存在** `bash`/`pwsh`/`read`/`write`/`edit`/`grep`/`glob` 任一工具名（用 `restrict` allow 白名单 + 断言）。
2. `read_redacted` 对 12 份合成文档（`testdata_v2/`）的召回率与现有 `check_read` 持平（PERSON/ID/PHONE/BANK_CARD 全中）。
3. **错误路径不含路径**：构造 5 种错误（不存在/二进制/超限/无权限/非文件），断言返回文本里不含输入路径的任何子串。
4. `write_raw` 写入后 roundtrip 无损：原文 → `read_redacted` → `write_raw` → 与原文件逐字节相同。
5. 预设 yml 里 grep 不到 `dsh-tool-executor-ptc`、`PII_GUARD_FAIL_OPEN`。
6. 沙箱 `mode` 显式设为 `read-only` 或 `workspace-write`（不是为了防读，是为了防写错地方）。

**Phase 1 明确不做的事**：不承诺防读（因为没 shell，攻击面已经消失）；不处理用户粘贴；不处理 docx 结构重排。

**为什么 Phase 1 是「删掉 bash」而不是「用语言约束管住 bash」**：
按 `DECISION-shell-redaction.md` §0.2 的逻辑，管住 bash 的收益低于成本；而**没有 bash 时，这个成本直接归零**。
用户设想的「用强语言约束」是把自己锁在「必须留 shell」的前提里再想办法——先去质疑这个前提。

### Phase 2（3–5 天）：格式能力补齐

- `read_docx` / `write_docx(template?)`：走 `presidio_pii/documents.py` 的 `read_units`/`write_units`（**路线 α，保原样式**），
  不引入 md 中转。文件读写用 `python-docx`，通过自建工具内部起 Python 子进程（可复用 `presidio_pii/server.py` 的 stdio 协议，扩 `op: "docx_read"` / `"docx_write"`）。
- `grep_redacted(pattern, path?)`：用 Python 的 `re` 扫文件，返回前脱敏。**必须自带超时**（P2-5）。
- 模板能力（可选）：`write_docx(template="xxx.docx", data={...})` 走 `python-docx` 遍历 + run 级替换（`docxtpl` 不可用，见 P2-1）。

### Phase 3（待定）：「位置一致性校验」

解决 §4.5 的占位符挪位问题。需要把 `engine.py:243` 的全局计数器改成**文档内计数器**，
并在还原时校验「占位符 ↔ 原位置」。这是设计级改动，需要单独评估对现有 155 条真值回归的影响。

---

## 7. 待拍板的 6 个决策

| # | 决策 | 选项 | 建议 |
|---|---|---|---|
| D1 | shell 留不留 | (a) 删掉（Phase 1）(b) 留但接受「不承诺防读」 | **(a)**。删掉之后 P0-1/P0-2 自动消解 |
| D2 | docx 还原走哪条路 | (a) 路线 α 保原样式（无 md 中转）(b) 路线 β 套模板（有 md 中转） | **(a)** 先做；(b) 作为可选能力 |
| D3 | 第三方工具的 isError 要不要一律 block | (a) 一律 block（安全优先，排障变难）(b) 保持透传（排障优先，路径会漏） | **(a)**，但给 `PII_GUARD_STRICT_ISERROR=0` 逃生开关 |
| D4 | 用户粘贴文本怎么办 | (a) 承认不管（文档明写）(b) 客户端侧脱敏（工作量大） | **(a)** 先承认，(b) 单独立项 |
| D5 | 线上/离线 NER 是否纳入 | (a) 不纳入，纯规则 (b) Phase 3 再评估 | **(a)**，与 `ROADMAP.md` §5 决策门槛一致 |
| D6 | 规则库（上一份报告）与本次工具面改造的先后 | (a) 工具面先（本报告 Phase 1）(b) 规则库先 | **(a)**。工具面是安全边界，规则库是召回率；边界先立 |

---

## 8. 参考资料（全是可核对的源码位置）

**dsh 0.2.2-rc.1 安装目录**：`C:\Users\sergg\AppData\Roaming\npm\node_modules\@deepseek-ai\dsh\node_modules\@deepseek-ai\`

| 主题 | 位置 |
|---|---|
| 极简模式完整组合 | `dsh-sdk-minimal/cordis.patch.yml`（179 行，:1-3 注释、:44-50 tool-fs、:82-93 终端、:144-170 持久 shell、:172-176 会话明文） |
| **公共底座（关键）** | `dsh-base/cordis.patch.yml`（20962B）：`:138-139` session-persistence-jsonl、`:296-297` tool-fs、`:302-303` tool-fs-search、`:411-412` spill-local、`:414-415` spill-policy、`:501-502` tool-executor-native、`:504-506` tool-executor-ptc（`disabled: true`）、`:292-294` fs-observation-policy（`disabled: true`） |
| **Web 面腾空 agent 平面（决定性）** | `dsh-web-app/cordis.patch.yml`（22879B）：`:467-476` 注释「the agent plane moves behind agent presets … the Web surface disables them here」；`:484-584` 共 22 行 `disabled: true`（tool-plugin-manager/tool-bash/tool-pwsh/tool-jobs/tool-fs/tool-fs-search/skill-filesystem/tool-skill/command-goal/tool-goal/plan-mode/compaction-basic/command-compact/tool-result-pruner/tool-subagent-control/tool-subagent/tool-subagent-fork/workflow-ptc/tool-workflow/agent-instructions/tool-todo/tool-web） |
| **preset 的能力边界** | `dsh-agent-preset/lib/index.js`（898B 全文）：`Config = z.object({ id, name, description, order, plugins })`，只是「一组 child plugin entry」，无 `disabled` 语义、不拥有 host 平面 |
| 覆盖语义 | `dsh-web-app/cordis.patch.yml:1-2` 注释「Applied after dsh-base's insert; rows here override base rows by id」；`$DSH_HOME/cordis.patch.yml`（本机 21763B / 421 行）是 home 层，作用于**所有** profile |
| waterfall 的 prepend 语义 | `cordis/lib/index.js:903-918`（`waterfall` 逐个 `callbacks.shift()`）、`:919-929`（`const method = options.prepend ? "unshift" : "push";`）→ **prepend = 数组最前 = 最外层、最先执行**；两个插件都 prepend 时由注册顺序决定，先注册的在内层 |
| Web 侧四个官方预设 | `dsh-web-app/presets/`：`cordis.patch.yml`(7434B)、`minimal.patch.yml`(3724B)、`ptc.patch.yml`(6963B)、`standard.patch.yml`(6858B)；`minimal.patch.yml:17-23` 给出 `tool-fs { read:false, readImage:true, write:false, edit:false }` 的最小形状 |
| post-execute 精确语义 | `dsh-tools/lib/pipeline.js:662-701`（:673 waterfall、:684 content/value 互斥、:687 isError 不可换 value、:744-746 isError 原样返回） |
| 执行链五段 | `dsh-tools/README.md`「`tools/pre-execute` → guards → `tools/execute` → `tools/post-execute` → `finalizeContent` → `tools/result`」 |
| canonical value 限制 | `dsh-tools/README.md` Known Limitations「Canonical values belong to execution…」 |
| `restrict` API | `dsh-tools/lib/index.js:453-467`（:455 需 scope、:458 空 filter、:463 不能命名 run_code、:464-466 未知名抛错） |
| `tool-fs` 五开关 | `dsh-tool-fs/lib/index.js:1967-1989`；README 配置表 |
| `read` 工具 schema | `dsh-tool-fs/lib/index.js:243-350`（:323 presentationMeta） |
| fs 错误带路径 | `dsh-fs-local/lib/index.js`（48449B）共 **57 处** `new FsError(`，**39 处**把 `displayPath`/`${path}` 拼进 message。带路径的 39 行完整清单：`193,202,205,281,283,284,309,310,343,371,373,387,403,414,473,502,505,506,508,509,514,515,596,618,668,746,747,937,938,939,976,1021,1023,1024,1025,1030,1031,1032,1037`；不含路径的 18 行：`129,143,184,419,451,484,493,601,743,834,836,856,858,867,868,870,970,985` |
| 读通道旁路 | `dsh-tool-fs-search/README.md`；`dsh-spill-local/README.md`（retrievalHint 原文）；`dsh-session-persistence-jsonl/README.md` |
| web_fetch 只允许 http/https | `dsh-web-fetch-http/lib/index.js:30` |
| 沙箱不承诺读隔离 | `dsh-sandbox-windows-acl/README.md`；`dsh-pwsh-sandbox/README.md` Known Limitations；`dsh-bash-sandbox/README.md`；`dsh-sandbox-local/README.md` |
| PTC canonical value 破口 | `dsh-tool-executor-ptc/lib/index.js:512-521`；`dsh-tool-executor-ptc/README.md`「PTC mode」 |
| office/docx 能力边界 | `dsh-skill-office/README.md`；`dsh-skill-office/assets/office-docx/SKILL.md` |
| 自建工具样例 | `dsh-tool-present/lib/index.js:19+`；`E:\Code\dsh_home\.agent-presets\liangshen\tool-activate.mjs`（176 行） |
| `ctx.fs` 方法签名（已核实） | `dsh-fs/lib/types/index.d.ts`：`resolve`(:110)、`stat`(:154)、`lstat`(:169)、`readText`(:178)、`streamText`(:188)、`readBytes`(:199)、`readByteRange`(:213)、`listDir`(:224)、`writeText`(:237)、`editText`(:251)、`patchText`(:267)、`deleteFile`(:282)、`moveFile`(:301)；`dsh-tool-fs/lib/index.js:195-196/341/606-610` 是真实调用样例 |
| yml 挂本地 mjs | `E:\Code\dsh_home\.agent-presets\liangshen\agent.cordis.yml:161-177` |
| 仓库内生产范式 | `plugins/dsh-pii-guard/lib/index.js`（733 行）：`:482-616` post-execute 主体（`:486` SKIP_TOOLS 透传、`:489` 非 shell 的 isError 透传、`:500-506` 下游 value 替换就 block、`:507` 取 source、`:615` `{ prepend: true }`）｜`:618-659` 写入侧 scoped shadow（`:624` `agent/created`、`:630` 用全局 `ctx.tools.get` 取原 definition、`:633-643` 包裹 `execute` 做 `restoreArgs`、`:650` `restrict({ deny: ["read_image"] })`）｜`:661-677` pre-step 只告警（`:677` `{ global: true }`）｜`:679+` 显示侧还原（`:728` `{ prepend: true, global: true }`） |
| 本仓库既有决策 | `docs/DECISION-shell-redaction.md` §0.2 / §0.5 / §1 / §4 / §5 |
| docx 现有实现 | `presidio_pii/documents.py:295-302`（`_set_docx_paragraph`）、`:321-347`（`_docx_units`）、`:564-596`（handler 表） |
| 占位符契约 | `presidio_pii/engine.py:243`（`ph = f"{PH_OPEN}PII:{ptype}:{counters[ptype]:04d}{PH_CLOSE}"`）、`:266-294`（`restore`） |

**外部参考**：
- Presidio `allow_list` 语义（后置过滤）与「recognizers can only add results, not remove those of other recognizers」（issue #2455）
- Elastic detection rules 官方立场：「Tune with exceptions, not by disabling… Disabling the rule means you lose detection coverage entirely」
- OPA bundle 验签失败 fail-safe（不激活新包、继续用旧包）

---

## 9. 与上一份报告的关系

`docs/RESEARCH-rule-libraries.md`（规则库化）回答的是「**识别什么**」；
本报告回答的是「**怎么保证识别结果真的生效、原文真的出不去**」。

两者必须配套，优先级按 D6：**先立工具面边界（本报告 Phase 1），再扩规则库**。
理由是：规则库做错了 → 少识别一个实体（可补救）；工具面做错了 → 原文已经进了 LLM 上下文（不可补救）。
