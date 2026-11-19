# 研究总纲：PII 防护体系（识别层 × 通道层）

> **状态：研究报告，未实施。** 本文只做设计论证与风险盘点，不含代码改动。
> **本文合并了此前三份文档**（原始版本已归档到 `docs/archive/`，仅作历史留存）：
>
> | 原文档 | 主题 | 归档位置 |
> |---|---|---|
> | `RESEARCH-rule-libraries.md` | 识别层：规则库化（可开关 / 可替换） | `docs/archive/RESEARCH-rule-libraries.md` |
> | `RESEARCH-minimal-tool-surface.md` | 通道层：极简工具面 + 工具级钉死 | `docs/archive/RESEARCH-minimal-tool-surface.md` |
> | `ANALYSIS-threat-focus.md` | 问题重排：谁在对抗谁 | `docs/archive/ANALYSIS-threat-focus.md` |
>
> **本文统一了问题编号**：`R-xx`（识别层，42 条）、`T-xx`（通道层，27 条）、`F-xx`（字段真空，7 条）。
> 附录 B 给出旧编号对照表，可直接跳回归档文档查细节。
>
> 相关：`docs/ROADMAP.md`（NER 分档）、`docs/DECISION-shell-redaction.md`（shell 脱敏决策）、
> `docs/PLAN-code-review-followups.md`（S1–S4）、`agent.md` §3（识别器设计约定）。

---

## 0. 一页纸结论

### 0.1 目标与判据

**目标（用户口径）**：防止大模型不受控地获取本地敏感信息字段——内容里的姓名、年龄、职务、身份证号等。

**唯一判据**：一条措施算数，当且仅当它能减少「**模型上下文里出现的字段原文**」。
据此，沙箱能否限制读、路径是否脱敏、插件机制摩擦，都不算数（它们不改变模型看到什么）。

按这把尺子量，防护水位由**两个可量化数字**决定：

| 维度 | 现状 | 含义 |
|---|---|---|
| **字段覆盖面** | **13 / 22**（实测） | 模型能拿到的字段种类，仍有一半没人管 |
| **读通道数** | **4 条直读 + 2 个原文落盘点**（read / grep / shell / MCP + spill / session） | 每条未封的直读通道都等价于「全部字段裸奔」 |

> 这两个数字一动，防护水位就真的动了。其余工作都是在这两个数字之外的边角。

### 0.2 十二条结论

1. **「只暴露最少工具」✅ 可行**，两套官方机制：`tool-fs` 五开关（`dsh-tool-fs/lib/index.js:1967-1989`）+ `agent.ctx.tools.restrict`（`dsh-tools/lib/index.js:453-467`）。
2. **「工具级钉死还原」✅ 可行，已有生产范式**：`plugins/dsh-pii-guard/lib/index.js:618-659` 的 scoped shadow（`agent/created` → 包住 `execute` → `restoreArgs`）。
3. **「工具级钉死脱敏」⚠️ 只能钉住成功结果**：`post-execute` 不能替换 `isError`（`dsh-tools/lib/pipeline.js:687`、`:744-746`），而 fs 层 57 处错误里 39 处内嵌 `displayPath`。
4. **「强语言约束禁止 bash 读文件」❌ 不可作为安全边界**：Windows 沙箱只限制写（`dsh-pwsh-sandbox/README.md:140`），本仓库 `docs/DECISION-shell-redaction.md:19`（§0 结论摘要第 2 条）已论证白名单不可靠。**正解是删掉 bash，不是约束 bash。**
5. **「规则库化」能拆，但拆的不是识别器**——是「识别器 + 坐标契约 + 优先级契约 + 类型契约 + 依赖声明」五件东西。15 个内置识别器里只有 9 个能数据化，**人名/名册/地名/机构/职务这 5 个必须留 Python**。
6. **第一必改项是 `coordinate`**：现有自定义规则硬编码 `wants_raw=True`（`presidio_pii/custom_rules.py:117`、`:155`），内置规则一旦走 JSON 通道，全角/插值/换行三类变体整批归零（实测 5 类输入丢 4 类）。
7. **「md 中转 + write_docx 按模板还原」是内部矛盾的**：`presidio_pii/documents.py:295-302` 注释原文「最小实现: 重写首个 run, 其余 run 清空 (丢失段内混合格式)」。必须产品拍板路线 α（保原样式）/ β（套模板）。
8. **PTC `run_code` 会静默击穿一切**：程序拿到的是 canonical `value` 而非 `content`（`dsh-tool-executor-ptc/lib/index.js:514-521`），post-execute 的脱敏对程序无效。当前未挂，属定时炸弹。
9. **最大的隐形缺口是字段真空**：`grep "年龄|BIRTH"` 在 `presidio_pii/*.py` **0 命中**，`preset.json` 13 类里没有 AGE——而你点名的「年龄」排在第一位。**这不是 bug，是需求真空。**
10. **规则库自己会变成新的明文 PII 存储面**（R-08）：用户为提升召回最自然的做法就是把真名写成精确匹配规则，于是脱敏工具的配置目录成了 PII 语料库，还会被 git / 云盘 / 备份 / 分享带出去。**这是「允许自定义加载规则」这个需求的内生副作用。**
11. **「关库」这个词本身有三个会静默反悔的语义**（R-40/41/42）：`entity_types: []` 是**全部启用**而非全部关闭；只要存在一条同类型自定义规则，该类型就**永久关不掉**；名册通道不是独立库而是人名库的内部通道。三条都已实测，**都不是设计失误，是语义没定清楚**。
12. **占位符是一个没有任何保护的普通字符串**（约束六 §4.6）：`analyze()` 里没有「跳过占位符区间」的逻辑，一条 `\d{4,}` 或一条把 `PERSON` 当屏蔽词的 UI 规则，都能在二次脱敏时把 `⟦PII:PERSON:0001⟧` 切成 `⟦PII:⟦PII:MISC:0001⟧:0001⟧`，之后再也无法还原。**「规则库化」要主推的自定义通道，恰好是唯一能触发它的一条路。** 另加五个实现层陷阱（R-43~R-47，详见 §5.7）：拼错类型名整库静默失效、`priority` 污染可翻转整类裁决、自定义类型等长冲突永远垫底、自定义类型关不掉、CLI 无库级开关入口。

### 0.3 现在最该做的三件事（按 ROI 排序）

| # | 动作 | 成本 | 收益 |
|---|---|---|---|
| 1 | **补 7 个字段类型**（`AGE`/`BIRTH_DATE`/`GENDER`/`ETHNICITY`/`EDUCATION`/`IM_ACCOUNT`/`EMPLOYEE_ID`），覆盖探针里的 9 个漏检样本；同时修 F-04（姓名弱上下文）、F-05（住址尾号） | 低（复用现成 `custom_rules` JSON 通道，已验证全链路无损） | 探针命中 13/22 → 22/22 |
| 2 | **封掉 4 条直读通道**（read / grep / shell / MCP 直读类），只留自建四件套 | 中（一个 JS 插件 + yml 改动） | 直读 4 条 → 1 条（只剩自建 `read_redacted`） |
| 3 | **修机构名左边界（F-06）并补负样本回归** | 低（只改 `_trim_org_start` / `_ORG_PREFIX_WORDS`） | 消除「模型看到错内容」的错位风险——`他是公司总经理` 现在会把「他是」并进机构名 |

> 注：`13/22` 是**样本级**计数（22 条字段探针），不是类型级。新增 7 个类型能覆盖其中 9 个漏检样本。

---

## 1. 现状：防线在哪，缺口在哪

### 1.1 已有能力（三层）

| 层 | 组件 | 作用 |
|---|---|---|
| 识别层 | `presidio_pii/chinese_recognizers.py` 15 个识别器 + `custom_rules.py` 自定义规则通道 | 把原文里的 PII 找出来，替换成 `⟦PII:<TYPE>:<SEQ>⟧` |
| 通道层 | `plugins/dsh-pii-guard`（post-execute 脱敏 + 写入侧还原 + 显示侧还原） | 在工具结果进出模型上下文的边界上拦截 |
| 配置层 | `plugins/dsh-pii-guard-terms`（4 条 HTTP 路由 + 2 块 UI 面板） | 用户可维护屏蔽词与 4 项设置 |

**已具备的规则数据模型**（这是规则库化的地基）：

| 能力 | 位置 | 说明 |
|---|---|---|
| 规则形状 | `presidio_pii/custom_rules.py:92-100` | `RuleSpec(name, entity_type, score, context_hint, negative_hint, priority)` |
| 正则通道 | `custom_rules.py:103-133` | 支持捕获组、hint 判定、validator |
| 代码通道 | `custom_rules.py:146-178` | `.py` 的 `analyze(text) -> [(s,e[,score])]` |
| 多源加载 | `custom_rules.py:283-321` | 分号/逗号分隔，`.json` / `.py` 分发，`strict` 模式 |
| 热更新 | `custom_rules.py:324-427` | 文件签名 + 1s 节流 + 线程锁 |
| 失效保留 | `custom_rules.py:403-406` | 加载失败/0 条时保留上一份（**安全设计，但与「关库」直接冲突，见 R-01**） |

### 1.2 实测字段覆盖率：13 / 22

探针：`PresidioPIIEngine(db_path=":memory:")`，22 条字段样本。

| 字段 | 探针句 | 结果 |
|---|---|---|
| 姓名（强上下文） | `由范志强负责本次审计。` | ✅ `PERSON 范志强` |
| 姓名（弱上下文） | `员工范志强，男，45岁。` | ❌ **漏**（F-04） |
| 姓名（名册） | `参会人员名单：范志强、姚志刚、谭俊杰` | ✅ 三人全中 |
| **年龄** | `该同志年龄 45 周岁。` | ❌ **漏**（F-01） |
| **年龄** | `年龄：38` | ❌ **漏** |
| **年龄** | `今年 40 岁。` / `现年 52 岁。` | ❌ **漏** |
| **出生日期** | `出生日期：1990-03-07` / `生于1985年12月。` | ❌ **漏**（F-02） |
| **性别 / 民族** | `性别：男，民族：汉族。` | ❌ **漏**（F-02） |
| **学历** | `学历：硕士研究生。` | ❌ **漏**（F-02） |
| **微信 / 工号** | `微信：zhangsan_1985` / `工号：E123456` | ❌ **漏**（F-03） |
| 籍贯 | `籍贯：山东济南。` | ⚠️ 只到「山东」（F-07） |
| 职务 | `现任省发展与改革委员会副主任。` | ✅ `JOB_TITLE 副主任` |
| 职务（坏边界） | `他是公司总经理。` | ⚠️ `ORGANIZATION 他是公司` 吞了「他是」（F-06） |
| 身份证 / 手机 / 邮箱 / 银行卡 / 车牌 | — | ✅ 全中 |
| 住址 | `住址：北京市朝阳区建国路88号3单元501。` | ⚠️ 只到「3单元」，`501` 丢了（F-05） |
| 单位 / 地名 | `安徽省数据资源管理局在合肥` / `他来自杭州市西湖区` | ✅ 命中 |

**合计 HIT=13 / MISS=9。**

`README.md:9` 的字段清单里本来就没有年龄/性别/民族/学历/出生日期，`preset.json` 的 `entity_types` 也只有 13 类。所以这不是实现 bug，是**需求真空**：产品的字段范围比目标窄。

### 1.3 读通道盘点：4 条直读 + 2 个原文落盘点

**计数口径**（必须写清，否则「5 条」「6 条」「7 条」会互相打架）：

- **直读通道**：模型一次工具调用就能拿到原文的接缝，共 **4 条** —— `read`、`grep`/`glob`、`bash`/`pwsh`、**MCP 工具**。
- **原文落盘点**：本身不是通道，但**只要有任意一条直读通道存在**，它就是原文明文 —— 共 **2 个** —— `spill` 文件、`session` JSONL。
- `web_fetch` 已不是通道（只允许 http/https，源码如下）。

| 类型 | 通道 | 是否读原文 | 关闭方式 | 是否可关 |
|---|---|---|---|---|
| 直读 | `read` | ✅ | `tool-fs` `read: false` | ✅ |
| 直读 | `grep` / `glob` | ✅ `grep` 返回 `Line N: <preview>` | 整包不写 `tool-fs-search`（无单工具开关） | ✅（Web 面 host 侧已 disabled） |
| 直读 | `bash` / `pwsh` | ✅ | **只能不挂** | ✅ |
| 直读 | **MCP 工具** | ✅ **且是全局注册、agent 平面收窄管不到** | 删 home 层对应 MCP server | ✅（但会丢功能） |
| 落盘点 | `spill` 文件 | ✅ **就是原文** | 无法关（host 平面） | ❌ 只能靠自建工具限长绕开 |
| 落盘点 | `session` JSONL | ✅ 明文（zstd 只是压缩） | 无法关（host 平面） | ❌ 文档明写 |
| — | `web_fetch` | ❌ 已堵死（只允许 http/https） | — | — |

`web_fetch` 的限制有源码为证（`dsh-web-fetch-http/lib/index.js:30`）：
```js
if (url.protocol !== "http:" && url.protocol !== "https:") throw new WebError(...)
```

**MCP 是第四条被忽视的通道**（新发现）：`dsh-mcp-client/lib/index.js:153` 用**全局** `ctx.tools.register(definition)`，不是 agent scoped。本机 `$DSH_HOME/cordis.patch.yml` 挂了 6 个 MCP server，其中两个是完整绕过：
- `mcp__codebuddy__codebuddy_execute` → `scripts/mcp-codebuddy.js:135-138` 把 `--task/--workdir/--files` 交给外部 CodeBuddy CLI 进程，**它自己读原文**；
- `mcp__playwright__*` → 浏览器可打开 `file://` 页面读本地 HTML/文本。

### 1.4 结论

防线真正薄弱的地方不是「机制不够精巧」，而是：
- **识别层漏了 9 个字段**（含用户点名的年龄）；
- **通道层还有 4 条直读路 + 2 个原文落盘点**（见 1.3 的计数口径）。

其余讨论（沙箱、路径、插件机制）都在这两个数字之外。

---

## 2. 战场 A：识别层（识别什么）

### 2.1 需求拆解：这句话实际要求了 5 件事

原文：「丰富配置功能，将人名、组织、地名、电话等不同的匹配规则独立为一条一条的规则库，允许自由打开或关闭，允许用户自定义加载更多的规则或替换已有的规则库。」

| # | 隐含要求 | 难点 |
|---|---|---|
| R1 | **粒度**：按实体类型拆成独立库，库内是「一条一条」的规则 | 过程式识别器无法表达为「一条一条」 |
| R2 | **开关**：库级启停，规则级可选启停 | 开关必须真的改变识别结果，且可验证 |
| R3 | **加载更多**：用户可新增规则库 | 来源可信性、schema 校验、与内置库冲突 |
| R4 | **替换**：用户库可替换内置库 | 内置是 Python 类、用户是 JSON——替换语义取决于同构程度 |
| R5 | **配置功能**：以上都通过配置 UI 完成 | UI 写入必须与引擎读取同源，且改完立刻生效 |

**R5 是隐藏的杀手**：现有 UI 写 `user_terms_rules.json`，引擎读 `custom_rules_path`，两侧各有一份路径（`plugins/dsh-pii-guard-terms/lib/index.js:37`、`.agent-presets/presidio-pii/preset.json:21`、`tools/release_gate.py:319-320`），门禁用一条等式兜住（`release_gate.py:323`）。**加第四处配置源会让这条等式直接失真**（R-12）。

### 2.2 内置识别器的可拆分性（决定方案上限）

| 类别 | 数量 | 成员 | 能否数据化为 JSON |
|---|---|---|---|
| 纯正则 | 6 | 手机、座机、邮箱、统一社会信用代码、护照、车牌 | 能 |
| 正则 + validator | 3 | 身份证 18 位、身份证 15 位、银行卡 | 能，但需 validator 引用 + 双档 score（`0.95/0.70`、`0.80/0.45`） |
| 过程式 | 5 | 人名、名册人名、地名、机构、职务 | **不能**，4 个还带 jieba 双分支 |
| 一对象两类型 | 1 | `IpMacRecognizer`（`chinese_recognizers.py:452-471`） | 需 `emits: [IP_ADDRESS, MAC_ADDRESS]` |

**结论**：规则库化不能只做「JSON 规则包」，必须允许 `kind: builtin`（后端指向 Python 类）与 `kind: regex` / `kind: code` 并存。**同构在 manifest 层，不在实现层。**

### 2.3 粒度契约：**库 = 实体类型**（这是全部设计的地基）

需求原话的粒度是「**人名作为一个库，开关这个库 = 开关是否屏蔽所有人名**」。这个粒度是对的，而且必须写死成契约：

```
库（library）        ← 用户操作的粒度 = 一个实体类型 = 一个开关：人名库 / 电话库 / 机构库…
  └─ 规则（rule）    ← 库内「一条一条」：左上下文规则、jieba-nr 规则、名册通道、后缀规则…
       └─ entity_type ← 占位符契约（⟦PII:PERSON:0001⟧），不可随库改名
```

**「库」不是「识别器」。** 15 个内置识别器 ↔ 12 个实体类型，是三处 1:N，不是 1:1：

| 库（=类型） | 由哪些识别器实现 | 关系 | 关掉后实测 |
|---|---|---|---|
| `PERSON` | `ChinesePersonRecognizer` + `ChineseRosterPersonRecognizer` | 2 → 1 | 6 个真实姓名全部明文 ✅ |
| `ID_NUMBER` | `ChineseIDRecognizer`(18 位) + `ChineseID15Recognizer`(15 位) | 2 → 1 | 15 位改由 `BANK_CARD` 接管（见下） |
| `PHONE_NUMBER` | 手机 `LightRecognizer` + 座机 `LightRecognizer` | 2 → 1 | 手机/座机同时失效 ✅ |
| `IP_ADDRESS` / `MAC_ADDRESS` | `IpMacRecognizer`（**一个对象产两个类型**） | 1 → 2 | 可分别关停（实测见下） |

→ **结论：库级开关的正确实现是「按 `entity_type` 过滤」，不是「按识别器实例过滤」。** 按实例过滤会在 `IP_ASSET`/`MAC_ADDRESS` 上做不到独立开关，在 `PERSON`/`ID_NUMBER`/`PHONE_NUMBER` 上则要人工维护「哪几个实例属于同一个库」的映射表。

**这个机制已经存在，不需要新造。** `presidio_pii/engine.py:169-182` 的 `_filter_entity_types()` + `preset.json` 顶层 `entity_types` + 设置页勾选（`plugins/dsh-pii-guard-terms/client.js:64-67`、`lib/index.js:288-332`）。实测「按类型过滤」与「移除识别器实例」输出**逐字节相同**：

```python
e1 = PresidioPIIEngine(db_path=":memory:")
e1.recognizers = [r for r in get_chinese_recognizers() if not isinstance(r, (ChinesePersonRecognizer, ChineseRosterPersonRecognizer))]
e2 = PresidioPIIEngine(db_path=":memory:", entity_types=[t for t in ALL if t != "PERSON"])
# r1.text == r2.text  ->  True
```

**规则级不暴露给用户。** UI 主界面只有库级开关；库内单条规则的 `enabled` 由 manifest 声明默认值，只在「高级」面板出现。理由——若把几千条规则平铺给用户，等于把精度调优的负担全部转嫁，用户最终会关掉一切（R-25 的 Elastic 教训：`Disabling the rule means you lose detection coverage entirely`）。

### 2.3.1 库级开关的五个实测陷阱（这一节是新增的，全部本机跑过）

> 本节只列「粒度契约本身」的陷阱（R-40 / R-41 / R-42）。另外五个**实现层**陷阱（R-43~R-47：拼错类型名整库静默失效、`priority` 污染翻转整类裁决、自定义类型不在 `_PRIO` 垫底、自定义类型关不掉、CLI 无入口）见 §5.7。

**① `entity_types: []` 的语义是「全部启用」，不是「全部关闭」。**
```python
PresidioPIIEngine(db_path=":memory:", entity_types=[])   # -> 由⟦PII:PERSON:0001⟧负责，电话 ⟦PII:PHONE_NUMBER:0001⟧。
PresidioPIIEngine(db_path=":memory:", entity_types=None) # -> 同上
```
代码是 `if not self.entity_types: return results`（`engine.py:178`）。设置页提示也照实写了「全部取消勾选表示启用全部类型」（`client.js:67`）。
→ 对隐私工具来说这是**最危险的默认值方向**：用户想「全关」时写下的空数组，实际含义是「全开」。新增 `R-40`。

**② 任意一条自定义规则会让该类型永久关不掉。**
```python
# 存在一条 entity_type=PERSON 的自定义规则，同时用户关掉了人名库
allowed = self.entity_types | {t for t in custom if t}   # engine.py:181
# 实测 -> ⟦PII:PERSON:0001⟧与⟦PII:PERSON:0002⟧参会。  counts = {'PERSON': 2}
```
`_filter_entity_types` 的设计意图是保护 `USER_TERM`（用户显式配置的屏蔽词不该被内置类型勾选顺手关掉），但副作用是**任何自定义规则都能给某个内置类型「续命」**。用户勾掉「人名」之后，只要他之前加过一条 `PERSON` 类型的自定义规则，人名仍然会被屏蔽——开关看起来生效了（UI 打勾状态正确），实际行为相反。新增 `R-41`。

**③ 关掉身份证库 ≠ 15 位身份证不再脱敏，而是「按银行卡脱敏」。**
```
输入：旧证件号 110101200307851。
ID 库开  -> 旧证件号 ⟦PII:ID_NUMBER:0001⟧。
ID 库关  -> 旧证件号 ⟦PII:BANK_CARD:0001⟧。      ← 仍然脱敏，但类型变了
```
（样本需同时满足 `_id15_valid` 与 `_luhn`；实测 `110101900307851` 的变体里有 7 个同时满足。）
→ 这是 R-06 的**实测确认**（`chinese_recognizers.py:384-386` 类注释早有书面预警）。对用户要明示：「关闭身份证库」的后果是「15 位旧证按银行卡类型脱敏」。

**④ `grep`/`glob` 类「部分关」做不到，但库级开关不涉及它们。** 见 1.3 与 `T-12`——这属于通道层，与库级开关是两回事，不要混谈。

**⑤ 名册不是一个可独立开关的库（原设计错误，本文修正）。**
原 `manifest` 示例写了 `"excludes": ["builtin.person.roster"]`，暗示「人名库」与「名册库」互斥。**这是错的。** 实测两者是**互补**关系：

| 文本 | `ChinesePersonRecognizer` | `ChineseRosterPersonRecognizer` |
|---|---|---|
| `名单：张三、杨同初（26）、李四、欧阳娜娜。` | 张三、李四 | 张三、**杨同初**、李四、**欧阳娜娜** |
| `- **原班级学号名单（28人）**：…邝也、陈敬之、杨同初（26）、欧阳娜娜…` | 5 个常见名 | 9 个（含**邝也**、**陈敬之**、**杨同初**、**欧阳娜娜**） |

→ 名册通道专门补「罕见姓 / 复姓 / 三字带虚字 / 带学号后缀」这四类漏检。它是**人名库内部的一条通道**，不是同级库。若把它拆成独立库，用户关掉它就会得到一个「常见姓名被屏蔽、罕见姓名全部明文」的状态——比全关更危险，因为用户以为自己还开着人名库。新增 `R-42`。

**正确的库清单（12 个，与 `_PRIO` 的 13 个键差一个）**：
`PERSON` / `ID_NUMBER` / `PHONE_NUMBER` / `EMAIL_ADDRESS` / `CREDIT_CODE` / `BANK_CARD` / `PASSPORT` / `LICENSE_PLATE` / `IP_ADDRESS` / `MAC_ADDRESS` / `LOCATION` / `ORGANIZATION` / `JOB_TITLE` —— 共 13 个类型，其中 `IP_ADDRESS` 与 `MAC_ADDRESS` 由同一个识别器产出但**可独立开关**，所以确实可以拆成 13 个独立库。

### 2.4 落点选择：独立清单文件（方案 b）

| 维度 | (a) `preset.json config.rule_libraries[]` | **(b) 独立清单 `.pii_presidio_store/rule-libraries.json`** | (c) 规则库目录 + 每库 `manifest.json` |
|---|---|---|---|
| 热更新 | **不可热**：`_get_engine()`（`presidio_pii/hooks.py:138-147`）首次构造后永不重读 | **可热**：清单进签名，复用 1s 节流 | 可热但最重：签名要变目录树哈希 |
| 防漂移 | 最差：UI 改写声明式 preset；`_preset_path()`（`hooks.py:76-80`）依赖文件已存在，新键指向不存在的文件会**静默退化到仓库根** | 最好：单一权威文件 | 中等：目录即真相，但「启用状态」还得另存 |
| 门禁改动 | 小 | 中（S2 重写 + schema 断言） | 大（+ 目录遍历，与 #11 冲突） |
| 语义分层 | 违反「配置即代码」 | 用户态数据，符合「可加载/可替换」 | 分发型规则库不能落 `.pii_presidio_store/` |

**推荐 (b)**，`preset.json` 只新增一个 `rule_libraries_path` 指向清单。(c) 作为 (b) 的演进形态保留——清单里的 `path` 允许指向目录，但不要一上来就做目录扫描。

### 2.5 manifest 形状（库级）

```jsonc
{
  "schema": 1,                        // 清单版本，引擎按此分流
  "id": "builtin.person",             // 稳定标识，替换/依赖都按它引用
  "name": "人名（中文）",
  "version": "0.1.0",
  "kind": "builtin",                  // builtin | regex | code
  "backend": "presidio_pii.chinese_recognizers:ChinesePersonRecognizer",
  "enabled": true,
  "order": 10,                        // 仅用于 UI 排序与日志，不参与裁决
  "emits": ["PERSON"],                // 类型白名单，防 typo
  "coordinate": "normalized",         // normalized | raw —— 见 2.7
  "requires": ["builtin.core"],       // 加载依赖（不满足则拒绝加载本库）
  "excludes": [],                     // 互斥（同时 enabled 则拒绝）；人名库内不拆出 roster
  "replaces": null,                   // 非空表示替换同 id 的内置库
  "rules": [                          // kind=regex/code 时是规则数组；builtin 时可空
    { "id": "person.left-context", "enabled": true, "pattern": "...", "score": 0.85 },
    { "id": "person.roster", "enabled": true, "note": "名册通道：罕见姓/复姓/学号后缀，属本库内部通道" }
  ]
}
```

> **`id` 的命名规则**：一个库 = 一个 `entity_type`，`id` 与 `emits` 必须一一对应（如 `builtin.person` ↔ `["PERSON"]`）。这是 2.3 粒度契约在清单层的落法，也是「开关人名库 = 开关所有人名」能被机械校验的原因。

| 字段 | 为什么必须有 | 没有会怎样 |
|---|---|---|
| `id` | 替换、依赖、互斥、UI 稳定引用 | 只能按文件名认库，改名即断（R-23） |
| `emits` | 类型白名单 | typo `PEROSN` → 落 99 优先级 + 生成不可还原的占位符（`engine.py:243` 按类型建序号，R-07） |
| `coordinate` | 坐标契约 | 走现有通道必继承 `wants_raw=True`，全角变体全丢（R-09、2.7） |
| `requires` | 跨库依赖 | 关掉 `ID_NUMBER` → 15 位身份证被 `BANK_CARD` 抢走（R-06） |
| `excludes` | 互斥 | 两个库同时启用时结果集合不确定 |
| `replaces` | 替换语义 | 无法表达「用我的库换掉内置的」 |
| `schema` | 版本演进 | 老清单被新引擎误读 |

### 2.6 开关语义：构建期 vs 运行期

| 语义 | 做法 | 优点 | 缺点 |
|---|---|---|---|
| **A. 构建期不加载**（Presidio 语义） | `enabled=false` 的库根本不实例化 | 零成本、零误报风险、异常不可能发生 | 关闭瞬间需重建识别器列表 |
| **B. 加载后过滤** | 照常加载，产出结果时按 `enabled` 丢弃 | 切换可即时、可回滚 | 成本照付；用户写的坏正则仍然会跑（ReDoS 不减） |

**推荐 A**，并补齐三条硬要求（缺一不可）：
1. **禁用 = 不实例化**，`_sync_recognizers()` 必须在拼接前过滤（`presidio_pii/engine.py:92-96` 目前是纯 `builtin + rules`，无过滤钩子）。
2. **必须有测试断言「关掉后结果里真的没有」**——Presidio issue #950 的教训是 `remove_recognizer()` 之后 `analyze()` 仍返回该实体。
3. **「全关」是合法状态**，不得命中「0 条保留旧规则」分支（R-01）。必须用显式空状态表达，而不是延续 `(?!)` 占位规则的权宜之计（`plugins/dsh-pii-guard-terms/lib/index.js:47/249-258`）。

### 2.7 坐标契约（最容易被忽略，但最致命）

现状：`analyze()` 里 `results.extend(rec.analyze(text if getattr(rec, "wants_raw", False) else probe))`（`presidio_pii/engine.py:148`）。内置识别器跑在归一化文本上、坐标再映射回原文（`:149-156`）；自定义规则硬编码 `wants_raw=True`（`custom_rules.py:117`、`:155`）。

**实测数据**（同一条 `1[3-9]\d{9}` 分别在原文与归一化文本上跑）：

| 输入变体 | 原文（现状自定义规则） | 归一化文本（内置识别器） |
|---|---|---|
| `13800138000` | ✅ 1 | ✅ 1 |
| `138 0013 8000` | ❌ 0 | ✅ 1 |
| `138-0013-8000` | ❌ 0 | ✅ 1 |
| `１３８００１３８０００`（全角） | ❌ 0 | ✅ 1 |
| `138\n0013\n8000` | ❌ 0 | ✅ 1 |

即 **5 类输入里 4 类直接归零**，而这几类变体正是中文公文最常见的写法。

**但方向是双向的，必须写清楚**：归一化会把 `-` 等分隔符统一成空格（`normalize()` 实测 `ORD-1234` → `ORD 1234`），所以**依赖特定分隔符字面量的规则在 `coordinate: normalized` 下同样会失效**：

| 规则 | 原文 | 归一化文本 |
|---|---|---|
| `ORD-\d{4}` 匹配 `ORD-1234` | ✅ 1 | ❌ 0 |

结论：`coordinate` 不是「raw 一律劣于 normalized」，而是**两类规则各有坐标系**。字段必须存在、必填、可校验。

**对策**：设为库级必填（默认 `normalized`，用户库显式声明 `raw` 才行）。不要做成规则级——同一库内混坐标会让 `_resolve_overlaps` 的输入来自两套坐标，出现不可复现的错位。用户规则里凡写了 `-`、`/`、`：` 的，UI 必须提示改用 `[\s\-]?` 之类宽松写法。

### 2.8 加载流程与三种状态

```
1. 读清单（唯一权威）；清单缺失 → state=degraded（不是 empty）
2. 对每个 enabled 库：
   a. schema 校验（版本、必填字段、kind 合法）
   b. requires 全部 enabled？ 否 → 拒绝本库，记录原因
   c. excludes 无冲突？       否 → 拒绝后到者，记录双方 id
   d. 装载（regex/code 走 strict 模式；builtin 走注册表）
   e. emits 校验：产出的类型必须在声明内
3. 汇总：
   - ok       : N 库启用，M 条规则
   - empty    : 用户显式全关（合法）
   - degraded : 加载失败，沿用上一份可用配置
4. 失败保留上一份（OPA fail-safe 语义），但**必须上报**：
   日志 + 状态接口 + UI banner（不能只 console.error）
```

**三种状态必须在 UI 上可区分**，这是「静默成功」反模式（R-02）的解药。

### 2.9 热更新

**清单必须进签名。** `_source_signature()`（`custom_rules.py:367-376`）只遍历 `self.sources`，开关存在清单里，改清单不改库文件 → 签名不变 → 开关永不生效（R-05）。

两条实现路径：
- **L1（简单）**：签名元组追加 `(manifest_path, mtime_ns, size)`。
- **L2（推荐）**：清单里存每个库文件的**内容哈希**，签名 = 清单自身的内容哈希。一次 stat 覆盖全部，还能检出「库文件被改但 mtime 没变」的边界情况。

另外两点：
- `presidio_pii/server.py` 目前只有 `redact` / `restore`（分派在 `server.py:92-102`），**没有 reload op**。加上它，「点开关立刻生效」才能从「等 1 秒」升级为确定性行为，也是解除 `plugins/dsh-pii-guard-terms/README.md:55`「改路径需重启 DSH」的唯一路径（R-04）。
- **写盘顺序 = 先写库文件，后写清单**。清单是提交点，避免「新开关 + 旧规则」的中间态。

### 2.10 优先级与冲突

现状排序键：`(-(r.end - r.start), priority.get(r.entity_type, 99), r.start)`（`presidio_pii/engine.py:203-206`）——**长度是第一优先级，priority 只解决等长重叠**。

四个已确认的问题：

1. **按类型计权、不按规则计权**。15 个库对应 13 个类型键（`engine.py:38-41` 的 `_PRIO`），两个 PHONE 库（手机/座机）只能共用一个优先级。
2. **未声明 priority 一律 99**，会反转 `PERSON(8)` 与 `ORGANIZATION(10)` 的次序。
3. **`entity_priorities()` 同类型取最小值**（`custom_rules.py:411-421`；docstring 写「取最高优先级」，数值上最小才算最高）——语义是「这个类型整体按最高优先级算」，关掉高优先级库后该类型优先级不会回落到内置值。
4. **用户词 `priority: 0` 与 `ID_NUMBER` 撞车**。UI 写的每条 USER_TERM 规则都是 `priority: 0`（`plugins/dsh-pii-guard-terms/lib/index.js:241-248`），与 `_PRIO["ID_NUMBER"] = 0` 同权；等长重叠时裁决退化成「看起点」。这是既有行为但从未被文档化。

**建议的解析顺序**（从高到低）：
```
rule.priority（显式声明）
  → library.priority（库级默认）
  → _PRIO[entity_type]（内置 13 类）
  → 99
```

并且 **保留「长实体优先」不动**。这是业界惯例——spaCy EntityRuler 原文：「the entity ruler prioritizes longer patterns over shorter, and if equal the match occurring first in the Doc is chosen」。Presidio 的 `remove_duplicates` 只在**同 entity_type 内**压制，跨类型裁决是本项目自建能力，必须自己写清规则。

---

## 3. 战场 B：通道层（怎么保证识别结果真的生效）

### 3.1 DSH 极简模式的真实形状

DSH 自带 `@deepseek-ai/dsh-sdk-minimal`，其 `cordis.patch.yml`（179 行）第 1-3 行注释原文：

> 「Standalone minimal SDK application. Unlike the ordinary SDK profile, this bundle does not layer over dsh-base: this insert is the complete Cordis tree.」

关键行：
- `tool-fs`（`:44-50`）：`config: { read: false, readImage: true, write: false, edit: false }` —— **极简模式就是把 read/write/edit 三个开关关掉**。
- `system-prompt`（`:113-118`）：`includeHarnessIdentity: false`、`includeRuntimeContext: false`。
- `sandbox-policy`（`:70-74`）：`mode: danger-full-access`。
- `terminal-pwsh` / `terminal-bash`（`:82-93`）+ `persistent-pwsh` / `persistent-bash`（`:144-170`）。

**极简 SDK 没有**：`dsh-tool-fs-search`、`dsh-tool-web`、`dsh-tool-subagent`、`dsh-tool-todo`、`dsh-tool-skill`、`dsh-spill-*`、`dsh-tool-executor-ptc`。

### 3.2 分层：host 平面 vs agent 平面（这一步决定「能不能真的收窄」）

`dsh-web-app/cordis.patch.yml:467-476` 注释是决定性的：

> 「the agent plane moves behind agent presets … Every row below composes what ONE agent contributes to the host registries: its tools, its prompt sections, its delegation backends. **The base keeps them for the TUI** … **the Web surface disables them here and lets each session mount a preset instead.**
> Disabling rather than deleting is deliberate: the base is shared, and a row absent from a surface overlay would silently reappear the day someone reorders the composition.」

实测 web-app 层 `disabled: true` **恰好 22 行**：
`tool-plugin-manager@484`｜`tool-bash@487`｜`tool-pwsh@490`｜`tool-jobs@503`｜`tool-fs@506`｜`tool-fs-search@509`｜`skill-filesystem@521`｜`tool-skill@524`｜`command-goal@530`｜`tool-goal@533`｜`plan-mode@536`｜`compaction-basic@546`｜`command-compact@549`｜`tool-result-pruner@552`｜`tool-subagent-control@562`｜`tool-subagent@565`｜`tool-subagent-fork@568`｜`workflow-ptc@571`｜`tool-workflow@574`｜`agent-instructions@577`｜`tool-todo@580`｜`tool-web@583`

**推论一（agent 平面）：不写就没有。** 预设的 `plugins` 数组不写 `tool-fs` / `tool-fs-search` / `tool-bash` / `tool-pwsh` / `tool-web` / `tool-todo`，这些工具就真的不存在——**不需要再写 `disabled: true`**（它们已在 web-app 层被 disabled）。

**推论二（host 平面）：预设删不掉。** 以下行在 base 里存在、在 web-app 层 **ABSENT**，属于 host 平面，`preset` 管不到：
`spill-local`（base `:411-412`）｜`spill-policy`（`:414-415`）｜`session-persistence-jsonl`（`:138-139`）｜`tool-executor-native`（`:501-502`）
要关只能改 profile 层 patch（`$DSH_HOME/cordis.patch.yml`，本机 421 行）或另起 profile。

`dsh-agent-preset/lib/index.js` 全文印证：`Config = z.object({ id: required, name, description, order, plugins: required })` —— preset 只是「一组 child plugin entry」，无 `disabled` 语义，不拥有 host 平面。

### 3.3 五条断言逐条判定

| # | 断言 | 判定 | 依据 |
|---|---|---|---|
| A1 | 只暴露最少量工具 | ✅ 可行 | `tool-fs` 五开关（`dsh-tool-fs/lib/index.js:1967-1989`）+ `agent.ctx.tools.restrict`（`dsh-tools/lib/index.js:453-467`） |
| A2 | 工具级钉死脱敏 | ⚠️ 只能钉住一半 | `post-execute` 可换成功结果的 `content`/`value`，**不能**换 `isError`（`pipeline.js:687`、`:744-746`） |
| A3 | 工具级钉死还原 | ✅ 可行，已有生产范式 | `plugins/dsh-pii-guard/lib/index.js:618-659` scoped shadow |
| A4 | 强语言约束禁止 bash 读文件 | ❌ 不可作为安全边界 | Windows 沙箱只管写（`dsh-pwsh-sandbox/README.md:140`）；仓库 `DECISION-shell-redaction.md:19` 已论证白名单不可靠 |
| A5 | md 中转 + write_docx 按模板还原 | ⚠️ 需求内部矛盾 | `presidio_pii/documents.py:295-302` 注释「最小实现: 重写首个 run, 其余 run 清空 (丢失段内混合格式)」 |

**A1 的两套机制细节**：

`tool-fs` 五开关（`dsh-tool-fs/lib/index.js:1967-1989`）逐字：
```js
if (resolved.read) applyReadTool(ctx, { limit, maxLineLength, maxBytes, streamMinSize });
if (resolved.readImage) ctx.inject(["attachments"], (imageCtx) => applyReadImageTool(imageCtx));
if (resolved.write || resolved.edit || resolved.applyPatch) {
  const sandbox = new FsSandboxController(ctx);
  if (resolved.write) applyWriteTool(ctx, sandbox);
  if (resolved.edit) applyEditTool(ctx, sandbox);
  if (resolved.applyPatch) applyApplyPatchTool(ctx, sandbox);
}
```
→ `{read:false, readImage:false, write:false, edit:false, applyPatch:false}` 一行 yml 就做到「无结构读通道」。

`restrict`（`dsh-tools/lib/index.js:453-467`）四个约束：必须 agent scope（`:455`）、空 filter 抛错（`:458`）、不能命名 `run_code`（`:463`）、未知名抛错（`:464-466`）；返回 disposer（`:467`）。

**A3 的范式**（`plugins/dsh-pii-guard/lib/index.js:618-659`）：
```js
ctx.on("agent/created", ({ agent }) => {
  const actx = agent?.ctx;
  for (const toolName of WRITE_TOOLS) {
    const original = ctx.tools?.get?.(toolName);   // 用全局 ctx 取原 definition，避免拿到自己注册的 wrapper
    disposers.push(actx.tools.register({ ...original, execute: async (args, exec) => {
      const { args: safeArgs, failed } = await restoreArgs(args, restoreFn);
      if (failed.length) throw new Error(`[pii-guard] placeholder restore failed: ${failed.join("; ")}`);
      return original.execute(safeArgs, exec);
    }}));
  }
  disposers.push(actx.tools.restrict({ deny: ["read_image"] }));
  actx.effect(() => dispose);
}, { global: true });
```

**A5 的矛盾点**：走 md 中转必然丢段内格式（`_set_docx_paragraph` 只保留首个 run）；套模板则不保留原样式。两条路互斥，必须二选一：
- **路线 α**：原地改写原文档（保样式，无 md 中转，不能跨格式）；
- **路线 β**：按模板重排（可跨格式，丢原样式）。

### 3.4 极简预设的工具面设计（Phase 1 目标形态）

| 工具 | 保留 | 理由 |
|---|---|---|
| `read_redacted` | ✅ 自建 | 唯一的结构化读通道，内部调 `ctx.fs.readText` + 脱敏 + 自己限长 |
| `write_raw` | ✅ 自建 | 唯一写通道，内部做占位符还原 + 自限长 |
| `restore` | ✅ 自建 | 显式还原（用户要求明文时） |
| `ls` | ✅ 自建 | 目录列举（只返回占位符化名字） |
| `present` | ✅ | 交付文件 |
| `read` / `write` / `edit` / `apply_patch` | ❌ 关 | `tool-fs` 五开关 |
| `grep` / `glob` | ❌ 不写 | `tool-fs-search` 整包不挂 |
| `bash` / `pwsh` | ❌ 不写 | 沙箱不管读，只能不挂 |
| MCP 直读类（codebuddy / playwright） | ❌ 删 | 全局注册，绕过一切工具级脱敏 |

`ctx.fs` 的可调用方法（`dsh-fs/lib/types/index.d.ts` 实测）：`resolve`(:110)、`stat`(:154)、`lstat`(:169)、`readText`(:178)、`streamText`(:188)、`readBytes`(:199)、`readByteRange`(:213)、`listDir`(:224)、`writeText`(:237)、`editText`(:251)、`patchText`(:267)、`deleteFile`(:282)、`moveFile`(:301)。

---

## 4. 七个结构性约束（做不到的事）

以下六条是「表面上能做，实际做不到」。每一条都对着具体源码路径，且都不是靠努力能绕过的。

### 4.1 约束一：isError 通道不可脱敏

`dsh-tools/lib/pipeline.js:687`：`if (result.isError) throw new TypeError("tools/post-execute cannot replace the value of a failed result");`
`:744-746`：`if (result.isError) return this.markCanonical(exec, { isError: true, error: result.error })` —— **原样返回，content 不可替换**。

而 `dsh-fs-local/lib/index.js` 共 **57 处 `new FsError(`，其中 39 处**把 `displayPath` 拼进 message（完整行号见附录 A）。

**后果**：文件名即 PII 时必然泄漏。
**缓解**：自建工具内部 catch + 抹路径（必做）；第三方工具可选「isError 全 block」强策略。

### 4.2 约束二：PTC `run_code` 下 post-execute 对程序无效

`dsh-tool-executor-ptc/lib/index.js:512-521` 逐字：
```js
const settle = (result) => {
  resolve(result.isError ? { isError: true, message: result.error.message }
                        : { isError: false, value: result.value });   // ← 给程序的是 value
```
`dsh-tools/README.md` Known Limitations 原文：
> 「**Canonical values belong to execution**… Replacing or redacting that content does not remove the canonical value available to a programmatic caller; **a policy that must deny that access must block execution or replace the value**.」

**后果**：一旦启用 PTC，post-execute 只改了 `content`（UI 与会话里看着脱敏了），程序内 `await tools.read(...)` 拿到的是**原文**。**这是最危险的一条，因为它是静默的**——现有测试、门禁、UI 全部正常。

**当前状态**：`presidio-pii` 预设挂了 `workflow-ptc` 但**没有挂** `dsh-tool-executor-ptc`（base 里该行已 `disabled: true`），所以现在是 native 执行器。
**缓解**：yml 里加注释锁死 + 门禁断言「预设不得出现 `dsh-tool-executor-ptc`」。

### 4.3 约束三：读通道不止 read 一个

见 1.3 的完整表。要点：
- `grep` 本身就是读取工具（`dsh-tool-fs-search/README.md` 原文：「a model that needs surrounding context reads the matched file with `read`」——反过来说 grep 自己就吐匹配行，`grepMaxLineBytes: 2000`）；
- `spill` 文件就是原文，且 `retrievalHint` 主动教模型去读（`dsh-spill-local/README.md` 原文：「Use read with offset/limit, or grep this path to search within it.」）；
- session JSONL 明文（`compression: zstd` 只是压缩，不是加密）；
- MCP 工具全局注册，agent 平面收窄管不到。

**后果**：只关 `read` 而留 `grep` = 掩耳盗铃。`docs/DECISION-shell-redaction.md:22`（§0 结论摘要第 5 条）已承认「溢出文件（spill）内容为原文，只能靠 read 通道守卫」——而现在 read 通道被关掉，spill 就是裸奔的原文。

### 4.4 约束四：用户粘贴的文本在工具级守卫之外

`plugins/dsh-pii-guard/lib/index.js:661-663` 注释原文：
> 「不改 decision.messages：该机制与 session log / KV cache 脱节，只做可观测告警」

代码只做计数告警：`console.error("[pii-guard] pre-step WARN: ... (not redacted; user-pasted text is outside the tool-result guard)")`。

**后果**：工具级方案只覆盖「工具结果 → 模型」这条边，覆盖不了「用户 → 模型」这条边。而这条边恰恰是最常见的 PII 入口。
**缓解**：客户端提交前脱敏，或在 `agent/pre-step` 改写并接受 KV cache 全失效。**无论哪种都超出「工具级钉死」的范围，必须明说。**

### 4.5 约束五：占位符是可被模型伪造的字符串

`presidio_pii/engine.py:243`：`ph = f"{PH_OPEN}PII:{ptype}:{counters[ptype]:04d}{PH_CLOSE}"`
`restore()`（`engine.py:266-294`）只扫文本中**出现**的占位符。

→ 模型可以手写 `⟦PII:PERSON:0001⟧`（它从上下文里见过这个字符串），`restore` 会把它换成对应的真实姓名。

**这是泄露吗？** 严格说不是——模型从没见过原文，造不出它不知道的信息。
**但这是语义错位**：模型可以把占位符挪到不该出现的位置，导致「张伟的身份证号」写进「李四」那一行。在自动生成的合同/报表里，这比漏脱敏更隐蔽——数字都对得上，只是张冠李戴。

**缓解**：写入侧还原继续做；但**还原后要做位置一致性校验**。代价是现有 `counters` 按 entity_type 全局递增（跨文档共享），**做不到文档内隔离**，属设计级改动。

### 4.6 约束六：占位符字符串本身没有任何保护（可被自定义规则切碎）

`_PH_RE = re.compile(r"⟦PII:[A-Z_]+:\d+⟧")`（`engine.py:23`）只用于两处：`count_placeholders()`（`:29-31`）与 `restore()`（`:304`）。**`analyze()` / `redact()` 里没有任何「跳过占位符区间」的逻辑**——`_drop_uuid_spans`（`:184-195`）只保护 UUID，占位符不在其列。

于是任何走 **raw 坐标**的自定义规则，只要能在占位符内部命中一段，就会把它切碎：

```
自定义规则 {"pattern": "[A-Z_]{4,}", "entity_type": "MISC"}
  一次脱敏: 由⟦PII:PERSON:0001⟧负责。
  二次脱敏: 由⟦PII:⟦PII:MISC:0001⟧:0001⟧负责。
  restore(d2) -> 由⟦PII:PERSON:0001⟧负责。   # 内层还原成外层占位符，外层再也认不出
```

**UI 屏蔽词同样中招**（`ENTITY_TYPE = "USER_TERM"`，`RegexRuleRecognizer.wants_raw = True`，`custom_rules.py:117`）：

```
屏蔽词填 "PERSON"
  一次脱敏: 由⟦PII:PERSON:0001⟧负责。
  二次脱敏: 由⟦PII:⟦PII:USER_TERM:0001⟧:0001⟧负责。
  count_placeholders("⟦PII:⟦PII:USER_TERM:0001⟧:0001⟧") -> 1   # 外层已成裸文本
```

实测五种危险 pattern 全部切碎：`[A-Z_]{4,}`、`\d{4,}`、`PII`、`[:：]`、`[⟦⟧]`。其中 `\d{4,}` 是最现实的——工号、订单号、批次号这类规则的首选写法。实测 `工号 E123456` 场景：

```
一次: 由⟦PII:PERSON:0001⟧负责，工号 E⟦PII:MISC:0001⟧。
二次: 由⟦PII:PERSON:⟦PII:MISC:0002⟧⟧负责，工号 E⟦PII:MISC:⟦PII:MISC:0003⟧⟧。
```

**真实触发链路**（不需要用户做错任何事）：模型让 shell `echo` 一个占位符、或把占位符写进文件再读回来 → 该文本再次经过 `before_llm` → 二次脱敏 → 占位符损坏 → 后续任何 `restore` 都无法还原该实体。

**为什么内置规则不会触发**：15 个内置识别器全走 normalized 坐标（`wants_raw` 未设置），且 `normalize()` 不改写 `⟦⟧`（实测 `normalize("由⟦PII:PERSON:0001⟧负责。")` 原样返回，`changed = False`），内置规则也不会匹配 `PII` / `[A-Z_]{4,}` 这类片段。所以**这个坑完全来自自定义规则通道，而自定义规则通道恰恰是「规则库化」要主推的东西**——两者互相踩。

**对策（三选一，建议至少做前两条）**：

1. **在 `analyze()` 里先把占位符区间当保护区**（复用 `_drop_uuid_spans` 的形状，加一个 `_drop_placeholder_spans`）：成本最低，彻底解决，且对内置规则零影响。
2. **`RegexRuleRecognizer.analyze` 跳过占位符区间**：只在自定义通道打补丁，内置不受影响。
3. **规则加载期拒绝能在占位符内部命中的 pattern**：需要构造探针串 `⟦PII:PERSON:0001⟧` 跑一遍，命中即 `_warn` 或拒绝。副作用是误杀合法规则（例如用户真想把 `0001` 当屏蔽词）。

> 顺带一个相关但独立的坑：`restore()` 的 `_PH_RE.findall()` 对切碎后的 `⟦PII:⟦PII:USER_TERM:0001⟧:0001⟧` 返回的是**内层**占位符，`count_placeholders()` 也只数到 1。也就是说「还原后没有残留占位符」这个校验（`count_placeholders(text) == 0`）**在切碎场景下会误报通过**。

### 4.7 约束七：spill 会把原文写进磁盘，且两个 prepend 监听器顺序无保证

`dsh-spill-policy/lib/index.js:237-255`（`{ prepend: true }`）：
```js
ctx.on("tools/post-execute", async (exec, result, next) => {
  const decision = await next();
  if (decision.kind !== "accept" || Object.hasOwn(decision, "value") || exec.name === "read") return decision;
  ...
  const retained = await bound(exec, content, exec.name, exec.callId, ...);
  return { kind: "accept", content: retained, ... };
}, { prepend: true });
```

三个问题叠在一起：
1. **`:239` 的 `exec.name === "read"` 是名字级豁免** —— `read` 的巨大结果永不被 spill。而 Phase 1 正好把 `read` 换成自建 `read_redacted`（名字不同）→ **自建工具的大结果会被 spill 成原文文件**。要么自建工具自限长（推荐），要么改名蹭豁免（语义欺骗，不推荐）。
2. **spill 通知直接教模型去读原文**（README 原文见 4.3）。
3. **两者都 `{ prepend: true }`，谁在外层由注册顺序决定**。`cordis/lib/index.js:919-929`：`const method = options.prepend ? "unshift" : "push";` —— 后注册的 unshift 到最前、成为最外层。
   - 若 **spill-policy 在外层**：拿到的是已脱敏 content → 落盘的是占位符版（安全）；
   - 若 **pii-guard 在外层**：spill-policy 先把**原文**写盘，pii-guard 再脱敏 → **磁盘上是原文，模型手里是占位符**（最坏组合：看起来安全，实际落盘泄露）。

**后果**：不只是「顺序可能不对」，而是**没有任何代码或测试在保证这个顺序**。
**缓解**：自建工具自己限长（源头不产生 spill）+ 门禁断言（构造超长结果后断言 spill 目录里是占位符）。

---

## 5. 问题总清单（81 条）

### 5.0 分级与分类口径

| 级别 | 定义 |
|---|---|
| **P0** | 会让「保护失效但工具仍报成功」——隐私工具里最不可接受的一类 |
| **P1** | 功能不达预期、契约被破坏、或维护成本显著上升 |
| **P2** | 体验/工程债，可排期 |

**对抗对象**（按用户口径的三分法再加两类）：

| 标记 | 含义 | 是否服务于目标 |
|---|---|---|
| 🎯 模型 | 直接影响「模型能拿到什么」 | **是，主战场** |
| 🧩 环境 | 平台机制摩擦、沙箱能力、分层结构 | 只有少数是必经之路 |
| 📁 路径 | 文件名/路径名这类可接受暴露 | 基本可放弃 |
| 🪤 误配置 | 用户以为自己关了/开了，实际没有 | 间接服务（假安全） |
| 🧱 工程 | 可维护性、可观测性、测试契约 | 不服务目标但必须做 |

**统计**：识别层 47（P0 13 / P1 18 / P2 16）+ 通道层 27（P0 8 / P1 11 / P2 8）+ 字段真空 7（P0 2 / P1 4 / P2 1）= **81 条**

### 5.1 对抗对象分布（原通道层 26 条的归属）

| 类别 | 条数 | 占比 | 具体 ID |
|---|---:|---:|---|
| 🧩 环境 | 11 | 42% | T-01、T-02、T-05、T-07、T-08、T-09、T-10、T-11、T-12、T-14、T-16 |
| 📁 路径 | 2 | 8% | T-03、T-25 —— 仓库已自行判定「接受」 |
| 🎯 模型 | 7 | 27% | T-04、T-06、T-13、T-15、T-17、T-23、T-24 |
| 🧱 工程/无关 | 6 | 23% | T-18、T-19、T-20、T-21、T-22、T-26 |

**环境类 11 条再分四档**（逐条对齐归档文档 `docs/archive/ANALYSIS-threat-focus.md` §2 的「要不要做」列）：

| 档 | 条数 | ID | 该怎么办 |
|---|---:|---|---|
| **必经之路** | 2 | T-05（host 平面三条原文落盘点）、T-07（spill 把原文写进磁盘） | 必须做——它们是原文落盘点，不是机制摩擦 |
| **一次性工程成本** | 3 | T-08、T-09、T-10（`restrict` 的用法：运行期 API / 未知名抛错 / 不能命名 `run_code`） | 做，但只是写插件的工程量，加 try/catch + 用底层工具名即可 |
| **记录即可** | 3 | T-11（KV cache 失效，性能项）、T-14（session JSONL 明文，文档写明）、T-16（写入侧审计看不出真实写入，可延后） | 不写进安全契约 |
| **删 shell 后消失** | 3 | T-01（Windows 沙箱不管读）、T-02（白名单不可靠）、T-12（`tool-fs-search` 无单工具开关） | 不做——删掉 shell 与 grep 之后这三条自动不存在 |

> **结论**：近一半篇幅在跟本地环境较劲，而不是跟模型较劲。删掉 `bash`/`read`/`grep` 之后，环境类里 **T-01、T-02、T-12 三条自动消失**，T-14 的紧迫性也大幅下降（没有 shell 就读不到 `$DSH_HOME/sessions`）。
>
> `T-27`（MCP 读通道）是本文新增的第 27 条，不在原 26 条内；它属于 🎯 模型类，且是**唯一一条既全局注册、又能完整绕过工具级脱敏**的通道。上表百分比均以原 26 条为分母。

### 5.2 识别层 R 系列（47 条）

> **R-40 / R-41 / R-42 是本次复核新增的**，全部由「库 = 实体类型」这个粒度契约反推得出，且都在本机实测过。详细推导见 §2.3、§2.3.1。

#### P0（13 条）

| ID | 问题 | 对抗 | 机制证据 | 后果 | 对策 |
|---|---|---|---|---|---|
| R-01 | **「关库」= 减少规则，正命中保留旧规则分支** | 🪤 | `custom_rules.py:403-406`：`if not rules and self.rules:` → warn + 更新签名 + return False | 用户关了库，旧规则继续脱敏；UI 显示「已关闭」但行为是「仍开启」 | 引入显式 `empty` 状态；`refresh()` 区分「加载失败」与「合法的 0 条」；加测试断言 |
| R-02 | **静默成功：库加载失败仍正常返回** | 🎯 | `load_json_rules` 非 strict 只 `_warn` 并返回 `[]`（`custom_rules.py:194`、`:213-214`） | 保护范围缩小，用户无感知。Presidio #2256：11/11 处漏检仍返回 200 | 状态接口 + UI banner + 门禁断言；「识别过且没命中」与「没有规则能识别」必须可区分 |
| R-03 | **`_load_lines` 词典缺失静默返回 `[]`** | 🎯 | `chinese_recognizers.py:121-126`：`if not fp.exists(): return []` | 用户包引用的词典缺失 → 该库零召回，无任何报错 | 用户侧词典必须 fail-loud；内置词典可保持宽容 |
| R-04 | **配置只读一次，无生产级重载入口** | 🪤 | `hooks.py:138-147`；`reset_singleton()`（`:180-184`）是测试辅助；`README.md:55` 自承认需重启 | 写进 preset 的开关**改完不生效**——直接违背 R5 | 落清单而非 preset；`server.py` 加 `reload` op |
| R-05 | **清单不进签名 → 改开关不触发 reload** | 🪤 | `custom_rules.py:367-376` 只遍历 `self.sources` | 开关状态永远停在首次加载时的快照 | 2.9 的 L1/L2 |
| R-06 | **跨库依赖未声明 → 关掉 A 使 B 失效** | 🎯 | `chinese_recognizers.py:384-386` 类注释：「必须与 18 位分开: 混合正则会让 15 位被 BANK_CARD 抢走 (13-19 位数!)，导致脱敏了但类型错误」 | 关了身份证库 → 15 位号码被识别成银行卡，**脱敏了但类型错误**（占位符类型错 → 语义丢失，非同类型不可互换） | manifest `requires` / `excludes`，加载期校验 |
| R-07 | **类型名是跨会话契约，改名即不可还原** | 🎯 | `engine.py:243`；`restore()` 按占位符字面匹配（`:266-294`） | 库的 `emits` 从 `LOCATION` 改成 `ADDRESS` → 历史会话里的 `⟦PII:LOCATION:0001⟧` 永远还原不了 | `emits` 白名单 + 内置类型名冻结；改名必须提供映射表 |
| R-08 | **规则库自己会变成明文 PII 存储面** | 🎯 | 现用户词表就是「一条一条规则」形态（`plugins/dsh-pii-guard-terms/lib/index.js:240-264`），`pattern` 是 `escapeLiteral(term)` 的原文 | 用户为提升召回把真名写成精确匹配 → 脱敏工具的配置目录成了明文 PII 集合，被 git / 云盘 / 备份 / 分享带走。**保护工具变成泄漏源。** | 见 5.5：默认禁字面量精确规则、只允许结构化模式；确需精确匹配走 `USER_TERM` 白名单通道并强制落 `.pii_presidio_store/`；门禁 #11 扩到规则库目录 |
| R-40 | **`entity_types: []` 的真实语义是「全部启用」，不是「全部关闭」** | 🪤 | `engine.py:178`：`if not self.entity_types: return results`；实测 `entity_types=[]` 与 `=None` 输出完全一致，两类都照常脱敏。UI 提示也写「全部取消勾选表示启用全部类型」（`client.js:67`） | 用户想「全关」写下空数组 → 实际「全开」。这是隐私工具里最危险的默认值方向：**以为关了一切，实际全开** | 引入独立的 `entity_types_mode: "allow-all" \| "allow-list"`，`[]` 在 `allow-list` 模式下表示全关；或至少把 `[]` 视为非法并在加载期 `_warn`。UI 侧把「全部取消」明确渲染成两个不同动作 |
| R-41 | **任意一条自定义规则会让该实体类型永久关不掉（开关失效）** | 🪤 | `engine.py:181`：`allowed = self.entity_types \| {t for t in custom if t}`。实测：关掉 `PERSON` 后，只要存在一条 `entity_type=PERSON` 的自定义规则，输出仍是 `⟦PII:PERSON:0001⟧与⟦PII:PERSON:0002⟧参会。`；无自定义规则时同样输入是 `欧阳娜娜与张伟参会。`（全明文） | 用户勾掉「人名库」、UI 打勾状态正确，**但人名仍被屏蔽**。这是「用户以为自己关了，实际没关」的反向版本：用户想放行却放行不了 | `custom` 的类型豁免只应给 `USER_TERM` 这类「纯用户词」类型，不应外溢到内置类型；或按规则来源细分优先级：内置库被禁用时连自定义规则一并停用，并在 UI 提示「该类型下有 N 条自定义规则，禁用将同时停用」 |
| R-42 | **名册通道被误当成独立库（设计错误，本次修正）** | 🎯 | 实测 `ChinesePersonRecognizer` 与 `ChineseRosterPersonRecognizer` 是**互补**而非互斥：`名单：张三、杨同初（26）、李四、欧阳娜娜。` 前者只出「张三、李四」，后者补齐「杨同初、欧阳娜娜」；`原班级学号名单（28人）…` 场景前者 5 个、后者 9 个（含「邝也」「陈敬之」） | 若把名册拆成独立库，用户关掉它 → **常见姓名被屏蔽、罕见姓名/复姓/三字名全部明文**，而用户以为还开着人名库。比全关更危险（假安全） | 名册必须作为 `builtin.person` 的内部通道（`rules[].id = "person.roster"`），在 manifest 层禁止单独 `enabled`；库级开关只按 `emits`/`entity_type` 生效 |
| R-43 | **`entity_types` 拼错 = 整库静默失效，无告警** | 🪤 | `_filter_entity_types` 只是 `r.entity_type in allowed` 集合判定（`engine.py:182`）；实测 `entity_types=["PERSOM","PHONE_NUMBER"]` → `由范志强负责，电话 ⟦PII:PHONE_NUMBER:0001⟧。` | 一行拼写错误就把整个人名库关掉，UI 打勾正常、手改 preset.json 无校验；「保护失效但工具仍报成功」 | 加载期把 `entity_types` 与实际产出的类型集合做差集，非空则 `_warn` 并保留旧值（复用 `CustomRuleSet.refresh` 的「0 条保留旧值」哲学） |
| R-44 | **`priority` 污染：一条永不匹配的规则就能翻转整类裁决** | 🪤 | `entity_priorities()` 取**最小值**（`custom_rules.py:411-421`，docstring 却写「取最高优先级」）；`_resolve_overlaps` 排序键 `(-(end-start), priority.get(type,99), start)`（`engine.py:203-206`） | 追加 `{"entity_type":"ORGANIZATION","pattern":"(?!)","priority":0}` → 等长冲突从 `PERSON` 翻成 `ORGANIZATION`，整类反转；同时 `score` **完全不参与裁决**，写 0.95 只是元数据 | ①`entity_priorities()` 与 `_PRIO` 的合并语义写进文档并加测试锁定；②拒绝 `pattern` 永不匹配却声明 priority 的规则；③或让 score 参与同长同 priority 的裁决 |

#### P1（18 条）

| ID | 问题 | 对抗 | 机制证据 | 对策 |
|---|---|---|---|---|
| R-09 | **`wants_raw` 硬编码导致坐标契约丢失** | 🎯 | `custom_rules.py:117`、`:155` | `coordinate` 库级必填（2.7） |
| R-10 | **`_PRIO` 按类型计权，15 包 vs 13 键** | 🎯 | `engine.py:38-41`；`engine.py:206` 的 `priority.get(..., 99)` | 四级解析顺序（2.10） |
| R-11 | **关库会让原本被吞掉的短实体「浮出水面」** | 🪤 | `_resolve_overlaps`（`engine.py:197-213`）只做长优先吞并，**无回退逻辑**。实测：`安徽省数据资源管理局在合肥` → 全开输出 `ORGANIZATION[安徽省数据资源管理局]`；摘掉 `ChineseOrganizationRecognizer` 后输出 `LOCATION[安徽省]` | 变更库组合必须跑全量回归并 diff 类型分布；UI 关库时提示「该库此前压制了哪些短实体」 |
| R-12 | **第四处配置副本让门禁等式失真** | 🧩 | `plugins/dsh-pii-guard-terms/lib/index.js:37` ↔ `preset.json:21` ↔ `release_gate.py:319-320`，判据 `:323` | 门禁改为「preset 路径 == 清单路径」+「清单内每库 path 存在」 |
| R-13 | **`_preset_path()` 依赖文件已存在** | 🪤 | `hooks.py:76-80`：`next((c for c in candidates if c.exists()), candidates[0])` | 新键必须指向已存在文件，否则静默退化到仓库根；加显式告警 |
| R-14 | **`warnIfPathDrift()` 只 console.error 不阻断** | 🪤 | `plugins/dsh-pii-guard-terms/lib/index.js:332-341` | 升级为强校验，或至少写入状态接口 |
| R-15 | **门禁对「关库」几乎零覆盖：13 个包无断言，只有 PERSON 被硬绑** | 🧱 | `release_gate.py:72-96`：`eng = PresidioPIIEngine(db_path=...)` **直接构造引擎、绕过 hooks**，清单里的 `enabled` 根本不读；断言只有 `counts.get("PERSON",0) > 0`（paper-01）与 `personal == 0`（normal-01 四类和）。实测 `paper-01` = `{PERSON:8, ORGANIZATION:2, LOCATION:1, EMAIL_ADDRESS:1}`，`normal-01` = `{ORGANIZATION:2}` → **关 PERSON 必 FAIL；关 ORGANIZATION/LOCATION/EMAIL 等则 FAIL 不了** | 门禁改「按清单加载」+ 逐库断言：①默认 enabled 时产出 > 0；②disabled 时该类型产出 == 0 且其余不变 |
| R-16 | **测试硬契约会被打破** | 🧱 | `tests/js/plugin_terms.mjs:115`（`routes.size === 4`）、`:223`（settings 恰好 4 键）、`tests/test_user_terms.py:125-129`、`tests/test_custom_rules.py:470-489` | 改契约必须同步改测试，**不能为过测试弱化断言** |
| R-17 | **`plugin_terms.mjs:108` 自己把 preset 写成 `{config:{custom_rules_path}}`** | 🧱 | 同上 | S2 判据改动时这一行必须一起改 |
| R-18 | **代码规则 = 加载任意 Python** | 🎯 | `custom_rules.py:251` `spec.loader.exec_module(mod)` | 第三方规则库不得自动执行；必须显式确认 + 来源标注 |
| R-19 | **用户正则无超时、无复杂度限制（ReDoS）** | 🧩 | 现状无任何 `timeout`；Cloudflare 2019-07-02 一条规则回溯导致全球 502 共 27 分钟 | 单条规则超时 + 长度上限 + 复杂度预检；超时**必须可观测**（Presidio 只 warning 是反面教材） |
| R-20 | **allow/deny 语义不对称，用户预期会落空** | 🎯 | Presidio #2455 原文：「recognizers can only add results, not remove those of other recognizers」 | 用户「加一条排除规则消误报」在当前架构下**不可能**；要么用白名单（后置过滤），要么明说 |
| R-21 | **整体覆盖写会吞用户手工规则** | 🪤 | `docs/PLAN-code-review-followups.md` S3：`readTerms()` 只认 `row.term` | 库化后写入改为「按 id 增量」，或保存前 diff 并提示 |
| R-22 | **仓库内规则库与门禁 #11 判据错位** | 🧱 | `_FORBIDDEN_TRACKED`（`release_gate.py:704-706`）**只按路径**判定，扫 `git ls-files`（`:711-712`）与 `git status --porcelain`（`:713-715`），再断言 `.gitignore` 规则数 `>= 5`（`:716-719`） | 一份放在仓库内 `rule_libraries/` 的示例库若混入真名，**#11 照样 PASS**。要么扩扫内容，要么强制示例库走虚构语料并加断言 |
| R-23 | **`replaces` 依赖 id 稳定，用户自造 id 会撞车** | 🪤 | manifest 里 `replaces`/`requires`/`excludes` 全按 `id` 引用（2.5） | 命名空间规则：内置带 `builtin.` 前缀，用户库禁用该前缀 |
| R-45 | **自定义类型不在 `_PRIO` 里 → 等长冲突永远垫底** | 🎯 | `_PRIO` 只有 13 个内置类型（`engine.py:38-41`），`_PRIO.get("AGE", 99)` = 99 vs `_PRIO["PERSON"]` = 8 | `AGE`、`USER_TERM`、工号、微信号等所有自定义字段库，与内置类型等长重叠时**无条件输**，字段被别的类型吞掉 | manifest 允许声明 `priority`，或新增 `_PRIO` 兜底规则：自定义类型默认取「同区间内置类型的最大值 + 1」 |
| R-46 | **自定义类型不从 UI 的 `knownEntityTypes` 走 → 看得见效果、关不掉开关** | 🪤 | `knownEntityTypes` 硬编码 13 类（`plugins/dsh-pii-guard-terms/lib/index.js:288-292` 的 `PRESET_DEFAULT_ENTITY_TYPES`，`:308` 直接返回）；`engine.py:181` 对 `custom` 类型豁免 | 存在 AGE 规则时：不设 `entity_types` / 13 类全勾 / 只勾 PERSON **三种都输出 `[("AGE","45")]`**，用户永远关不掉 | 让 UI 的 `knownEntityTypes` 从 `/api/.../terms` 一并返回当前规则里出现的类型；或引入 `locked: true`（如 `USER_TERM`）与普通自定义类型两种语义 |
| R-47 | **CLI 完全没有库级开关入口** | 🧩 | `presidio_pii/cli.py` grep `entity_types`/`entity-type` **零命中**；`cli.py:83` `return PresidioPIIEngine(**kwargs)` 只传 db_path/custom_rules/whitelist；`cli.py:339` restore 分支直接 `PresidioPIIEngine(db_path=":memory:")` | 同一份配置在 DSH 预设与 CLI 两条路径上行为不同；而 CLI 正是 office 二进制、离线批量场景的主入口 | 加 `--entity-types PHONE_NUMBER,ID_NUMBER` 与 `--no-entity-types`，语义与 `preset.json` 的 `entity_types` 对齐 |

#### P2（16 条）

| ID | 问题 | 说明 |
|---|---|---|
| R-24 | 「加载更多」vs「启用」没区分 | Elastic 做法：`Install all` 默认装而不启用 |
| R-25 | 「全开」不等于更安全 | Elastic 原文：Building block rules「Enabling them early is the most common cause of alert floods」；对应本项目「误报洪水 → 用户关掉一切」 |
| R-26 | 替换内置库后的升级覆盖 | Elastic：「each update replaces the rule with the Elastic version」 |
| R-27 | 无法用 JSON 替换过程式库 | 5 个过程式识别器只能被 `kind: code` 替换，而 code = 执行任意 Python。**产品决策，不是技术细节** |
| R-28 | 默认集怎么定 | Presidio 策略可抄：默认关小众、只开通用高精度 |
| R-29 | UI 承载能力不足 | `handleList` 返回 `string[]`（`plugins/dsh-pii-guard-terms/lib/index.js:347-362`），无分组/无来源/无启停；`client.js:517-522` 硬绑两块面板 |
| R-30 | 规则库与引擎版本兼容 | manifest 需 `schema` + `min_engine_version` |
| R-31 | 规则库来源可信性 | OPA 用 `.signatures.json` + JWT；nuclei 用 ECDSA。本项目至少要有「来源标注 + 内容哈希」 |
| R-32 | 分发型规则库不能落 `.pii_presidio_store/` | 该目录被 `.gitignore:5` 与门禁 #11 禁入，是用户态数据 |
| R-33 | 每 analyze 前 refresh 的 stat 成本 | 多库 = 多文件 stat；L2 的内容哈希可压到 1 次 |
| R-34 | 1s 节流窗口的行为不一致 | 点开关后 1 秒内行为仍在旧态；`reload` op 解决，但需 UI 反馈 |
| R-35 | 规则数增长对延迟的影响未量化 | 现状无 benchmark；ROADMAP 有「0.5–2ms」粗估但无库数量维度 |
| R-36 | 无「关掉这个库会漏什么」的代价提示 | 安全责任转移：用户为降误报关掉人名库 → 真姓名泄漏 |
| R-37 | 规则库「版本」与引擎版本是两条线 | `kind: code` 的库在引擎升级后可能 `analyze()` 签名不兼容，而 `CodeRuleRecognizer` 只 warn 一次并返回 `[]`（`custom_rules.py:172-177`）——又一次静默归零 |
| R-38 | 跨平台路径与编码 | `mod_name = f"pii_custom_{abs(hash(str(p.resolve())))}"`（`custom_rules.py:244`）依赖 `hash()`，而 Python 的 str `hash()` **每进程随机化**（`PYTHONHASHSEED`）→ 同一文件在不同进程模块名不同，热更新重复注册 `sys.modules` |
| R-39 | 没有「规则库」的可观测性 | 只有 `_warn` 到 stderr。需要：启用了哪些库、各产出多少实体、哪些库加载失败、上次 reload 时间 |

### 5.3 通道层 T 系列（27 条）

#### P0（8 条）

| ID | 问题 | 对抗 | 证据 | 缓解 |
|---|---|---|---|---|
| T-01 | 「禁止 bash 读文件」不可实现，沙箱层不承诺读隔离 | 🧩 | `dsh-sandbox-windows-acl/README.md`、`dsh-pwsh-sandbox/README.md:140`、`dsh-bash-sandbox/README.md` 三层一致 | **删除 bash**，或 AppContainer 级改造（成本极高） |
| T-02 | 本仓库已论证「白名单/命令判别」安全收益低，用户方案是它的更弱版本 | 🧩 | `docs/DECISION-shell-redaction.md:19` 原文「白名单只能算弱化版，命令拼接/别名/`& {}` 很容易绕过，安全收益低」 | 明确告知，不写进契约 |
| T-03 | `isError` 结果不可脱敏，而 fs 层 57 处错误中 39 处内嵌 `displayPath` | 📁 | `pipeline.js:687`、`:744-746`；`dsh-fs-local/lib/index.js` 39 处行号见附录 A | 自建工具内部 catch + 抹路径（必做）；第三方可选强 block |
| T-04 | PTC `run_code` 给程序的是 canonical value | 🎯 | `dsh-tool-executor-ptc/lib/index.js:514-521`；`dsh-tools/README.md` canonical value 限制 | 预设禁止挂 `dsh-tool-executor-ptc` + 门禁断言 |
| T-05 | 读通道多元：`grep` / `spill` / session JSONL 全是原文 | 🎯 | `tool-fs-search/README.md`、`spill-local/README.md`、`session-persistence-jsonl/README.md` | `grep` 属 agent 平面（不写就没）；`spill-local`/`spill-policy`/`session-persistence-jsonl` 属 host 平面，只能改 `$DSH_HOME/cordis.patch.yml` 或接受 |
| T-06 | 用户粘贴文本在工具级守卫之外 | 🎯 | `plugins/dsh-pii-guard/lib/index.js:661-677` 注释原文 | 文档明写；客户端侧脱敏（超出本方案） |
| T-07 | spill 落盘原文 + 两个 prepend 监听器顺序无保证 | 🎯 | `dsh-spill-policy/lib/index.js:237-255`（`:239` 姓名级豁免）、`cordis/lib/index.js:919-929`（`unshift`） | 自建工具自限长；门禁断言 spill 目录里是占位符 |
| T-27 | **MCP 工具是第四条读通道，且全局注册、agent 平面管不到** | 🎯 | `dsh-mcp-client/lib/index.js:153` 用全局 `ctx.tools.register`；`$DSH_HOME/cordis.patch.yml` 挂 6 个 server；`scripts/mcp-codebuddy.js:135-138` 把 `--task/--workdir/--files` 交给外部 CLI；`mcp__playwright__*` 可开 `file://` | home 层删除直读类 MCP（codebuddy / playwright）；其余按需保留 |

#### P1（11 条）

| ID | 问题 | 对抗 | 证据 | 缓解 |
|---|---|---|---|---|
| T-08 | `restrict` 是运行期 API，不能配在 yml | 🧩 | `dsh-tools/lib/index.js:453-467` | 写 JS 插件在 `agent/created` 时 restrict |
| T-09 | `restrict` 命名未知工具直接抛错，组合一变插件启动失败 | 🧩 | `:464-466` | 包 try/catch + 白名单校验已知名 |
| T-10 | `restrict` 不能命名 `run_code`（保留传输名） | 🧩 | `:463` | 只能 restrict 底层工具 |
| T-11 | `restrict` 变更会 invalidate KV cache | 🧩 | `dsh-tools/README.md` 原文 | 预设期一次性定好，别在会话中途改 |
| T-12 | `tool-fs-search` 无单工具开关（只能整包取舍） | 🎯 | `tool-fs-search/README.md` 配置表只有 `sampleOverCapGlobResults` 等；web-app `:509-510` 已 disabled | 预设里**不写**即可；需 grep 能力时自建 `grep_redacted` |
| T-13 | `spill` 的 `retrievalHint` 主动教模型去读原文 | 🎯 | `spill-local/README.md` 原文 | 自建工具里抹掉 locator / hint |
| T-14 | 会话 JSONL 明文（默认 zstd 也非加密） | 🎯 | `session-persistence-jsonl/README.md` | 文档明写；或改 `compression: none` + 受限目录（但 shell 仍可读） |
| T-15 | `failOpen` 开关存在，打开就变成「无保护工具面」 | 🎯 | `plugins/dsh-pii-guard/lib/index.js:93`、`:128`、`:603` | 极简预设**禁止** `PII_GUARD_FAIL_OPEN=1` + 门禁断言 |
| T-16 | 写入侧 tool/call 落盘的是占位符版参数 → 审计看不出真实写入 | 🧱 | `plugins/dsh-pii-guard/lib/index.js:618-659` 注释原文 | 增「写入时记 ph→type」审计事件，只记类型不记原文 |
| T-17 | 占位符编号跨文档共享（`counters` 全局递增），跨文档同号可能撞 | 🎯 | `engine.py:243` | 批量处理必须 `commit=False` 后整批 commit（已有约定），或改文档内计数 |
| T-18 | docx `md` 中转丢段内格式，与「按模板还原」冲突 | 🧱 | `documents.py:295-302` 注释、`office-docx/SKILL.md` 原文 | 产品拍板路线 α / β（见 7） |

> 注：`T-12` 原编号为 P1-5，`T-13` 原为 P1-6，`T-14` 原为 P1-7 —— 因合并后插入 T-27 与重排，编号已按对抗对象重新聚集（🎯 类连排）。旧编号对照见附录 B。

#### P2（8 条）

| ID | 问题 | 证据 | 缓解 |
|---|---|---|---|
| T-19 | `docxtpl` 本机不可用，模板占位符填充需自研 | 本机 `ImportError` | 自研（`python-docx` 遍历 + run 级替换）或加依赖 |
| T-20 | 中日韩文字需显式 `w:eastAsia` 字体 | `office-docx/SKILL.md` 原文 | 生成器里统一设 eastAsia |
| T-21 | `python-docx` 不分页不渲染 | `office-docx/SKILL.md` 原文 | 明写限制；需渲染时走 `office-render` |
| T-22 | md 中转丢批注/修订/内容控件/域代码/公式 | `documents.py:321-347` 已在捞 textbox/comments，说明这些是真实格式 | 路线 β 时明写「不保留」 |
| T-23 | 自建工具的正则无超时，用户自定义规则可 ReDoS | 参考 Presidio `REGEX_TIMEOUT_SECONDS` 默认 60s 且超时只 warn | 加超时 + 指标 |
| T-24 | `restrict` deny 掉 `read_image` 会导致附件图无法看（现有 pii-guard 已这么做） | `plugins/dsh-pii-guard/lib/index.js:650` + 注释 | 保持现状，文档明写 |
| T-25 | `present` 工具暴露源文件路径 | `office-docx/SKILL.md`「It exposes the current source file without copying or preserving its bytes」 | 文件名在写入前就改成占位符名 |
| T-26 | 持久 shell 的 description 写着误导性文案 | `dsh-sdk-minimal/cordis.patch.yml:166` | 自建工具描述要写准确 |

### 5.4 字段真空 F 系列（7 条，本文新增）

这一组是前两份报告**完全没提**的，但恰恰是最直接服务目标的。

| ID | 缺陷 | 级别 | 实测 | 对策 |
|---|---|---|---|---|
| F-01 | **年龄（AGE）零覆盖** | **P0** | `grep "年龄\|BIRTH"` 在 `presidio_pii/*.py` **0 命中**；`该同志年龄 45 周岁` / `年龄：38` / `今年 40 岁` / `现年 52 岁` 全漏 | 加 `AGE` 规则库（见 5.6） |
| F-02 | **出生日期 / 性别 / 民族 / 学历 零覆盖** | **P0** | `出生日期：1990-03-07`、`生于1985年12月`、`性别：男，民族：汉族`、`学历：硕士研究生` 全漏 | 每个字段一个 `kind: regex` 库，标签驱动 |
| F-03 | 微信 / 工号 等账号类零覆盖 | P1 | `微信：zhangsan_1985`、`工号：E123456` 全漏 | 加 `IM_ACCOUNT` / `EMPLOYEE_ID` 库 |
| F-04 | 姓名弱上下文漏 | P1 | `员工范志强，男，45岁。` → `[]` | 补左上下文候选词（职务词 + 姓名） |
| F-05 | 住址尾号丢失 | P1 | `住址：北京市朝阳区建国路88号3单元501。` → 只到「3单元」，`501` 丢 | 门牌正则补「室/号/单元 + 楼层房号」 |
| F-06 | 机构名左边界吞代词/动词 | P1 | `他是公司总经理。` → `ORGANIZATION 他是公司`；`担任办公室主任一职。` → `ORGANIZATION 担任办公室` | 扩 `_ORG_PREFIX_WORDS` / `_trim_org_start` |
| F-07 | 籍贯只到省 | P2 | `籍贯：山东济南。` → 只识别「山东」 | 籍贯字段专用规则（省+市） |

**F-01 / F-02 为什么是 P0**：它们直接对应用户点名的「年龄」，且 `preset.json` 的 13 类里没有这些类型——用户开了「PII 防护」也不会得到任何保护，属于「保护失效但工具报成功」。

### 5.5 展开：规则库本身就是新的泄露面（R-08）

这一条值得单独说，因为它是需求的**内生副作用**，不是实现 bug。

**机制**：现有 `USER_TERM` 通道的规则形状就是「字面量」——
```jsonc
{ "name": "user-term-0001", "entity_type": "USER_TERM",
  "pattern": "张三", "score": 0.95, "priority": 0, "term": "张三" }
```
`pattern` 是 `escapeLiteral(term)` 的结果（`plugins/dsh-pii-guard-terms/lib/index.js:241-248`），即**原文以明文形式躺在磁盘上**。当前只有「用户主动屏蔽词」一个入口，体量有限；一旦开放「加载/替换整个规则库」，动机链条会自然把体量放大：

> 想让某个人名 100% 被识别 → 最直观的做法就是把人名写成一条精确匹配规则。

于是**为了脱敏而维护的配置文件，本身成了一个明文 PII 语料库**。它会：
- 被 `git status` 看到（除非落在 `.pii_presidio_store/`，`.gitignore:5` 已覆盖）；
- 被云盘 / OneDrive / 同步工具 / 备份带走；
- **不会**被门禁 #11 直接拦住——#11 也扫 `git status --porcelain` 的未跟踪项（`release_gate.py:713-715`），但判据是**路径正则**（`:704-706`），只认「放在禁地里的文件」，不认「放在允许位置、内容是真实 PII」的规则库。一份放在仓库内 `rule_libraries/` 的示例库若混入真名，**#11 照样 PASS**（R-22）；
- 被用户分享给同事（「我这个规则库识别率很高，发你一份」）——**分享规则库 = 分享一批真实姓名**。

**对策（三层）**：

| 层 | 措施 |
|---|---|
| 规则层 | 规则库默认只接受**结构化模式**（正则/词边界/上下文），不接受「单条字面量精确匹配」。需精确匹配时强制走 `USER_TERM` 白名单通道 |
| 存储层 | 用户规则库与清单**必须**落 `.pii_presidio_store/`（已 gitignore），仓库内只放**明显虚构**的示例（复用 `agent.md` §1 的虚构准则） |
| 校验层 | 门禁新增两项：①扫 `.pii_presidio_store/` 之外的规则文件是否含疑似真实 PII；②检查仓库内示例规则库的 `pattern` 是否命中已知虚构语料白名单 |

**这条与「替换已有规则库」需求直接冲突**：替换意味着用户会拿到并改写一份完整规则库，而完整规则库如果要「识别率高」，就必然包含大量真实样本。**设计时必须明确：内置规则库是逻辑（边界/上下文/后缀），不是样本。** 一旦内置库混入样本，用户会照着抄，整条防线从源头崩掉。

### 5.6 年龄规则的可实现性（已实测跑通）

不需要改引擎，用现成的 `custom_rules` JSON 通道加一条：

```json
[{"name": "age-ctx", "entity_type": "AGE",
  "pattern": "\\d{1,3}(?=\\s?周?岁)", "score": 0.85, "priority": 5,
  "context_hint": ["年龄", "现年", "今年", "年方", "周岁"]}]
```

**实测结果**：
- `该同志年龄 45 周岁，现任副主任。` → `该同志年龄 ⟦PII:AGE:0001⟧ 周岁，现任⟦PII:JOB_TITLE:0001⟧。`
- `restore(rd.text, "probe", doc_id="d1")` → 原文，**无损 `True`**，`restored = {'⟦PII:AGE:0001⟧': '45', '⟦PII:JOB_TITLE:0001⟧': '副主任'}`
- `_PRIO` 里没有 `AGE` 不影响（未声明类型兜底 99）

**但朴素写法会误伤**（实测）：

| 规则 | `覆盖20岁以上人群` | `儿童用药：3岁以下禁用` |
|---|---|---|
| `\d{1,3}\s*(?:岁\|周岁)` | ❌ 误判 `AGE: 20岁` | ❌ 误判 `AGE: 3岁` |
| 上表带 `context_hint` 的写法 | ✅ 不命中 | ✅ 不命中 |

这正是 `agent.md` §3「无边界不成实体」要防的：**年龄不能靠单位词判定，必须靠标签上下文**，并复用 `_QUANTITY_PREFIX`（`共分设含计约由`）那类排除逻辑。

**两个实现坑**：
1. `custom_rules` 传 JSON 必须传**文件路径**（`custom_rules=str(path)`）；直接传 list of dict 会 `AttributeError: 'dict' object has no attribute 'analyze'`（`engine.py:154`）。
2. `restore()` 必须传匹配的 `doc_id`，否则 `RedactResult.text` 原样返回占位符。`restore` 返回的是 `RedactResult` 不是 str（字段：`text/doc_id/entity_counts/n_restored/n_replaced/restored/unrestored/n_whitelisted/session_id`）。

顺带一个语言约束：Python 正则**不支持变长 lookbehind**，`(?<=年龄\s?)\d{1,3}(?=\s?周?岁)` 会报 `look-behind requires fixed-width pattern`，规则被跳过并 warn（不中断，符合设计）。
### 5.7 库级开关的五个实现陷阱（本轮实测新增，R-43~R-47）

把「库 = 实体类型」这个粒度当真之后，实测出五个会「静默改变用户意图」的地方。它们全部是 P0/P1，且都不是设计失误，而是**语义没定清楚**。

#### R-43（P0）`entity_types` 拼错 = 整库静默失效，无告警

```python
PresidioPIIEngine(entity_types=["PERSOM", "PHONE_NUMBER"])   # 少一个 N
# 输出: 由范志强负责，电话 ⟦PII:PHONE_NUMBER:0001⟧。
#       ^^^^^^ PERSON 库整体消失，原文直接进模型
```

`_filter_entity_types` 只是 `r.entity_type in allowed` 的集合判定，拼错的字符串永远不会命中任何实体，于是**一行 putStr 写错就把整个人名库关掉了**。UI 保存侧有白名单校验（`plugins/dsh-pii-guard-terms/lib/index.js:326-332`：`if (!allowed.has(raw)) throw new Error("unknown entity type: " + raw)`），但**直接编辑 `preset.json` 完全没有校验路径**——而 `preset.json` 是文档里教用户手改的文件。

对策：加载期把 `entity_types` 与 `get_chinese_recognizers()` 实际产出的类型集合做差集，差集非空则 `_warn` 并保留旧值（复用 `CustomRuleSet.refresh` 的「0 条规则保留旧值」同一套哲学）。

#### R-44（P0）规则只提供 `priority`，一条永不匹配的规则就能翻转整类裁决

`_filter_entity_types` 之后是 `_resolve_overlaps`，排序键 `(-(end-start), priority.get(type, 99), start)`。而 `entity_priorities()`（`presidio_pii/custom_rules.py:411-421`）对同类型**取最小值**，于是：

```python
# 等长同区间冲突：PERSON(prio 8) vs ORGANIZATION(prio 10)
基线                                    -> ["PERSON"]
# 追加一条永不匹配的规则，只声明 priority=0
{"name":"flip","entity_type":"ORGANIZATION","pattern":"(?!)","score":0.9,"priority":0}
追加后                                  -> ["ORGANIZATION"]   # 整类裁决顺序反转
```

一条 `pattern: "(?!)"`（永不匹配，不产生任何实体）的规则，仅仅因为写了 `priority: 0`，就能把 `ORGANIZATION` 的全局优先级从 10 抬到 0，压过 `PERSON`。用户理解不了这个后果，UI 也提示不了——它看起来只是「加了一条自己的规则」。

同时注意 **`score` 完全不参与裁决**：`_resolve_overlaps` 的排序键里没有它，`redact()` 里也没有用它。自定义规则里写 `score: 0.95` 只是元数据，不影响任何合并结果（实测同类型 `ABCD` score 0.10 依然吞掉 `AB` score 0.99，因为长优先）。

#### R-45（P1）自定义类型不在 `_PRIO` 里 → 等长冲突永远垫底

`_PRIO` 只有 13 个内置类型，`AGE`、`USER_TERM`、任何自定义类型都兜底 99（数值越大优先级越低）。实测 `_PRIO.get("AGE", 99)` = 99 vs `_PRIO["PERSON"]` = 8：**AGE 与 PERSON 等长重叠时 AGE 无条件输**。字段类库（年龄、工号、微信号）全都落在这个坑里。

#### R-46（P1）自定义类型不从 UI 的 `knownEntityTypes` 走 → 用户看得见效果、关不掉开关

`knownEntityTypes` 硬编码为 13 个内置类型（`plugins/dsh-pii-guard-terms/lib/index.js:288-292` 的 `PRESET_DEFAULT_ENTITY_TYPES`，`:308` 直接返回）。而 `engine.py:181` 的类型豁免让自定义类型**永远保留**：

```python
# 存在一条 AGE 规则时
不设 entity_types   -> [("AGE", "45")]
13 类全勾           -> [("AGE", "45")]   # AGE 不在勾选列表里，但照样生效
只勾 PERSON         -> [("AGE", "45")]   # 同上
```

对 `USER_TERM` 这是**正确的设计意图**（用户屏蔽词不该被内置类型勾选顺手关掉）。但对 `AGE` 这类「自定义但属于隐私字段」的库，就成了「UI 里没有这个开关，行为却一直生效」——用户永远看不见也关不掉。

#### R-47（P1）CLI 完全没有库级开关入口

`presidio_pii/cli.py` 全文件 grep `entity_types` / `entity-type` **零命中**；`cli.py:83` `return PresidioPIIEngine(**kwargs)` 只传 `db_path` / `custom_rules` / `whitelist`；`cli.py:339` 的 restore 分支直接 `PresidioPIIEngine(db_path=":memory:")`。

后果：**同一份配置在两条使用路径上行为不同**。DSH 预设里勾掉人名库，`dsh-pii-guard` 生效；同一用户跑 `presidio-pii redact` 命令行，人名库照常工作。而 CLI 恰恰是文档里列的四个补充场景（office 二进制、离线批量）的主入口。

对策：`--entity-types PHONE_NUMBER,ID_NUMBER` 与 `--no-entity-types`（全部关闭）两个参数，语义与 `preset.json` 的 `entity_types` 完全对齐。

#### 补充：`entity_types: []` 的两处实现不同步

| 位置 | 语义 |
|---|---|
| `presidio_pii/engine.py:178` | `if not self.entity_types: return results` → **全部启用** |
| `plugins/dsh-pii-guard-terms/client.js:67` | 「全部取消勾选表示启用全部类型」→ 同上 |
| `docs/` 各处的 manifest 示例 | 未说明 |

三处一致，所以不是 bug——但它和用户对「空集合 = 空集」的直觉相反。这是 R-40 的根因，也是**唯一一个「行为正确但直觉错误」必须靠文案解决**的点。

### 5.8 性能实测：构建期不加载 vs 运行期过滤（D7 的量化依据）

3480 字符合成文本（含人名/机构/地名/职务/电话/身份证），jieba 可用，warmup 1 次 + 取 5 次平均：

| 方案 | 15 识别器中实际运行 | 耗时 | 相对全开 |
|---|---:|---:|---:|
| A. 全开（不设 `entity_types`） | 15 | **18.4 ms** | 1.00× |
| B. 真删识别器（只留 PHONE + ID） | 2 | **3.2 ms** | **0.17×（5.75× 加速）** |
| C. 运行期过滤（15 个照跑，结果过滤） | 15 | **13.6 ms** | 0.74×（只省 26%） |

**这就是 D7「构建期不加载 vs 运行期过滤」的量化答案**：当前 `preset.json` 勾选走的是 C，用户以为关掉一个库能省时间，实际只省 26%；改成构建期不加载（B）能拿到 5.75×。

但 B 有一个前置条件：`entity_types` 必须在 `__init__` 时就知道。而当前 `set_entity_types()` 是运行期改 `self.entity_types`，`_sync_recognizers()`（`engine.py:94-96`）用的是 `self._builtin_recognizers + list(self._rule_set.rules)`，**没有任何「按类型筛识别器」的逻辑**。要实现 B，得让 `_sync_recognizers` 接收 `entity_types` 并过滤 `_builtin_recognizers`——这同时解决了 R-41（自定义规则给内置类型续命）吗？不，两者是独立问题。

#### 附带发现：热更新已经存在，不需要重启

这一点修正了此前「改路径要重启」的笼统印象——**只有路径要重启，勾选不用**：

| 改动 | 生效方式 | 位置 |
|---|---|---|
| `preset.json` 的 `entity_types` / `whitelist_path` | 下次工具调用即生效（一次 `stat`） | `hooks.py:177-192` `_maybe_reload_preset` + `hooks.py:207` |
| `preset.json` 的 `custom_rules_path` / `db_path` | **进程重启**（`_get_engine` 单例只在首次构造时读） | `hooks.py:198-207` |
| 规则文件内容 | 1 秒内（`rules_check_interval` 节流） | `custom_rules.py:379-409` |

`_preset_signature()`（`hooks.py:168-174`）只比 `(st_mtime_ns, st_size)`。实测同长度改写也会更新 `mtime_ns`，所以正常编辑器保存不会漏检；真正的漏检场景是 `os.utime` 保留时间戳的写入（rsync、某些 git checkout 路径）。

---

## 6. 路线图

### Phase 0（1 天）：字段补齐 —— **最高 ROI，先做**

目标：字段覆盖面 13/22 → 22/22。

1. 加 `AGE` / `BIRTH_DATE` / `GENDER` / `ETHNICITY` / `EDUCATION` / `IM_ACCOUNT` / `EMPLOYEE_ID` 七个 `kind: regex` 规则库（走 `custom_rules` JSON 通道，每条带 `context_hint`，不写裸单位词）。
2. 修 F-04（姓名弱上下文）、F-05（住址尾号）、F-06（机构左边界）、F-07（籍贯）。
3. 每种新字段必须补 `test_common_words_are_not_pii` 类负样本用例，并在**有/无 jieba 两种模式**各跑一次（`agent.md` §3）。
4. 门禁 #1 扩到新字段（当前只硬绑 PERSON）。

> 为什么排第一：成本低（不改引擎）、直接对目标、可独立验证。而且这组字段正是用户点名的。

### Phase 1（1–2 天）：「删掉 bash」版最小 PII 预设

1. `tool-fs` 全部五开关关掉，改用自建 `read_redacted` / `write_raw` / `restore` / `ls`。
2. 预设 `plugins` 数组**不写** `tool-fs-search` / `tool-bash` / `tool-pwsh` / `tool-web` / `tool-todo`（agent 平面不写就没）。
3. 自建工具**内部自限长**（避免触发 spill-policy）。
4. 自建工具**内部 catch fs 错误并抹 `displayPath`**（绕开 T-03 的 isError 通道）。
5. 加门禁三条：①预设不得出现 `dsh-tool-executor-ptc`；②预设不得出现 `PII_GUARD_FAIL_OPEN=1`；③构造超长结果后断言 spill 目录里是占位符。
6. home 层删除 `mcp-codebuddy` 与 `mcp-playwright`（T-27）。

### Phase 2（3–5 天）：格式能力补齐

1. `write_docx` 工具：内部起 Python 调 `python-docx`，做「模板占位符 → 原文」的 run 级替换（不能用 `paragraph.text=`，会丢格式）。
2. 产品拍板路线 α / β（见 7）。
3. 明写不支持的格式（批注/修订/内容控件/域代码/公式）。

### Phase 3（1 周）：规则库地基（不带 UI）

1. `RuleSpec` 加 `rule_id` / `enabled`；新增 `LibrarySpec`（`id/name/kind/emits/coordinate/requires/excludes/replaces/priority`）。
2. `RegexRuleRecognizer` / `CodeRuleRecognizer` 的 `wants_raw` 改为读 `coordinate`。
3. `CustomRuleSet` 支持清单（`manifest` 参数 + 签名覆盖清单 + 三态 `ok/empty/degraded`）。
4. `engine._sync_recognizers()` 加过滤钩子；`_prio` 改四级解析。
5. 测试：关库后结果里真的没有；全关返回合法空态；`requires` 不满足时拒绝。

### Phase 4（1 周）：内置库化

1. 拆 `chinese_recognizers.py`：`_is_cjk` 等共享工具进公共模块；删死代码 `_next_is_boundary`（`chinese_recognizers.py:193`，**0 处使用**）。
2. 合并重复常量：`_ORG_SUFFIX`(:767)/`_RE_ORG`(:772)/`_ORG_SUFFIX_EXT`(:786) 三份后缀表；`_LOC_SUFFIX_CHARS`(:693) 与 `_re_generic` 手写 `(?:省|市|县|区)`(:706)。
3. 内置 manifest（`kind: builtin`）与用户 manifest 同构。
4. 门禁 #1 改「按清单加载」+ 逐库断言（R-15）。

### Phase 5（待定）：UI 与位置一致性校验

1. 清单 schema + 校验器（Python 侧，供 CLI/引擎/门禁共用）。
2. `server.py` 加 `reload` op。
3. UI：库列表（名称/来源/类型/规则数/开关/三态），新增路由 —— **`tests/js/plugin_terms.mjs:115` 的 `routes.size === 4` 会挂，需同步改**。
4. 「替换」流程：`replaces` 字段 + 冲突提示 + 升级策略。
5. 位置一致性校验（约束五）。

---

## 7. 待拍板的决策（合并去重后 10 条）

| # | 决策 | 选项 | 建议 |
|---|---|---|---|
| D1 | **删除 shell 还是保留？** | 删 / 保留但接受泄漏 | **删**。约束一~三已经把「保留」论证死；保留等于承认工具级方案无效 |
| D2 | **docx 走路线 α 还是 β？** | α 原地改写（保样式）/ β 套模板（跨格式） | **α 优先**，β 作为「用户明确要求套模板」时的显式选项 |
| D3 | **isError 通道怎么办？** | 自建工具抹路径 / 第三方全 block | **自建工具抹路径**（必做）+ 第三方保持现状 + 逃生开关（用户不能自关） |
| D4 | **用户粘贴文本认不认？** | 承认不管 / 客户端脱敏 / pre-step 改写 | **承认不管并写进文档**；客户端方案单独立项 |
| D5 | **NER 要不要纳入？** | 纳入 / 不纳入 | **不纳入**（ROADMAP 已有结论：tiny 1:3 性价比不足） |
| D6 | **规则库粒度** | 只库级 / 库级 + 规则级 | **库级为主**，规则级进高级面板 |
| D7 | **开关语义** | 构建期不加载 / 运行期过滤 | **构建期不加载**（§2.6）——不只是语义选择：实测 5.75× 性能差（§5.8），运行期过滤只省 26% |
| D8 | **默认集** | 全开 / 只开通用高精度 | **只开通用高精度**，人名/电话/身份证/邮箱/银行卡默认开，机构/地名/职务默认关（误报率最高），AGE 类默认开 |
| D9 | **清单落点** | 用户态 / 仓库内 | **两者都要**：内置清单在仓库，用户清单在 `.pii_presidio_store/` |
| D10 | **占位符保护打在哪一层？** | `analyze()` 全局保护区 / 只改 `RegexRuleRecognizer` / 加载期拒绝危险 pattern | **`analyze()` 全局保护区**（§4.6 约束六）：复用 `_drop_uuid_spans` 形状，一处解决全部通道，内置规则零影响 |

**「替换」的边界**（原 D3）：允许 JSON 替换人名库吗？技术上不行——只有 `kind: code` 能替换，而 code = 执行任意 Python。**建议：内置过程式库标记为「不可数据化替换」，UI 明示。**

---

## 8. 验收契约（改之前先认清哪些是硬约束）

| 契约 | 位置 | 会不会被打断 |
|---|---|---|
| `routes.size === 4` | `tests/js/plugin_terms.mjs:115` | 加路由必挂 |
| settings 文件恰好 4 键 | `tests/js/plugin_terms.mjs:223` | 加设置键必挂 |
| 清空写 1 条 `(?!)` | `tests/js/plugin_terms.mjs:202-204` | 库化后语义要重定义 |
| 空数组 → 0 条规则 | `tests/test_user_terms.py:125-129` | 与 R-01 直接相关 |
| 破损/删除文件保留旧规则 | `tests/test_custom_rules.py:470-489` | 与 R-01 直接相关 |
| `refresh()` 返回「是否真的换过规则」，条数由 `reload_custom_rules()` 返回 | `custom_rules.py:379-409`、`engine.py:98-105` | 改签名逻辑必须保持两个返回值语义（`test_broken_file_keeps_previous_rules` 断言 `reload_custom_rules() == 1`） |
| 门禁 #1 只硬绑 PERSON + 四类负例 | `release_gate.py:72-96`（`:86-87` 的 `ok = ...`；**直接构造引擎，绕过 hooks，不读 enabled**） | 关掉 PERSON 必 FAIL；关掉其余 13 个包则**不 FAIL**（R-15） |
| 门禁 #10 源码树 digest | `release_gate.py:628-643`（覆盖 `presidio_pii/**` + `pyproject.toml`），校验在 `:663` | 改引擎必重跑 `.pii_presidio_store/update_tree_digest.py`（**不在 `tools/` 下**）重算 `release/presidio-pii-dsh-0.1.0.json`；脚本本体在 gitignore 内，CI 无此脚本 |
| 识别器双模式（有/无 jieba） | `agent.md` §3 | 每个过程式库都要各跑一次 |

**新增契约（本总纲建议）**：

| 契约 | 理由 |
|---|---|
| 预设不得出现 `dsh-tool-executor-ptc` | 约束二（T-04） |
| 预设不得出现 `PII_GUARD_FAIL_OPEN=1` | T-15 |
| 自建工具的返回长度必须落在 `spill-policy` 的 `maxInlineTokens` 以内 | 约束七（T-07） |
| spill 目录内容断言为占位符 | T-07 |
| 每个规则库默认 enabled 时产出 > 0；disabled 时该类型产出 == 0 | R-15 |
| `preset.json` 的 `entity_types` 必须与实际识别器产出类型集合无差集（差集非空即 FAIL） | R-43 |
| 占位符二次脱敏不变式：`analyze(analyze(text).text)` 中不得出现嵌套 `⟦PII:⟦PII:` | 约束六（R-44 同源） |
| `entity_types: []` 的语义必须以显式测试锁定（当前 = 全部启用） | R-40 |
| CLI 的 `--entity-types` 与 `preset.json` 的 `entity_types` 行为一致 | R-47 |

---

## 9. 参考资料

**Microsoft Presidio**
- 规则注册表配置：https://presidio.dataprivacystack.org/analyzer/recognizer_registry_provider/
- 默认注册表（多数国家识别器默认 `enabled: false`）：https://raw.githubusercontent.com/data-privacy-stack/presidio/main/presidio-analyzer/presidio_analyzer/conf/default_recognizers.yaml
- `remove_duplicates` 只做同类型压制：https://raw.githubusercontent.com/data-privacy-stack/presidio/main/presidio-analyzer/presidio_analyzer/entity_recognizer.py
- 反模式：#2256（静默 200 漏检）、#2277（配置键未生效）、#950（移除 API 失效）、#2455（allow/deny 不对称）、#2417（白名单放大成全放行）

**业界实践**
- spaCy EntityRuler（长优先 + 同长取先）：https://spacy.io/api/entityruler
- OPA Bundles（roots 划界 + 验签 fail-safe）：https://www.openpolicyagent.org/docs/management-bundles
- Elastic 预置检测规则（安装≠启用、例外优于关闭）：https://www.elastic.co/docs/solutions/security/detect-and-alert/install-prebuilt-rules
- Cloudflare 2019 ReDoS 复盘：https://blog.cloudflare.com/details-of-the-cloudflare-outage-on-july-2-2019/
- gitleaks 单条坏正则 panic：#1846

**本仓库**
- 引擎与规则加载：`presidio_pii/engine.py`、`presidio_pii/custom_rules.py`、`presidio_pii/chinese_recognizers.py`
- 配置面：`presidio_pii/hooks.py`、`.agent-presets/presidio-pii/preset.json`
- UI：`plugins/dsh-pii-guard-terms/lib/index.js`、`client.js`
- 拦截：`plugins/dsh-pii-guard/lib/index.js`
- 门禁：`tools/release_gate.py`、`docs/RELEASE-GATE.md`
- 设计约定：`agent.md` §3
- DSH 侧：`dsh-tool-fs`、`dsh-tools`、`dsh-tool-executor-ptc`、`dsh-spill-policy`、`dsh-mcp-client`、`dsh-web-app/cordis.patch.yml`、`dsh-base/cordis.patch.yml`

---

## 附录 A：关键源码位置索引

### 引擎与规则

| 位置 | 内容 |
|---|---|
| `presidio_pii/engine.py:38-41` | `_PRIO` 13 类优先级（含注释「人名高于机构名…地名高于人名」） |
| `presidio_pii/engine.py:92-96` | `_sync_recognizers()` = `builtin + rules`，无过滤钩子 |
| `presidio_pii/engine.py:148` | `rec.analyze(text if wants_raw else probe)` |
| `presidio_pii/engine.py:203-206` | `_resolve_overlaps` 排序键 `(-len, priority, start)` |
| `presidio_pii/engine.py:243` | 占位符生成 `⟦PII:{ptype}:{seq:04d}⟧` |
| `presidio_pii/custom_rules.py:92-100` | `RuleSpec` 定义 |
| `presidio_pii/custom_rules.py:117`、`:155` | `wants_raw = True` 硬编码 |
| `presidio_pii/custom_rules.py:244` | `mod_name = f"pii_custom_{abs(hash(...))}"`（PYTHONHASHSEED 缺陷） |
| `presidio_pii/custom_rules.py:367-376` | `_source_signature()` 只遍历 `self.sources` |
| `presidio_pii/custom_rules.py:403-406` | `if not rules and self.rules:` → 保留上一份 |
| `presidio_pii/custom_rules.py:411-421` | `entity_priorities()` 同类型取最小值 |
| `presidio_pii/chinese_recognizers.py:121-126` | `_load_lines` 文件缺失返回 `[]` |
| `presidio_pii/chinese_recognizers.py:193` | `_next_is_boundary` —— **死代码，0 处调用** |
| `presidio_pii/chinese_recognizers.py:384-386` | 类注释：ID15 必须与 18 位分开，否则被 BANK_CARD 抢走 |
| `presidio_pii/chinese_recognizers.py:452-471` | `IpMacRecognizer` 一对象两类型，不调 `super().__init__` |
| `presidio_pii/hooks.py:76-80` | `_preset_path()` 依赖文件已存在 |
| `presidio_pii/hooks.py:138-147` | `_get_engine()` 单例，配置只读一次 |
| `presidio_pii/server.py:92-102` | 只有 `redact` / `restore`，无 reload |
| `presidio_pii/documents.py:295-302` | `_set_docx_paragraph` 只保留首个 run |
| `presidio_pii/documents.py:564-577` | `_HANDLERS` 12 个格式 |
| `presidio_pii/documents.py:582` | `READ_ONLY_EXTS = {".pdf", ".doc", ".xls"}` |

### DSH 侧

| 位置 | 内容 |
|---|---|
| `dsh-tool-fs/lib/index.js:1967-1989` | `read`/`readImage`/`write`/`edit`/`applyPatch` 五开关 |
| `dsh-tools/lib/index.js:453-467` | `restrict()` 四个约束 + disposer |
| `dsh-tools/lib/pipeline.js:673` | post-execute waterfall |
| `dsh-tools/lib/pipeline.js:684` | content/value 不能同时 |
| `dsh-tools/lib/pipeline.js:687` | isError 不能换 value |
| `dsh-tools/lib/pipeline.js:744-746` | isError 原样返回 |
| `dsh-tool-executor-ptc/lib/index.js:514-521` | `settle` 给程序的是 `value` |
| `dsh-spill-policy/lib/index.js:237-255` | spill post-execute（`:239` 的 `read` 豁免） |
| `cordis/lib/index.js:919-929` | `prepend` = `unshift` |
| `dsh-mcp-client/lib/index.js:153` | MCP 工具用全局 `ctx.tools.register` |
| `dsh-web-app/cordis.patch.yml:467-476` | agent 平面说明（决定性注释） |
| `dsh-web-app/cordis.patch.yml` | 22 行 `disabled: true`（行号见 3.2） |
| `dsh-base/cordis.patch.yml:138-139/411-415/501-506` | host 平面行 |
| `dsh-fs/lib/types/index.d.ts` | `readText`:178、`readBytes`:199、`listDir`:224、`writeText`:237 |

### `dsh-fs-local/lib/index.js` 的 39 处带路径 FsError

`193,202,205,281,283,284,309,310,343,371,373,387,403,414,473,502,505,506,508,509,514,515,596,618,668,746,747,937,938,939,976,1021,1023,1024,1025,1030,1031,1032,1037`

另 18 处**不带**路径：`129,143,184,419,451,484,493,601,743,834,836,856,858,867,868,870,970,985`

---

## 附录 B：旧编号对照表

### 识别层（原 `RESEARCH-rule-libraries.md`）

| 新 ID | 旧 ID | | 新 ID | 旧 ID | | 新 ID | 旧 ID |
|---|---|---|---|---|---|---|---|
| R-01 | P0-1 | | R-09 | P1-1 | | R-24 | P2-1 |
| R-02 | P0-2 | | R-10 | P1-2 | | R-25 | P2-2 |
| R-03 | P0-3 | | R-11 | P1-3 | | R-26 | P2-3 |
| R-04 | P0-4 | | R-12 | P1-4 | | R-27 | P2-4 |
| R-05 | P0-5 | | R-13 | P1-5 | | R-28 | P2-5 |
| R-06 | P0-6 | | R-14 | P1-6 | | R-29 | P2-6 |
| R-07 | P0-7 | | R-15 | P1-7 | | R-30 | P2-7 |
| R-08 | P0-8 | | R-16 | P1-8 | | R-31 | P2-8 |
| | | | R-17 | P1-9 | | R-32 | P2-9 |
| | | | R-18 | P1-10 | | R-33 | P2-10 |
| | | | R-19 | P1-11 | | R-34 | P2-11 |
| | | | R-20 | P1-12 | | R-35 | P2-12 |
| | | | R-21 | P1-13 | | R-36 | P2-13 |
| | | | R-22 | P1-14 | | R-37 | P2-14 |
| | | | R-23 | P1-15 | | R-38 | P2-15 |
| | | | | | | R-39 | P2-16 |

### 通道层（原 `RESEARCH-minimal-tool-surface.md`）

| 新 ID | 旧 ID | 说明 |
|---|---|---|
| T-01 | P0-1 | |
| T-02 | P0-2 | |
| T-03 | P0-3 | |
| T-04 | P0-4 | |
| T-05 | P0-5 | |
| T-06 | P0-6 | |
| T-07 | P0-7 | |
| T-27 | **新增** | MCP 读通道（本文新增） |
| T-08 | P1-1 | |
| T-09 | P1-2 | |
| T-10 | P1-3 | |
| T-11 | P1-4 | |
| T-12 | P1-5 | |
| T-13 | P1-6 | |
| T-14 | P1-7 | |
| T-15 | P1-8 | |
| T-16 | P1-9 | |
| T-17 | P1-10 | |
| T-18 | P1-11 | |
| T-19 | P2-1 | |
| T-20 | P2-2 | |
| T-21 | P2-3 | |
| T-22 | P2-4 | |
| T-23 | P2-5 | |
| T-24 | P2-6 | |
| T-25 | P2-7 | |
| T-26 | P2-8 | |

### 字段真空（本文新增，原 `ANALYSIS-threat-focus.md` §6 只有叙述，无编号）

| 新 ID | 来源 |
|---|---|
| F-01 … F-07 | 本文新编号；实测数据来自 `ANALYSIS-threat-focus.md` §6 的 22 条字段探针 |

### 本文复核新增（无旧 ID）

| 新 ID | 来源 |
|---|---|
| R-40 | 本文复核 m01643 时实测发现（`entity_types: []` = 全启用） |
| R-41 | 本文复核时实测发现（自定义规则让类型永久关不掉） |
| R-42 | 本文复核时修正的设计错误（名册非独立库，实测互补） |
| T-27 | 本文复核时新增（MCP 工具的全局注册读通道） |
| R-43 | 本文实测发现（`entity_types` 拼错 = 整库静默失效） |
| R-44 | 本文实测发现（`priority` 污染可翻转整类裁决） |
| R-45 | 本文实测发现（自定义类型不在 `_PRIO`，等长冲突垫底） |
| R-46 | 本文实测发现（自定义类型看得见效果、关不掉开关） |
| R-47 | 本文实测发现（CLI 无库级开关入口） |

---

## 附录 C：三份原文档的分工与本文的取舍

| 原文档 | 原问题 | 本文处理 |
|---|---|---|
| `RESEARCH-rule-libraries.md`（415 行） | 只回答「识别什么」，**字段清单漏了年龄一族** | §2 保留全部设计（manifest / 坐标 / 优先级 / 三态 / 热更新），39 条问题全部保留并重编号；本次复核新增 R-40/R-41/R-42 三条 |
| `RESEARCH-minimal-tool-surface.md`（660 行） | 只回答「怎么保证原文出不去」，**42% 篇幅在与环境较劲** | §3 保留极简形状与五条断言判定；§4 六条约束全部保留；26 条问题保留并按「对抗谁」加列 |
| `ANALYSIS-threat-focus.md`（190 行） | 只做重排，未落到字段层 | 分类结论并入 §5.1；两个真空升级为 §5.4 的 F 系列，成为 Phase 0 的直接输入 |

**一句话**：先把 `年龄/出生日期/性别/民族/学历/微信/工号` 补进识别层（成本低、直接对目标），再把工具面删到最小（成本中、防止绕过），路径类问题放最后。
