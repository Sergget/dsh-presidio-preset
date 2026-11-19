> **【已归档 2026-11-18】** 本文已合并进 docs/RESEARCH-pii-protection.md（研究总纲），
> 此处仅作历史留存。新文档统一了问题编号（`R-xx` / `T-xx` / `F-xx`），
> 附录 B 提供旧编号对照表。**请以新文档为准，本文不再更新。**
> 保留本文件的目的：完整保留当时的推演过程与逐行源码取证，便于追溯结论来源。

---
# 研究报告：PII 规则库化（可开关 / 可替换的 rule library）

> 状态：**研究报告，未实施**。本文只做设计论证与风险盘点，不含代码改动。
> 范围：`presidio_pii/`（引擎与规则加载）、`plugins/dsh-pii-guard-terms/`（配置 UI）、
> `tools/release_gate.py`（门禁）、`.agent-presets/presidio-pii/`（preset 配置）。
> 文中每条结论都带源码位置或公开链接；标注「推断」的是由源码直接推导、未实机验证的结论。
> 相关：`docs/ROADMAP.md`（NER 分档）、`docs/PLAN-code-review-followups.md`（S1–S4 已知问题）、
> `agent.md` §3（识别器设计约定）。

---

## 0. 结论摘要

**能拆，但拆的不是「识别器」——是「识别器 + 坐标契约 + 优先级契约 + 类型契约 + 依赖声明」这五件东西。**

1. **改动量被低估的地方**：15 个内置识别器里，只有 9 个能被 JSON 数据化（6 个纯正则 + 3 个正则加 validator）；**人名 / 名册 / 地名 / 机构 / 职务这 5 个是过程式判定，必须留 Python**；`IpMacRecognizer` 一个对象产两类实体，需要额外声明（见 §2.3）。也就是说「人名等规则独立为规则库」这句话里，最难的那个恰好不能数据化。
2. **第一必改项不是拆分，是 `wants_raw`**：`presidio_pii/custom_rules.py:117` 与 `:155` 把自定义规则硬编码成「在原文上匹配」，内置规则一旦走现有 JSON 通道，全角/插值/换行三类变体会整批回退（`tests/test_variants.py:31-57`、`:102-116`）。必须先加 `coordinate` 字段。
3. **三个机制性阻断，任何一个不解决，「打开/关闭」就是假的**：
   - 「0 条规则保留上一份」的分支（`custom_rules.py:403-406`）——**关库 = 减少规则**，正是这条分支的高发路径；
   - 配置只读一次、无生产级重载入口（`hooks.py:138-147`，`reset_singleton()` 是测试辅助）——**改完不生效**；
   - 清单若不进签名（`custom_rules.py:367-376` 只看 `self.sources`）——**改开关不触发 reload**。
4. **`_PRIO` 是真障碍**：优先级按 `entity_type` 计权（`engine.py:38-41`），15 个包只对应 13 个类型键；未声明 priority 的规则一律落 99，会直接把 PERSON/ORGANIZATION 的次序反转（`engine.py:206` 的 `priority.get(r.entity_type, 99)`）。
5. **推荐落点：独立清单文件（方案 b）**，而不是塞进 `preset.json`。理由见 §3.2——preset 那条路从机制上就满足不了「热生效」。
6. **默认集必须「默认关小众、只开通用」**。这不是抄作业，是上游既定策略：Presidio 自己的 `default_recognizers.yaml` 里绝大多数国家专属识别器默认 `enabled: false`。
7. **潜在问题 39 条**，其中 P0 八条、P1 十五条、P2 十六条（§4）。最致命的不是技术 bug，是**「关掉规则后静默漏检，而工具仍然报告成功」**——Presidio 有公开实证（issue #2256：两个 LLM 网关实测 11/11 处漏检，仍返回 200）。
8. **最反直觉的风险：规则库自己会变成新的 PII 存储面**（§4.2）。用户为了提升召回，最自然的做法是把真实姓名、手机号写进规则库当精确匹配——于是脱敏工具的配置文件本身成了明文 PII 集合，还大概率被 git / 云盘 / 备份带出去。**这是「允许用户自定义加载规则」这个需求自带的副作用，必须在设计阶段就挡住。**

---

## 1. 需求拆解：这句话实际要求了 5 件事

原文：「丰富配置功能，将人名、组织、地名、电话等不同的匹配规则独立为一条一条的规则库，允许自由打开或关闭，允许用户自定义加载更多的规则或替换已有的规则库。」

| # | 隐含要求 | 难点 |
|---|---|---|
| R1 | **粒度**：按实体类型拆成独立库，且库内是「一条一条」的规则 | 过程式识别器（人名等）无法表达为「一条一条」 |
| R2 | **开关**：库级启停，规则级可选启停 | 开关必须真的改变识别结果，且可验证 |
| R3 | **加载更多**：用户可新增规则库 | 来源可信性、schema 校验、与内置库冲突 |
| R4 | **替换**：用户库可替换内置库 | 内置是 Python 类、用户是 JSON——**替换语义是否成立取决于同构程度** |
| R5 | **配置功能**：以上都通过配置 UI 完成 | UI 写入必须与引擎读取同源，且**改完立刻生效** |

R5 是隐藏的杀手：现有 UI 写 `user_terms_rules.json`，引擎读 `custom_rules_path`，两侧各有一份路径（`plugins/dsh-pii-guard-terms/lib/index.js:37`、`.agent-presets/presidio-pii/preset.json:21`、`tools/release_gate.py:319-320`），门禁用一条等式兜住（`release_gate.py:323`）。**加第四处配置源会让这条等式直接失真。**

---

## 2. 现状：地基已经有一半

### 2.1 已有的（可直接复用）

| 能力 | 位置 | 说明 |
|---|---|---|
| 规则数据模型 | `custom_rules.py:92-100` | `RuleSpec(name, entity_type, score, context_hint, negative_hint, priority)` —— 「一条一条」的形状已经存在 |
| 正则规则通道 | `custom_rules.py:103-133` | `RegexRuleRecognizer`，支持捕获组、hint 判定、validator |
| 代码规则通道 | `custom_rules.py:146-178` | `.py` 的 `analyze(text) -> [(s,e[,score])]`，声明 `ENTITY_TYPE/SCORE/PRIORITY/RULE_NAME` |
| 多源加载 | `custom_rules.py:283-321` | 分号/逗号分隔，`.json` / `.py` 分发，`strict` 严格模式 |
| 热更新 | `custom_rules.py:324-427` | 文件签名 + 1s 节流 + 线程锁 |
| 失效保留 | `custom_rules.py:399-406` | 加载失败/0 条时保留上一份规则（**这条是安全设计，但和「关库」直接冲突，见 §4 P0-1**） |
| 逐条精度 | 各识别器内部 | 15 个识别器已有成熟的边界/上下文/黑名单逻辑 |

### 2.2 缺的四块

| 缺失 | 证据 |
|---|---|
| **无 `enabled` 概念** | `grep enabled presidio_pii/*.py` 只命中 `cli.py:117` 的日志开关；`RuleSpec` 无该字段；`_sync_recognizers()`（`engine.py:92-96`）是纯 `builtin + rules` 拼接，**没有过滤钩子** |
| **无库/分组概念** | `CustomRuleSet` 只有 `sources`（文件路径列表），没有「这个文件属于哪个库」 |
| **无来源与顺序** | 规则加载后不知道来自哪个库，无法做「替换某库」「调整库优先级」 |
| **无 reload 通道** | `server.py` 的 stdio 协议只有 `redact` / `restore`（分派在 `server.py:92-102`），Node 侧没有触发 `reload_rules(force=True)`（`hooks.py:150-155`）的入口 |

### 2.3 内置识别器的可拆分性（决定方案上限）

| 类别 | 数量 | 成员 | 能否数据化为 JSON |
|---|---|---|---|
| 纯正则 | 6 | 手机、座机、邮箱、统一社会信用代码、护照、车牌 | 能 |
| 正则 + validator | 3 | 身份证 18 位、身份证 15 位、银行卡 | 能，但需 validator 引用 + 双档 score（`0.95/0.70`、`0.80/0.45`） |
| 过程式 | 5 | 人名、名册人名、地名、机构、职务 | **不能**，4 个还带 jieba 双分支 |
| 一对象两类型 | 1 | `IpMacRecognizer`（`chinese_recognizers.py:452-471`） | 需 `emits: [IP_ADDRESS, MAC_ADDRESS]` |

**结论**：规则库化不能只做「JSON 规则包」，必须允许 `kind: builtin`（后端指向 Python 类）与 `kind: regex` / `kind: code` 并存。**同构在 manifest 层，不在实现层。**

---

## 3. 设计

### 3.1 三层粒度（必须显式定，否则 UI 无法承载）

```
库（library）        ← 用户日常操作的粒度：人名库、电话库、机构库…
  └─ 规则（rule）    ← 「一条一条」：左上下文规则、jieba-nr 规则、后缀规则…
       └─ 实体类型（entity_type）← 占位符契约，不可随意改名
```

**建议**：UI 主界面只暴露**库级开关**；库内单条规则的 `enabled` 由 manifest 声明默认值，只在「高级」面板出现。理由——若把几千条规则平铺给用户，等于把精度调优的负担全部转嫁，用户最终会关掉一切（见 §4 P2-5 Elastic 教训）。

### 3.2 落点选择：独立清单文件（方案 b）

三个候选：

| 维度 | (a) `preset.json config.rule_libraries[]` | **(b) 独立清单 `.pii_presidio_store/rule-libraries.json`** | (c) 规则库目录 + 每库 `manifest.json` |
|---|---|---|---|
| 热更新 | **不可热**：`_get_engine()`（`hooks.py:138-147`）首次构造后永不重读 | **可热**：清单进签名，复用 1s 节流 | 可热但最重：签名要变目录树哈希 |
| 防漂移 | 最差：UI 改写声明式 preset，且 `_preset_path()`（`hooks.py:80`）依赖文件已存在，新键指向不存在的文件会**静默退化到仓库根** | 最好：单一权威文件 | 中等：目录即真相，但「启用状态」还得另存 |
| 门禁改动 | 小（只改 S2 段） | 中（S2 重写 + schema 断言） | 大（+ 目录遍历，且与 #11 冲突） |
| 语义分层 | 违反「配置即代码」 | 用户态数据，符合「可加载/可替换」 | 分发型规则库不能落 `.pii_presidio_store/` |

**推荐 (b)**，`preset.json` 只新增一个 `rule_libraries_path` 指向清单。(c) 作为 (b) 的演进形态保留——清单里的 `path` 允许指向目录，但不要一上来就做目录扫描。

### 3.3 manifest 形状（库级）

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
  "coordinate": "normalized",         // normalized | raw —— 见 §3.5
  "requires": ["builtin.core"],       // 加载依赖（不满足则拒绝加载本库）
  "excludes": ["builtin.person.roster"], // 互斥（同时 enabled 则拒绝）
  "replaces": null,                   // 非空表示替换同 id 的内置库
  "rules": [                          // kind=regex/code 时是规则数组；builtin 时可为空
    { "id": "person.left-context", "enabled": true, "pattern": "...", "score": 0.85 }
  ]
}
```

字段必要性逐一说明：

| 字段 | 为什么必须有 | 没有会怎样 |
|---|---|---|
| `id` | 替换、依赖、互斥、UI 稳定引用 | 只能按文件名认库，改名即断 |
| `emits` | 类型白名单 | 用户 typo `PEROSN` → 落 99 优先级 + 生成不可还原的占位符（`engine.py:243` 按类型建序号） |
| `coordinate` | 坐标契约 | 走现有通道必继承 `wants_raw=True`，全角变体全丢（`tests/test_variants.py:31-57`） |
| `requires` | 跨库依赖 | 关掉 `ID_NUMBER` → 15 位身份证被 `BANK_CARD` 抢走（`chinese_recognizers.py:384-386` 类注释书面记录） |
| `excludes` | 互斥 | 两个库同时启用时结果集合不确定 |
| `replaces` | 替换语义 | 无法表达「用我的库换掉内置的」 |
| `schema` | 版本演进 | 老清单被新引擎误读 |

### 3.4 开关语义：构建期 vs 运行期

两条路，语义完全不同：

| 语义 | 做法 | 优点 | 缺点 |
|---|---|---|---|
| **A. 构建期不加载**（Presidio 语义） | `enabled=false` 的库根本不实例化 | 零成本、零误报风险、异常不可能发生 | 关闭瞬间需要重建识别器列表；`_prio` 里该类型的键仍在（无害，因为无产出入） |
| **B. 加载后过滤** | 照常加载，产出结果时按 `enabled` 丢弃 | 切换可即时、可回滚 | 成本照付；用户写的坏正则仍然会跑（ReDoS 风险不减） |

**推荐 A**，并且补齐三条硬要求（缺一不可）：

1. **禁用 = 不实例化**，且 `_sync_recognizers()` 必须在拼接前过滤（`engine.py:92-96`）。
2. **必须有测试断言「关掉后结果里真的没有」**——Presidio issue #950 的教训是 `remove_recognizer()` 之后 `analyze()` 仍返回该实体。
3. **「全关」是合法状态**，不得命中「0 条保留旧规则」分支。必须用显式的空状态表达，而不是靠写 `(?!)` 占位规则（现有的 `NEVER_MATCH` 约定，`plugins/dsh-pii-guard-terms/lib/index.js:47/249-258`，是权宜之计，不该复用到库级）。

### 3.5 坐标契约（最容易被忽略，但最致命）

现状：`analyze()` 里 `results.extend(rec.analyze(text if getattr(rec, "wants_raw", False) else probe))`（`engine.py:148`）。内置识别器跑在归一化文本上，坐标再映射回原文（`engine.py:149-156`）；自定义规则硬编码 `wants_raw=True`（`custom_rules.py:117`、`:155`）。

**问题**：内置规则包一旦走 `kind: regex`，就继承了 `wants_raw=True`。

**实测数据**（`1[3-9]\d{9}` 这条规则分别在原文与归一化文本上跑）：

| 输入变体 | 在原文上匹配（现状） | 在归一化文本上匹配（内置识别器） |
|---|---|---|
| `13800138000` | ✅ 1 | ✅ 1 |
| `138 0013 8000` | ❌ 0 | ✅ 1 |
| `138-0013-8000` | ❌ 0 | ✅ 1 |
| `１３８００１３８０００`（全角） | ❌ 0 | ✅ 1 |
| `138\n0013\n8000` | ❌ 0 | ✅ 1 |

即：**同一份正则，坐标选错，5 类输入里 4 类直接归零**。`tests/test_variants.py:31-57`、`:102-116` 会整批变红，而这几类变体正是中文公文最常见的写法。

**但方向是双向的，这点必须写清楚**：归一化会把 `-` 等分隔符统一成空格（`normalize()` 实测 `ORD-1234` → `ORD 1234`）。所以**任何依赖特定分隔符字面量的规则，在 `coordinate: normalized` 下同样会失效**：

| 规则 | 原文 | 归一化文本 |
|---|---|---|
| `ORD-\d{4}` 匹配 `ORD-1234` | ✅ 1 | ❌ 0（归一化成 `ORD 1234`） |

结论：`coordinate` 不是「raw 一律劣于 normalized」，而是**两类规则各有坐标系**。字段必须存在，且必须在 manifest 里显式、必填、可校验。

**对策**：`coordinate` 成为库级必填字段（默认 `normalized`，用户库显式声明 `raw` 才行）。不要做成规则级——同一库内混坐标会让 `_resolve_overlaps` 的输入来自两套坐标，出现不可复现的错位。用户自定义规则里凡写了 `-`、`/`、`：` 等分隔符的，UI 必须提示「此规则在归一化坐标下可能失效，请改用 `[\s\-]?` 之类的宽松写法」。

### 3.6 加载流程与三种状态

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

**三种状态必须在 UI 上可区分**，这是「静默成功」反模式的解药（Presidio #2256）。

### 3.7 热更新

**清单必须进签名**。现有 `_source_signature()`（`custom_rules.py:367-376`）只遍历 `self.sources`，开关存在清单里，改清单不改库文件 → 签名不变 → 开关永不生效。

两条实现路径：
- **L1（简单）**：签名元组追加 `(manifest_path, mtime_ns, size)`。
- **L2（推荐）**：清单里存每个库文件的**内容哈希**，签名 = 清单自身的内容哈希。一次 stat 覆盖全部，且能检出「库文件被改但 mtime 没变」的边界情况。

另外：
- `server.py` 加 `reload` op（现只有 `redact`/`restore`，`server.py:92-98`），把「点开关立刻生效」从「等 1 秒」升级为确定性行为。这是解除 `plugins/dsh-pii-guard-terms/README.md:55`「改路径需重启 DSH」的唯一路径。
- **写盘顺序 = 先写库文件，后写清单**。清单是提交点，避免「新开关 + 旧规则」的中间态。

### 3.8 优先级与冲突

现状排序键：`(-(r.end - r.start), priority.get(r.entity_type, 99), r.start)`（`engine.py:205-206`）。

四个已确认的问题：

1. **按类型计权、不按规则计权**。15 个库对应 13 个类型键，两个 PHONE 库（手机/座机）只能共用一个优先级。
2. **未声明 priority 一律 99**，会反转 PERSON(8) 与 ORGANIZATION(10) 的次序。
3. **`entity_priorities()` 同类型取最小值**（`custom_rules.py:411-421`，docstring 写「取最高优先级」，数值上是最小值才算最高），语义是「这个类型整体按最高优先级算」——关掉高优先级库后，该类型优先级不会回落到内置值。
4. **用户词的 `priority: 0` 与 `ID_NUMBER` 撞车**。UI 写的每条 USER_TERM 规则都是 `priority: 0`（`plugins/dsh-pii-guard-terms/lib/index.js:241-248`），与 `_PRIO["ID_NUMBER"] = 0` 同权；等长重叠时裁决退化成「看起点」，这属于既有行为但从未被文档化。库化时若要给用户库一个稳定的库级优先级，必须先决定它和内置 0 档的相对次序。

**建议的解析顺序**（从高到低）：
```
rule.priority（显式声明）
  → library.priority（库级默认）
  → _PRIO[entity_type]（内置 13 类）
  → 99
```

并且：**保留「长实体优先」不动**。这是业界惯例——spaCy EntityRuler 原文：「the entity ruler prioritizes longer patterns over shorter, and if equal the match occurring first in the Doc is chosen」。Presidio 的 `remove_duplicates` 只在**同 entity_type 内**压制，跨类型裁决是本项目自建能力，必须自己写清规则。

---

## 4. 潜在问题清单（39 条，按严重度分级）

严重度定义：
- **P0**：会让「保护失效但工具仍报成功」——隐私工具里最不可接受的一类；
- **P1**：功能不达预期、契约被破坏、或维护成本显著上升；
- **P2**：体验/工程债，可排期。

### P0（8 条）

| # | 问题 | 机制证据 | 后果 | 对策 |
|---|---|---|---|---|
| P0-1 | **「关库」= 减少规则，正命中保留旧规则分支** | `custom_rules.py:403-406`：`if not rules and self.rules:` → warn + 更新签名 + return False | 用户关了库，旧规则继续脱敏；全关时也会保留。UI 显示「已关闭」但行为是「仍开启」 | 引入显式 `empty` 状态；`refresh()` 区分「加载失败」与「合法的 0 条」；有测试断言 |
| P0-2 | **静默成功：库加载失败仍正常返回结果** | `load_json_rules` 非 strict 模式只 `_warn` 并返回 `[]`（`custom_rules.py:194`、`:213-214`） | 保护范围缩小，用户无感知。Presidio #2256 公开实证：11/11 处漏检仍返回 200 | 状态接口 + UI banner + 门禁断言；「识别过且没命中」与「没有规则能识别」必须可区分 |
| P0-3 | **`_load_lines` 词典缺失静默返回 `[]`** | `chinese_recognizers.py:121-126`：`if not fp.exists(): return []` | 用户包引用的词典缺失 → 该库零召回，无任何报错 | 用户侧词典必须 fail-loud；内置词典已在包内，可保持宽容 |
| P0-4 | **配置只读一次，无生产级重载入口** | `hooks.py:138-147`；`reset_singleton()`（`:180-184`）是测试辅助；`README.md:55` 自承认需重启 | 写进 preset 的开关**改完不生效**——直接违背 R5 | 落清单而非 preset；`server.py` 加 `reload` op |
| P0-5 | **清单不进签名 → 改开关不触发 reload** | `custom_rules.py:367-376` 只遍历 `self.sources` | 开关状态永远停在首次加载时的快照 | §3.7 的 L1/L2 |
| P0-6 | **跨库依赖未声明 → 关掉 A 使 B 失效** | `chinese_recognizers.py:384-386` 类注释书面记录：ID15 必须与 18 位分开，否则被 `BANK_CARD` 抢走 | 关了身份证库 → 15 位号码被识别成银行卡，**脱敏了但类型错误**（占位符类型错 → 语义丢失，且非同类型不可互换） | manifest `requires` / `excludes`，加载期校验 |
| P0-7 | **类型名是跨会话契约，改名即不可还原** | `engine.py:243`：`f"{PH_OPEN}PII:{ptype}:{counters[ptype]:04d}{PH_CLOSE}"`；`restore()` 按占位符字面匹配（`engine.py:266-294`） | 用户把库的 `emits` 从 `LOCATION` 改成 `ADDRESS` → 历史会话里的 `⟦PII:LOCATION:0001⟧` 永远还原不了 | `emits` 白名单 + 内置类型名冻结；改名必须提供映射表 |
| P0-8 | **规则库自己会变成明文 PII 存储面** | 现状：用户词表就是「一条一条规则」的形态（`plugins/dsh-pii-guard-terms/lib/index.js:240-264`），`pattern` 是字面量转义后的原文。需求「允许用户自定义加载规则」把这个形态放大成「一整个库」 | 用户为提升召回，最自然的做法是把真名/真号码写进规则库当精确匹配 → 脱敏工具的配置目录成了明文 PII 集合，还会被 git、云盘、备份、同步工具带出去。**保护工具变成泄漏源。** | 见 §4.2：默认禁字面量精确规则、只允许正则/结构化模式；确需精确匹配时走「加盐哈希」或留在 `USER_TERM` 白名单通道并强制落 `.pii_presidio_store/`（`gitignore` 已覆盖）；门禁 #11（`release_gate.py:704-706`）扩到规则库目录 |

### P1（15 条）

| # | 问题 | 机制证据 | 对策 |
|---|---|---|---|
| P1-1 | **`wants_raw` 硬编码导致坐标契约丢失** | `custom_rules.py:117`、`:155` | `coordinate` 库级必填（§3.5） |
| P1-2 | **`_PRIO` 按类型计权，15 包 vs 13 键** | `engine.py:38-41`；`engine.py:206` 的 `priority.get(..., 99)` | 四级解析顺序（§3.8） |
| P1-3 | **关库会让原本被吞掉的短实体「浮出水面」，输出集合不可预测** | `_resolve_overlaps`（`engine.py:197-213`）只做「长优先」吞并，**没有任何回退逻辑**。实测：`安徽省数据资源管理局在合肥` → 全开时输出 `ORGANIZATION[安徽省数据资源管理局]`；把 `ChineseOrganizationRecognizer` 摘掉后，同一个句子立刻输出 `LOCATION[安徽省]` | 「关掉机构库」的下游影响不是「机构不再识别」，而是**地名开始以另一种粒度出现**。用户看到的类型分布、统计口径、占位符编号全部变化，且没有任何提示 | 变更库组合时必须跑全量回归并 diff 类型分布；UI 在关库时提示「该库此前压制了哪些短实体」。这条要写进文档，不能只当实现细节 |
| P1-4 | **第四处配置副本让门禁等式失真** | `plugins/dsh-pii-guard-terms/lib/index.js:37` ↔ `preset.json:21` ↔ `release_gate.py:319-320`，判据 `release_gate.py:323` | 门禁改为「preset 路径 == 清单路径」+「清单内每库 path 存在」 |
| P1-5 | **`_preset_path()` 依赖文件已存在** | `hooks.py:80`：`next((c for c in candidates if c.exists()), candidates[0])` | 新键必须指向已存在文件，否则静默退化到仓库根；加显式告警 |
| P1-6 | **`warnIfPathDrift()` 只 console.error 不阻断** | `plugins/dsh-pii-guard-terms/lib/index.js:332-345` | 升级为强校验，或至少写入状态接口 |
| P1-7 | **门禁对「关库」几乎没有覆盖：13 个包零断言，只有 PERSON 被硬绑** | `release_gate.py:72-96`：`eng = PresidioPIIEngine(db_path=...)` **直接构造引擎、绕过 `hooks`**，所以清单里的 `enabled` 它根本不读；断言只有两条——`counts.get("PERSON", 0) > 0`（`paper-01`）与 `personal == 0`（`normal-01` 上 PERSON/ID_NUMBER/PHONE_NUMBER/BANK_CARD 四类和为 0） | 实测 `paper-01` 的 `entity_counts` = `{PERSON: 8, ORGANIZATION: 2, LOCATION: 1, EMAIL_ADDRESS: 1}`，`normal-01` = `{ORGANIZATION: 2}`。→ **关掉 PERSON 库必 FAIL；关掉 ORGANIZATION/LOCATION/EMAIL 库则不 FAIL**（`n_replaced` 仍 > 0）。13 个包等于没有任何门禁断言兜底 | 门禁必须改为「按清单加载」并新增**逐库断言**：①每库默认 enabled 时产出 > 0；②该库 disabled 时对应类型产出 == 0 且其余类型不变。否则「关错了」永远不会被发现 |
| P1-8 | **测试硬契约会被打破** | `tests/js/plugin_terms.mjs:115`（`routes.size === 4`）、`:223`（settings 恰好 4 键）、`tests/test_user_terms.py:125-129`（空数组→0 条）、`tests/test_custom_rules.py:470-489`（破损文件保留旧规则） | 改契约必须同步改测试，且**不能为了过测试而弱化断言** |
| P1-9 | **`plugin_terms.mjs:108` 自己把 preset 写成 `{config:{custom_rules_path}}`** | 测试自己造漂移 | S2 判据改动时这一行必须一起改 |
| P1-10 | **代码规则 = 加载任意 Python** | `custom_rules.py:251` `spec.loader.exec_module(mod)` | 第三方规则库不得自动执行；必须显式确认 + 来源标注 |
| P1-11 | **用户正则无超时、无复杂度限制（ReDoS）** | 现状无任何 `timeout`；Cloudflare 2019-07-02 一条规则回溯导致全球 502 共 27 分钟 | 单条规则超时 + 长度上限 + 复杂度预检；超时必须**可观测**（Presidio 只 warning 是反面教材） |
| P1-12 | **allow/deny 语义不对称，用户预期会落空** | Presidio #2455 原文：recognizers can only add results, not remove those of other recognizers | 用户「加一条排除规则消误报」在当前架构下**不可能**；要用白名单（后置过滤），或明说 |
| P1-13 | **整体覆盖写会吞用户手工规则** | `docs/PLAN-code-review-followups.md` S3：`readTerms()` 只认 `row.term` | 库化后写入必须改为「按 id 增量」，或至少在保存前 diff 并提示 |
| P1-14 | **仓库内规则库与门禁 #11 的判据错位** | `_FORBIDDEN_TRACKED`（`release_gate.py:704-706`）只按**路径**判定，扫 `git ls-files`（`:711-712`）与 `git status --porcelain`（`:713-715`），再断言 `.gitignore` 规则数 `>= 5`（`:716-719`） | 一份放在仓库内 `rule_libraries/` 的示例库若混入真实姓名/号码，**#11 照样 PASS**——路径不在禁区，门禁看不见内容。要么扩扫内容，要么强制示例库走虚构语料并加断言 |
| P1-15 | **`replaces` 依赖 id 稳定，用户自造 id 会撞车** | manifest 设计里 `replaces`/`requires`/`excludes` 全按 `id` 引用（§3.3） | 用户库用 `id: "person"` 撞上内置 `builtin.person` 时，行为取决于加载顺序（不可控）。需要命名空间规则：内置带 `builtin.` 前缀，用户库禁止使用该前缀 |

### P2（16 条）

| # | 问题 | 说明 |
|---|---|---|
| P2-1 | **「加载更多」vs「启用」没有区分** | Elastic 的成熟做法：`Install all` 默认装而不启用。用户说「加载」到底指哪个？ |
| P2-2 | **「全开」不等于更安全** | Elastic 原文：Building block rules 「Enabling them early is the most common cause of alert floods」；本项目对应「误报洪水 → 用户关掉一切」 |
| P2-3 | **替换内置库后的升级覆盖问题** | Elastic：不保留定制的档位「each update replaces the rule with the Elastic version」。用户替换了人名库，引擎升级怎么办？ |
| P2-4 | **无法用 JSON 替换过程式库** | 5 个过程式识别器（人名/名册/地名/机构/职务）只能被 `kind: code` 替换，而 code = 执行任意 Python。这是**产品决策**，不是技术细节 |
| P2-5 | **默认集怎么定** | Presidio 策略可抄：默认关小众、只开通用高精度（信用卡/邮箱/IP/电话/URL） |
| P2-6 | **UI 承载能力不足** | `handleList` 返回 `string[]`（`plugins/dsh-pii-guard-terms/lib/index.js:347-362`），无分组/无来源/无启停字段；`client.js:517-522` 硬绑 `TermsSection` + `SettingsSection` 两块 |
| P2-7 | **规则库与引擎版本兼容** | manifest 需 `schema` + `min_engine_version`，否则老库被新引擎误读 |
| P2-8 | **规则库来源可信性** | OPA 用 `.signatures.json`（每文件 SHA-256）+ JWT；nuclei 用 ECDSA。本项目至少要有「来源标注 + 内容哈希」 |
| P2-9 | **分发型规则库不能落 `.pii_presidio_store/`** | 该目录被 `.gitignore:5` 与门禁 #11（`release_gate.py:704-706`）禁入，是**用户态数据**；分发包要另找位置 |
| P2-10 | **每 analyze 前 refresh 的 stat 成本** | 多库 = 多文件 stat；目录扫描方案代价更高。L2 的「清单内容哈希」可把成本压到 1 次 |
| P2-11 | **1s 节流窗口的行为不一致** | 用户点开关后 1 秒内行为仍在旧态；`reload` op 解决，但需要 UI 反馈 |
| P2-12 | **规则数增长对延迟的影响未量化** | 现状无 benchmark；新增库后需要一次基线测量（ROADMAP 有「0.5–2ms」的粗估，但没有库数量维度） |
| P2-13 | **无「关掉这个库会漏什么」的代价提示** | 安全责任转移：用户为降误报关掉人名库 → 真姓名泄漏。需要 UI 明示影响范围（哪些类型将不再识别） |
| P2-14 | **规则库的「版本」与引擎版本是两条线** | manifest 的 `schema` 只管清单格式，管不了「这条规则依赖的识别器 API 变没变」。`kind: code` 的库在引擎升级后可能 `analyze()` 签名不兼容，而 `CodeRuleRecognizer` 只会 warn 一次并返回 `[]`（`custom_rules.py:172-177`）——又一次静默归零 |
| P2-15 | **跨平台路径与编码** | 规则库路径可能含中文/空格；`_import_path` 用的 `mod_name = f"pii_custom_{abs(hash(str(p.resolve())))}"`（`custom_rules.py:244`）依赖 `hash()`，而 Python 的 `hash()` 对 str **每进程随机化**（`PYTHONHASHSEED`），于是同一文件在不同进程里模块名不同——热更新时会重复注册 `sys.modules` 条目，长跑进程有泄漏风险 |
| P2-16 | **没有「规则库」的可观测性** | 现状只有 `_warn` 到 stderr。库化后需要：启用了哪些库、各产出多少实体、哪些库加载失败、上次 reload 时间。没有这些，「关掉库导致召回下降」永远事后才发现 |

### 4.1 三条外部实证（可直接引为设计依据）

1. **「规则不可用 + 静默成功 = 数据裸奔」**——Presidio issue #2256：`/analyze` 同时请求多个实体时，无 recognizer 的实体被静默丢弃仍返回 200，两个 LLM 网关实测 11/11 处漏掉 fiscal code，而信用卡/邮箱/IBAN 都正常拦截。
2. **「配置键写了但代码没读」**——Presidio issue #2277：文档声称顶层 `supported_countries` 会被自动应用，实际 schema `extra="forbid"` 直接 ValueError，provider 从不读该键。→ 配置字段必须「声明 + 校验 + 真正使用」三处对齐。
3. **「移除规则的 API 不真的移除」**——Presidio issue #950：`registry.remove_recognizer()` 之后 `analyze()` 仍返回该实体结果。→ 开关必须有测试断言。

### 4.2 展开：规则库本身就是新的泄露面（P0-8）

这一条值得单独说，因为它是需求的**内生副作用**，不是实现 bug。

**机制**：现有 `USER_TERM` 通道的规则形状就是「字面量」——

```jsonc
{ "name": "user-term-0001", "entity_type": "USER_TERM",
  "pattern": "张三", "score": 0.95, "priority": 0, "term": "张三" }
```

`pattern` 是 `escapeLiteral(term)` 的结果（`plugins/dsh-pii-guard-terms/lib/index.js:241-248`），
即**原文以明文形式躺在磁盘上**。当前只有「用户主动屏蔽词」这一个入口，体量有限；
一旦开放「加载/替换整个规则库」，用户的动机链条会自然把体量放大：

> 想让某个人名 100% 被识别 → 最直观的做法就是把人名写成一条精确匹配规则。

于是**为了脱敏而维护的配置文件，本身成了一个明文 PII 语料库**。它会：
- 被 `git status` 看到（除非落在 `.pii_presidio_store/`，`.gitignore:5` 已覆盖）；
- 被云盘 / OneDrive / 同步工具 / 时间机器备份带走；
- **不**会被门禁 #11 直接拦住——#11 除扫 `git ls-files` 外，也扫 `git status --porcelain` 里的未跟踪/已暂存项（`release_gate.py:711-715`），落进 `.pii_presidio_store/`、`testdata/` 或 `*-redacted/` 会被逮住。但它的判据是**路径正则**（`_FORBIDDEN_TRACKED`，`release_gate.py:704-706`），只认「放在禁地里的文件」，不认「放在允许位置、内容是真实 PII」的规则库：一份放在仓库内 `rule_libraries/` 的示例库若混入真名，**#11 照样 PASS，泄漏成立**。这是 P0-8 真正要补的缺口；
- 被用户分享给同事（「我这个规则库识别率很高，发你一份」）——这一条最危险，**分享规则库 = 分享一批真实姓名**。

**对策（三层）**：

| 层 | 措施 |
|---|---|
| 规则层 | 规则库默认只接受**结构化模式**（正则/词边界/上下文），不接受「单条字面量精确匹配」。需要精确匹配时强制走 `USER_TERM` 白名单通道 |
| 存储层 | 用户规则库与清单**必须**落在 `.pii_presidio_store/`（已 gitignore），仓库内只放**明显虚构**的示例（`agent.md` §1 强制示例必须虚构，这里可复用同一准则） |
| 校验层 | 门禁新增两项：①扫描 `.pii_presidio_store/` 之外的规则文件是否含疑似真实 PII；②检查仓库内示例规则库的 `pattern` 是否命中已知虚构语料白名单 |

**这条与「替换已有规则库」需求直接冲突**：替换意味着用户会拿到并改写一份完整规则库，
而完整规则库如果要「识别率高」，就必然包含大量真实样本。**设计时必须明确：
内置规则库是逻辑（边界/上下文/后缀），不是样本。** 一旦内置库混入样本，
用户会照着抄，整条防线从源头崩掉。

---

## 5. 分阶段落地建议

**Phase 1（地基，不带 UI）** —— 目标：让「开关」在 Python 侧真实生效
1. `RuleSpec` 加 `rule_id` / `enabled`；新增 `LibrarySpec`（`id/name/kind/emits/coordinate/requires/excludes/replaces/priority`）。
2. `RegexRuleRecognizer` / `CodeRuleRecognizer` 的 `wants_raw` 改为读 `coordinate`。
3. `CustomRuleSet` 支持清单：`manifest` 参数 + 签名覆盖清单 + 三态（`ok/empty/degraded`）。
4. `engine._sync_recognizers()` 加过滤钩子；`_prio` 改为四级解析。
5. 测试：关库后结果里真的没有；全关返回合法空态；`requires` 不满足时拒绝。

**Phase 2（内置库化）** —— 目标：15 个识别器变成 15 个可开关的库
1. 拆 `chinese_recognizers.py`：`_is_cjk` 等共享工具进公共模块；删死代码 `_next_is_boundary`（`chinese_recognizers.py:193`，0 处使用）。
2. 合并重复常量：`_ORG_SUFFIX`(:767)/`_RE_ORG`(:772)/`_ORG_SUFFIX_EXT`(:786) 三份后缀表；`_LOC_SUFFIX_CHARS`(:693) 与 `_re_generic` 手写 `(?:省|市|县|区)`(:706)。
3. 内置 manifest（`kind: builtin`）与用户 manifest 同构。
4. 门禁 #1 改用「按清单加载」，并新增**逐库断言**（默认开时产出 > 0；关掉时该类型产出 == 0 且其余不变）。现有门禁只有 PERSON 一条硬断言，另 13 个包处于零覆盖状态。

**Phase 3（UI 与替换）** —— 目标：用户可加载/替换
1. 清单 schema + 校验器（Python 侧，供 CLI/引擎/门禁共用）。
2. `server.py` 加 `reload` op。
3. UI：库列表（名称/来源/类型/规则数/开关/状态三态），新增路由 —— **注意 `tests/js/plugin_terms.mjs:115` 的 `routes.size === 4` 会挂，需同步改**。
4. 「替换」流程：`replaces` 字段 + 冲突提示 + 升级策略（保留用户库 / 提示覆盖）。

---

## 6. 验收契约（改之前先认清哪些是硬约束）

| 契约 | 位置 | 会不会被打断 |
|---|---|---|
| `routes.size === 4` | `tests/js/plugin_terms.mjs:115` | 加路由必挂 |
| settings 文件恰好 4 键 | `tests/js/plugin_terms.mjs:223` | 加设置键必挂 |
| 清空写 1 条 `(?!)` | `tests/js/plugin_terms.mjs:202-204` | 库化后语义要重定义 |
| 空数组 → 0 条规则 | `tests/test_user_terms.py:125-129` | 与 P0-1 直接相关 |
| 破损/删除文件保留旧规则 | `tests/test_custom_rules.py:470-489` | 与 P0-1 直接相关 |
| `refresh()` 返回「是否真的换过规则」，条数由 `reload_custom_rules()` 返回 | `custom_rules.py:379-409`、`engine.py:98-105` | 改签名逻辑必须保持这两个返回值语义，测试 `test_broken_file_keeps_previous_rules` 断言的正是 `reload_custom_rules() == 1` |
| 门禁 #1 只硬绑 PERSON + 四类负例 | `release_gate.py:72-96`（`:86-87` 的 `ok = ...`；**直接构造引擎，绕过 hooks，不读 enabled**） | 关掉 PERSON 必 FAIL；关掉 ORGANIZATION/LOCATION/EMAIL 等 13 个包则**不 FAIL**——覆盖近乎为零 |
| 门禁 #10 源码树 digest | `release_gate.py:628-643`（覆盖 `presidio_pii/**` + `pyproject.toml`），校验在 `:663` | 改引擎必重跑 `.pii_presidio_store/update_tree_digest.py`（**不在 `tools/` 下**）重算 `release/presidio-pii-dsh-0.1.0.json`；脚本本体在 gitignore 内，CI 无此脚本 |
| 识别器双模式（有/无 jieba） | `agent.md` §3 | 每个过程式库都要各跑一次 |

---

## 7. 需要拍板的 6 个决策

1. **粒度**：只做库级开关，还是库级 + 规则级？（建议：库级为主，规则级进高级面板）
2. **开关语义**：构建期不加载（A）还是运行期过滤（B）？（建议 A）
3. **「替换」的边界**：允许 JSON 替换人名库吗？（技术上不行——只有 `kind: code` 能替换，而 code = 执行任意 Python。建议：内置过程式库标记为「不可数据化替换」，UI 明示）
4. **默认集**：组织/地名/职务是否默认开启？（这三类误报率最高；建议默认开人名/电话/身份证/邮箱/银行卡，其余可选）
5. **失败策略**：库加载失败时「保留上一份 + 告警」还是「拒绝启动」？（建议保留 + 强告警，与现有 `custom_rules.py:399-406` 一致，但**必须让用户看见**）
6. **清单位置**：`.pii_presidio_store/rule-libraries.json`（用户态，不进仓库）还是仓库内 `rule_libraries/`（可分发）？（建议两者都要：内置清单在仓库，用户清单在 store）

---

## 8. 参考资料

**Microsoft Presidio**
- 规则注册表配置：https://presidio.dataprivacystack.org/analyzer/recognizer_registry_provider/
- 默认注册表（多数国家识别器默认 `enabled: false`）：https://raw.githubusercontent.com/data-privacy-stack/presidio/main/presidio-analyzer/presidio_analyzer/conf/default_recognizers.yaml
- `remove_duplicates` 只做同类型压制：https://raw.githubusercontent.com/data-privacy-stack/presidio/main/presidio-analyzer/presidio_analyzer/entity_recognizer.py
- 反模式：静默 200 漏检 #2256、配置键未生效 #2277、移除 API 失效 #950、allow/deny 不对称 #2455、白名单放大成全放行 #2417

**业界实践**
- spaCy EntityRuler（长优先 + 同长取先）：https://spacy.io/api/entityruler
- OPA Bundles（roots 划界 + 验签 fail-safe）：https://www.openpolicyagent.org/docs/management-bundles
- Elastic 预置检测规则（安装≠启用、例外优于关闭）：https://www.elastic.co/docs/solutions/security/detect-and-alert/install-prebuilt-rules
- Cloudflare 2019 ReDoS 复盘：https://blog.cloudflare.com/details-of-the-cloudflare-outage-on-july-2-2019/
- gitleaks 单条坏正则 panic：#1846

**本仓库**
- 引擎与规则加载：`presidio_pii/engine.py`、`presidio_pii/custom_rules.py`、`presidio_pii/chinese_recognizers.py`
- 配置面：`presidio_pii/hooks.py`、`.agent-presets/presidio-pii/preset.json`
- UI：`plugins/dsh-pii-guard-terms/lib/index.js`
- 门禁：`tools/release_gate.py`、`docs/RELEASE-GATE.md`
- 设计约定：`agent.md` §3
