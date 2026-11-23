# RESEARCH-pii-protection 实施计划

> 来源：`docs/RESEARCH-pii-protection.md`（2026-11-20 复核版，81 条问题清单 + 12 条结论 + §6 路线图 + §7 十条决策）。
> 状态：**计划待执行**。制定时间：2026-11-20（Node 引擎迁移已合并推送：`54e8519` / `167eae3`）。
> 执行原则：每阶段独立可验收、独立可提交；阶段末跑全量回归五套（plugin_terms / plugin_jobs / plugin_display / engine-equivalence / protocol-smoke）+ 全量 pytest，全绿才进入下一阶段。

## 0. 迁移后现状（计划的前提）

- 运行时 = Node 引擎（`node_pii/server.mjs`，guard 经 `NODE_BIN` spawn）；Python `presidio_pii/` 保留为**等价性基准 + CLI**。
- 由此新增一条全局硬约束：**任何识别层改动必须双端同步**（Python 改了，`node_pii/` 对应模块必须等价改；golden 样本随之扩充），否则 `tests/node/engine-equivalence.mjs` 41/41 基线破坏。
- 自定义规则 JSON 通道双端已实现（Python `custom_rules.py` / Node `custom_rules.mjs`），是 Phase 0 的落点；**规则 pattern 只能写 Python `re` 与 JS `RegExp` 的公共子集**（禁变长 lookbehind——Python 直接跳过该规则并 warn）。

## 1. 范围

**做**：§6 路线图 Phase 0 → Phase 4（Phase 5 待定），按 ROI 排序执行。
**不做（本轮）**：NER 模型分档（ROADMAP 长期项，D5 已论证性价比不足）；`RESEARCH-pii-protection.md` 中所有标记「待拍板」的决策不擅自实施，见 §5。

## 2. 阶段拆解

### Phase 0 — 字段补齐（预估 1 天，ROI 第一）

研究报告 §0.3 第一件事 + §5.4 F 系列。目标：字段覆盖 13/22 → 22/22（样本级计数）。

| # | 任务 | 落点 | 验收 |
| --- | --- | --- | --- |
| 0.1 | 新增 7 个字段规则库（`kind: regex`，每字段一个 JSON 文件）：`AGE` / `BIRTH_DATE` / `GENDER` / `ETHNICITY` / `EDUCATION` / `IM_ACCOUNT` / `EMPLOYEE_ID`；全部 `context_hint` 标签驱动（参照 §5.6 已跑通的 age-ctx 样例），**不写裸单位词**（"20岁以上/3岁以下"负样本必须零命中） | 仓库内 `rule_libraries/`（D9：内置清单落仓库） | 双端加载无 warn；正样本命中、负样本零命中 |
| 0.2 | `preset.json` 扩 `entity_types` 至 20 类（13 + 7）；同步门禁与 UI 保存侧白名单 | `.agent-presets/presidio-pii/preset.json`、`plugins/dsh-presidio-pii/lib/terms.js:326-332` | preset 保存回路正常；plugin_terms 全绿 |
| 0.3 | 修 F-04 姓名弱上下文（"员工范志强，男，45岁。"→[]，左上下文职务词+姓名） | Python `chinese_recognizers.py` + Node `recognizers.mjs`（双端） | 该句命中 PERSON；既有精度闸门不回归 |
| 0.4 | 修 F-05 住址尾号（门牌正则补"室/号/单元+楼层房号"） | 同上双端 | "88号3单元501"完整命中 LOCATION |
| 0.5 | 修 F-06 机构左边界（"他是公司总经理"→ORGANIZATION 他是公司） | Python `_trim_org_start`/`_ORG_PREFIX_WORDS`（`chinese_recognizers.py:802,869`）+ Node 对应实现 | "他是"不再被吞进机构名 |
| 0.6 | 修 F-07 籍贯（"籍贯：山东济南"省+市专用规则） | 新规则库或 Location 增强（双端） | 完整命中"山东济南" |
| 0.7 | 每个新字段补 `test_common_words_are_not_pii` 类负样本用例，**有/无 jieba 双模式各跑一次** | `tests/` | 双模式全绿 |
| 0.8 | golden 扩充：`tools/gen_equivalence_golden.py` 加 7 字段正/负样本 → `tests/node/golden.json` 重生成 | `tools/` + `tests/node/` | engine-equivalence 扩容后 100% 匹配 |
| 0.9 | 门禁 #1 扩新字段（当前只硬绑 PERSON，`release_gate.py:72-96`） | `release_gate.py` | 新字段 disabled→0 产出断言（R-15 口径） |

**阶段验收**：22/22 字段探针全命中；五套回归 + pytest 全绿；golden 等价性保持 100%。

### Phase 1 — 「删掉 bash」最小 PII 预设（预估 1–2 天）

研究报告 §0.3 第二件事 + §6 Phase 1 + 通道层 T 系列主战场。**前置决策：D1（删 shell）、D3（自建工具抹路径）需先拍板**。

| # | 任务 | 落点 | 验收 |
| --- | --- | --- | --- |
| 1.1 | 自建四件套工具 `read_redacted` / `write_raw` / `restore` / `ls`（内部自限长防 spill；内部 catch fs 错误抹 `displayPath`） | 新插件 `plugins/dsh-presidio-pii/`（复用 guard 的 server 通道与 scoped shadow 范式 `plugins/dsh-presidio-pii/lib/guard.js:618-659`） | 超长结果不落原文；错误信息无路径泄漏 |
| 1.2 | 预设 `plugins` 数组不写 `tool-fs-search` / `tool-bash` / `tool-pwsh` / `tool-web` / `tool-todo`；`tool-fs` 五开关全关 | `.agent-presets/` | 工具面枚举断言（研究报告 §3.4 表） |
| 1.3 | 门禁三条：①预设不得出现 `dsh-tool-executor-ptc`（R: 结论#8 定时炸弹）②不得出现 `PII_GUARD_FAIL_OPEN=1` ③构造超长结果后断言 spill 目录里是占位符 | `release_gate.py` | 三断言入库，人为破坏可 FAIL |
| 1.4 | home 层删 `mcp-codebuddy` / `mcp-playwright`（T-27） | DSH home 配置（**跨仓库**，需单独确认） | 预设内 MCP 面收窄 |

**阶段验收**：直读通道 4 → 1（仅剩守卫后的 `read_redacted`）；门禁三断言 PASS。

### Phase 2 — 占位符保护 + 观测性（预估 2 天，从 §6 Phase 2/3 提炼的先置小步）

研究报告结论#12（约束六）+ R-43 + R-39。D10 已给方案：打在 `analyze()` 全局保护区。

| # | 任务 | 落点 | 验收 |
| --- | --- | --- | --- |
| 2.1 | `analyze()` 加 `_drop_placeholder_spans`（复用 `_drop_uuid_spans` 形状）：占位符区间进保护区，二次脱敏不可切碎 | Python `engine.py` + Node `engine.mjs`（双端） | 新不变式测试：任何规则组合下输出无嵌套 `⟦PII:⟦PII:`；golden 重生成 |
| 2.2 | R-43：加载期把 `entity_types` 与实际产出类型做差集，非空 `_warn` + 保留旧值 | 双端引擎 | 手改 preset 拼错类型名 → 告警且不静默失效 |
| 2.3 | R-39 最小观测面：状态接口返回启用的库/各库产出计数/上次 reload 时间 | `server.py` + `server.mjs`（协议加 status op） | 协议 smoke 扩 status 用例 |

### Phase 3 — 规则库地基（预估 1 周）

研究报告 §6 Phase 3 + §2 全节设计（manifest / 坐标契约 / 优先级 / 三态 / 热更新）。**前置决策：D6、D7、D9 需拍板**。

| # | 任务 | 验收 |
| --- | --- | --- |
| 3.1 | `RuleSpec` 加 `rule_id` / `enabled`；新增 `LibrarySpec`（`id/name/kind/emits/coordinate/requires/excludes/replaces/priority`） | schema 测试锁定 |
| 3.2 | `RegexRuleRecognizer` / `CodeRuleRecognizer` 的 `wants_raw` 改读 `coordinate`（修 R-09 / 结论#6） | 全角/插值/换行三类变体不再整批归零 |
| 3.3 | `CustomRuleSet` 支持清单：manifest 参数 + 签名覆盖清单 + 三态 `ok/empty/degraded`（修 R-01/R-02/R-05） | 关库=真关（结果里真的没有，Presidio #950 教训断言）；加载失败保留旧值且可观测 |
| 3.4 | `engine._sync_recognizers()` 加过滤钩子（禁用=不实例化，D7：运行期过滤）；`_prio` 四级解析（修 R-44/R-45 priority 污染与垫底） | `"(?!)"+priority:0` 不再翻转整类裁决 |
| 3.5 | `requires` 不满足时拒绝加载（修 R-06 关身份证→15位被吞成银行卡） | 交叉依赖测试 |
| 3.6 | CLI 加 `--entity-types` / `--no-entity-types`（修 R-47） | CLI 与 preset 语义一致断言 |

### Phase 4 — 内置库化 + 门禁重构（预估 1 周）

研究报告 §6 Phase 4。

- 拆 `chinese_recognizers.py`：共享工具进公共模块；删死代码 `_next_is_boundary`（`:193`，0 处使用）；合并三份机构后缀表与两份地名单位表。**Node `recognizers.mjs` 同步重构，golden 41→扩容样本全等价是唯一裁决标准**。
- 内置 manifest（`kind: builtin`）与用户 manifest 同构；名册按 R-42 固定为 `builtin.person` 内部通道，禁止单独 `enabled`。
- 门禁 #1 改「按清单加载」+ 逐库断言：默认 enabled→产出>0；disabled→该类型==0 且其余不变（修 R-15）。
- R-08 泄露面：默认禁字面量精确规则、只允许结构化模式；确需精确匹配走 `USER_TERM` 白名单通道并强制落 `.pii_presidio_store/`；门禁 #11 扩到规则库目录。

### Phase 5 — UI 与一致性（待定）

清单 schema 校验器、`reload` op、库列表 UI（`routes.size === 4` 硬契约会挂，`tests/js/plugin_terms.mjs:115` 需同步改）、`replaces` 替换流程、位置一致性校验。**启动条件：Phase 3 落地后评估**。

## 3. 双引擎 parity 纪律（本计划新增的全局约束）

1. 每个识别层任务的 DoD 必含：Python 实测输出 == Node 实测输出（同输入同 sid 同配置）。
2. golden 样本随每个新字段/新行为扩充，`gen_equivalence_golden.py` 重生成后 engine-equivalence 必须 100%。
3. 规则 pattern 公共子集白名单：禁变长 lookbehind（Python 跳过规则）、禁 Unicode 属性类差异点（`\p{...}` JS 专属）；如必须用，双端各写等价实现并在库 manifest 声明 `engine_variants`。
4. 行为性修复（F-04/05/06/07、占位符保护）先写 Python 复现→修→锁测试，再镜像到 Node，避免双端漂移。

## 4. 排期与依赖

```
Phase 0（字段补齐）──┐
                      ├─→ Phase 2（占位符保护）──→ Phase 3（库地基）──→ Phase 4（内置库化）──→ Phase 5（待定）
Phase 1（删 bash）──┘
```

- Phase 0 与 Phase 1 无相互依赖，可并行；Phase 1 依赖 D1/D3 拍板。
- Phase 2.1（占位符保护）建议插队在 Phase 3 之前：自定义通道越铺越宽，占位符可碎性是「唯一能触发它的路」，越晚修风险敞口越大。
- 单阶段规模参照研究报告自估（0=1天、1=1–2天、2≈2天、3=1周、4=1周）；每一阶段独立成一笔或两笔 commit（代码/文档分离）。

## 5. 待拍板决策（阻塞项标注）

| 决策 | 内容 | 阻塞 |
| --- | --- | --- |
| D1 | 删 shell / 保留但承认无效（研究报告论证：白名单约束不可作为安全边界） | **阻塞 Phase 1** |
| D2 | docx 路线 α（原地保样式）vs β（套模板） | 阻塞 write_docx（本轮未排期） |
| D3 | 自建工具抹 displayPath + 逃生开关形态 | **阻塞 Phase 1** |
| D5 | NER 不纳入（维持不纳入） | 不阻塞 |
| D6 | 库级开关为主、规则级进高级面板 | 阻塞 Phase 3 UI 部分 |
| D7 | 构建期不加载 vs 运行期过滤（实测 5.75× 性能差） | **阻塞 Phase 3.4** |
| D8 | 默认开/关集合（建议：人名/电话/身份证/邮箱/银行卡/AGE 类默认开，机构/地名/职务默认关） | 阻塞 Phase 0 preset 定稿 |
| D9 | 清单双落点（内置在仓库 / 用户在 `.pii_presidio_store/`） | 阻塞 Phase 0 落点定稿 |
| D10 | 占位符保护打 analyze() 全局 | 建议采纳，阻塞 Phase 2.1 |

## 6. 验收契约（不改写的硬约束）

执行全程不得破坏：`routes.size === 4`、settings 恰 4 键、清空写 `(?!)`、空数组→0 条、破损保留旧规则、refresh 返回布尔；新增 9 条契约以研究报告 §8 为准（禁 PTC、禁 FAIL_OPEN=1、spill 占位符断言、逐库 enabled 断言、entity_types 差集、无嵌套占位符不变式、`entity_types: []` 语义锁定、CLI 一致性、门禁 #10 tree digest 重跑提醒）。

## 7. 第一步（若本计划获批）

Phase 0 全表 0.1–0.9，从 0.1 的 7 个规则库 JSON 开始——研究报告 §5.6 已实测跑通 age-ctx 样例，链路风险最低；D8/D9 两个阻塞决策在本阶段内即可一并确认。
