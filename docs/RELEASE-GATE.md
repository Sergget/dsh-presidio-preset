# 发布门禁清单（v0.1.0）

用途：上线前逐项勾选。每项写明**判定标准**、**当前状态**、**证据位置**。
状态取值：`PASS` / `FAIL` / `SKIP`（无法执行，如离线/待决策）/ `MANUAL`（需人工操作，如重启 DSH）/ `BLOCKED`（等用户决策）/ `PENDING`（未验证）。与 `tools/release_gate.py` 输出一致。

判定原则：宁可标 SKIP/MANUAL/BLOCKED/PENDING，不用"看起来能用"凑 PASS；任何靠降级依赖绕过的项一律记 FAIL。

> **运行时口径更新（2026-11-20，Node 引擎迁移）**：guard 插件的脱敏服务已从 spawn Python `presidio_pii/server.py` 切换为 spawn Node `node_pii/server.mjs`（零 npm 依赖；等价性 41/41、协议 smoke 3/3，详见 [NODE-ENGINE.md](NODE-ENGINE.md)）。门禁判据本身不变——#1/#3/#5 等仍以「脱敏行为」为准；`presidio_pii/` Python 引擎保留作为等价性基准与 CLI Office 文档用途，`python -m pytest` 与 `python tools/release_gate.py` 照常运行。fail-closed 语义不变（spawn 失败/退出/超时 → 阻断）。

---

## 0. 总览

| # | 门禁项 | 状态 |
|---|---|---|
| 1 | 读取侧拦截（引擎/插件层） | PASS |
| 2 | 读取侧拦截（DSH 进程内 E2E） | PASS（2026-11-10 重启后 9 步实测，等价口径见 §2） |
| 3 | redact→restore 无损（md + office 三格式） | PASS |
| 4 | 自动 restore 接线（模型回复侧） | PASS（2026-11-10 拍板方案 B 并实现：显示侧还原） |
| 5 | 格式覆盖面 | PASS（文本类 + pwsh 前台 + job_output/job_list） |
| 6 | 依赖漏洞 | FAIL（2026-11-16 复核：环境 `opentelemetry-api 1.45.1` 报 `CVE-2026-126360`，修法 1.45.2；与本轮代码无关，见 §6） |
| 7 | 密钥扫描（工作树 + 历史） | PASS |
| 8 | 单元测试套件 | PASS（2026-11-16：222 passed，含用户屏蔽词 9 条；深夜 FP 修复后 228 passed） |
| 9 | 可复现安装（wheel + 干净环境） | PASS |
| 10 | 源码可溯源（origin 含 HEAD / 产物清单） | PASS（A：origin 已含 HEAD，2026-11-10 推送） |
| 11 | 仓库不落真实 PII / 映射库 | PASS |
| 12 | 外部语料（网络下载）回归 | PASS（离线时 SKIP） |
| 13 | Phase1 最小工具面（门禁①②③） | PASS（四件套挂载、shell/直读面移除；GATE_PHASE1_DONE） |
| 14 | 生产配置实体类型接线（双端 hooks） | PASS（2026-11-20 新增；事故后补门禁，只走生产路径，不再用测试内显式传规则的自证口径） |

> **本轮修复（2026-11-16，人名泄漏 + meta.lines 原文）**：会话 `session-18565589-7045-4c0a-aedd-852209df044d` 暴露两条独立缺陷并已修复。
> (A) 新版 `read` 的 `tool/result.meta.lines` 直接派生自 canonical `value.lines`（48 行原文），而 `tools/post-execute` 只改 `content` 碰不到 `meta` → 模型看到占位符，但 session log 与 GUI 卡片仍留明文。修法：插件用 `redactValueLeaves()` 递归把 `result.value` 的原文替换成占位符，返回公开的 `{kind:"accept", value}` 决策；`pipeline.js createSuccessResult()` 用新 value 重跑 `render` + `presentationMeta`，content / meta.lines / meta.path 一起脱敏。仅当检测到 PII 且工具带 `meta` 时走此路径（无 PII 零 schema 风险），shell+job 保持原 content 路径以保留截断/非文本标记；`redact()` 恒发 `mode:"full"` 拿原文映射，`PII_GUARD_DISPLAY=mask` 时显示侧打码由 Node 侧 `displayValue()` 复刻。
> (B) `ChinesePersonRecognizer` 的 `_NON_NAME_CHARS` 含「之」「同」「也」且不支持复姓/带学号后缀 → 名单里 3 个名字连 `content` 都漏检。修法：新增独立 `ChineseRosterPersonRecognizer`（不动现有人名识别器，其测试全绿），只在「显式名单引导词 + 冒号 + ≥3 项顿号/逗号链」且每项为 2-4 纯汉字时触发，内联 26 个复姓常量 + `_ROSTER_NEGATIVE` 负样本词整链否决，只 emit 名字本体（剥掉「（26）」学号后缀，保证 restore 无损）。`get_chinese_recognizers()` 现 15 个识别器，`_resolve_overlaps` 长实体去重。
> 精度约束（agent.md:82-84）：未改 `assets/*.txt`；补一条 `test_common_words_are_not_pii` 负样本「名单：身份证、手机号、银行卡、人名等个人信息。」；`tests/test_roster_person.py` 覆盖 4 类历史漏检形态 + 17 条负样本 + 15 条整引擎负样本 + 无 jieba 模式，全合成值。真实文档 E2E：名单 27 token 全部占位符、`tokens_still_plaintext=0`、`PERSON=31 / PHONE_NUMBER=3`、`restore_byte_exact=true`；真实 `server.py` IPC 的 JS E2E 验证 `accept+value` 全脱敏且不原地改冻结对象。残留边界不变：`tool/call` 原始参数仍落盘、pwsh/bash 的 `meta.cwd`、用户直接粘贴进输入框的文本、read_image。

> **本轮新增（2026-11-16，用户自定义屏蔽词 UI）**：新 bundle `plugins/dsh-pii-guard-terms`（包名 `dsh-pii-guard-terms`，patch 行 `dsh-pii-guard-terms:terms`）在**设置页**注册 `settings.section`（id `pii-guard-terms`, order 30）+ `settings.section.icon`，用户可自行增删「需要屏蔽的词或短语」。
> 链路：设置页 → `GET/POST /api/dsh-pii-guard/terms[/save]`（Host 半体 `ctx.webServer.register`，自实现 loopback + `Sec-Fetch-Site`/Origin 同源证明三层围栏，64 KB 请求体上限）→ 原子写 `E:/Code/dsh-presidio-preset/.pii_presidio_store/user_terms_rules.json`（每词一条自定义规则 `entity_type:"USER_TERM"`、`priority:0`、`pattern` 为 `escapeLiteral` 后的字面量、附加 Python 会忽略的 `term` 键用于无损回读）→ `preset.json` 的 `config.custom_rules_path` 指向该文件 → 引擎 `CustomRuleSet.refresh()` 每秒比对 `(path, mtime_ns, size)` 签名，**1 秒内热更新**，无需重启。
> 关键坑：`CustomRuleSet.refresh()` 在规则产出 0 条而旧规则非空时**保留旧规则**（`custom_rules.py:403-406`），所以「清空全部词」必须写单条永不匹配占位规则 `pattern:"(?!)"`，不能写空数组；`escapeLiteral` 保证含正则元字符的词按字面匹配（`a.c` → `a\.c`），且不用捕获组（有捕获组时只脱敏 group(1)）。
> 证据：`tests/js/plugin_terms.mjs` 30 条冒烟、`tests/test_user_terms.py` 9 条单测（规则文件语义 + 热更新）、`pytest` **222 passed**；真实运行进程联调：裸请求 403 `missing same-origin proof`、`DELETE` 405、cross-site 403、保存后规则文件落盘、清空后回落占位规则；同一已缓存引擎在保存后 1.3s 内命中 `⟦PII:USER_TERM:0001⟧`，清空后命中归零。门禁 #5 新增 `terms=` 与 `terms_wiring=` 两项断言。限制：最多 500 条、单条 ≤200 字符、纯字面匹配（不支持正则）。

：`python tools/release_gate.py --json $env:TEMP\pii_verify_leak\pii_gate_full_leak.json` → **PASS 11 / FAIL 1 / SKIP 0 / MANUAL 0（677.1s，退出码 1）**，证据：`$env:TEMP\pii_verify_leak\verify2_result.json` 与 `pii_gate_full_leak.json`。#1/#2/#3/#4/#5/#7/#8/#9/#10/#11/#12 全 PASS；#5 `src=repo plugin=ok; installed_sync=ok; js_smoke=pass/display=pass`、#8 **213 passed in 45.94s**、#9 wheel 两次构建一致（`3ce8d89dbdf81293…`，61357B，`reproducible=True`）、#10 `HEAD=db7c77a6 origin/master=db7c77a6 ahead=0`（`commit_match=False tree_digest_match=False`，按「origin 可达」路径 A PASS）。**唯一 FAIL 是 #6 依赖漏洞**：环境 `opentelemetry-api 1.45.1` 报 `CVE-2026-126360`（fix 1.45.2），属本机已安装包的上游 advisory，与本轮 PII 代码/依赖声明无关（11-11 复核时 pip-audit 为 0）；升级 `opentelemetry-api>=1.45.2` 后重跑 #6 即可恢复 12/12，本次不擅自改动依赖。`tests/js/plugin_jobs.mjs` 现 24 条、`plugin_display.mjs` 6 条，均由 #5 调用。
> 另记：本轮验证全程在 `pwsh` 工具的 Windows Job runner 故障（`0xC0000142`）下通过 Playwright server 的 `windowsHide:true` 子进程通道完成；`pwsh`/`glob`/`grep` 工具本身不可用，不影响产物结论。

> **门禁 #14 新增（2026-11-20，生产接线事故闭环）**：真实启动暴露 golden/门禁全绿但生产失效的组合缺陷——①hooks 只加载 preset 用户词表，`rule_libraries/extended-fields.json` 从未进生产链路（测试里显式传规则=自证）；②Python `_known_entity_types` 漏 `_PRIO` 键（MAC_ADDRESS 被判未知剔除）；③双端 `analyze()` 把 wants_raw 原文坐标结果混入归一化桶过 `norm.back()`，跨度整体平移一字（双端同错所以 57/57 golden 测不出）；④guard 模块加载期 `resolveRepo(null)` 误报「无法确定仓库根」。修法：双端 hooks 合并内置库+用户规则（分号多路径，逐文件热更新）；`engine.py` 并入 `set(_PRIO)`；analyze 拆 raw/probe 两桶只映射后者；加载期静默解析。防回归：`tests/node/preset-runtime-types.mjs`（8 项，只走 PII_DSH_PRESET→getEngine 生产路径）+ `tools/check_runtime_types.py`（Python 同口径）+ `check_runtime_wiring()` 作为第 14 项门禁；`--only 14` PASS（node=ok py=ok declared=20 missing=[] unproduced=[] unknown_warning=False）。全量回归：pytest 281 passed、golden 57/57、五套 JS 全绿。详见 [INCIDENT-20261120-runtime-wiring.md](INCIDENT-20261120-runtime-wiring.md)。

> **复核结论（2026-11-16 晚，用户自定义屏蔽词 UI 落地后全量门禁）**：`python tools/release_gate.py --json C:/Users/sergg/AppData/Local/Temp/pii_gate_run2/gate.json` → **PASS 11 / FAIL 1 / SKIP 0 / MANUAL 0（157.1s）**。#1/#2/#3/#4/#5/#7/#8/#9/#10/#11/#12 全 PASS；#5 新增 `terms=ok; terms_wiring=ok(.pii_presidio_store/user_terms_rules.json)`；#8 **222 passed in 13.53s**；#9 wheel 两次构建仍字节一致（`3ce8d89dbdf81293…`，61357B，`reproducible=True`）。**唯一 FAIL 仍是 #6 依赖漏洞**，且仍是环境级 `opentelemetry-api 1.45.1` → `CVE-2026-126360`（fix 1.45.2），与本轮改动无关；本轮未升级该全局包。另：本轮 `pwsh`/`glob`/`grep` 工具持续故障（`Windows Job runner exited with exit code 3221225794` / `ripgrep provider failure`），全部验证经 Playwright server 的 `windowsHide:true` 子进程通道完成。

> **FP 修复（2026-11-16 深夜，教体局汇报会话误脱敏）**：会话 `session-50aeeb15` 读 docx 时「荣获/余人/阳光/文明」被误判 PERSON。根因两条：jieba 词典把高频常用词误标 `nr`（宋庆龄 freq 227 < 文明 6584，freq 阈值不可行），nr 分支与回退分支均放行；回退分支 `_left_context_ok` 对数字前驱直接放行（「8300余人」）。修法：`_PERSON_STOPWORDS` 扩 36 词（只收明确非人名高频词）；`_left_context_ok` 对 ASCII 数字/字母前驱与 `_DIGIT_PREFIX`（余万多几成）显式拒绝；回退分支 3 字窗口前 2 字命中停用词则拒；`_PRE_NAME_CHARS` 补「获」修 FN（「荣获宋庆龄奖学金」）。真实 docx 复扫实体 29→20、FP 清零；`228 passed`，门禁 #5 PASS。无 jieba 双模式新增 1 个既有点（宋庆龄退化为宋庆，TEST-MATRIX 已补记）。

> **症状②修复（2026-11-17 凌晨，助手答案残留占位符）**：会话存档统计 272 处占位符（tool/result 180 + assistant/message 92），其中 46 处在终态 assistant text/reasoning —— 模型把工具结果里的占位符复述进自己的回答。实时流经 assistant-stream 显示还原（`plugin_display.mjs` 覆盖），但**终态 assistant 消息固化的是模型原始输出**（内核 `dsh-agent-loop` `assistant/message` 直接 `session.append`，无终态事件可拦；回放路径不走 stream），GUI 重开/回放时看到占位符。插件层修法 = 防源头：`tools/post-execute` 里 agent 首次产生脱敏映射时，注入一条 additionalContext（官方范式 `dsh-repeat-tool-reminder`，shape `{role:"user", id, content:[{type,text}], source:{kind:"pii-guard", form:"notice"}}`），内容为占位符三条使用规则（逐字符保留/不猜测/展示保持原样）；`noticedAgents` WeakSet 保证每代理只注入一次（保护 KV cache）。注意边界：注入只对新会话生效，且**已固化的历史消息无法追溯修复**（需内核支持终态事件才能根治）。验证：`plugin_jobs.mjs` 28 条 ALL PASS（新增 4 条 notice 用例）、228 pytest、门禁 #5 PASS（`installed_sync=ok`，sha `e2f32501…`）。

> **最终复核（2026-11-11，v0.2 强化后）**：`python tools/release_gate.py --json $env:TEMP\pii_gate_full.json` → **PASS 12 / FAIL 0 / SKIP 0 / MANUAL 0，退出码 0**（622.0s）。#1 引擎层 12 处替换、`#3` 三格式逐字还原、`#5` 仓库/安装插件 sha256 一致 + 21 条 JS 冒烟全过、`#6` pip-audit 0、`#8` **175 passed**、`#9` 两次构建字节一致（`63a3b1eb…08a`，59489B）、`#12` 外部语料全无损，均在正常环境实测通过。证据：`$env:TEMP\pii_gate_full.json`。
> 本轮变更：拆掉 persona 五步 CLI 双轨；插件改为默认全工具结果扫描 + fail-closed；新增写入侧 scoped shadow 占位符还原、`read_image` 隐藏、`agent/pre-step` 兜底告警；修复末尾手机号漏检（15 条新回归用例）。
> 注意：`release/presidio-pii-dsh-0.1.0.json` 仍记录 2026-11-10 的 wheel 哈希与 commit，因源码已变且工作树未提交，#10 按「origin 可达」路径 A 判定 PASS；**下次正式发布时须重跑 #9/#10 重新生成清单**。

> **历史复核（2026-11-10，正常 PowerShell 窗口）**：`python tools/release_gate.py --json $env:TEMP\release_gate_final.json` → **PASS 12 / FAIL 0 / SKIP 0 / MANUAL 0，退出码 0**（195.3s）。#6 pip-audit 0、#8 160 passed、#9 两次构建字节一致（`77154909…`，58831B）均在正常环境实测通过；此前 DSH 会话内的 3 个 FAIL 确认为沙箱写权限假阴性。**门禁已全部通过，可发布**。证据：正常窗口终端输出（`tools/release_gate.py --json $env:TEMP\release_gate_final.json`）。

---

## 1. 读取侧拦截（引擎/插件层）

- [x] **判定标准**：read/grep 结果中的 PII 被替换为 `⟦PII:TYPE:NNNN⟧`，敏感人名明文不出现；个人类实体计数为 0 时不得误报。
- **当前状态**：PASS
- **证据位置**：
  - 插件实现：`E:/Code/dsh_home/plugins/dsh-pii-guard/lib/index.js`（接缝 `tools/post-execute`，`prepend: true`；2026-11-11 起默认对**所有**工具的文本结果脱敏，黑名单 `SKIP_TOOLS={job_kill,read_image}`；服务异常 **fail-closed 阻断**，仅 `PII_GUARD_FAIL_OPEN=1` 排障时透传）
  - 复测（引擎层，detector 修复后重跑）：`paper-01.md` → PERSON 8 / ORGANIZATION 2 / LOCATION 1 / EMAIL_ADDRESS 1，共 12 个占位符，明文人名 absent=true；空白序列与原文完全一致（`whitespace_seq_same=true`，换行/Tab/缩进无损）
  - 计数变化说明：修复前 PERSON 9 / 共 13，多出的 1 条是章节标题「方法」+尾随空格被误判为人名（常用词被尾随空白绕过 `is_common_word` 检查），修复后误报消失，不是漏报；6 篇 paper 语料均同此规律
  - 运行日志：`.pii_presidio_store/hook_log.jsonl`（含 09:56:18 一次 `n_replaced=4` 的成功脱敏记录）。该日志 2026-11-06 起只存元数据（实体类型/数量、内容指纹、`conv_sha1`/`doc_sha1`），不再写原文；存量文件已原地清洗（4,403,418 B → 14,249 B，明文行 65 → 0）

## 2. 读取侧拦截（DSH 进程内 E2E）

- [x] **判定标准**：用户在 DSH 中选 `presidio-pii` 预设，按门禁脚本列出的 9 步（完全退出/重启 + 以下 7 项内容检查）重跑：
  ① read `paper-01.md` 前 8 行含 `⟦PII:PERSON:xxxx⟧` 且无真实人名；
  ② read `normal-01.md` 中 PERSON/ID_NUMBER/PHONE_NUMBER/BANK_CARD 计数全为 0；
  ③ grep `13800000000` 命中行已脱敏；
  ④ pwsh `Get-Content paper-01.md` 输出已脱敏；
  ⑤ pwsh 无 PII 命令（`git status`/`Get-Process`）输出逐字节不变；
  ⑥ pwsh 后台任务 + `job_output` 续读已脱敏；
  ⑦ `job_list` 的命令/描述回显已脱敏。
- **当前状态**：PASS（2026-11-10）—— 用户完成托盘完全退出 + 重启选 `presidio-pii` 预设后，由模型在本会话内用 DSH 内置 read/grep/pwsh/job_* 工具实测步骤 3–9，全部符合；`hook_log.jsonl` 新增 15 条 `before_llm`（n_replaced 与各步骤一一对应，日志仅含元数据无明文）。
- **证据位置**：`.pii_presidio_store/e2e_9steps_2026-11-10.md`（9 步逐条结果与对账）。注意两点：① 步骤 5 为等价口径——`testdata_v2` 文本语料无真实手机号（PHONE_NUMBER 为占位符示例），以"无 PII 行标签命中含 PII 行"验证 grep 拦截；② isError 进程内不易稳定触发，仍由 node 冒烟（门禁 #5）覆盖。执行环境 DSH 0.2.2-rc.1，preset 挂载经 `tools/verify_preset_plugins.mjs` 校验。

## 3. redact→restore 无损

- [x] **判定标准**：还原后的文本单元与源文件**逐字相等**，且残留占位符数 = 0。
  注意：office 容器（zip）的 SHA256 必然变化（时间戳/元数据），**不以容器字节相同作为判据**；md/txt 这类纯文本才要求 SHA256 相同。
- **当前状态**：PASS
- **证据位置**（本轮 pillow 13.0.0 / certifi 2026.10.18 下重跑）：

| 文件 | 单元数 | 单元逐字相等 | 还原占位符 | 残留占位符 |
|---|---|---|---|---|
| `testdata_v2/resume/resume-01.docx` | 27 | True | 13 | 0 |
| `testdata_v2/payroll/payroll-01.xlsx` | 111 | True | 70 | 0 |
| `testdata_v2/report/report-07.pptx` | 19 | True | 13 | 0 |

  - 纯文本：`paper-01.md` redact→restore 后 SHA256 相同（`md_byte_identical=True`）
  - 映射落盘载体：`<产物>.mapping.csv`（`presidio_pii/cli.py` 导出），restore 优先读它，脱敏目录可整体搬运

## 4. 自动 restore 接线（模型回复侧）

- [x] **判定标准**：模型在回复里输出占位符时，用户看到的是原文（或打码值），且还原动作没有把 PII 重新送进模型上下文。
- **当前状态**：PASS（2026-11-10 判定，2026-11-18 补强）—— 用户拍板**方案 B**：`agent/assistant-stream` 显示侧改写；显示模式等 4 项 P0/P1 配置已接入设置页，可即时切换、无需重启 DSH。
- **实现**：
  - 插件新增 `agent/assistant-stream` 监听器（`prepend+global`，先于 session-controller 折叠器）：把助手文本流中的占位符同步替换为映射值；跨 chunk 分裂的占位符用「扣尾补头」缓冲（`splitDisplayable`），`end` 帧兜底放行，`start` 帧清缓冲。改写只影响显示流与重连基线——持久化发生在 `live.push()` 内部（早于 emit），**会话存储与模型上下文不受影响**。
  - **设置项（已接线到设置页，2026-11-18）**：设置页「PII 防护」菜单（屏蔽词与防护配置合并为同一菜单、页内分区）可编辑 4 项 P0/P1 配置，保存到单一数据源 `.pii_presidio_store/guard-settings.json`（被 .gitignore 覆盖、不含 PII）：
    - `displayMode`（显示还原模式）：`full`（显示完整原值，默认）/ `mask`（Python 端 `_mask_value` 完成后仅下发打码值，原文不过 Node）/ `off`（关闭，回到纯占位符）。
    - `failOpen`（服务异常策略）：`false`（默认，fail-closed 阻断工具结果）/ `true`（透传，**仅排障**；开启时设置页显示警告）。
    - `shellDisabled`（Shell 守卫总开关）：`true` 时整个进程不拦截 shell/后台任务。
    - `shellAllowlist`（Shell 命令白名单）：RegExp source，仅对 pwsh 生效；前端 `new RegExp` 预校验，非法正则拒绝保存。
    - **即时生效**：guard 插件每次事件按 mtime+size 读取该文件并缓存，改完下一次工具调用即生效，无需重启 DSH；文件缺失或字段缺省时回退到进程启动时的 env 值（`PII_GUARD_DISPLAY` / `PII_GUARD_FAIL_OPEN` / `PII_GUARD_SHELL` / `PII_GUARD_SHELL_ALLOWLIST`），保持旧部署语义。
  - `server.py` 新增 `op=restore` 协议与 redact 响应的**增量 map 下发**（只含本次新增映射；mask 模式下发打码值）。映射键口径与 `before_llm` 一致（`hooks.session_id()` 哈希）。
- **证据位置**：
  - 源码断言：`tools/release_gate.py --only 4` → PASS（plugin_display / server_restore 全命中）
  - 行为冒烟：`tests/js/plugin_display.mjs` 8 条（无映射透传、跨 chunk 分裂不丢字符、扣尾缓冲、end 兜底、start 清缓冲、**off 模式即时切换与回切**）；`tests/js/plugin_jobs.mjs` 24 条（2026-11-16 扩充：新增 meta/value 重渲染、无 PII 不动 value、shell 不走 value 三条，见 #5）；`tests/js/plugin_terms.mjs` 42 条（2026-11-18 重写：settings 读写/持久化/非法值拒绝、S1 伪造 cookie 拒绝、S4 真实落盘检查）
  - 闭环验证：redact→map→restore(full) 逐字还原（`full_ok=true`）；mask 值形如 `13*******78`、`z***@example.com`
  - 残余说明：B 依赖 `agent/assistant-stream` 非公开契约（dsh 0.2.2-rc.1 实测可用），dsh 升级需复验；用户把还原后的明文复制进输入框属于使用约定问题，插件不可拦截

## 5. 格式覆盖面

- [x] **判定标准（文本类）**：md/txt/csv/json/xml 经 read 拿到的内容必须是已脱敏文本。
- **当前状态**：文本类 PASS；office 类“不泄露但不可用”；pwsh 前台已按 P1-全纳入（PASS，2026-11-06 拍板）。
- **证据**：
  - md/txt/csv/json：读取侧拦截生效（csv 实测 PERSON/ID/PHONE/ORG 计数 > 0）
  - docx/xlsx/pptx 经 read：原始字节 UTF-8 解码后占位符 0、PII 明文 0 —— 因 zip DEFLATE 压缩，内容本身不可用，**不构成泄露**，但用户也读不到内容；此类文件应走 CLI 产物级 redact/restore
  - rg 对 docx 内证件号默认 `exit=1`，加 `--text` 仍 `exit=1`
- [x] **判定口径说明（2026-11-20 复审修正）**：第 5 项原先断言字面量 `svc.on("error"`，而 B1 竞态修复
  把 `svc` 改成「服务实例句柄」对象后，真正挂 error 处理的是 `proc` —— 合法重构被判成回归。
  现改为正则断言 `\.on\(\s*["']error["']`：锁**行为**（子进程挂了 error 处理），不锁变量名。
  同理，门禁断言列表里凡是「实现细节字符串」都要能经受重构，否则门禁会变成阻碍改进的枷锁。
- [x] **shell（pwsh 前台 + 后台任务 + isError）输出**：PASS —— 插件自 2026-11-11 起改为**默认全工具扫描**（`SKIP_TOOLS = {job_kill, read_image}` 黑名单），`read`/`grep`/`pwsh`/`job_*`/MCP/PTC/web 等文本结果一律脱敏；`job_output`/`job_list` 单块超过 256,000 字节先截断再脱敏并追加截断标记；非文本输出（NUL>1% 或不可打印>30%）不脱敏并追加标记行；shell/后台任务的 `isError` 文本同样脱敏（其它工具的 `isError` 维持透传）；下游按 `value` 替换 canonical 结果时**阻断**而非静默放行；逃生开关 `PII_GUARD_SHELL=off`（对 pwsh 与后台任务生效）/ `PII_GUARD_SHELL_ALLOWLIST=<regex>`（仅 pwsh），命中写 `shell_bypass` 审计，不含明文。
  - **写入侧（2026-11-11 新增）**：`agent/created` 里用公开 scoped shadow（`agent.ctx.tools.register({...original, execute})` + `agent.ctx.effect`）包住 `write`/`edit`/`apply_patch`/`str_replace_editor`，把模型参数里的 `⟦PII:...⟧` **还原回原文**再交给原实现，避免占位符写坏用户文件；`read_image` 用 `agent.ctx.tools.restrict({deny:["read_image"]})` 在 PII 预设内隐藏；`agent/pre-step` 兜底扫描只告警、不改写消息。
  - **fail-closed（2026-11-11 新增）**：Python 服务 spawn 失败/退出/超时/坏响应 → 返回 `{kind:"block"}` 阻断工具结果，绝不放行明文；仅 `PII_GUARD_FAIL_OPEN=1`（排障用，默认关闭）回退到旧的降级透传。
  - **meta/value 重渲染（2026-11-16 新增）**：带 `presentationMeta` 的工具（新版 `read` 的 `meta.lines`、`grep` 的命中行）在检测到 PII 时，插件返回 `{kind:"accept", value}`（递归 `redactValueLeaves()` 把 canonical value 的原文换占位符），由 `pipeline.js createSuccessResult()` 重跑 `render` + `presentationMeta`，模型上下文 / session log `meta` / GUI 卡片一起脱敏；绝不与原 `content` 路径同时返回（pipeline.js:684 会抛 TypeError）。无 PII、无 meta、shell+job、下游改过 content 时保持原 content 路径，TRUNC_MARK / 非文本标记 / 256 KB 装饰不丢。`redact()` 恒发 `mode:"full"`，`PII_GUARD_DISPLAY=mask` 的显示侧打码由 `displayValue()` 在 Node 侧复刻。
  - 引擎级语义回归：`tests/test_shell_redaction.py` 23 条（14 条无 PII 日常输出逐字节不变、9 条含 PII 的结构保持与还原）
  - 插件行为冒烟：`tests/js/plugin_jobs.mjs` 24 条（job_output/job_list 脱敏、256 KB 截断上限、无 PII 不变、job_kill 放行、非文本标记、read 仍拦、默认全工具扫描、pwsh/job isError 脱敏、read isError 透传、spawn 失败 **fail-closed 阻断**、下游 value 替换阻断、非法 allowlist 不放行、写入侧 wrapper 占位符还原、read_image 隐藏、pre-step 只告警、**meta 工具走 value 重渲染**、**无 PII 不替换 value**、**shell 不走 value 重渲染**），由门禁 #5 调用 node 执行
  - 一键门禁 #5：插件源码断言（含 job 工具、截断常量、isError 范围）+ node 冒烟 + 引擎语义抽查
  - 插件已纳入仓库：`plugins/dsh-pii-guard/lib/index.js`（sha256 `B43F93AF…E4071`，与安装态 `E:/Code/dsh_home/plugins/dsh-pii-guard/lib/index.js` 逐字节一致；#5 比对 sha256，drift 即 FAIL，反向验证：改动仓库副本 → FAIL，恢复 → PASS）
  - 修复一处连带缺陷：归一化曾吞掉数字间的连续空白，把 Get-Process 表格列拼成伪卡号；现改为只吞单个分隔符
  - 未覆盖（P3 剩余）：base64/UTF-16/图片内文字（已知缺口，见决策备忘 §3）；bash 同构（本机无 bash）
  - 进程内 E2E 随 #2 重启后人工跑（手动步骤 6–9）；isError 在进程内不易稳定触发，仅由 node 冒烟覆盖

## 6. 依赖漏洞

- [x] **判定标准**：`pip check` 无破损依赖；`pip-audit` 对安装集合报 0 条已知漏洞。
- **当前状态**：FAIL（2026-11-16 复核，上游环境 advisory，非本轮代码引入）
- **证据**：
  - 2026-11-16 `pip-audit`：`opentelemetry-api 1.45.1` → `CVE-2026-126360`，fix versions `1.45.2`；`pip check` 无破损依赖。升级该包到 ≥1.45.2 后重跑 #6 即可恢复 PASS。该包不在本轮 PII 改动范围内（仓库依赖声明未变），故如实记 FAIL，不用「看起来能用」凑 PASS。
  - 升级前后：`pillow 12.3.0 → 13.0.0`（原 41 条 advisory）；`certifi 2026.7.22 → 2026.10.18`（原 PYSEC-2026-4320）
  - `pip check` → No broken requirements
  - `uvx pip-audit -r <freeze 去掉本地 git 包>` → `No known vulnerabilities found`
  - 说明：audit 输入须剔除 `presidio-pii-dsh` 的 `-e git+ssh://…@ea22be4…` 行，否则 pip-audit 会尝试拉未推送的远端 ref 而失败（不是漏洞，是溯源问题，见第 10 项）

## 7. 密钥扫描

- [x] **判定标准**：工作树与全部可达历史中无真实凭据；命中项须逐条定性，真凭据需轮换。
  **扫描器自测夹具**（`tests/test_release_gate_rules.py` 里为验证正则而放的假值）按路径豁免，
  但每次都在 evidence 里披露豁免条数，不允许静默丢弃。
- **当前状态**：PASS（2026-11-20 复审后：`commits=51`、`diff_lines=30148`、命中 0；
  `selftest_fixtures_exempted=10`）
- **证据**：
  - 工具：PATH 无 gitleaks → 自写 `git log -p --all --no-color` + 12 类正则（AWS key、PRIVATE KEY、GitHub token/PAT、Slack、Google API key、`sk-`、JWT、secret/key/token/password 赋值、URI 带凭据、bcrypt、PEM 证书）
  - 历史扫描按 diff 头 `+++ b/<path>` 归属文件，命中项带路径（`aws_key@history:path:AKI***LE`），便于逐条定性
  - 复审记录：本轮修门禁时我在 `docs/PLAN-phase0-1-implementation.md` 里引用了 AWS 文档示例 key
    作为「假值示例」，被自己的门禁抓出（2 处）。已改写措辞并重写这两笔**未推送**提交，
    历史里不再含该字面量——门禁确实会咬人，包括咬写门禁的人。
- **覆盖与漏检说明**：
  - 覆盖：所有分支/tag 可达提交的文本 diff + 提交消息 + 全部 tracked 文本文件
  - 漏检可能：二进制/图片 diff 内嵌内容、reflog 与不可达对象（dangling）、submodule 内部历史、上述 12 类之外的私有云格式与高熵随机串（无固定前缀）
  - 结论：作为"无已知凭据泄露"的证据足够；如需更强保证，需在联网环境装 gitleaks 并加 `gitleaks git --log-opts="--all"`

## 8. 单元测试套件

- [x] **判定标准**：`pytest -q` 全绿，无 skip 掩盖失败。
- **当前状态**：PASS —— `228 passed`（2026-11-16 深夜 `python -m pytest -q --no-header`；含 `tests/test_roster_person.py` 37 条名单识别/负样本/无 jieba 用例、`test_common_words_are_not_pii` 名单泛称负样本与「荣获/余人/阳光/文明/万人」FP 修复负样本（2026-11-16 晚间第二轮）、`test_person_in_natural_context` 新增「荣获宋庆龄」FN 正向；基线 175 → 212 → 213 → 222 → 228）
- **证据位置**：`tests/`（`test_engine.py`、`test_flow.py`、`test_structures.py`、`test_variants.py`、`test_custom_rules.py`、`test_shell_redaction.py`、`test_phone_last_in_list.py`、`test_roster_person.py`）；`$env:TEMP\pii_verify_leak\verify3_result.json`

## 9. 可复现安装

- [x] **判定标准**：不依赖未推送 git ref，仅用本地构建产物即可安装；安装后 `presidio-pii redact/restore` 在干净环境可运行且无损。
- **当前状态**：PASS
- **证据**：
  - 产物：`dist/presidio_pii_dsh-0.1.0-py3-none-any.whl`（57,350 B）。可复现哈希：`SOURCE_DATE_EPOCH=1700000000` 下连续两次构建均得 SHA256 `75050E227825CF06C5C7146D2A484F103EFA9D2DB954957FABDF3D7E66B0361A`（zip 条目时间戳与顺序均一致；随 shell/日志/归一化修复重建）。旧哈希 `097965DC…0234`、`5A154716…7C20` 不作发布依据。
  - 构建后端已锁定：`pyproject.toml` 的 `requires = ["setuptools==84.2.1", "wheel==0.48.0"]`（锁定前后 wheel 哈希同为 `75050E…0361A`，证明本次产物未受后端浮动影响；升级后端必须重建并更新清单）。详见 [RELEASE-RUNBOOK.md](RELEASE-RUNBOOK.md) 第 2.2 节。
  - 一键检查：`tools/release_gate.py` 第 9 项会构建两次比对哈希，并做干净 venv 安装与 CLI 往返。
  - 构建配置：`pyproject.toml` 新增 `[build-system]`、`[tool.setuptools.packages.find] include=["presidio_pii*"]`、`[tool.setuptools.package-data] presidio_pii=["assets/*.txt"]`
  - 干净环境：`$env:TEMP\pii_venv_7054b1`（uv，py3.13），非 editable；`presidio_pii.__file__` 指向该 venv `site-packages`，`assets_ok=True`
  - CLI 验证：`presidio-pii.exe redact/restore` 正常；`paper.md` `md_identical=True`，`resume.docx` `docx_units_equal=True`；重建后的 wheel 重装后 `ws_equal=True`、`epoch_hits=0`、`uuid_hits=0`
  - CSV 判据补充：还原后逐单元格一致（`rows_equal=True`，2 行 × 5 列）；容器字节不一致属既有行为（输出带 BOM + CRLF，与本次 detector 改动无关）

## 10. 源码可溯源（origin 是否含 HEAD）

- [x] **判定标准**：发布包对应的提交在远端可达（`origin` 含 HEAD），**或**发布物改为已构建 wheel 并记录哈希；
  「清单绑定的提交」必须等于 HEAD **或是 HEAD 的祖先**，且源码树摘要与当前源码一致。
- **为什么允许祖先**：清单本身是被 git 跟踪的文件，要求 `commit == HEAD` 会让「提交清单」这个动作
  自己把判定打回 False，形成「提交→失配→改清单→再失配」的死循环。绑定强度由
  `source.source_tree_sha256`（覆盖 wheel 实际打包的 `presidio_pii/**` + `pyproject.toml`）承担，
  提交只证明谱系；源码一改摘要即失配，仍能挡住「清单绑定旧代码」。
- **当前状态**：PASS（2026-11-20，`artifact_only` 路径）。分支 `refactor/node-pii-engine`
  领先 `origin/master` 8 个提交，尚未合并；清单已重绑到当前源码。
- **证据**：`release/presidio-pii-dsh-0.1.0.json`
  - `artifact.sha256` = `791CF2810DDC58E5DC43B84FAA83F1A69D757918D7EA11BA4BBFEFD72B99EF71`，bytes=68,184，与 `release/` 内 wheel 逐字节一致
  - `source.source_tree_sha256` = `1429357d…`，由 `presidio_pii/**` + `pyproject.toml` 的路径/内容哈希排序后再哈希得到
  - `source.commit` = `a0b195e`（HEAD `6b9e154` 的祖先，清单提交紧随其后）
- **验证**：`python tools/release_gate.py --only 10` → PASS；把清单里的 sha256 改成假值后同一检查立即 FAIL（`sha_ok=False`），恢复后重新 PASS
- **残余说明**：因分支未合并，当前走的是产物级溯源（B 路径）；合并进 `master` 并推送后
  会自动回到 A 路径（HEAD 在远端可达），届时需重跑门禁确认。

## 11. 仓库不落真实 PII / 映射库

- [x] **判定标准**：真实语料、映射库、脱敏产物均不入版本库。
- **当前状态**：PASS
- **证据位置**：`.gitignore` 已忽略 `.pii_presidio_store/`、`*.mapping.csv`、`*.session.csv`、`*-redacted/`、`*-restored/`、`testdata/`、`testdata_v2/*`（保留 `!testdata_v2/negative/`）、`sim_*.jsonl`、`build/`、`dist/`、`eval_result.json`、`.review_tmp/`；`git status --porcelain` 仅有源码/测试/文档改动与 `release/` 清单，无真实语料、映射库或脱敏产物

## 12. 外部语料（网络下载）回归

- [x] **判定标准**：测试文件只能来自网络公开样例；注入合成 PII 后 redact→restore 逐字无损、占位符清零、明文中无注入值。
  不允许用本地语料或自造文件替代。
- **当前状态**：PASS（2026-11-07）
- **证据**：`tools/external_corpus_check.py`（下载缓存只放系统临时目录，不入库；报告不打印正文）

| 样例 | 来源 | 大小 | 单元 | 替换 | 逐字还原 | 残留 | 泄漏 |
|---|---|---|---|---|---|---|---|
| docx | filesamples.com sample1.docx | 1,311,881 B | 359 | 1,436 | True | 0 | 0 |
| xlsx | filesamples.com sample1.xlsx | 29,380 B | 785 | 3,140 | True | 0 | 0 |
| pptx | apache/poi SampleShow.pptx | 39,083 B | 10 | 40 | True | 0 | 0 |
| csv | filesamples.com sample1.csv | 502 B | 1 | 4 | True | 0 | 0 |
| txt | filesamples.com sample3.txt | 3,541 B | 1 | 4 | True | 0 | 0 |

- 门禁 #12 在线时自动下载并跑上述回归；离线时标 **SKIP** 并说明“不允许用本地语料替代”，不会静默通过。

---

## 整体过一遍的顺序

1. ~~勾第 2 项~~：✅ 已完成（2026-11-10）——DSH 完全退出 → 重启 → 选 `presidio-pii` → 9 步实测全 PASS，证据见 `.pii_presidio_store/e2e_9steps_2026-11-10.md`
2. 决策第 4 项（restore 接线 A/B/C），决策后补实现与用例；第 5 项已按 P1-全 + P2 实现
3. 第 10 项已按 B（产物级溯源）通过：清单在 `release/presidio-pii-dsh-0.1.0.json`；重建 wheel 或改源码后必须更新清单，否则 #10 转 FAIL。若后续决定推送，门禁会自动优先按“远端可达”判定
4. 每项勾选时把证据落盘路径写进本文件，避免"口头通过"
