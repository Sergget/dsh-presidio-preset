# 代码审查报告（2026-11-19）

## 审查范围与方法

- **审查对象**：当前工作树未提交改动（相对 `HEAD a31dac6`，分支 `master`）。
- **规模**：26 个 tracked 修改 + 多个新增/删除文件，`+1696 / -850`；涉及 Python 引擎（`presidio_pii/`）、JS 插件（`plugins/dsh-pii-guard*`、`dsh-client-connection` 边界）、工具与发布配置（`tools/release_gate.py`、`release/*.json`）、文档（`docs/`、`README*`、`agent.md`）与测试（`tests/`）。
- **方法**：3 路并行审查（Python 引擎与测试 / JS 插件 / 工具·文档·发布配置）+ 主审查员源码核对 + 测试复现与环境实验。
- **行号基准**：均为**当前工作树版本**（未提交）。
- **说明**：Python 引擎审查员的报告未送达，Python 部分由主审查员抽样核对（`db.py`、`journal.py`、`hooks.py`、`tests/`）并以测试环境实验覆盖。JS / 工具文档两路审查员报告完整送达。

## 总体结论

| 级别 | 数量 | 概要 |
|---|---|---|
| **Blocker** | 4 | JS 重试进程竞态、ReDoS 防护可绕过、发布溯源口径矛盾、`entity_types` 未知类型→零脱敏（漏 PII） |
| **Suggestion** | 15 | JS 读取端校验/异步回填/配置源分裂/cookie 围栏等；工具依赖审计与密钥扫描口径；Python 白名单热更新/密钥文件 ACL/测试脆弱性 |
| **Nit** | 7 | 标题层级、文档同步、硬编码路径、过时示例、ACL 自查无效等 |

核心风险集中在三处：**JS 侧进程管理与 ReDoS 防护**（直接影响 agent 工具循环可用性）、**发布溯源口径不一致**（按 RUNBOOK 回退会用错哈希/拉错产物），以及 **`entity_types` 未知类型导致静默零脱敏**（fail-open 漏 PII，与「宁可过度脱敏也不能漏脱敏」的安全方向相反）。另需说明：当前 `pytest` 大面积 `WinError 5` 为 **DSH workspace-write 沙箱对系统 temp 目录的写入限制**，非代码回归（见「四、测试与验证」）。

> **修复状态（2026-11-19）**：用户要求「修复 p0 p1」后，4 个 Blocker（B1/B2/B3/B4）已全部修复并逐条探针复验，P1 验证闭环已在 danger-full-access 下重跑完整测试套件（**258 passed, 8 subtests passed**）。详见「六、P0/P1 修复闭环」。随后「继续开发，推荐下一步修复」，按推荐收口了 S11（白名单热更新读坏被静默清空）+ S14 测试覆盖 + S12（HMAC 密钥文件 Windows ACL），详见「七、后续修复」；再按用户指定收口 S13（过滤时序测试断言过弱）+ S3（settingsFile 数据源分裂），详见「八、S13 / S3 修复」。全量复跑 **260 passed, 8 subtests passed**，三套 JS 烟测（display/jobs/terms）全绿。下列一～四章保留原始审查发现作为历史记录，修复后现状以第六、七、八章为准。

---

## 一、Blocker（必须修复）

### B1. 重试使旧进程的退出回调污染新进程状态
- **位置**：`plugins/dsh-pii-guard/lib/index.js:229-233, 304`
- **问题**：`callServerWithRetry` 在 catch 内执行 `svc = null`（304 行）后重试 spawn 新进程；但旧进程的 `svc.on("exit", ...)` 回调（229-233 行）闭包引用的是**模块级** `svc` 与全局 `pending`。旧进程最终退出时会执行 `svc=null`（此刻 `svc` 已指向新进程，被误清），并遍历 `pending` 以 "pii server exited" 拒绝掉属于新进程的在途等待者。并发重试时，慢的重试在 304 行无条件 `svc=null`，会把快重试刚建立的新进程也清掉。
- **原因**：原代码无重试故无此竞态；新增重试后每个进程对象的回调没有与实例绑定，模块级共享状态被跨实例污染。`fail-closed` 依赖 `svc`/`pending` 状态可靠，被污染后会误杀健康服务、级联拒绝在途请求。
- **改法**：给每个 spawn 的进程对象绑定其专属的 exit/error handler，回调内先判断 `if (svc !== thisProc) return;` 再清 `svc`/`pending`；重试时仅比较引用后再清空自己那次的 `svc`，并对旧进程补 `kill()`（配合 S5）。

### B2. `hasNestedQuantifier` 可被 `{m,n}` 与嵌套组绕过，ReDoS 防护形同虚设
- **位置**：`plugins/dsh-pii-guard-terms/lib/index.js:405, 407`（经主审查员源码核对属实）
- **问题**：405 行 `/\([^()]*[*+][^()]*\)[*+{]/` 的组内部分只认 `*`/`+`，不含 `{m,n}`；407 行 `/\([^()]*\|[^()]*\)[*+]/` 的组后部分也只认 `*`/`+`。审查员逐字复制该函数后用 Node 实测：
  - DETECT：`(a+)+$`=true、`(a|a)+$`=true、`(a+){2}$`=true；但 `(a{1,})+$`=**FALSE**、`(a{2,}){3,}$`=FALSE、`((a+))+$`=FALSE、`(a|a){100}$`=FALSE、`(?:a{1,})+$`=FALSE。
  - 耗时（`re.test("a"*n+"b")`）：`(a{1,})+$` n=18→13ms、n=22→179ms；`((a+))+$` n=22→209ms，呈指数增长。
- **原因**：用脆弱的正则匹配正则，漏掉花括号量词与嵌套捕获组。这些形式能通过 `normalizeSettings`（431 行）校验被写入 `shellAllowlist`，随后 guard 在 `index.js:137` 同步执行 `allowlist.test(cmd)` 时灾难性回溯，冻结 agent 工具循环。
- **改法**：改用 `safe-regex` 类库；或将组内/组后量词统一识别为 `* + {m,} {m,n}`（含 `{` 后形式），并对嵌套捕获组 `((...))` 递归展开再判定。同时在下发端兜底（见 S1）。

### B3. 发布溯源口径矛盾：RUNBOOK 与 release JSON 不一致
- **位置**：`docs/RELEASE-RUNBOOK.md:12-13,60,70,72,84,118-126,137` 与 `release/presidio-pii-dsh-0.1.0.json:9-10,23,29-30`
- **问题**：JSON 已改为 artifact-level 口径（artifact 66,668 B / sha256 `8C99677F…6BE6E` / commit `a31dac6` / `provenance_mode=artifact-level` / note「按路径 B 判定」）；RUNBOOK 第 5 节仍写「已选 A：远端可达」（118 行），123 行仍是旧值 `77154909…20CF8` / 58,831 B / `69021c9` / `origin-reachable`。
- **原因**：口径切换时只更新了 JSON，未同步 RUNBOOK。按 RUNBOOK §6.1 回退会用错哈希、拉错产物。
- **改法**：以 JSON 为准统一全文；第 5 节标题改为「路径 B（产物级）为当前口径、推送后转 A」。

### B4. `entity_types` 含未知/拼错类型名时静默零脱敏（fail-open 漏 PII）
- **位置**：`presidio_pii/engine.py:86`（构造时赋值）、`:178-182`（过滤逻辑）；经主审查员源码核对属实。
- **问题**：`self.entity_types = {t for t in (entity_types or []) if t}`（86 行）不做类型名合法性校验；`_filter_entity_types`（178-182 行）在集合非空时返回 `[r for r in results if r.entity_type in allowed]`，不在集合内的识别结果**全部丢弃**。若配置含未知/拼错的类型名（如 env `PII_DSH_ENTITY_TYPES=PHONE`，或手工编辑 preset），所有结果被过滤，`redact` 静默零脱敏、原文完整泄漏。
- **原因**：与 `hooks.py:224-229`「宁可过度脱敏也不能因为配置坏了就漏脱敏」的安全方向相反，是漏 PII 的 fail-open。UI（`index.js:326-332`）虽校验类型名，但 env 与手工编辑 preset 无校验，路径真实可达且无任何告警。审查员探针实测：`entity_types=['PHONE']`（拼错）对含手机号文本 `n_replaced=0`、原文完整泄漏；有效类型 baseline `n_replaced=2`。
- **改法**：在 `__init__`/`set_entity_types` 校验类型名是否在「内置类型 ∪ 自定义规则类型」内，未知类型告警并忽略；当过滤后有效类型集合为空时视为全开（fail toward 多脱敏），绝不静默零脱敏。

---

## 二、Suggestion（建议修复）

### S1. guard 读取端不校验 allowlist（写入端防护可被绕过）
- `plugins/dsh-pii-guard/lib/index.js:137` — `getAllowlist` 直接 `new RegExp(cfg.shellAllowlist)`，无 `hasNestedQuantifier` 校验。terms 写入端的 ReDoS 检查（B2，本身已可绕过）之外，env `PII_GUARD_SHELL_ALLOWLIST` 或直接改 `guard-settings.json` 都能完全跳过校验。**改法**：在 `getAllowlist` 构造正则前复用同一套（修正后的）ReDoS 校验，不合法则拒绝加载并告警。

### S2. phMap 恢复异步回填，首帧/末帧仍透传原始占位符且无重绘
- `plugins/dsh-pii-guard/lib/index.js:716-719, 698, 390-404` — `acc.replace(PH_FULL, (ph)=>{ if(!phMap.has(ph)) scheduleRestore(ph); return ph; })` 在回填完成前直接 `return ph` 透传原始 `⟦PII:...⟧`；`splitDisplayable`（378-384）与 end 帧（698）用的是回填前的 `phMap`。占位符在一次输出里通常只出现一次，回填完成后没有重渲染机制 → 用户永久看到原始占位符。**这与本轮「phMap 重启后懒加载恢复」修复的核心目标直接冲突**：当前实现只在「同一占位符后续帧再现」时才命中缓存，实际不成立。**改法**：占位符首帧先扣住（放入 `displayBufs.pending`），`scheduleRestore` 完成（`then` 内 397 行 set 后）触发补发帧；或让流式替换返回「待定 token」，回填后用带 index 的 text-delta 覆盖。
- *补充核查*：phMap 恢复的 SID 一致性不构成问题——`callServer` 在 261 行统一注入 `sid: SID`（`SID="pii-guard-"+process.pid`，64 行），`restoreText` 经 `callServerWithRetry → callServer` 与脱敏侧同一 sid，能命中映射，不报告为问题。

### S3. settingsFile 数据源分裂，仅配 bundle config.repo 时设置失效（✅ 已修复，见第八章）
- `plugins/dsh-pii-guard/lib/index.js:61, 78` + `plugins/dsh-pii-guard-terms/lib/index.js:45-50, 589` — terms 端 `resolveRepo(rawConfig)` 取 `config.repo` 优先于 env；guard 端 `REPO = env PII_GUARD_REPO ?? 默认`（61 行），`GUARD_SETTINGS_FILE` 由 `REPO` 拼出（78 行），只认 env。若只配 bundle `config.repo` 而不配 `PII_GUARD_REPO`，terms 写到 A 路径、guard 读 B 路径，UI 保存的设置不生效。S2 的 `warnIfPathDrift`（461-474）只比对 termsFile vs preset `custom_rules_path`，未覆盖 settingsFile。**改法**：guard 也读取 bundle `config.repo`，或 terms 写文件时以 guard 实际使用的 settingsFile 为准；把 settingsFile 纳入 drift 校验。

### S4. shellDisabled 三处判定口径不一致
- `plugins/dsh-pii-guard/lib/index.js:84-88, 94` + `plugins/dsh-pii-guard-terms/lib/index.js:70` — guard `coerceShellDisabled`（84-88）把 `off/1/true/disabled` 都判为 true（守卫关）；而 guard `ENV_FALLBACK.shellDisabled`（94）与 terms `SETTINGS_DEFAULTS.shellDisabled`（70）只认 `off`。当 `PII_GUARD_SHELL=1` 时，实际守卫按 coerce 为「关」，UI 默认显示「开」，用户保存后反把行为写反。**改法**：统一为一个共享解析函数，三处复用。

### S5. timeout 不终止底层请求，重试放大孤儿进程泄漏
- `plugins/dsh-pii-guard/lib/index.js:250-253` — `callServer` 的 timeout 分支只 `pending.delete(id); reject(...)`，不 `kill()` 进程也不关 stdin；重试（304 行 `svc=null`）后旧 python 进程成为无主孤儿（`server.py` 是 stdin 长驻循环，不会自行退出）。原代码已有此泄漏，三次重试放大到最多 3 个孤儿进程。**改法**：timeout 时 `svc.kill()` 并清理引用，或复用同一 svc 而非每次 spawn（配合 B1 的引用判断）。

### S6. cookie/同源围栏在 HTTPS 场景失效，GUI 写操作全部 403
- `plugins/dsh-pii-guard-terms/lib/index.js:107, 145` — `sessionCookieName`（107）用 `new URL(\`http://${host}\`).host` 硬编码 http 且只取 host；`hasSameOriginProof`（145）`parsed.host === headers.host`。而 harness（`dsh-client-connection/lib/index.js:307-316, 335-337`）`requestAudience` 在 `secure=true` 时返回 **origin**（含 `https:`），cookie 名按 origin 哈希。HTTPS 部署下插件算出的 cookie 名与 harness 写入的不同 → 带 cookie 的写路由（terms/settings/preset save）被 403 拒绝。**改法**：把 `secure` 标志传入插件，按 `secure ? origin : host` 计算 audience；同源证明同样按 scheme+host 比较。

### S7. #6 依赖审计口径已改「本包闭包」，文档未标注
- `tools/release_gate.py:401-493` + `docs/RELEASE-GATE.md:19,37,40,132,137` + `RELEASE-RUNBOOK.md:15,42,77` — 审计口径已改为「本包闭包」（仅 `python-docx`/`python-pptx`/`openpyxl`，不含 `opentelemetry-api`），旧 FAIL（`opentelemetry-api 1.45.1` / `CVE-2026-126360`）在新规则下应重跑、会转 PASS，文档未标注这一变化。**改法**：重跑门禁并在文档同步标注新口径与结论变化。

### S8. `_resolve_closure` 审「最新满足版本」而非实际安装版本，潜在误放行
- `tools/release_gate.py:421-444` — 用 `pip install --dry-run --ignore-installed` 解析，pip-audit 审的是「最新满足版本」而非实际 site-packages 安装版本；部署装旧版时门禁 PASS 而真实有漏洞。**改法**：审实际锁定版本（`pip freeze ∩ 本包闭包`）。

### S9. `_SAFE_EXPR` 白名单过宽，#7 密钥扫描漏报
- `tools/release_gate.py:517-523, 530-543` — `[\w.]+\(`（任意函数调用）+ `[\w.]+\.[\w.]+`（任意属性访问）过宽，会把 `config.HARDCODED_SECRET_VALUE`、`get_token()` 形态误判为求值表达式而 suppressed。**改法**：只放行白名单生成器。

### S10. README.en.md 与 README.md 内容未对齐
- `README.en.md:132-135` vs `README.md:121-126` — 英文版把 `agent.cordis.yml` 描述为 standard/compatible with dsh 0.2.x，缺 legacy 与 bundle `cordis.patch.yml`（权威源）条目，违反 `agent.md:35-37` 内容对齐要求。
- `README.en.md:118-126` vs `README.md:119` — 英文版架构节缺 `docs/SECURITY-NOTES.md`（部署前必读）条目。

### S11. 热更新写坏 preset 时白名单被静默清空，未兑现「保留旧值」承诺（✅ 已修复，见第七章）
- `presidio_pii/hooks.py:207-210` — `_maybe_reload_preset` 注释（L193-194）承诺「读取失败保留旧值，实体类型与白名单分开 try」，实体类型路径做到了（`set_entity_types` 遇 `PresetUnreadable` 保留旧值）；但 `set_whitelist([])` 照常执行。原因：`_whitelist()→_preset_path()→_preset_config()`（L51-66）在 JSON 解析失败时只告警并返回 `{}`，不抛 `PresetUnreadable`，所以 L207-210 的 try 捕获不到。审查员探针实测：GOOD whitelist=`['ZhangSan']`，写坏 preset 后 BAD whitelist=`[]`，而 entity_types 正确保留——两者处理不一致。**改法**：让 `_preset_config()` 在读坏时也抛 `PresetUnreadable`（或在 `set_whitelist` 前先验 preset 可读），使异常路径真正保留旧值。**修复**：配置读取链加 `strict` 开关，热更新以 `strict=True` 调用，异常路径真正保留旧值。

### S12. HMAC 密钥文件在 Windows 上 ACL 未收紧，注释虚假（✅ 已修复，见第七章）
- `presidio_pii/hooks.py:302, 323-326` — HMAC 密钥文件（`journal_hmac.key`）在 Windows 上仅调用 `os.chmod(key_file, 0o600)`，而 Windows 的 chmod 只影响只读位、几乎不改 ACL；注释却声称「Windows 上按当前用户 ACL 收紧」。`journal_hmac.key` 可反查所有日志指纹，若继承父目录的 Users/Authenticated Users 读权限，同机其他账号可读密钥从而暴力枚举反推原文，削弱 HMAC 加固意义。`db.py` 已有成熟的 `_harden()` 可直接复用。**改法**：Windows 分支调用 `db._harden(key_file, directory=False)`，或删掉虚假注释并明确记录该限制。**修复**：`hooks.py` 导入 `db._harden`，密钥文件「新建」与「既有复用」两条路径都调用 `_harden(key_file, directory=False)`（幂等、失败只告警不阻断），删掉虚假 chmod 注释。

### S13. `test_filter_runs_before_overlap_resolution` 断言过弱，无法验证过滤时序（✅ 已修复，见第八章）
- `tests/test_security_hardening.py:86-90` — 只断言 `found <= {"ORGANIZATION"}`，若过滤发生在冲突消解之后导致结果为空集，空集同样满足该断言、测试照样通过；且 TEXT（L68）中并无与 LOCATION 明确重叠的 ORGANIZATION 实体，测试意图无法真正验证。审查期探针实测：`entity_types=['ORGANIZATION']` 对原 TEXT 返回 `[]`，旧断言恒真。**改法**：改为直接注入两段完全重叠、类型不同的 `RecognizerResult`（LOCATION(0,10) 与 ORGANIZATION(0,5)），断言过滤后只剩 ORGANIZATION、且经消解后区间仍为 (0,5)。**修复**：见第八章——用注入结果替代真实语料，断言过滤时序；反证「先消解再过滤」得到空集、测试必失败。

### S14. `test_unknown_preset_keeps_previous_values` 未覆盖白名单保留（✅ 已修复，见第七章）
- `tests/test_preset_hot_reload.py:94-113` — 只验证 entity_types 在写坏 preset 后保留，未验证 whitelist，恰好漏掉 S11 的白名单被清空问题。**改法**：先经 preset 设置一个白名单，写坏 preset 后同时断言 whitelist 仍保留旧值。**修复**：测试基线改为同时收窄 entity_types + 设白名单，写坏后同时断言两者保留。

### S15. 热更新测试直接读写仓库真实 preset.json，脆弱且不安全
- `tests/test_preset_hot_reload.py:20, 30, 37, 45` — 测试直接读写仓库真实 `.agent-presets/presidio-pii/preset.json`，靠 `setUp`/`cleanup` 备份恢复：测试被中断/进程崩溃时 `_restore` 可能不执行而留下被改坏的 preset；并行运行会互相踩踏；只读 CI 或 preset 为符号链接时会失败。hooks 已支持 `PII_DSH_PRESET` 覆盖（L48）。**改法**：用 env 指向临时 preset 副本，不碰仓库真实文件。

---

## 三、Nit（可选优化）

### N1. 分节标题层级缺失
- `plugins/dsh-pii-guard-terms/client.js:356, 653-660` — TermsSection 标题由 h2 降为 h3（356），而 `PiiGuardSection`（653-660）本身没有 h2 顶级标题，整个插件面板只有 h3，无顶级分节标题，可访问性/大纲层级混乱。**改法**：在 `PiiGuardSection` 顶部补一个 h2 作为插件总标题，各 Section 保留 h3。（此项与「五、UI 标签化改造」直接相关，建议合并处理。）

### N2. terms README 文档未同步新增 API 与配置项
- `plugins/dsh-pii-guard-terms/README.md:3, 14-25` — 第 3 行仍说「4 项 P0/P1 配置」，未提实体类型/白名单；14-25 路由表只列 settings/terms 4 条，未列新增的 `/api/dsh-pii-guard/preset` 与 `/preset/save`。**改法**：补齐路由表与配置项说明。

### N3. 权威源硬编码绝对路径
- `README.md:121-122` vs `.agent-presets/presidio-pii/bundle/cordis.patch.yml:110` — 权威源硬编码 `file:///E:/Code/dsh_home/plugins/dsh-pii-guard/lib/index.js`，换机失效。**改法**：改为相对路径或安装时动态解析。

### N4. resolved_crp/ui_terms resolve 基准不一致
- `tools/release_gate.py:319-323` — `resolved_crp` 用 `REPO.resolve`，`ui_terms` 用 `cwd.resolve`，`PII_GUARD_TERMS_FILE` 相对路径会误判 MISMATCH 误拦截。**改法**：统一基准目录。

### N5. journal.py 文档串「单向 SHA256」与实现不符
- `docs/SECURITY-NOTES.md:95` vs `presidio_pii/journal.py:6-8`（经主审查员核对属实）— `journal.py` 模块文档串仍写「内容指纹是单向 SHA256」，而 `hooks.py:334-342` 的 `_fingerprint` 已改为 HMAC-SHA256。**改法**：把文档串改为「带本地密钥的 HMAC-SHA256 前 16 位」。

### N6. agent.md 示例用例数过时
- `agent.md:39` — 示例「23 regression cases ↔ 23 个回归用例」已过时（实际 228 passed，见 `RELEASE-GATE.md:21` / `RUNBOOK:41`）。**改法**：更新示例数字。

### N7. `_harden` 收紧后的 Windows 自查无效，回滚分支形同虚设
- `presidio_pii/db.py:61-63` — 收紧后的「自查」用 `os.access(path, R_OK|W_OK)`，Windows 上管理员对 DACL 有绕过能力，该检查几乎总返回 True，回滚分支形同虚设；而一旦真的执行 `_icacls(path, ["/inheritance:e"])`，重新启用继承反而可能把权限变得比收紧前更宽。**改法**：Windows 上改用 `icacls` 回读实际 ACE 判断，或去掉这个无效自查、保留「失败即告警」语义。

---

## 四、测试与验证

### 已执行的验证
1. `python -m pytest tests/ -q --disable-warnings` → **61 failed / 80 passed / 1 skipped / 129 errors**，失败均为 `PermissionError: [WinError 5]`。
2. 改用工作区内 `--basetemp=E:\Code\dsh-presidio-preset\.pytest-basetemp-fresh` 重跑核心测试 → 仍失败，`cleanup_dead_symlinks(basetemp)` 对 basetemp `iterdir` 抛 WinError 5（8 errors）。
3. 隔离实验（python via stdin）：`tempfile.mkdtemp()` 成功返回 `C:\Users\sergg\AppData\Local\Temp\dsh-aVqQNM\tmp1_ax3emx`，紧接着 `Path(tmp)/"sub"` 的 `mkdir()` 在**任何 `_harden` 调用之前**就抛 `PermissionError: [WinError 5]`。
4. 权限探针：`icacls` 对工作区内目录做 `/inheritance:r /grant:r ...` 返回 `Access is denied`；目录 ACL 含 `Everyone:(I)(CI)(DENY)(DC)` 与 `Mandatory Label\Low Mandatory Level:(I)(OI)(CI)(NW)`（低完整性级别 NoWrite-up）。
5. 源码核对：`db.py:get_max_seq` 已改动态计算 `digit_start = 5 + len(ptype) + 1 + 1`（上一轮 #5 修复收口，正确）；`_harden` 失败仅告警不阻断（设计如此）；`journal.py:6-8` 文档串过时（N5）。
6. Python 审查员独立复现：三个测试文件 `18 failed / 11 passed / 1 skipped / 4 errors`，主因同为该沙箱临时目录的 `Everyone:(I)(CI)(DENY)(DC)` 特殊 ACL，导致 `icacls /inheritance:r` 报 `Access is denied (exit 5)`、sqlite 无法 open db、临时目录清理 `PermissionError`；审查员确认**工作区路径下 DB 读写正常**。
7. Python 审查员 fail-open 探针：`:memory:` / 工作区路径下实测 `entity_types=['PHONE']`（拼错）对含手机号文本 `n_replaced=0`、原文完整泄漏（B4）；写坏 preset 后 whitelist 被清空而 entity_types 保留（S11）。

### 结论
- **大面积测试失败是环境问题，不是代码回归**：DSH workspace-write 沙箱阻止向系统 temp 目录（`C:\Users\...\Temp\dsh-aVqQNM` / `dsh-iSKABG`）写入子目录，`pytest` 在创建 numbered temp dir 阶段即失败，与 `db.py`/`_harden` 无关。两名独立审查员 + 主审查员的隔离实验三方印证。
- **待办**：需在 **danger-full-access** 模式（或工作区内完全干净的 basetemp + 无低完整性标签）下重跑完整测试套件，以获得可信的通过率。这是当前唯一未闭环的验证项。
- `plugins/` 下无任何 JS 测试文件——本轮 JS 改动（重试、ReDoS、preset、cookie 围栏等）**零自动化测试覆盖**，建议至少为 `hasNestedQuantifier` 与 `callServerWithRetry` 的进程状态机补单元/集成测试。
- 测试自身脆弱性：热更新测试直接读写仓库真实 preset.json（S15）、过滤时序测试断言过弱（S13），建议一并加固。

---

## 五、附：配置页 UI 标签化改造建议（用户新需求）

> 对应本会话新需求：`考虑优化配置页的UI，使用标签切换管理不同的设置类目`。此项**不是本轮代码审查发现**，而是用户后续提出的功能需求，单列于此便于统一交付。

### 现状
`plugins/dsh-pii-guard-terms/client.js` 中 `TermsSection` / `SettingsSection` / `PresetSection` 三个设置面板由 `PiiGuardSection`（653-660 行）用 `pii-guard__divider` 纵向拼接，用户需滚动浏览全部类目。更关键的是，"什么该脱敏、什么不该、什么例外"按**存储后端**被切散：
- 黑名单词条 → `TermsSection`（`terms.json`，API `/terms`、`/terms/save`）
- 白名单路径 + 实体类型 → `PresetSection`（`preset.json` → `whitelistPath` / `entityTypes`，API `/preset/save`）
- 运行开关 + Shell 命令例外 → `SettingsSection`（`guard-settings.json`，API `/settings/save`）

这与本轮 S3「配置源分裂」是同一病根：用户判断规则要在三个标签间来回找。

### 改造方向（按用户意图归类，仅渲染层）
用户问「白名单、黑名单和例外的规则统一一个 section 更符合逻辑？」——**采纳按逻辑归类，而非按存储后端分面板**；但不把运行开关也塞进来，收敛为两个标签：
1. **脱敏规则**（第一项）：词条黑名单 + 白名单路径（`whitelistPath`）+ 实体类型（`entityTypes`）——三者都是"哪些内容要/不要脱敏"。标签内部用子卡片分区，各区保留独立保存按钮与状态提示。
2. **防护设置**：`SettingsSection` 现有内容——`failOpen` / `shellDisabled` / `displayMode` 以及 **`shellAllowlist`（Shell 命令例外）**。

- **「例外」的定义（用户确认）**：特指 **Shell 命令例外**（`shellAllowlist` 正则命中即跳过守卫执行命令），归入「防护设置」，不并入「脱敏规则」。
- **工程约束**：黑名单在 `terms.json`、白名单/实体类型在 `preset.json`，是两个后端、两套状态/校验/保存。合并到同一标签后，一个页面需协调两次保存与失败处理——可行，但不是免费的重新分组；实施时各子卡片必须独立保存，避免一处失败拖累另一处。

### 落地要点（若后续实施）
- 在 `PiiGuardSection` 内引入 `useState` 维护当前激活标签；顶部渲染标签栏，两个标签面板按需渲染。
- 标签类目：脱敏规则 / 防护设置（取代此前确认的"沿用现有三类 Terms/Settings/Preset"方案，以本次决定为准）。
- 默认激活：第一项（脱敏规则），不使用 localStorage 记忆上次选择（沿用此前确认）。
- i18n：zh/en 文案各补 2 条标签标题；标签文案沿用现有各 Section 标题措辞，不另造命名。
- 样式：复用现有 `--dsw-alias-*` CSS 变量，做选中态/悬停态，保持与宿主 UI 风格一致。
- 可访问性：标签用 `role="tablist"/"tab"/"tabpanel"` + 键盘导航；按 N1 在 `PiiGuardSection` 顶部补 h2 总标题，各 Section 保留 h3。
- **影响面**：只改 `client.js` 渲染层，不动 `terms/lib/index.js` 后端路由与数据结构，风险低。
- **交付决策（用户已确认，2026-11-19）**：**本次仅出方案、不改代码**；后续若实施，应与 N1（补 h2 总标题）合并处理。

---

## 附录：确认无问题的范围（本次不报告）

- `isPathFragment`（`index.js:177-188`）+ `redactExempted`（190-203）逐实体判定修复有效：正文公司名不再被误放行，路径片段正确放行。
- `RECOVERABLE` 分类正确（`index.js:289` `= /unavailable|spawn failed|exited|timeout/i`）：bad response / 非法参数不重试，直接 fail-closed。
- terms `writePreset`/`writeSettings` 用 tmp+rename 原子写；entityTypes 白名单校验、去重保序；whitelistPath 长度/控制字符/绝对路径校验，均正确。
- preset 字段形状与 Python `hooks.py:70-179` 消费方式一致（`config.whitelist_path` 与顶层 `entity_types`，空=全开）。
- `docs/SECURITY-NOTES.md` 声明逐节准确（§1 CSV 优先级、门禁 #11 阻断、§2 行号 220-231/234-255、§3 icacls/0700/0600 与 HMAC、§4 PresetUnreadable、§5 盲区）；README 权威源标注与实际一致；删除的文档无实质丢失（归入 `docs/archive/`）。
- `chinese_recognizers.py`：仅注释文字调整（L899/L913「政协委员履职」→「委员会履职」），无逻辑影响。
- `get_max_seq` 修复（`db.py:133-150`）：审查员探针实测 9999→10000→10001 连续递增、跨 ptype 不串号，修复正确；`test_security_hardening` 的 5 个用例覆盖充分。
- `release_gate.py` 的 `_SAFE_VALUE`/`_SAFE_EXPR`/`_mask`/`_scan_text` 及对应 5 个测试：硬编码凭据仍被抓、运行时生成/间接引用被合理抑制、掩码不泄漏原值，未发现问题（注意：这与工具/文档审查员的 S9「白名单过宽」不矛盾——S9 针对的是更宽泛的 `[\w.]+\(` 形态，需合并评估）。
- `SessionRegistry.close()`/`__enter__`/`__exit__` 实现正确。
- **fail-open 总评（历史记录）**：审查时未彻底消除——① `entity_types` 含未知类型→零脱敏（漏 PII，危险方向，B4）；② 白名单热更新读坏→被清空（S11，违背保留旧值承诺）。首次加载读坏回退全开、`entity_types` 热更新读坏保留旧值这两个路径正确。**更新（2026-11-19）**：B4 已在第六章修复，S11 已在第七章修复，两条 fail-open 路径均已消除。

---

## 六、P0/P1 修复闭环（2026-11-19）

用户要求「修复 p0 p1」。以下 4 个 Blocker 已全部修复并逐条用独立探针复验；P1 验证闭环已在 danger-full-access 下重跑完整测试套件。一～五章的发现作为历史记录保留，**修复后现状以本章为准**。

### 6.1 Blocker 修复（4/4 完成）

| 编号 | 问题 | 修改位置 | 修复机制 | 探针验证 |
| --- | --- | --- | --- | --- |
| B4 | `entity_types` 未知类型→静默零脱敏（fail-open 漏 PII） | `presidio_pii/engine.py` | 新增 `_known_entity_types()`（内置识别器 ∪ 自定义规则的 entity_type）与 `_sanitize_entity_types()`（过滤未知类型 + `stderr` 告警 + 全部无效返回空集=全开）；`__init__` 与 `set_entity_types` 统一走清洗 | `_b4_probe.py`（`:memory:` DB）：baseline `n_replaced=2`；typo `['PHONE']` 清洗后有效集为空但仍 `n_replaced=2`（不再零脱敏）→ **PASS** |
| B2 | `hasNestedQuantifier` 正则只认 `*+`、漏 `{m,n}` 与嵌套组→ReDoS 绕过 | `plugins/dsh-pii-guard-terms/lib/index.js`（`hasNestedQuantifier`，导出） | 脆弱正则改为结构化括号树解析：`readQuant()` 识别 `* + ? {n} {n,} {n,m}`（含 lazy/possessive），`parseBody()` 跳过转义/字符类并解析各 `(?...)` 前缀递归子组，`overlap()` 判定交替分支字面前缀重叠；拒绝嵌套重复 + 量化重叠分支 | `_b2_probe.mjs`：8 种攻击形态（`(a{1,})+$`、`((a+))+$`、`(?:a{1,})+$`、`(a|a){100}$` 等）全 DETECT；7 种安全模式（`^(get|set)\s`、`^git (status|log)$` 等）全放行 → **PASS** |
| B1 | 重试时旧进程 `exit` 回调引用模块级 `svc`/`pending`，污染新进程 | `plugins/dsh-pii-guard/lib/index.js` | 模块级 `svc` 持有「实例句柄」`{proc, pending: Map, rl}`；新增 `retireService(handle)` 仅当 `svc===handle` 才清理并 kill；`ensureService` 每实例独立 pending；抽出 `callServerOn(handle,...)`；`callServerWithRetry` 用 `failedHandle` 按引用淘汰，不再无条件 `svc=null` | `_b1_probe.cjs`（node:vm + mock spawn/readline）模拟旧 A 进程 exit 后新 B 在途：`svc` 仍指向 B、B pending 完好、B waiter 存活、A waiter 被自身 exit 拒绝 → **PASS** |
| B3 | RUNBOOK 发布溯源口径与 release JSON 矛盾（回退用错哈希） | `docs/RELEASE-RUNBOOK.md` | 全文统一到 JSON 口径（artifact-level / 66,668 B / `8C99677F…6BE6E` / commit `a31dac6`）；第 5 节标题改「当前口径：路径 B 产物级；推送后转 A」并重写 A/B 两条；旧值（`77154909…20CF8` / 58,831 B / `69021c9`）明确标注历史对照；L12-13/L15/L29/L33/L59/L69-71/L83/L117-122/L136 全部对齐 | `grep` 复核无「已选 A / 绑定旧提交 / 已推送清单值」等残留矛盾表述，历史对照值保留合理 |

三个代码探针文件（`_b4_probe.py` / `_b2_probe.mjs` / `_b1_probe.cjs`）验证通过后已删除，不进入工作树。

### 6.2 P1 验证闭环

- 环境：DSH 文件策略由 `workspace-write` 切至 `danger-full-access`（`workspace-write` 沙箱阻止向系统 temp 目录写入，导致此前 61 failed/129 errors 的 `WinError 5`，非代码回归）。
- 命令：`python -m pytest tests/ -q --disable-warnings`（全权限，无 `--basetemp`）。
- 结果：**258 passed, 8 subtests passed in 200.67s (0:03:20)，exit=0**，零失败、零 error。
- 结论：完整测试套件在全权限下全绿，确认此前大面积失败纯属沙箱写入限制；本轮 4 项修复未引入回归。

### 6.3 剩余未修项（本轮范围外）

- 15 条 Suggestion（S1–S15）与 7 条 Nit（N1–N7）中，S11/S12/S14 已在「继续开发」轮次修复（见第七章），S13/S3 已在后续轮次修复（见第八章），其余未修改，包括但不限于：S15 测试质量、N1 标题层级等。
- 其中 S11（白名单热更新读坏→清空）原列为下轮优先，已修复；S12（HMAC 密钥文件 Windows ACL）同属安全域一并收口。
- 配置页 UI 标签化改造（第五章方案：脱敏规则 / 防护设置两类 + Shell 命令例外归入防护设置）本轮仅出方案、未改代码；后续实施应与 N1 合并。

---

## 七、后续修复：S11 / S14 / S12（2026-11-19）

用户要求「继续开发，推荐下一步修复」。按报告 6.3 的推荐，先收口最后一条未消除的 fail-open 路径 S11 及其测试盲区 S14，再顺手收掉同属安全域的 S12；三处均已修复并全量回归通过。

### 7.1 修复内容

| 编号 | 问题 | 修改位置 | 修复机制 |
| --- | --- | --- | --- |
| S11 | 热更新写坏 preset → 白名单被静默清空（`set_whitelist([])` 照常执行） | `presidio_pii/hooks.py` | 配置读取链加 `strict` 开关：`_preset_config(strict)` 读坏时抛 `PresetUnreadable`（非 strict 仍告警返回 `{}`，保持首次加载回退全开）；`_preset_path(strict)` / `_whitelist_file(strict)` / `_whitelist(strict)` 逐层传递；白名单文件 `OSError` 在 strict 下也抛 `PresetUnreadable`。`_maybe_reload_preset` 的 `set_whitelist` 改调 `_whitelist(strict=True)`，`PresetUnreadable` 走「保留旧值」告警。字段缺失/文件不存在仍返回 `[]`（合法的清空白名单），只有「存在但读不出来」才触发保留旧值。 |
| S14 | `test_unknown_preset_keeps_previous_values` 只覆盖 entity_types、漏白名单 | `tests/test_preset_hot_reload.py` | 基线改为同时收窄 `entity_types=['PHONE_NUMBER']` 并设 `whitelist_path`；写坏 preset 后同时断言 entity_types 与 whitelist 保留旧值，并从行为层验证（人名仍不脱敏、白名单词仍豁免）。 |
| S12 | HMAC 密钥文件 Windows 上只 `chmod(0o600)` 不改 ACL，注释虚假 | `presidio_pii/hooks.py` | 导入 `db._harden`；密钥文件「新建」与「既有复用」两条路径都调用 `_harden(key_file, directory=False)`（Windows `icacls` / POSIX `chmod 0600`，幂等、失败只告警不阻断），删掉虚假的 chmod 注释。 |

### 7.2 验证证据

- 单文件：`python -m pytest tests/test_preset_hot_reload.py -q --disable-warnings` → **5 passed in 53.26s，exit=0**（S11/S14）。
- 单文件：`python -m pytest tests/test_security_hardening.py -q --disable-warnings` → **20 passed in 25.09s，exit=0**（含新增 2 条 HmacKeyFileHardeningTest，S12）。
- 全量：`python -m pytest tests/ -q --disable-warnings` → **260 passed, 8 subtests passed in 301.99s，exit=0**，零失败、零回归（S12 阶段最终态）。
- fail-open 两条路径（B4 的未知类型零脱敏、S11 的白名单读坏清空）至此**全部消除**；`entity_types`/`whitelist` 在 preset 写坏时均保留上一次已知好配置。

---

## 八、S13 / S3 修复（2026-11-19）

用户明确指定「S13+S3」。两条均已修复、逐条反证、全量回归通过。

### 8.1 修复内容

| 编号 | 问题 | 修改位置 | 修复机制 |
| --- | --- | --- | --- |
| S13 | `test_filter_runs_before_overlap_resolution` 断言恒真：原 TEXT 里根本没有 ORGANIZATION，`found <= {"ORGANIZATION"}` 空集也通过 | `tests/test_security_hardening.py`（`EntityTypesFilterTest`）、`presidio_pii/chinese_recognizers.py`（测试新增 import） | 不再依赖真实语料，直接注入两段完全重叠、类型不同的 `RecognizerResult`：LOCATION(0,10)、ORGANIZATION(0,5)。断言 `_filter_entity_types` 后只剩 ORGANIZATION，且 `_resolve_overlaps` 后区间仍为 (0,5)。反证：把顺序换成「先消解再过滤」→ 长 LOCATION 先吞掉 ORGANIZATION → 结果空集，测试必失败（已实测 `wrong order -> []`）。 |
| S3 | settingsFile 数据源分裂：guard 端 `REPO` 只认 env，terms 端 `resolveRepo(rawConfig)` 认 `config.repo`，只配 bundle config 时 UI 设置不生效 | `plugins/dsh-pii-guard/lib/index.js` | 新增与 terms 对齐的 `resolveRepo(config)`（`config.repo` > `PII_GUARD_REPO` > 默认，统一 `\\`→`/` 并去尾斜杠）；`REPO`/`SERVER`/`HOOK_LOG`/`GUARD_SETTINGS_FILE` 由 `const` 改 `let`，`apply()` 里新增 `configurePaths(options)` 按实际 config 重算派生路径并清 `_cfg` 缓存。第二参数 `options` 同时兼容宿主传入的 bundle config 与单测注入的 `redact`/`restore` mock（宿主调用约定 `apply(ctx, config)` 见 `cordis/lib/index.js:365`，键名直通）。 |

### 8.2 验证证据

- S13 单文件：`python -m pytest tests/test_security_hardening.py -q --disable-warnings` → **20 passed in 30.16s，exit=0**；反证「先消解再过滤」实测输出 `wrong order -> []`（断言会失败），证明测试不再恒真。
- S3 JS 烟测：`node tests/js/plugin_terms.mjs` → **63 passed, 0 failed**；`node tests/js/plugin_display.mjs plugins/dsh-pii-guard/lib/index.js` → 全 PASS（含新增「S3 config.repo 覆盖 env」用例）；`node tests/js/plugin_jobs.mjs plugins/dsh-pii-guard/lib/index.js` → `[result] ALL PASS`。S3 专项反证：临时注释掉 `configurePaths(options)` 后，新增用例如期 `FAIL`（visible 被截断，guard 读错 env 旧路径的 off 设置），恢复后 PASS。
- 全量：`python -m pytest tests/ -q --disable-warnings` → **260 passed, 8 subtests passed in 313.09s，exit=0**，零失败、零回归（S13/S3 最终态）。
- 宿主调用约定调研（只读，子 agent）：`cordis/lib/index.js:365` `runtime.callback(this.ctx, config)`、`cordis-plugin-loader/lib/index.js:591` `registry.plugin(plugin, this.options.config, ...)` 证实宿主把 yml 条目的 `config` 对象作为第二参数原样传给 `apply`；官方插件 `dsh-skill-filesystem` 以 `apply(ctx, config)` 读取同名键为佐证。
