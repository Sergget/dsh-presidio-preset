# code-review 改进项落地计划

> 来源：2026-11-16 对「用户自定义屏蔽词 UI」（`dsh-pii-guard-terms`）及此前人名泄漏修复的代码审查报告。
> 结论：**可合并，0 blocker / 4 suggestion / 2 nit**。本报告把逐条建议排期、明确落点与验收标准，供后续迭代认领。
> 核心链路已实测成立（词表写入 → 规则文件 → 1s 热更新 → 命中 `⟦PII:USER_TERM:0001⟧` → 还原无损），以下均为健壮性 / 可维护性增强，非阻塞发布。

## 优先级说明

- **P1**：安全 / 数据正确性相关，建议下一个迭代优先处理。
- **P2**：测试保真度与文档准确性，可与 P1 同批或随后处理。

---

## Suggestion（建议）

### S1 — [P1] 同源兜底「任意非空 Cookie 即通过」过宽

- **落点**：`plugins/dsh-pii-guard-terms/lib/index.js:79-80`（`hasSameOriginProof()` 末尾兜底 `return typeof cookie === 'string' && cookie.length > 0`）。
- **问题**：缺少 `Sec-Fetch-Site` / `Origin` 的非浏览器客户端，或 DNS rebinding 场景下，伪造 `Cookie: x=1` 即可通过应用层门禁。当前依赖 loopback + cross-site 拦截纵深，且 webServer 层疑似已有全局鉴权（GUI 返回 401），但这一点未在代码注释或测试中坐实。
- **改法（择一）**：
  1. 校验宿主会话 cookie 的特定名称 / 签名，而非任意非空值；或
  2. 在 handler 注释中显式声明「本路由依赖 webServer 全局鉴权」，并补一条伪造 cookie 应被拒绝的测试用例。
- **验收**：`tests/js/plugin_terms.mjs` 新增「伪造 Cookie 被 403 拒绝」用例；loopback + 合法同源仍 200。

### S2 — [P1] 规则文件路径三处独立配置，无交叉校验

- **落点**：`plugins/dsh-pii-guard-terms/lib/index.js:27`（`rawConfig.termsFile` / `PII_GUARD_TERMS_FILE`）、`.agent-presets/presidio-pii/preset.json:21`（`custom_rules_path`）、`tools/release_gate.py:296-303`（#5 仅断言 `custom_rules_path` 非空）。
- **问题**：一旦两处路径漂移（例如设置了环境变量 `PII_GUARD_TERMS_FILE`），UI 保存的词不会进入脱敏链路，而门禁仍全绿——静默失效。
- **改法（择一）**：
  1. Host `apply()` 启动时读取 preset 的 `custom_rules_path` 并与自身生效路径比对，不一致则打日志告警 / fail-closed；
  2. 门禁 #5 增加交叉校验，断言两处指向同一文件。
- **验收**：人为制造路径漂移后，要么服务拒绝启动、要么门禁 #5 报 FAIL，不能静默通过。

### S3 — [P2] `readTerms()` 依赖自定义键 `term`，手工编辑规则会被整体覆盖

- **落点**：`plugins/dsh-pii-guard-terms/lib/index.js:168`。
- **问题**：只认 `row.term`，若规则文件被手工写入不含该键的 `USER_TERM` 规则，UI 列表不显示它，点保存即整体覆盖丢失。
- **改法**：从 `pattern` 反解字面量作为显示兜底；或在列表加载时提示「存在 N 条无法识别的规则」并阻止盲目覆盖。
- **验收**：构造一条无 `term` 键的 `USER_TERM` 规则，UI 加载后再次保存不丢失该规则（或明确告警并阻止覆盖）。

### S4 — [P2] 测试断言与注释不符，关键前提缺测试保护

- **落点**：`tests/js/plugin_terms.mjs:110`。
- **问题**：注释写「rule file must exist right after apply」，断言却是 `check('rule file created on apply', routes.size === 2)`——只查路由数量，没碰文件。而「引擎首次构造前文件必须存在」正是整套设计的前提。
- **改法**：改为 `check('rule file created on apply', existsSync(termsFile))`（`existsSync` 已在 :8 导入）。
- **验收**：删除规则文件后该用例应 FAIL。

---

## Nit（拾遗）

### N1 — [P2] README priority 表述不准确

- **落点**：`plugins/dsh-pii-guard-terms/README.md:40`。
- **问题**：文档称 `priority: 0` 让词「与内置高优先实体（身份证 / 统一社会信用代码 / 护照）同级」。实际 `_PRIO`：`ID_NUMBER=0`、`CREDIT_CODE=1`、`PASSPORT=2`，用户词=0 仅与身份证同级、高于信用代码和护照。
- **改法**：改为「与身份证同级、高于其它内置实体」。

### N2 — [P2] 测试注释与用例不符，缺真正的非 loopback 用例

- **落点**：`tests/js/plugin_terms.mjs:121-126` 与 `makeReq():57`。
- **问题**：注释 `// --- gate order: non loopback` 与用例名 `loopback origin accepted`、传入的 loopback 头矛盾；`makeReq` 把 `remoteAddress` 硬编码 `127.0.0.1`，无法构造非 loopback 请求。
- **改法**：修正注释；让 `makeReq` 接受可覆盖的 `remoteAddress`，补一条非 loopback 被 403 拒绝的用例。
- **验收**：非 loopback 请求返回 403。

---

## 建议执行顺序

1. **第一批（P1）**：S1（同源兜底收紧 + 伪造 cookie 用例）、S2（路径交叉校验）——二者都关系安全 / 静默失效风险。
2. **第二批（P2）**：S3（规则读回兜底）、S4（测试断言修复）、N1（README 表述）、N2（非 loopback 用例）。
3. 每批完成后跑：`pytest -q`、两个 JS 冒烟（`plugin_terms.mjs` / `plugin_jobs.mjs`）、完整 `release_gate.py`。

## 已知非本计划范围（发布前已记录的环境项）

- 完整门禁 #6 唯一 FAIL 来自环境级 `opentelemetry-api 1.45.1` 的 CVE-2026-126360（修复版本 1.45.2），与本仓库代码无关；升级属全局环境变更，需另行确认，不在本计划内。
- 设置页视觉外观未做自动化验证（Playwright 页面非 DSH GUI），建议手动刷新确认。
