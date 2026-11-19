# 全项目 Code Review 报告

> 审查日期：2026-11-18
> 审查范围：`presidio_pii/`（Python 引擎）、`plugins/dsh-pii-guard/`（JS 守卫）、`plugins/dsh-pii-guard-terms/`（Host + Client 设置页）、`.agent-presets/presidio-pii/`（preset 配置）、`tests/`（Python + JS 测试）、`tools/`（构建与验证脚本）
> 审查人：Kimi (P8)

---

## 总体评估

项目整体架构清晰，实现了从文件读取 → 脱敏 → LLM 上下文 → 写回还原的完整闭环。核心引擎覆盖 14 类中文 PII 实体，识别器设计合理（Luhn 校验、后缀词典、jieba 分词辅助），fail-closed 安全策略正确。JS 守卫插件与 Python 引擎通过 stdio JSON 协议通信，职责分离明确。

**主要风险集中在**：本地敏感信息泄露面（shell 路径豁免、phMap 内存丢失、CLI 输出明文映射文件）、UI 配置项未挂载（terms 插件不在 preset 中）、以及若干边界条件处理。

---

## 一、正确性问题

### P0 — 严重

**无。**

### P1 — 高

1. **phMap 纯进程内存，重启即丢，显示还原失效**
   - 位置：`plugins/dsh-pii-guard/lib/index.js:334`
   - 问题：`phMap = new Map()` 仅在 `tools/post-execute` 收到 `msg.map` 时填充，从不回读 DB。DSH 重启后 phMap 清空，后续 assistant-stream 中的占位符因 `phMap.get(ph) ?? ph` 查不到而原样透传。
   - 影响：用户已报告此问题（m00144）。重启后所有历史占位符无法还原显示。
   - 建议：在 `agent/created` 或首次 `assistant-stream` 时，从 DB 懒加载当前会话的映射关系填充 phMap。

2. **agent.cordis.yml 与 bundle/cordis.patch.yml 插件清单不一致**
   - 位置：`.agent-presets/presidio-pii/agent.cordis.yml`（215 行）vs `.agent-presets/presidio-pii/bundle/cordis.patch.yml`（239 行）
   - 问题：`agent.cordis.yml` 缺少 `pii-guard` 插件、`tool-jobs`、`tool-schedule`、`plugin-manager` 禁用、`plugin-market` 禁用。如果 DSH 优先加载 `agent.cordis.yml`，守卫插件不会挂载。
   - 影响：取决于 DSH 加载顺序，可能导致 PII 防护完全失效。
   - 建议：统一两个文件，或明确哪个是权威源，删除另一个。

### P2 — 中

3. **shell 路径豁免逻辑过于宽松**
   - 位置：`plugins/dsh-pii-guard/lib/index.js:175-190`（`redactExempted`）
   - 问题：`isLikelyPath(text)` 仅检查是否含 `/` 或 `\` 且无 >50 字符的词。满足条件时，shell 输出中所有 ORGANIZATION 类型实体被还原回原文（不脱敏）。
   - 影响：组织名称在路径上下文中泄露。虽然设计意图是避免路径被脱敏后无法使用，但豁免范围过大。
   - 建议：限制豁免仅适用于文件路径参数位置，而非整个 shell 输出；或增加路径白名单机制。

4. **placeholderNotice 注入依赖 WeakSet，跨会话不持久**
   - 位置：`plugins/dsh-pii-guard/lib/index.js`（`noticedAgents` WeakSet）
   - 问题：placeholderNotice 只在首次产生映射时注入一次，用 WeakSet 按 agent 去重。如果 agent 被 GC 后重建，同一 agent 可能重复注入。
   - 影响：轻微——重复注入 notice 不会导致功能错误，但会浪费 token。
   - 建议：可接受当前设计，或改用 Map 按 session.id 追踪。

### P3 — 低

5. **`get_max_seq` 使用 `SUBSTR(placeholder, -5, 4)` 提取序号**
   - 位置：`presidio_pii/db.py`
   - 问题：假设占位符格式为 `⟦PII:TYPE:NNNN⟧`，取倒数第 5-2 字符。如果序号超过 9999，提取会出错。
   - 影响：极大数据量时可能出现序号冲突。
   - 建议：使用正则提取，或改用自增 ID。

---

## 二、安全边界

### P0 — 严重

**无。**

### P1 — 高

6. **custom_rules.py 动态加载 .py 文件，import 即执行**
   - 位置：`presidio_pii/custom_rules.py:220-299`（`_import_path`）
   - 问题：使用 `importlib.util.spec_from_file_location` 动态加载 Python 规则文件，import 时执行模块级代码。如果规则文件被篡改，可执行任意代码。
   - 影响：本地代码执行风险。虽然文件路径受控（`.pii_presidio_store/`），但如果攻击者能写入该目录，即可 RCE。
   - 建议：限制规则文件目录权限；考虑用沙箱执行（如 `RestrictedPython`）；或在文档中明确标注风险。

7. **terms 插件 REPO 路径硬编码**
   - 位置：`plugins/dsh-pii-guard-terms/lib/index.js:36`
   - 问题：`REPO = 'E:/Code/dsh-presidio-preset'` 硬编码，不像 guard 插件支持 `PII_GUARD_REPO` 环境变量覆盖。
   - 影响：项目移动后 terms 插件无法找到规则文件和设置文件。
   - 建议：与 guard 插件对齐，支持环境变量覆盖。

### P2 — 中

8. **shell allowlist 正则注入风险**
   - 位置：`plugins/dsh-pii-guard-terms/lib/index.js`（`normalizeSettings`）
   - 问题：`shellAllowlist` 校验正则合法性，但未限制 ReDoS（正则拒绝服务）。恶意构造的正则可能导致 CPU 耗尽。
   - 影响：本地 DoS。
   - 建议：限制正则复杂度，或使用 RE2 等安全正则引擎。

9. **fail-closed 策略在 service spawn 失败时阻断所有工具调用**
   - 位置：`plugins/dsh-pii-guard/lib/index.js`（`ensureService` + `callServer`）
   - 问题：如果 Python 服务进程崩溃或无法启动，所有工具调用的 post-execute 都会因 fail-closed 而阻断。
   - 影响：服务不可用时整个 agent 瘫痪。虽然 fail-closed 是正确策略，但缺乏降级路径。
   - 建议：增加健康检查和自动重启机制；考虑短暂的 fail-open 窗口（如 3 次重试后才阻断）。

---

## 三、UI 配置项完整性

### P1 — 高

10. **dsh-pii-guard-terms 插件未挂载到 preset**
    - 位置：`.agent-presets/presidio-pii/bundle/cordis.patch.yml`
    - 问题：插件清单中缺少 `- id: pii-guard-terms \n name: 'dsh-pii-guard-terms'`。用户无法通过设置页配置屏蔽词。
    - 影响：用户已报告此问题（m00144）。屏蔽词功能完全不可用（UI 层面）。
    - 建议：在 bundle 的 cordis.patch.yml 中追加 pii-guard-terms 插件声明，重启 DSH。

### P2 — 中

11. **UI 设置项缺少 `whitelist_path` 配置入口**
    - 位置：`plugins/dsh-pii-guard-terms/client.js`
    - 问题：设置页只有屏蔽词 CRUD 和 displayMode/failOpen/shellDisabled/shellAllowlist，没有白名单文件路径配置。
    - 影响：用户无法通过 UI 配置白名单，只能手动编辑 preset.json。
    - 建议：在 SettingsSection 中增加 whitelist_path 配置项。

12. **UI 设置项缺少 `entity_types` 启用/禁用控制**
    - 位置：`plugins/dsh-pii-guard-terms/client.js`
    - 问题：13 种实体类型全部启用，用户无法选择性禁用某类识别器（如关闭 PERSON 识别以减少误报）。
    - 影响：误报时无法快速调整。
    - 建议：增加实体类型开关列表。

---

## 四、本地敏感信息泄露面

### P1 — 高

13. **CLI redact 输出明文 mapping.csv 和 session.csv**
    - 位置：`presidio_pii/cli.py`
    - 问题：`redact` 子命令在输出目录生成 `mapping.csv`（占位符→原文映射）和 `session.csv`（会话凭据）。这些文件包含明文 PII。
    - 影响：如果输出目录被打包、上传或共享，PII 泄露。
    - 建议：mapping.csv 加密存储；或在文档中明确标注这些文件包含敏感信息，不得外发。

14. **phMap 内存中存留明文 PII**
    - 位置：`plugins/dsh-pii-guard/lib/index.js:334`
    - 问题：phMap 存储占位符→原文的映射，在进程内存中明文存在。
    - 影响：进程被 dump 时 PII 泄露。但这是设计所需（显示还原），风险可接受。
    - 建议：文档中说明；考虑进程退出时清理。

### P2 — 中

15. **journal 日志记录 SHA256 指纹**
    - 位置：`presidio_pii/journal.py`、`presidio_pii/hooks.py`
    - 问题：日志记录原文的 SHA256 指纹。虽然不记原文，但 SHA256 可被用于暴力破解短文本。
    - 影响：对于短 PII（如手机号 11 位），SHA256 可被彩虹表反查。
    - 建议：使用 HMAC-SHA256 加盐，或仅记录长度和实体类型。

16. **sessions.db 明文存储映射关系**
    - 位置：`.pii_presidio_store/sessions.db`
    - 问题：SQLite 数据库明文存储所有会话的占位符→原文映射。
    - 影响：数据库文件被复制即泄露全部 PII。
    - 建议：数据库文件加密（如 SQLCipher）；或至少设置文件权限为仅当前用户可读。

---

## 五、工具调用覆盖度

### 覆盖良好

- `tools/post-execute`：拦截所有工具调用结果，prepend 确保最先执行
- `agent/created`：注册 WRITE_TOOLS shadow wrapper + read_image restrict
- `agent/pre-step`：粗筛裸手机号/身份证告警
- `agent/assistant-stream`：显示侧还原（扣尾补头处理跨 chunk 占位符）

### 已知盲区（设计决策）

17. **shell 命令参数不脱敏**
    - 位置：`plugins/dsh-pii-guard/lib/index.js`（WRITE_TOOLS 不含 pwsh/bash）
    - 问题：模型如果将占位符传入 shell 命令参数，不会被还原为原文。
    - 影响：模型可能将 `⟦PII:ORGANIZATION:0001⟧` 传入 `pwsh` 的 `command` 参数，导致文件找不到。
    - 状态：已知边界，preset 文档中有说明（Known gaps）。
    - 建议：考虑对 shell 命令参数也做还原，或至少在 placeholderNotice 中明确告知模型不要在 shell 中使用占位符。

18. **tool/call 原始参数落盘不脱敏**
    - 位置：DSH 框架层
    - 问题：工具调用的原始参数（含占位符）被 DSH 框架记录到会话日志。
    - 影响：会话日志中包含占位符而非原文，这是预期行为。但如果日志被发送到外部，占位符本身可能泄露实体类型和数量。
    - 建议：文档中说明会话日志包含占位符元信息。

---

## 六、测试覆盖与文档一致性

### 测试覆盖良好

- Python：9 个测试文件，覆盖引擎、自定义规则、流程、手机号边界、名单人名、shell 脱敏、结构化文档、用户词、变体
- JS：3 个测试文件（display/jobs/terms），覆盖显示还原、工具拦截、terms API

### 文档问题

19. **agent.cordis.yml 与 bundle/cordis.patch.yml 不一致**（见问题 2）
20. **README 提到的屏蔽词设置页依赖未挂载的插件**（见问题 10）

---

## 七、下一步工作与优化方向

### 2026-11-18 修复收口（本轮）

| 编号 | 问题 | 处理 | 落点 / 验证 |
|---|---|---|---|
| #1 | phMap 重启丢映射 | **已修** | `agent/assistant-stream` 命中未缓存占位符时异步调 `restoreText` 回填；`tests/js/plugin_display.mjs` 新增两条（重启恢复、缓存不重复 IPC），11/11 |
| #3 | shell 路径豁免过宽 | **已修** | 删除 `isLikelyPath`，改 `isPathFragment(text, value)` 逐实体判定；`plugin_jobs.mjs` 新增「路径中的机构名豁免 / 正文中的机构名仍脱敏」两条 |
| #5 | `get_max_seq` 定宽截取 | **已修** | `SUBSTR(placeholder, ?)` 按类型长度算偏移，seq 12345 由 1234 修正为 12345 |
| #7 | terms REPO 硬编码 | **已修** | `resolveRepo()`：bundle config `repo` > env `PII_GUARD_REPO` > 默认值 |
| #8 | shellAllowlist 无 ReDoS 防护 | **已修** | `hasNestedQuantifier()` 拒嵌套量词/重叠分支；守卫侧 `ALLOWLIST_MAX_CMD=4096`；`plugin_terms.mjs` 新增 3 条 |
| #9 | fail-closed 无重试窗口 | **已修** | `callServerWithRetry()`：3 次、指数退避，只重试「不可用/spawn failed/exited/timeout」，确定性失败立即抛出 |
| #11 #12 | UI 缺 `whitelist_path` / `entity_types` | **已修** | Host 新增 `GET/POST /api/dsh-pii-guard/preset[/save]`；client 新增 `PresetSection`（勾选网格 + 全选/全不选 + 白名单路径）。Python 侧 `engine._filter_entity_types()` + `hooks._entity_types()` / `_maybe_reload_preset()` 消费，preset 变更按 mtime 热加载 |
| #13 | CLI 明文 mapping.csv / session.csv | **改为文档化** | 见 `docs/SECURITY-NOTES.md` §1：这是产物级可逆脱敏的必需载体，加密会引入密钥管理问题；发布/分发约束已写明 |
| #15 | journal 裸 SHA256 指纹 | **已修** | `_fingerprint()` 改 HMAC-SHA256，密钥 `journal_hmac.key`（0600），env `PII_DSH_LOG_HMAC_KEY` 可覆盖 |
| #16 | sessions.db 明文 | **加固+文档化** | `db._harden()` 走 `icacls /inheritance:r`（POSIX 0700/0600），失败回滚并告警；明文属性见 `SECURITY-NOTES.md` §3 |
| #6 | `_import_path` 执行 `.py` | **保留+文档化** | 能力即风险，见 `SECURITY-NOTES.md` §2；只从显式配置加载，不扫描目录 |
| #2 #19 | `agent.cordis.yml` 与 bundle 不一致 | **文档化** | README 架构节标注 `bundle/cordis.patch.yml` 为权威源、`agent.cordis.yml` 为 legacy |
| #10 #20 | terms 插件未挂载 | **误判撤销** | terms 是独立 Host+Client bundle，已 `link:` 装入 `profiles/web/package.json`；`cordis_inspect_query` 确认 `settings.section` occupant 存在、active=true。**不应**写进 agent preset 的 plugins 列表 |
| #4 | shell 参数不做写侧还原 | **保留（设计边界）** | 已记入 `SECURITY-NOTES.md` §5 盲区表 |
| #17 #18 | shell 参数 / tool-call 参数含占位符 | **保留（设计边界）** | 同上 |

### 2026-11-19 补充收口（回归阶段新发现）

| 编号 | 问题 | 处理 | 落点 / 验证 |
|---|---|---|---|
| #21 | preset 写坏导致实体类型白名单 **fail-open** | **已修** | `_entity_types()` 读不出来时抛 `PresetUnreadable` 而非静默返回 `[]`（空列表 = 全部启用）；`_maybe_reload_preset()` 保留旧值、`_get_engine()` 首次加载回退全部启用。`tests/test_preset_hot_reload.py` 5 条锁定，反证「改回 `return []`」→ 1 failed |
| #22 | `_get_engine()` 漏 `global _PRESET_SIG` | **已修** | 签名只写到局部变量，模块级恒为 `None` → 每次调用都重新解析 preset，热更新节流失效。`global _ENGINE, _PRESET_SIG` |
| #23 | `SessionRegistry` 无 `close()` | **已修** | Windows 上不关连接会让 db/wal/shm 持续被占用（临时目录删不掉）。新增 `close()` + `__enter__`/`__exit__` |
| #24 | `agent.cordis.yml` 遗留旧 persona | **保留（legacy）** | 与 #2 同源；dsh 0.2.x 不读该文件，已在 README 标为维护陷阱 |

### 长期方向

1. **服务高可用**：Python 服务崩溃自动重启 + 健康检查（现为 3 次重试后 fail-closed）
2. **数据库加密**：sessions.db 使用 SQLCipher（当前靠文件系统 ACL）
3. **识别器精度提升**：基于用户反馈持续优化误报/漏报
4. **审计面板**：UI 展示脱敏统计、映射数量、泄露风险指标
5. **配置原子性**：preset.json 目前是 tmp+rename 原子写，但 Node 侧 `writePreset` 与
   Python 侧热更新之间没有版本号握手；并发保存极端情况下可能读到中间态（已用
   `PresetUnreadable` 兜住，不会 fail-open，但会短暂降级）


---

## 审查方法

- 逐文件阅读全部核心源码（Python 13 文件 + JS 3 文件 + 配置 4 文件 + 测试 12 文件）
- 交叉检查配置一致性（preset.json / cordis.patch.yml / agent.cordis.yml）
- 安全边界分析（fail-open 路径、注入面、权限模型）
- 本地泄露面枚举（文件系统、进程内存、日志、数据库）
