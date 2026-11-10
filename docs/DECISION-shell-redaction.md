# 决策备忘：shell 输出纳入脱敏

> 状态：**P1-全 + P2 + isError 已拍板并实现（2026-11-06/07）**。pwsh 前台与 `job_output`/`job_list`
> 均已纳入 `GUARDED_TOOLS`；shell/后台任务的 `isError` 文本同样脱敏（read/grep 维持透传）；
> 后台任务单块 >256,000 字节先截断再脱敏并追加截断标记；
> 逃生开关以环境变量实现（`PII_GUARD_SHELL=off` / `PII_GUARD_SHELL_ALLOWLIST=<regex>`，
> 命中写 `shell_bypass` 审计）；非文本输出追加 `[pii-guard] non-text output, redaction skipped`。
> 未做：base64/UTF-16/图片内文字、bash 同构（P3 剩余）。
> 实施中修复一处连带缺陷：归一化只吞单个数字间分隔符（曾把表格列拼成伪卡号）。
> 以下原文保留作拍板依据。
> 对应门禁：[RELEASE-GATE.md](RELEASE-GATE.md) 第 5 项「格式覆盖面」中的 shell 子项（现为 PASS）。
> 所有实测数字来自本机：`D:\Python\313\python.exe`（3.13.13，jieba 已加载）、DSH 0.2.x、Windows。

## 0. 结论摘要

1. **前置的两个 detector 缺陷已修复（2026-11-06）**，shell 输出可以在此基线上推进：
   - 人名命中曾把紧跟的**空格/Tab/换行一起吞掉**（修复前 `张伟 phone` → `⟦PII:PERSON:0001⟧phone`）；现已改为只裁首尾空白，替换后空白序列与原文一致；
   - 纯数字误报曾把 **13 位时间戳**判成银行卡、把 **UUID 尾部**判成银行卡（且只替换后半段）；现已加数字边界（排除字母/下划线/连字符）、epoch-ms 区间过滤、UUID 整体跳过。
2. **推荐默认全量拦截** `pwsh` 的模型可见文本（stdout + `[stderr]` 段 + 状态标记），而不是"只认读文件命令"的白名单——白名单只能算弱化版，命令拼接/别名/`& {}` 很容易绕过，安全收益低。
3. **成本可接受**：默认每流 64 KB 截断下，前台命令最坏约 180 ms（stdout+stderr 各 64 KB）；典型 1–16 KB 输出 3–22 ms。
4. **逃生开关只允许人在配置层开**，默认全开，模型不可自行关闭；每次跳过都写审计日志（含命令哈希，不含明文）。
5. **残余风险需接受**：base64/UTF-16/图片内文字不会被检测；溢出文件（spill）内容为原文，只能靠 read 通道守卫。

## 1. 现状（源码级证据）

Windows 上 preset 只挂 `pwsh`（`tool-bash` 在 win32 下 `disabled: true`，见 `.agent-presets/presidio-pii/agent.cordis.yml:75-81`）。

DSH `pwsh` 的模型可见结果形态（`@deepseek-ai/dsh-tool-pwsh` 与 `@deepseek-ai/dsh-pwsh-local` 的 asar 源码）：

| 事实 | 证据 |
| --- | --- |
| 结果是**单个 text content block**，不是结构化 stdout/stderr 字段 | `dsh-tool-pwsh/lib/index.js` `presentResult`：`result.content.length === 1 && block.type === "text"` |
| 文本 = stdout + `[stderr]\n…` + 状态标记 | `renderPwshResult`（第 155–176 行） |
| 非零退出**不是** `isError`，只是文本 `[exit code: N]` | 同上第 133–136、172 行；只有 spawn 失败/abort 才是 isError |
| 超长输出按**每流 64,000 字节**截断，附 `[output truncated; full output: <spillPath>]` | `dsh-pwsh-local` `maxOutputBytes` 默认 `64e3`；spill 上限 64 MB |
| 输出统一按 UTF-8 解码；PowerShell 端强制 UTF-8 编码前置 | `dsh-pwsh-local` `ENCODING_PREAMBLE` |
| 后台/超时会转成 job，输出改由 `job_output` 返回 | `renderPwshPromoted`、`@deepseek-ai/dsh-tool-jobs` |
| `job_list` 会回显 **命令文本与描述** | `dsh-tool-jobs/lib/index.js`（`job` 结构含 command/description） |

插件现状（实施后）：`GUARDED_TOOLS = {read, grep, pwsh, job_output, job_list}`，源码在仓库内 `plugins/dsh-pii-guard/lib/index.js`、安装于 `E:/Code/dsh_home/plugins/dsh-pii-guard/lib/index.js`（门禁 #5 校验两边一致）。

## 2. 拦截范围（建议）

| 工具 | 字段 | 是否拦截 | 说明 |
| --- | --- | --- | --- |
| `pwsh` | 全部 text content（含 stdout、`[stderr]` 段、退出码/超时/信号/沙箱标记、截断提示） | **是** | 一个文本块，整体过一次 detector；不拆字段 |
| `pwsh` | `result.isError`（spawn 失败、abort） | **是（已实现）** | 错误文本常带路径/文件名；只改 content，不改 `isError` 标记，错误分类展示不受影响 |
| `pwsh` | `[output truncated; … spillPath]` 中的路径 | 按普通文本处理 | 路径里的中文姓名会被替换，导致模型无法再 `cat` 该溢出文件；但溢出内容是原文，本就应只允许经 `read`（有守卫）获取 |
| `job_output` | text content | **是** | 后台命令的续读输出，与前台同源 |
| `job_list` | command/description 回显 | **是** | 命令里可能写死文件名/姓名 |
| `job_kill` | 状态文本 | 可选 | 一般无 PII，可放行 |
| `read` / `grep` | 现状 | 已拦截 | 不放宽 |
| 退出码语义 | `[exit code: N]` 行 | **不得改动** | UI 依赖 `parseExitStatus` 解析；脱敏只替换实体 span，理论上不会命中该行 |

> bash（非 Windows）按同构处理；本机不启用，不单列。

## 3. 二进制与非 UTF-8 输出

- `pwsh` 已在命令前注入 UTF-8 编码前置；Node 侧按 UTF-8 解码，非法字节会变成替换字符或乱码，**不会以原始二进制形式进入上下文**。
- 建议策略：**仍走 detector，但先做文本性判定**——NUL 占比 > 1% 或不可打印字符 > 30% 时视为二进制：不脱敏，但在结果末尾追加一行 `[pii-guard] non-text output, redaction skipped`（让"没脱敏"可见，而不是静默放行）。
- **明确残余风险**（不承诺覆盖）：
  - `base64`/十六进制编码后的 PII 不会被识别（实测 base64 样本 0 处替换）；
  - `Get-Content` 读 UTF-16 文件时 NUL 很多，会被判为非文本而跳过；
  - 图片/PDF 内文字天然不可见。

## 4. 误伤风险清单（全部为实测，非推测）

测试方法：对每条样例直接调用引擎 `redact()`，对比前后文本（样例均为合成数据）。

| 类别 | 实测变化 | 后果 | 处置建议 |
| --- | --- | --- | --- |
| **空格/换行被吞**（最高优先级） | `张伟 phone` → `⟦PII:PERSON:0001⟧phone`；`张伟\nphone` → `⟦PII:PERSON:0002⟧phone`；`张伟\tdept` 同理 | **YAML/TSV/日志分行结构被破坏**；模型解析或复述时直接错行 | 先修 detector：人名 span 不得包含尾随空白；验收断言"换行/空格计数不变" |
| **列对齐崩坏** | 表格 `张伟           13800138000` → `⟦PII:PERSON:0009⟧          ⟦PII:PHONE_NUMBER:0005⟧` | `ls`/`docker ps`/`Get-Process` 等表格错位；人眼与模型都难对齐 | 可接受（占位符 17–21 字符 vs 原文 2–11）；如需保形可选用定长占位符（如 `⟦P0001⟧`），但需同步改 restore 正则 |
| **路径被替换** | `E:\workspace\张伟\合同-姚志刚.docx` → `E:\workspace\⟦PII:PERSON:0006⟧\合同-⟦PII:PERSON:0007⟧.docx` | 模型照抄该路径再执行命令 → 文件不存在；报错环路 | 接受（泄露优先）；文案提示"占位符不可用于再次执行命令" |
| **13 位时间戳误判** | `epoch=1699289554123` → 判为 `BANK_CARD` | 日志里的毫秒时间戳、订单号、追踪号被替换，且无法用于对账 | 修 detector：BANK_CARD 仅 16–19 位且 Luhn 通过，禁止 13 位；ID 同理 |
| **UUID 局部替换** | `550e8400-e29b-41d4-a716-446655440000` → `550e8400-e29b-41d4-a⟦PII:BANK_CARD:0002⟧` | UUID 既泄露前段又损坏尾部；模型无法引用该 ID | 修 detector：命中落在 `[0-9a-f]{8}-…` 或长 hex 串内部时禁用数字类识别器 |
| **JSON 语义改写** | `{"user":"张伟","phone":"13800138000"}` → 值变占位符；`json.loads` 仍 **OK** | 结构合法但内容不可回填；模型若把该 JSON 再提交给服务会失败 | 接受；验收断言"JSON 仍可解析" |
| **diff 可读但不可应用** | `+ 联系人: ⟦PII:PERSON:0004⟧<⟦PII:EMAIL_ADDRESS:0001⟧>` | patch 上下文与真实文件不匹配，`git apply` 失败 | 接受；验收断言 diff 行数与 `+/-` 前缀不变 |
| **ANSI 颜色** | `\x1b[31m13800138000\x1b[0m` → `\x1b[31m⟦PII:PHONE_NUMBER:0003⟧\x1b[0m` | 颜色与转义序列**保留**，实测无破坏 | 无需处理 |
| **进度条** | `[=========>     ] 45% 138/300 12.3MB/s` → **不变** | 无影响 | 无需处理 |
| **git hash / 提交号** | `ea22be4…` 40 位 hex → **不变** | 无影响 | 无需处理（需回归防数字误判扩大） |
| **PowerShell 报错文本** | `+ cat .\张伟.txt` → `+ cat .\⟦PII:PERSON:0008⟧.txt` | 报错示例里的文件名被替换，可读性下降 | 接受 |
| **base64** | 样本 → **不变** | 不误伤，但也**不检测**（见第 3 节） | 记为覆盖缺口 |
| **代码里的数字/人名** | `row.id === 110101199003077890` → 占位符；`return 张伟` → 占位符 | 代码片段不再可复制执行 | 接受；提示模型"看到占位符时不要据此重跑命令" |

## 5. 逃生开关设计

原则：**模型不能自关**，否则等于没有守卫；开关只影响当前 DSH 进程，必须重启生效（与插件加载语义一致）。

| 层级 | 机制 | 默认 | 粒度 | 留痕 |
| --- | --- | --- | --- | --- |
| 单命令 | preset 配置中的 `shellAllowlist`（正则，匹配 `exec.args.command`） | 空 | 单条命令模式（如 `^(git (status|log|diff)|Get-ChildItem)\b`） | 命中即写审计 |
| 单会话 | 环境变量 `PII_GUARD_SHELL=off`（仅启动时读取） | 开 | 整个 DSH 进程 | 启动时写一条 `shell_disabled` |
| 全局 | preset `config.shell_redaction: false` | true | 所有会话 | 同上 |

- 审计记录写入现有 `.pii_presidio_store/hook_log.jsonl`：字段 `event:"shell_bypass"`、`tool`、`reason`（`allowlist`/`env`/`config`）、`cmd_sha1`（命令文本 SHA1 前 8 位）、`bytes`、`ts`。**不写命令原文**。
- 不提供"模型在参数里声明关闭"的通道（`pwsh` 参数 schema 由 DSH 掌控，不能加字段；即便能加，模型可滥用）。
- 若开启"严格模式"（后续阶段）：忽略所有 bypass，审计降级为告警。

## 6. 性能开销（实测）

环境：py3.13 + jieba；常驻 `server.py`（stdio JSON 行协议），SQLite 映射库。测法：合成日志文本（约 1/40 行含 PII），每档取中位数。

| 单次文本量 | 引擎内中位 | 服务往返中位（含 IPC+落库） |
| --- | --- | --- |
| 1 KB | 1.6 ms | 3.1 ms |
| 4 KB | 5.3 ms | 6.9 ms |
| 16 KB | 20.5 ms | 22.4 ms |
| 64 KB | 82.7 ms | 88.2 ms |
| 128 KB | 165.4 ms | 179.9 ms |
| 512 KB | 926 ms | —（不做全量） |
| 1 MB | 2303 ms | —（不做全量） |

- 吞吐约 **0.8 MB/s**（1 MB 后降到 0.46 MB/s，长文本里 jieba 分段开销上升）。
- 首次请求含引擎/词表初始化约 **2.1 s**；插件按需 spawn，所以「本会话第一条被守卫的 shell 命令」会多这一拍。
- **默认截断下最坏**：stdout 64 KB + stderr 64 KB ≈ **180 ms**；典型 4 KB ≈ 7 ms。20 条命令累计约 1–4 s，可感知但不阻塞。
- 若放开 `job_output` 大块续读：1 MB ≈ 2.3 s，**必须有上限**（建议 256 KB 封顶 + 提示）。
- 串行性：单 Python 服务按行排队；并发两条 64 KB 命令各自等待，总体线性叠加。若并发场景多，可后续做 2–4 个 worker 进程。

## 7. 渐进落地路径（选一条）

| 路径 | 范围 | 改动面（不含时间估计） | 风险 |
| --- | --- | --- | --- |
| **P0（前置，已完成）** | 无 | detector 两处：人名尾随空白；数字类误报（13 位/BANK_CARD 局部命中/hex 内部） | 已完成并回归（132 passed）；shell 文本不再被吞分隔符 |
| **P1-窄** | 仅 `pwsh` 且命令匹配只读白名单（`cat/Get-Content/type/Get-ChildItem/Select-String/findstr/head/tail`） | 插件加命令解析与白名单（约 60 行）+ 8 条用例 | 白名单易被 `& {…}`/别名/管道绕过，"看起来守住了"最危险；命令字符串解析本身易误判 |
| **P1-全（推荐）** | 全部 `pwsh` 文本块 | 插件 `GUARDED_TOOLS` 加 `pwsh`（约 5 行）+ 文本性判定（约 20 行）+ 回归 20 条日常命令 | 需要 P0 完成；日常命令输出若被误伤，影响面比 read 更大 |
| **P2（已完成）** | 追加 `job_output` / `job_list` | 同 P1 + 256 KB 截断（插件 + node 冒烟，现共 13 条） | 大输出延迟；`job_list` 回显命令 |
| **P3（部分完成）** | `isError` 文本已完成；bash 同构、严格模式未做 | isError 约 5 行 + node 冒烟 3 条 | Windows 无 bash，验收只能在其他机器 |

推荐顺序：**P0 → P1-全 → P2 →（按需）P3**。
若你更看重"先别动日常命令"，则先 P1-窄，但需明确接受"白名单外仍可泄露"。

## 8. 验收判据

### A. 证明"shell 路径不再泄露"（负向）

用合成 PII 文件与命令，逐条断言模型可见文本中**明文出现次数 = 0**、占位符数 > 0：

1. `Get-Content secret.txt`（含人名/手机/身份证）
2. `type secret.txt`（别名路径）
3. `Select-String -Path secret.txt -Pattern 13800138000`（grep 等价）
4. `cat missing.txt`（错误信息里含 PII 文件名）
5. `Get-Content ok.txt; Write-Error "张伟 13800138000"`（**仅 stderr** 泄露）
6. 非零退出：`cmd /c "type secret.txt & exit 2"`（确认 `isError=false` 时仍被脱敏，标记行保留）
7. 后台任务：`run_in_background` + `job_output` 续读（同一明文）——P2 已覆盖
8. `Get-Content big.txt` 超 64 KB（截断提示存在且正文已脱敏）
9. 反向用例（**已知不覆盖**，断言"不替换 + 有跳过提示"而非静默）：base64 编码的 PII、UTF-16 文件
10. spawn 失败/abort 的 `isError` 文本：已由 `tests/js/plugin_jobs.mjs` 覆盖（pwsh/job 脱敏，read 维持透传）

### B. 证明"日常命令没被搞坏"（正向）

- **强不变量**：对**不含 PII** 的 20 条常用命令输出，脱敏前后**逐字节相同**（`git status`、`git diff`、`git log --oneline`、`Get-ChildItem`、`python -m pytest`、`pip list`、`node -v`、`docker ps`、`Get-Process | Format-Table`、JSON 输出等）。
- 含 PII 时只允许"实体 span 被替换"，其余结构不变量：
  - 换行数、空格数（除实体内部外）不变；
  - `[stderr]`、`[exit code: N]`、`[timed out after …]`、`[output truncated; …]`、`[still running …]` 行逐字保留；
  - JSON 输出仍 `json.loads` 通过；
  - ANSI 转义字节序列完整。
- 逃生开关：开启 allowlist 后该命令**逐字节不变**；每次跳过在 `hook_log.jsonl` 有且仅有 1 条 `shell_bypass`，且不含明文。

### C. 性能

- 64 KB p95 ≤ 150 ms；128 KB p95 ≤ 350 ms；首条命令额外 ≤ 3 s；
- 不触发插件 `CALL_TIMEOUT_MS = 30 s`；
- 1 MB 场景必须命中上限策略（截断或拒绝），不得全量过 detector。

### D. 审计与可回退

- 任一绕过路径都能在日志中查到；关闭开关后行为回到当前基线（`pwsh` 透传）；
- 插件异常（服务崩溃/超时/spawn 失败）仍是"降级透传 + stderr 告警"，不阻塞命令；spawn 失败已补 `error` 事件处理（否则 Node 未处理事件会终止宿主），并由 node 冒烟覆盖。
- 配置写错（`PII_GUARD_SHELL_ALLOWLIST` 非法正则）时忽略该开关并告警，按"不放行"处理，不会静默关闭拦截。
- 部署路径可覆盖：`PII_GUARD_PY`（解释器）、`PII_GUARD_REPO`（仓库根）。

## 9. 已拍板的问题（结论）

> 以下 1–5 已于 2026-11-06/07 拍板并实现：1→全部拦截含 `job_output`/`job_list`；2→P1-全；
> 3→仅配置层、需重启、模型不可关，默认全开；4→是（shell/job 的 `isError` 脱敏，read/grep 维持透传）；
> 5→256 KB 截断并提示。第 6 条未改（仍用 `⟦PII:TYPE:NNNN⟧` 长占位符）。

1. **范围**：只拦 `pwsh` 前台，还是一并拦 `job_output` / `job_list`（后台任务会绕过）？
2. **路径**：P1-全（推荐，需先做 P0）还是 P1-窄（只读命令白名单，接受白名单外泄露）？
3. **逃生开关**：是否接受"仅配置/环境变量、需重启、模型不可关"？默认值是否全开？
4. **isError 文本**：shell 的 spawn/abort 错误是否也脱敏？
5. **大输出**：超过阈值（建议 256 KB）是截断并提示，还是直接拒绝并让用户先用 CLI 脱敏？
6. **占位符长度**：是否为了保住表格/列宽改用短占位符（会牵连 restore 正则与既有映射）？

## 10. 与门禁清单的对应

- **直接对应**：[RELEASE-GATE.md](RELEASE-GATE.md) 第 5 项「格式覆盖面」的 shell 子项 —— 当前 `PASS`（P1-全 + P2 + isError 已实现，门禁 #5 复核）。
- **联动项**：
  - 第 2 项「DSH 进程内 E2E」：shell 用例（第 8 节 A）需在重启后与 read/grep 三用例一起跑，才能算读取/E2E 全绿；
  - 第 3 项「redact→restore 无损」：shell 场景的还原多一步"模型把占位符写回回复"，需用现有 `after_llm` 链路补一条端到端用例；
  - 第 4 项「自动 restore 接线」：shell 脱敏后，若模型在回复里引用占位符，用户看到的是占位符还是原文，取决于第 4 项的 A/B/C 决策——两者需一起拍。
