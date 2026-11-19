# Presidio PII Redactor for DeepSeek Harness

**简体中文** | [English](README.en.md)

面向 DeepSeek Harness (DSH) 的本地化、轻量、可逆 PII（个人可识别信息）脱敏与还原中间件。借鉴 Microsoft Presidio 的模块化架构，全程离线运行于 CPU，不依赖任何重型 ML 组件（无需 spaCy/PyTorch），依靠优化的正则表达式、校验位算法与词典查表完成识别。

## 特性

- **多实体识别**：中文人名、身份证号（18 位含校验位、15 位旧版）、手机与座机号、邮箱、统一社会信用代码、银行卡（Luhn 校验；校验失败降级保留而非丢弃）、护照、车牌号、IP/MAC 地址、省/市/县级行政区（`LOCATION`）、组织机构（`ORGANIZATION`）以及职位（`JOB_TITLE`）。另设名单型识别通道：显式名单链里的罕见姓、复姓、含「之/同/也」的三字名、带「（26）」学号后缀均覆盖，且不放松通用人名过滤。
- **工具结果整体重渲染**：对带 `presentationMeta` 的工具（如新版 `read` 卡片），DSH 的 post-execute 守卫会替换 canonical `value`，由 `render()` 与 `presentationMeta()` 从脱敏后的值重新生成——模型上下文、session log 的 `meta`、GUI 卡片拿到的是同一份占位符，不再出现「正文已脱敏、卡片仍留原文」。
- **自定义规则**：用 JSON 正则模板或 Python 代码规则扩展识别——CLI 的 `--rules FILE`、环境变量 `PII_DSH_CUSTOM_RULES`，或 DSH preset 的 `config.custom_rules_path`。详见[自定义规则](#自定义规则)。
- **设置页里自己加屏蔽词**：安装 `plugins/dsh-pii-guard-terms` 后，DSH 设置页多出「PII 防护」**一个菜单**，屏蔽词与防护配置在同一页内分区管理。屏蔽词分区直接输入词或短语即可，保存后 **1 秒内**生效（无需重启）。词条写入 `.pii_presidio_store/user_terms_rules.json`（`entity_type` 为 `USER_TERM`、按字面匹配），由 `config.custom_rules_path` 接线到引擎；写接口只接受本机同源请求（loopback + `Sec-Fetch-Site`/Origin 校验），上限 500 条、单条 200 字符。
- **PII 防护配置**：同一个「PII 防护」菜单内还提供 4 项 P0/P1 配置——显示还原模式（`full`/`mask`/`off`）、服务异常时的 fail-open 策略（仅排障）、Shell 守卫总开关、Shell 命令白名单（正则，保存前校验）。配置写入 `.pii_presidio_store/guard-settings.json`（被 gitignore、不含 PII），**下一次工具调用即生效**（无需重启）；字段缺失时回退到进程启动时的环境变量。保存接口要求本机同源请求且带合法会话 cookie，非法正则或显示模式会被拒绝。
- **写法容错**：全角数字字母、数字内插值（`138 0013 8000`）、换行截断的证件号、带空格的姓名，识别前统一归一化，非标准写法同样能命中，且还原仍映射回原文。
- **词边界过滤**：每个命中都必须落在词边界上，词内片段一律丢弃（`内容要求` 里的 `容要求`、`所有部门` 里的 `所有部`、`图书馆` 里的 `书馆`）。装上可选的 jieba 分词后，候选还须与分词边界对齐并符合词性（人名 `nr`、地名 `ns`），几乎消除误报。
- **可逆脱敏**：用抗碰撞的 Unicode 占位符替换敏感数据（如 `⟦PII:ID_NUMBER:0001⟧`）。
- **SQLite 会话映射库**：按会话记录映射关系，存于本地轻量 SQLite 数据库，保证 LLM 返回后文本可 100% 无损还原。
- **Office 文档支持**：可接入 `.docx`、`.pptx`、`.xlsx` 与纯文本。
- **格式覆盖**：可脱敏/还原 `.docx`（段落、表格、页眉页脚、文本框、批注、修订、脚注）、`.xlsx`（单元格与批注）、`.pptx`（文本框、表格、备注），以及 `.txt`、`.md`、`.csv`、`.json`、`.xml`、`.html`、`.eml`、`.rtf`。`.pdf`、`.doc`、`.xls` 为**只读检测**——可扫描识别但不能写回。
- **白名单**：指定关键词不替换——CLI 用 `--whitelist FILE`（每行一个词）或 `--keep TERM`，DSH preset 用 `PII_DSH_WHITELIST`。与白名单区域重叠的实体一律保留。

## 快速开始

```bash
cd dsh-presidio-preset
pip install -e .
pip install -e ".[segment]"   # 可选: jieba 分词, 精度显著提升

# 运行往返演示
python -m presidio_pii.cli --demo

# 脱敏文档 (txt/md/docx/xlsx/pptx)
python -m presidio_pii.cli redact report.docx
# -> report-redacted/report.docx
#    report-redacted/report.docx.mapping.csv   (占位符 <-> 原文)
#    report-redacted/report.docx.session.csv   (session id / 路径)

# 简写: 直接给文件路径等价于 redact
python -m presidio_pii.cli report.docx

# -v 显示阶段进度与逐单元命中; -d 指定输出目录
python -m presidio_pii.cli redact report.docx -v -d out/

# 还原 (从文件旁的 CSV 读取映射, 不依赖映射库)
python -m presidio_pii.cli restore report-redacted/report.docx
# -> report-restored/report.docx
```

输出布局: 脱敏产物落在源文件同级的 `<文件名>-redacted/`, 还原产物落在 `<文件名>-restored/`。
`-o` 写入显式文件路径, 与 `-d` 互斥。裸脚本运行时, 脱敏对应关系存放在
`<文件名>.mapping.csv` (`idx,ptype,placeholder,original`, UTF-8 带 BOM, 可直接用 Excel 打开),
整个脱敏目录拷到别的机器也能还原; `.pii_presidio_store/` 下的 SQLite 映射库只是兜底。
CLI 默认使用内存映射库 (不逐条写盘); 需要让同一会话跨多个文件时, 加 `--session` 走持久化
SQLite 映射库。DSH preset 使用自己的落盘格式, 不受影响。

## 自定义规则

内置实体覆盖不到的业务标识符 (工号、会员号、订单号等) 无需改引擎源码即可扩展。
两种模板可混用:

- **JSON 正则模板** — `pattern`、`entity_type`, 可选 `score`、`priority`、
  `context_hint`、`negative_hint`、`validator`。
- **Python 代码规则** — `.py` 文件提供 `analyze(text) -> [(start, end[, score])]`,
  以及可选的 `ENTITY_TYPE` / `SCORE` / `PRIORITY`。

```bash
export PII_DSH_CUSTOM_RULES=/path/rules.json;/path/order_rule.py
python -m presidio_pii.cli redact 文档.docx --rules rules.json
```

自定义规则在原文上匹配, 与内置识别器一样享受白名单豁免、重叠仲裁与占位符还原。
`--rules` 显式指定的规则走严格加载: 文件缺失或规则非法时以非零退出码中止,
不会在"规则没生效"的情况下静默继续脱敏。

`priority` (0-99, 默认 99) 只决定等长重叠的归属——想让自定义类型在同一个 span 上
胜过某个内置类型, 给它一个更小的数字。规则文件支持热更新: 引擎按文件签名
(mtime + size) 检查, 默认每秒最多一次, 文件变化后自动替换识别器; 热更新失败
(文件被删、JSON 损坏、规则全部非法) 时保留上一份可用规则。设 `PII_DSH_RULES_RELOAD=0`
可关闭自动检查, 改用 `reload_rules()` / `engine.reload_custom_rules()` 显式重载。

完整字段说明与 agent 生成规则的工作流见
[`.agent-presets/presidio-pii/README.md`](.agent-presets/presidio-pii/README.md#自定义识别规则)。

## 测试

```bash
pip install -e ".[dev]"
pytest tests/ -v                          # 228 个回归用例

# 无 DSH 检测真实文档 (泄漏检查 + 还原无损 + 占位符清零, JSON 报告)
python tools/standalone_check.py 报告.docx 名单.xlsx

# 无 DSH 模拟多轮对话, 记录结构化发出/接收日志 (JSONL)
python tools/dsh_sim.py --turn "示例用户「张三（化名）」的身份证号是 000000000000000000，帮我查"

# 生成合成测试语料 (虚构单位/公司/人名/证件号), 切分成多份小文档
python tools/gen_test_corpus.py --base 项目建议书-redacted/项目建议书.docx --out testdata/ --parts 12

# 按真值清单评估召回与误报
python tools/eval_corpus.py --dir testdata/

# 多类型语料: 简历/合同/公文/报告/文献/工资表/通讯录 (共 84 份)
python tools/gen_corpus_v2.py --out testdata_v2 --per-type 12
python tools/eval_corpus.py --dir testdata_v2/
```

详见 [tools/README.md](tools/README.md)。

## 架构

- **`presidio_pii/engine.py`**：核心脱敏与还原流水线 + 优先级重叠消解。
- **`presidio_pii/chinese_recognizers.py`**：中文 PII 识别器（兼容 Presidio API）。
- **`presidio_pii/db.py`**：SQLite 会话映射存储。
- **`presidio_pii/documents.py`**：txt/docx/xlsx/pptx 的文本单元抽取与回写。
- **`presidio_pii/cli.py`**：命令行接口。
- **`tools/`**：无 DSH 文档检测、DSH 流程模拟、合成语料生成与评估。
- **`docs/ROADMAP.md`**：开发计划，含可选的 NER 模型分档。
- **`docs/RESEARCH-pii-protection.md`**：研究总纲（未实施）——识别层规则库化 × 通道层极简工具面，含实测字段覆盖率、读通道盘点与 73 条问题清单。
- **`docs/SECURITY-NOTES.md`**：安全边界与已知风险——CLI 明文映射、`.py` 规则以 import 执行、本地库落地形态、已知盲区。部署前必读。
- **`.agent-presets/presidio-pii/`**：DeepSeek Harness (DSH) agent preset 集成，两种形态并存：
  - **`bundle/cordis.patch.yml`（权威源）**：dsh 0.2.x 实际加载的预设补丁，插件清单、
    工具开关、persona 前缀都在这里。改预设行为**只改这个文件**。
  - `agent.cordis.yml` + `preset.yml` + `skills/presidio-pii/SKILL.md`：**legacy 形态**，
    仅供历史追溯与旧版 harness 参考。dsh 0.2.x 不读取 `agent.cordis.yml`，它已不再
    与 bundle 同步（缺 `pii-guard`、`tool-jobs`、`tool-schedule` 等插件条目）。**不要
    把它当作配置来源**——改了不会生效，这是一个已知的维护陷阱。
  - `preset.json` + `hook.py`：钩子契约入口（before_llm / after_llm）。该形态面向
    能挂载 Python 钩子的 DSH 运行时；当前 dsh 0.2.x 不提供此接缝。但 `preset.json`
    本身**仍是活的配置源**：`entity_types`、`config.whitelist_path`、
    `config.custom_rules_path` 由 `presidio_pii/hooks.py` 读取，设置页会写它。
- **`plugins/dsh-pii-guard/lib/index.js`**：DSH `tools/post-execute` 拦截插件（read/grep/pwsh/
  job_output/job_list）。安装位置为 `<DSH_HOME>/plugins/dsh-pii-guard/lib/index.js`，
  两边必须逐字节一致（门禁 #5 校验），改完需完全重启 DSH。
- **`plugins/dsh-pii-guard-terms/`**：设置页 UI + 配置 API（屏蔽词、防护开关、实体类型
  与白名单）。它是独立的 Host+Client bundle，装进 **web profile**（`profiles/web/package.json`
  里 `"dsh-pii-guard-terms": "link:<repo>/plugins/dsh-pii-guard-terms"`），**不要**写进
  agent preset 的 `plugins` 列表——那是两类不同的东西。仓库根可用 bundle config `repo`
  或环境变量 `PII_GUARD_REPO` 覆盖，默认 `E:/Code/dsh-presidio-preset`。

## 发布与门禁

```powershell
# 一键发布门禁（逐项 PASS/FAIL/SKIP/MANUAL，--json 落盘证据）
python tools/release_gate.py --json "$env:TEMP/release_gate.json"
```

判据、证据与未决项见 [docs/RELEASE-GATE.md](docs/RELEASE-GATE.md)，发布/回退操作见
[docs/RELEASE-RUNBOOK.md](docs/RELEASE-RUNBOOK.md)。插件同步：

```powershell
Copy-Item plugins/dsh-pii-guard/lib/index.js <DSH_HOME>/plugins/dsh-pii-guard/lib/index.js -Force
```
