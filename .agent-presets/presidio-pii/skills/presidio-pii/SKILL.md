---
name: presidio-pii
description: presidio-pii 脱敏引擎的完整 CLI 操作手册——脱敏/还原命令、实体类型、自定义规则、白名单、会话映射库与安全边界。处理含 PII 的文档、文本或需要脱敏后进入 LLM 上下文的任务时使用。
whenToUse: 需要脱敏/还原中文 PII（人名、身份证、手机号、银行卡、统一社会信用代码等）、处理敏感文档、生成自定义识别规则、或把脱敏后的文本送入 LLM 上下文时使用。
user-invocable: true
disable-model-invocation: false
---

# presidio-pii — 中文 PII 脱敏/还原引擎操作手册

本地零依赖（无 spaCy/PyTorch）中文 PII 识别、脱敏、无损还原引擎。本技能是 CLI 层权威参考；引擎实现细节见仓库 `presidio_pii/` 源码。

## 一、核心命令速查

> **沙箱执行前提（本机必读）**：引擎已 `pip install -e` 安装（包名 `presidio-pii-dsh`），
> 任意 cwd 都能 `import presidio_pii`。但**两处必须显式处理**，否则 PermissionError：
> 1. **一切路径用绝对路径**，仓库根 = `E:\Code\dsh-presidio-preset`；不要依赖当前工作目录
>    （CLI 会在 cwd 下建 `.pii_presidio_store`，沙箱内会 WinError 5）。
> 2. **输出目录先用 pwsh 建好**（`New-Item -ItemType Directory`），再跑 CLI：
>    python 子进程无法写入自己创建的目录（写 docx 会被拒）。
> 3. 所有产物（脱敏文件、mapping CSV、session CSV、日志、db）统一落在
>    `E:\Code\dsh-presidio-preset\.pii_presidio_store\` 下，不写进用户项目目录。

```powershell
# 环境确认（首次部署：仓库根目录 pip install -e .）
python -m presidio_pii.cli --demo          # 内置 round-trip 演示（内存库，不落盘）
python -m presidio_pii.cli redact 报告.docx            # 脱敏 → 报告-redacted/ 目录
python -m presidio_pii.cli restore 报告-redacted\报告.docx   # 还原 → 报告-restored/ 目录
python -m presidio_pii.cli redact 文档.docx -v -d out\  # 详细进度 + 指定输出目录
python -m presidio_pii.cli redact 文档.docx -o 指定路径  # -o 与 -d 互斥
```

- 裸文件路径默认执行 `redact`。
- 输出布局：`<name>-redacted/`（脱敏产物 + `.mapping.csv` + `.session.csv`），`<name>-restored/`（还原产物）。
- `.mapping.csv` 是自包含还原凭据（UTF-8 BOM，Excel 可开），脱离 SQLite 也能还原。
- 支持格式：txt/md/docx/xlsx/pptx（读写）、csv/json/xml/html/eml/rtf（读写）、pdf/doc/xls（仅检测）。

## 二、实体类型

`ID_NUMBER`(18位含校验+15位) · `PHONE_NUMBER` · `EMAIL_ADDRESS` · `CREDIT_CODE` · `BANK_CARD`(Luhn) · `PASSPORT` · `LICENSE_PLATE` · `IP_ADDRESS`/`MAC_ADDRESS` · `PERSON`(中文人名) · `LOCATION`(县级以上行政区) · `ORGANIZATION` · `JOB_TITLE`

占位符形态 `⟦PII:TYPE:0001⟧`（Unicode 全角括号，抗 LLM 篡改）；变体容忍：全角数字/字母、号码内分隔符、换行截断、名字内空格。

## 三、白名单

```powershell
$env:PII_DSH_WHITELIST = 'C:\path\whitelist.txt'   # 每行一个关键词，# 注释
```

命中白名单的区域不脱敏，重叠实体一并跳过（白名单写「合肥市数据资源局」时，「合肥市」也不会单独脱敏）。

## 四、自定义规则

内置实体覆盖不到的业务标识符（工号/会员号/订单号）用规则文件扩展，无需改引擎。

- **JSON 正则模板**（`.json`）：`name`/`entity_type`/`pattern` 必填；`score`、`priority`(0-99 默认99)、`context_hint`、`negative_hint`、`validator` 可选。
- **Python 代码规则**（`.py`）：暴露 `analyze(text) -> [(start, end[, score])]` + 可选 `ENTITY_TYPE/SCORE/PRIORITY`。
- 多文件用分号分隔：`$env:PII_DSH_CUSTOM_RULES = 'rules.json;extra.py'`。

**关键行为**：
- `--rules` 显式规则严格加载（文件缺失/规则全非法 → 非零退出，避免静默漏检）；env 注入宽松加载（单条失败跳过）。
- 冲突仲裁：长度 > 优先级 > 起点；`priority` 只影响等长重叠，想让自定义类型胜过内置类型（`ID_NUMBER=0`…`MAC_ADDRESS=12`），把 priority 调小。
- 热更新：引擎按 mtime+size 签名每秒检查一次规则文件；变更后下次识别自动生效，失败保留上一份规则不静默降级。

## 五、agent 生成规则的最小工作流

1. 确认内置实体覆盖不了：`python -m presidio_pii.cli redact 样本.txt -v`
2. 按 JSON/Python 模板写规则，`entity_type` 大写下划线业务语义
3. 正反例验证：正例产出占位符，反例（示例文本/近似串）保持原文
4. 注入 `PII_DSH_CUSTOM_RULES` 或 preset config，多轮回归还原链路
5. 规则文件入版本管理；含敏感示例先脱敏再提交

## 六、会话映射库与安全

- 映射库默认 `.pii_presidio_store/sessions.db`（SQLite），含**明文 PII**，已 gitignore——**绝不提交、不同步**。
- 会话结束可调 `SessionRegistry.delete_session(sid)` 清除。
- 代码规则文件 import 即执行：只加载明确指向的规则文件，勿指向不可信来源。
- 还原是唯一允许「把 PII 放回文本」的环节，且只对最终用户可见输出执行。

## 七、工作流红线（本 preset 强制）

1. 原文含 PII → 先脱敏再进任何 prompt/tool call/外部服务。
2. 交付前验证无损还原：`restore` 产物与原文逐字节一致。
3. 映射文件、hook 日志、脱敏中间产物一律留在 `.pii_presidio_store/` 或 `*-redacted/`，不提交。

## 八、测试集核对（处理敏感文档前必做）

首次使用或拿不准链路时，按 `references/test-guide.md` 核对：

- 素材在 `testdata_v2/`（7 类虚构文档 + manifest 真值 + 白名单，全部虚构）。
- 核对工具 `tools/verify_check.py`（沙箱友好版：**pwsh 预建产物目录后**再跑）。
- 三项判定：泄漏检查 / 还原无损 / 占位符清零，全过才算 PASS。
