---
name: presidio-pii
description: PII 防护模式下的 Node 原生脱敏/还原能力参考——支持实体类型、自定义规则、白名单、安全文件工具与安全边界。处理含 PII 的文档或文本任务时使用。
whenToUse: 需要了解或调试 PII 脱敏能力、实体类型、自定义屏蔽词、白名单、安全文件通道（read_redacted / write_raw / restore / ls）时使用。
user-invocable: true
disable-model-invocation: false
---

# presidio-pii — PII 防护模式与脱敏引擎手册

本预设内置由 `dsh-presidio-pii` 统一插件提供的纯 Node 零依赖中文 PII 识别、脱敏与无损还原引擎。

## 一、运行时安全文件面与主路径

在 `PII 防护模式` 下，运行时守卫自动接管：

1. **工具结果脱敏（`dsh-presidio-pii/guard`）**：所有工具文本输出在写入 session log 与进入上下文之前强制脱敏为 `⟦PII:TYPE:NNNN⟧` 占位符，显示侧根据配置（`full` / `mask` / `off`）自动还原。
2. **受限安全文件工具（`dsh-presidio-pii/fs`）**：
   - `read_redacted`：读取文本文件并立即返回脱敏后的占位符内容（路径仅保留 basename）。
   - `write_raw`：写入完整文本到目标路径（只写明文或通过 `restore` 还原后的文本）。
   - `restore`：将文本中的 `⟦PII:TYPE:NNNN⟧` 占位符还原回原文（仅在最终交付给用户或显式要求明文落盘时使用）。
   - `ls`：列出目录内文件名，不返回真实目录树。
3. **服务异常保护（fail-closed）**：脱敏服务不可用时默认阻断输出，绝不放行明文（除非用户在设置页显式开启 `failOpen` 排障）。

## 二、支持实体类型（共 20 类）

- **内置核心 13 类**：`ID_NUMBER` · `PHONE_NUMBER` · `EMAIL_ADDRESS` · `CREDIT_CODE` · `BANK_CARD` · `PASSPORT` · `LICENSE_PLATE` · `IP_ADDRESS` · `MAC_ADDRESS` · `PERSON` · `LOCATION` · `ORGANIZATION` · `JOB_TITLE`
- **内置扩展 7 类**（`rule_libraries/extended-fields.json`）：`AGE` · `BIRTH_DATE` · `GENDER` · `ETHNICITY` · `EDUCATION` · `IM_ACCOUNT` · `EMPLOYEE_ID`

占位符格式为 `⟦PII:TYPE:0001⟧`（抗 LLM 篡改的 Unicode 全角括号），引用占位符时必须逐字符保留原样。

## 三、数据目录与设置页（动态路径，无硬编码）

运行期配置、映射库与日志统一存放在 DSH 数据目录（默认 `$DSH_HOME/data/presidio-pii/`，或通过 bundle `config.dataDir` / 环境变量 `PII_GUARD_DATA_DIR` / `PII_GUARD_REPO` 指定）：

- `user_terms_rules.json`：设置页「PII 屏蔽词」保存的自定义字面量规则（`USER_TERM`），约 1 秒内热更新生效。
- `guard-settings.json`：显示还原模式（`full` / `mask` / `off`）、`failOpen`、`shellDisabled`、`shellAllowlist`，保存后下次工具调用即生效。
- `preset.json`：启用的 `entity_types` 与 `whitelist_path`（每行一个白名单词，`#` 开头为注释；相对路径相对数据目录解析）。
- `sessions.db` / `hook_log.jsonl`：会话映射数据库与审计日志，绝不提交或外传。

## 四、可选补充：仓库内 Python CLI（仅开发仓库处理 Office 二进制时）

若当前在源仓库中需要离线批量处理 `.docx` / `.xlsx` / `.pptx` 二进制文档，可显式指定仓库根路径运行：

```powershell
# 在源码仓库根目录执行（相对当前目录，不硬编码机器路径）
python -m presidio_pii.cli redact <文档路径> -d .\.pii_presidio_store\out
python -m presidio_pii.cli restore .\.pii_presidio_store\out\<文档名> -d .\.pii_presidio_store\restored
```

## 五、安全边界

- session log 中保留的是脱敏占位符，但工具调用原始入参仍会落盘，因此切勿将明文 PII 写入提示词或工具参数。
- 图片（`read_image` 已禁用）、base64/UTF-16 编码载荷与用户在输入框直接粘贴的明文不在工具结果守卫拦截范围内。
