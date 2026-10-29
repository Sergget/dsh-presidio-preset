# presidio-pii — DSH Agent Preset

为 DeepSeek Harness (DSH) 提供本地可逆 PII 脱敏:提示离开 harness 前脱敏,LLM 响应返回后还原。全程离线,零 spaCy/PyTorch 依赖。

## 工作原理

```
用户 prompt ──> before_llm ──> ⟦PII:PERSON:0001⟧的身份证是⟦PII:ID_NUMBER:0001⟧ ──> LLM
                                                                        │
用户看到原文 <── after_llm <── 张伟的身份证是⟦...⟧(还原后完整原文) <──────┘
```

- 脱敏映射存入本地 SQLite (`presidio_pii.db.SessionRegistry`)
- 占位符使用 Unicode 全角括号 `⟦ ⟧`,抗 LLM 篡改/误改
- 同一会话 (conversation_id) 多轮请求共享映射表,任何一轮的响应都能还原

## 集成方式

1. 安装本包: `pip install -e <repo-root>`
2. 在 DSH preset 配置中引用 `preset.json` 声明的两个钩子:
   - `before_llm(prompt, conversation_id)` → 脱敏文本
   - `after_llm(response, conversation_id)` → `(还原文本, 统计字典)`, 只需文本时取 `[0]`
   - 每次调用自动写入结构化日志 `.pii_presidio_store/hook_log.jsonl` (可用 `PII_DSH_LOG_PATH=0` 关闭)
3. `conversation_id` 由 DSH 传入;未传入时按日期派生,同一天内共享会话

## 配置

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `db_path` | `<repo>/.pii_presidio_store/sessions.db` | 映射库位置 |
| `session_scope` | `conversation` | 会话粒度 |
| `supported_extensions` | txt/md/docx/xlsx/pptx | 文档格式 |
| `whitelist_path` | `null` | 白名单文件（每行一个关键词，`#` 注释）；等价于环境变量 `PII_DSH_WHITELIST` |

## 白名单

命中白名单的区域不脱敏；与白名单重叠的实体一并跳过（白名单写 `合肥市数据资源局` 时，
其中的 `合肥市` 也不会被单独脱敏）。

```bash
# 环境变量指向白名单文件
export PII_DSH_WHITELIST=/path/to/whitelist.txt
```

文件格式：

```
# 每行一个关键词
国家数据局
智数科技
合肥市数据资源局
```

## 识别实体

`ID_NUMBER`(身份证,含校验位)、`PHONE_NUMBER`、`EMAIL_ADDRESS`、`CREDIT_CODE`(统一社会信用代码)、`BANK_CARD`、`PERSON`(中文人名)、`LOCATION`(县级行政区)、`ORGANIZATION`、`JOB_TITLE`

## 安全注意

- 映射库含明文 PII,`.pii_presidio_store/` 已加入 `.gitignore`,勿提交、勿同步
- 会话结束后可调用 `SessionRegistry.delete_session(sid)` 清除映射
