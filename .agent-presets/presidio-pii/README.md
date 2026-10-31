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
| `custom_rules_path` | `null` | 自定义识别规则文件，分号分隔多个；等价于环境变量 `PII_DSH_CUSTOM_RULES` |

`config` 段由 `presidio_pii/hooks.py` 直接读取，优先级 **环境变量 > preset.json > 内置默认值**。
相对路径先按仓库根目录解析，不存在时再按 preset.json 所在目录解析。
`preset.json` 自身路径可用 `PII_DSH_PRESET` 覆盖。

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

`ID_NUMBER`(身份证,含校验位)、`PHONE_NUMBER`、`EMAIL_ADDRESS`、`CREDIT_CODE`(统一社会信用代码)、`BANK_CARD`(Luhn 通过 0.80 / 未通过降级 0.45 保留)、`PASSPORT`(护照)、`LICENSE_PLATE`(车牌)、`IP_ADDRESS`/`MAC_ADDRESS`、`PERSON`(中文人名)、`LOCATION`(县级行政区)、`ORGANIZATION`、`JOB_TITLE`

## 自定义识别规则

内置实体覆盖不到的业务标识符（工号、会员号、订单号、内部编号等）可通过规则文件扩展，无需改引擎源码。DSH agent 可直接按模板生成规则文件并注入 `custom_rules_path` 或环境变量 `PII_DSH_CUSTOM_RULES`。

### 接入开关（四层等价）

| 层 | 写法 |
|---|---|
| preset.json | `"config": { "custom_rules_path": "rules.json;extra.py" }` |
| 环境变量 | `export PII_DSH_CUSTOM_RULES=/path/rules.json;/path/extra.py` |
| CLI | `python -m presidio_pii.cli redact 文档.docx --rules rules.json` |
| Python API | `PresidioPIIEngine(custom_rules=load_custom_rules("rules.json"))` |

文件按扩展名分发：`.json` = 正则模板，`.py` = 代码规则。多个文件用分号 `;` 分隔。

### 正则模板（JSON）

```json
[
  {
    "name": "employee_id",
    "entity_type": "EMPLOYEE_ID",
    "pattern": "工号[:：\\s]*([A-Z]\\d{6})",
    "score": 0.9,
    "context_hint": ["工号", "编号"],
    "negative_hint": ["示例", "如"]
  }
]
```

| 字段 | 必填 | 说明 |
|------|------|------|
| `name` | 是 | 规则名，唯一 |
| `entity_type` | 是 | 产出实体类型，决定占位符形态 `⟦PII:EMPLOYEE_ID:0001⟧` |
| `pattern` | 是 | 正则；含捕获组时实体取组 1（`工号: A123456` 只脱敏号码） |
| `score` | 否 | 置信分，默认 0.80 |
| `context_hint` | 否 | 匹配点前方 20 字符内需含任一提示词才生效（压误报） |
| `negative_hint` | 否 | 前方 20 字符内含任一词则跳过（排除示例/演示文本） |
| `validator` | 否 | `"模块路径:函数名"`，接收整段匹配文本，返回 false 丢弃；相对路径按规则文件所在目录解析 |

非法正则的规则默认跳过并写 stderr；但**显式指定**的规则（CLI `--rules`）走严格模式：
文件缺失、类型不支持或规则全部非法时直接以非零退出码中止，避免静默漏检。
环境变量 / preset 注入走宽松模式（单个规则失败不阻断 hook 初始化）。

### 代码规则（Python）

需要校验逻辑（校验位、前缀表、查库）时用 Python 模板：

```python
# order_rule.py
ENTITY_TYPE = "ORDER_NO"
SCORE = 0.9

def analyze(text):
    import re
    return [(m.start(), m.end()) for m in re.finditer(r"ORD-\d{10}", text)]
```

`analyze(text)` 返回坐标列表：`(start, end)` 或 `(start, end, score)`，坐标为原文下标。非法坐标（越界、倒序）自动丢弃；规则抛异常或返回 `None` 时该规则被隔离（警告一次后跳过），内置识别与其他规则照常工作，不会中断脱敏流水线。

### 与引擎的协作

自定义规则与内置识别器走同一通道，自动获得：

- **白名单豁免**：命中白名单的自定义实体同样跳过
- **冲突仲裁**：与内置实体重叠时按长度 > 优先级 > 起点裁决
- **还原映射**：新 `entity_type` 自动进入会话映射库，`after_llm` 无需额外配置即可还原

注意：自定义规则在**原文**上匹配（不经过全角/插值归一化）。若需要容忍全角变体，在 pattern 中自行兼容，如 `[０-９\d]`。

### agent 生成规则的最小工作流

1. 确认内置实体确实覆盖不了（先跑 `python -m presidio_pii.cli redact 样本.txt -v` 看命中）
2. 按上面的 JSON/Python 模板写规则，`entity_type` 用业务语义命名（大写下划线）
3. 用带正反例的样本验证：正例应产出 `⟦PII:<TYPE>:0001⟧`，反例（示例文本、近似串）应保持原文
4. 注入 `PII_DSH_CUSTOM_RULES` 或写入 preset.json 的 `custom_rules_path`，多轮对话回归一遍还原
5. 规则文件纳入版本管理；含业务敏感示例的先脱敏再提交

## 安全注意

- 映射库含明文 PII,`.pii_presidio_store/` 已加入 `.gitignore`,勿提交、勿同步
- 会话结束后可调用 `SessionRegistry.delete_session(sid)` 清除映射
- **代码规则文件 import 即执行其中代码**：只加载 `PII_DSH_CUSTOM_RULES` / `custom_rules_path` 明确指向的文件，规则文件应与配置一样受访问控制保护，勿指向不可信来源
