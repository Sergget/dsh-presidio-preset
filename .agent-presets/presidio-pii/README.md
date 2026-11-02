# presidio-pii — DSH Agent Preset

为 DeepSeek Harness (DSH) 提供本地可逆 PII 脱敏能力。全程离线，零 spaCy/PyTorch 依赖。

本目录包含**两种集成形态**，适用不同的 DSH 运行时：

| 形态 | 文件 | 适用运行时 | 当前状态 |
|------|------|-----------|---------|
| **bundle 声明行 preset**（推荐，唯一正路） | `bundle/package.json` + `bundle/cordis.patch.yml` | dsh 0.2.x（本机实测 0.2.1-rc.5） | ✅ 已装并验证 |
| 目录式预设（已废弃） | `agent.cordis.yml` + `preset.yml` + `skills/` | 仅旧版 dsh | ⚠️ dsh 0.2.x 不再读取该目录 |
| 钩子契约入口（存档） | `preset.json` + `hook.py` | 能挂载 Python 钩子的 DSH 运行时 | ⚠️ dsh 0.2.x 不提供该接缝 |

> **要跑测试？直接看 [`START-HERE.md`](START-HERE.md)** —— 里面有可直接粘贴到新会话的启动提示词，
> 以及每条约束的实测依据。

## 标准 cordis preset（推荐用法）

### 工作原理

```
用户提出敏感文档任务
      │
      ▼
agent 检测文本/文档含 PII
      │
      ▼
python -m presidio_pii.cli redact <文件>   ← 脱敏发生在 prompt/工具 I/O 之前
      │                                    （产出 <名>-redacted/ + .mapping.csv）
      ▼
用脱敏文本作为工作副本：分析、编辑、送入 LLM 上下文、工具调用
      │
      ▼
python -m presidio_pii.cli restore <脱敏文件>  ← 无损还原
      │
      ▼
验证还原产物与原文一致，交付用户可见输出
```

与透明拦截方案（`preset.json` 钩子）的本质区别：**脱敏是 agent 工作流的一个显式步骤，不是运行时改写请求**。dsh 0.2.x 的 LLM 请求深度冻结（扩展只读），请求改写型钩子没有挂载点；本形态按 dsh 支持的扩展方式实现同等防护目标。

### 部署

> **⚠️ 重要**：`$DSH_HOME/.agent-presets/<id>/` 目录机制在 dsh 0.2.x **已废弃**——官方技能文档
> `editing-cordis-compositions` 明确「Nothing reads that directory any more」。把目录拷进去
> **不会**出现在 preset 菜单。唯一正路是 bundle 声明行（下述步骤 2-3）。

1. 安装引擎（一次性）：
   ```powershell
   cd <仓库根目录>
   pip install -e .
   pip install -e ".[segment]"   # 可选：jieba 分词，人名/地名精度显著提升
   ```
2. 用 bundle 安装 preset（本目录 `bundle/` 下双件套：`package.json` + `cordis.patch.yml`，
   plugins 逐字取自 `agent.cordis.yml`）：
   - **方式 A（推荐）**：在 dsh 会话内用 `plugin_manager` 工具，
     `action: install_bundle`，`target` 指向本 `bundle/` 目录绝对路径。
   - **方式 B**：把 `bundle/cordis.patch.yml` 的内容追加到 patch 层：
     - GUI 用的 **desktop profile**：`$DSH_HOME/profiles/desktop/cordis.patch.yml`
     - 其它 profile / 全局：`$DSH_HOME/cordis.patch.yml`（home 层）
3. **验证（需先重启 DSH）**：
   - 组合层：`dsh --profile web --dump-config` 输出应含 `preset-presidio-pii`
     与「PII 防护模式」（desktop profile 由 Electron 独占管理，CLI 不能 dump）。
   - GUI：重启后新建会话，Agent Preset 选择器应出现「PII 防护模式」。
4. `$DSH_HOME/.agent-presets/presidio-pii/` 旧目录可删——官方迁移指引明确
   「Install it, verify the row, then delete the legacy directory」。仓库内保留本目录作为权威源。

> **⚠️ 必须重启 DSH（GUI）**：dsh 0.2.x **没有 patch 热加载**。`patchReload: "live"` 只存在于
> **web** profile 的 `package.json`，desktop profile 没有该字段；asar 全量检索中 `patchReload`
> 零命中（它是 profile 声明字段，不是代码字符串）。改完 patch 必须重启 Electron 应用，
> 只刷新浏览器无效。

已在 dsh 0.2.1-rc.5 上实测：home 层追加后 `dsh --profile web --dump-config` exit 0，
`preset-presidio-pii` 完整呈现（17 个插件行 + persona）。

### 配置

配置通过环境变量完成，无需改 preset 文件：

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `PII_DSH_DB_PATH` | `<仓库>/.pii_presidio_store/sessions.db` | 映射库位置 |
| `PII_DSH_LOG_PATH` | `<仓库>/.pii_presidio_store/hook_log.jsonl` | 流程日志；`0` 关闭 |
| `PII_DSH_WHITELIST` | 无 | 白名单文件（每行一个关键词，`#` 注释） |
| `PII_DSH_CUSTOM_RULES` | 无 | 自定义规则文件，分号分隔（.json 正则模板 / .py 代码规则） |
| `PII_DSH_RULES_RELOAD` | `1` | 规则热更新检查间隔（秒）；`0` 关闭 |

## 钩子契约入口（原方案，存档性质）

`preset.json` 声明两个钩子，`hook.py` 提供薄 shim：

- `hook.before_llm(prompt, conversation_id)` → 脱敏文本
- `hook.after_llm(response, conversation_id)` → `(还原文本, 统计字典)`，只需文本取 `[0]`
- 会话语义：`session_id` 由 `conversation_id` 派生（稳定哈希），同一会话多轮共享映射表；
  未传入时按日期派生，同一天内共享
- 占位符使用 Unicode 全角括号 `⟦ ⟧`，抗 LLM 篡改/误改
- 每次调用自动写入结构化日志 `.pii_presidio_store/hook_log.jsonl`（`PII_DSH_LOG_PATH=0` 关闭）

`config` 段由 `presidio_pii/hooks.py` 直接读取，优先级 **环境变量 > preset.json > 内置默认值**。
`preset.json` 自身路径可用 `PII_DSH_PRESET` 覆盖。

**限制**：该形态依赖 DSH 运行时提供「LLM 请求前/响应后」Python 钩子接缝。dsh 0.2.x 的
LLM 请求深度冻结（监听器与适配器只读），且 preset 只接受 cordis 插件声明、不扫描
`preset.json`，因此该形态在当前 dsh 上不可加载。保留此文件作为钩子契约的规范定义，
供支持 Python 钩子的运行时或未来 dsh 版本使用。

## 识别实体

`ID_NUMBER`(身份证,含校验位)、`PHONE_NUMBER`、`EMAIL_ADDRESS`、`CREDIT_CODE`(统一社会信用代码)、`BANK_CARD`(Luhn 通过 0.80 / 未通过降级 0.45 保留)、`PASSPORT`(护照)、`LICENSE_PLATE`(车牌)、`IP_ADDRESS`/`MAC_ADDRESS`、`PERSON`(中文人名)、`LOCATION`(县级行政区)、`ORGANIZATION`、`JOB_TITLE`

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

## 自定义识别规则

内置实体覆盖不到的业务标识符（工号、会员号、订单号、内部编号等）可通过规则文件扩展，无需改引擎源码。DSH agent 可直接按模板生成规则文件并注入 `custom_rules_path` 或环境变量 `PII_DSH_CUSTOM_RULES`。

### 接入开关（四层等价）

| 层 | 写法 |
| --- |---|
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
    "priority": 3,
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
| `priority` | 否 | 0-99 整数，默认 99；仅等长重叠时比大小，数字越小越优先 |
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
PRIORITY = 3

def analyze(text):
    import re
    return [(m.start(), m.end()) for m in re.finditer(r"ORD-\d{10}", text)]
```

`analyze(text)` 返回坐标列表：`(start, end)` 或 `(start, end, score)`，坐标为原文下标。非法坐标（越界、倒序）自动丢弃；规则抛异常或返回 `None` 时该规则被隔离（警告一次后跳过），内置识别与其他规则照常工作，不会中断脱敏流水线。

### 与引擎的协作

自定义规则与内置识别器走同一通道，自动获得：

- **白名单豁免**：命中白名单的自定义实体同样跳过
- **冲突仲裁**：与内置实体重叠时按长度 > 优先级 > 起点裁决；`priority` 只影响等长重叠。
  内置优先级见 `engine._PRIO`（`ID_NUMBER=0` … `MAC_ADDRESS=12`），自定义类型默认 99。
  想让自定义实体在同一 span 上胜过内置类型，把 `priority` 调得比它更小
- **还原映射**：新 `entity_type` 自动进入会话映射库，`after_llm` 无需额外配置即可还原

注意：自定义规则在**原文**上匹配（不经过全角/插值归一化）。若需要容忍全角变体，在 pattern 中自行兼容，如 `[０-９\d]`。

### 规则热更新

引擎按规则文件的签名（mtime + size）检测变更，默认每秒最多检查一次；文件改动后
下一次识别自动生效，无需重启 DSH。钩子侧也可调用 `hooks.reload_rules()` 显式重载，
返回当前规则条数。

- 检查间隔：preset 的 `rules_reload_interval` 或环境变量 `PII_DSH_RULES_RELOAD`（秒）
- 关闭自动检查：设为 `0`（仍可显式重载）
- 加载失败（文件被删、JSON 损坏、规则全部非法）：保留上一份可用规则并写 stderr，
  避免运行中静默变成「不脱敏」
- CLI 一次性运行不受影响；`--rules` 显式规则始终严格加载

### agent 生成规则的最小工作流

1. 确认内置实体确实覆盖不了（先跑 `python -m presidio_pii.cli redact 样本.txt -v` 看命中）
2. 按上面的 JSON/Python 模板写规则，`entity_type` 用业务语义命名（大写下划线）
3. 用带正反例的样本验证：正例应产出 `⟦PII:<TYPE>:0001⟧`，反例（示例文本、近似串）应保持原文
4. 注入 `PII_DSH_CUSTOM_RULES` 或写入 preset.json 的 `custom_rules_path`，多轮对话回归一遍还原；改完规则文件后热更新自动生效，也可调用 `hooks.reload_rules()` 立即重载
5. 规则文件纳入版本管理；含业务敏感示例的先脱敏再提交

## 安全注意

- 映射库含明文 PII，`.pii_presidio_store/` 已加入 `.gitignore`，勿提交、勿同步
- 会话结束后可调用 `SessionRegistry.delete_session(sid)` 清除映射
- **代码规则文件 import 即执行其中代码**：只加载 `PII_DSH_CUSTOM_RULES` / `custom_rules_path` 明确指向的文件，规则文件应与配置一样受访问控制保护，勿指向不可信来源；热更新会在文件变更后重新 import，信任边界不变
