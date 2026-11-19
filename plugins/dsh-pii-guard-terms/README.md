# dsh-pii-guard-terms

设置页插件：让用户在界面里维护 **PII 屏蔽词**（词或短语），以及 4 项 P0/P1 防护配置。保存后这些设置会真正进入脱敏链路。

## 它做什么

- 在 DSH 设置页注册**一个**分节「PII 防护」(`settings.section`，id `pii-guard-terms`，order 30)，分区内同时容纳屏蔽词与防护配置：
  - 屏蔽词：添加 / 删除需要自动脱敏的词或短语。
  - 防护配置：显示还原模式 `displayMode`（`full`/`mask`/`off`）、fail-open 策略 `failOpen`、Shell 守卫总开关 `shellDisabled`、Shell 命令白名单 `shellAllowlist`（正则，保存前校验）。
- 用户添加 / 删除词条，点「保存」后写入规则文件。
- 写入的文件就是 Python 脱敏服务的自定义规则来源，因此**保存后约 1 秒内生效**（`CustomRuleSet.refresh` 默认 1 秒轮询），工具结果与提示词都会先脱敏再进入模型上下文。
- 防护配置写入 `.pii_presidio_store/guard-settings.json`（被 .gitignore 覆盖、不含 PII）。guard 插件每次事件按文件签名读取并缓存，**下一次工具调用即生效、无需重启 DSH**；字段缺失时回退到进程启动环境变量（`PII_GUARD_DISPLAY` / `PII_GUARD_FAIL_OPEN` / `PII_GUARD_SHELL` / `PII_GUARD_SHELL_ALLOWLIST`）。

## 路由

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/dsh-pii-guard/terms` | 读取当前词条、规则文件路径与上限 |
| POST | `/api/dsh-pii-guard/terms/save` | 覆盖写入词条列表 |
| GET | `/api/dsh-pii-guard/settings` | 读取 4 项防护配置与文件路径 |
| POST | `/api/dsh-pii-guard/settings/save` | 校验并合并写入防护配置 |

写操作受三层围栏保护：loopback 来源、HTTP 方法、**同源证明**（`Sec-Fetch-Site: same-origin` 或同源 `Origin`；桌面壳无 fetch 头时，要求 Cookie 中存在对应 host 的 `dsh-auth-*` 会话 cookie 且值非空，不再接受任意 Cookie 兜底）。任何一层不满足都返回 403 / 405。

> 路径一致性（S2）：Host 启动时读取 `.agent-presets/presidio-pii/preset.json` 的 `config.custom_rules_path`，与本插件词表路径归一化后比对；不一致会在 DSH 日志里告警（`terms path drift`），避免「界面在改 A 文件、引擎在读 B 文件」的静默失效。

## 规则文件

默认路径：`E:/Code/dsh-presidio-preset/.pii_presidio_store/user_terms_rules.json`

格式是 `presidio_pii` 自定义规则的 JSON 数组，每个词一条：

```json
{
  "name": "user-term-0001",
  "entity_type": "USER_TERM",
  "pattern": "某个词",
  "score": 0.95,
  "priority": 0,
  "term": "某个词"
}
```

- `pattern` 是转义后的字面量（不是正则），因此词里的 `.`、`*`、`(` 等字符按字面匹配。
- `term` 是自定义键，Python 侧忽略它，用于把词条从规则文件里无损读回。
- `entity_type` 必须全大写加下划线（占位符格式 `⟦PII:USER_TERM:0001⟧` 依赖这一点）。
- `priority: 0` 让用户词与内置最高优先级的身份证（`ID_NUMBER`，同为 0）同级，并**高于**统一社会信用代码（`CREDIT_CODE`，1）与护照（`PASSPORT`，2）；同优先级内长词优先仍然生效。

**清空词表**不会写空数组，而是写一条永不匹配的占位规则（`pattern: "(?!)"`）。原因：规则加载器在一次重载产出 0 条规则时会保留上一版规则，空数组会让旧词继续被脱敏。

## 让规则真正被加载

`.agent-presets/presidio-pii/preset.json` 的 `config.custom_rules_path` 指向本插件的规则文件，`config.rules_reload_interval` 保持 `1.0`。

> 注意：规则来源路径在 Python 服务**首次构造引擎时**读取一次。改路径需要重启 DSH；改词条内容不需要，会在 1 秒内热更新。

## 安装

```text
plugin_manager action=install_bundle target="<仓库根目录>/plugins/dsh-pii-guard-terms"
```

裸绝对目录会被 pnpm 以 link 方式挂进 profile，改源码即时可见；Host 半体的模块代次可能仍需重启 DSH。

## 限制

- 词条上限 500 条，单条最长 200 字符，不允许控制字符。
- 词条按字面匹配，不支持通配符或正则。
- 词表本身是用户数据，落在一个 JSON 规则文件里；该文件不会被脱敏（它是屏蔽词定义，不是被屏蔽内容）。
