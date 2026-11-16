# dsh-pii-guard-terms

设置页插件：让用户在界面里维护 **PII 屏蔽词**（词或短语），保存后这些词会真正进入脱敏链路。

## 它做什么

- 在 DSH 设置页注册一个名为「PII 屏蔽词」的分节（slot `settings.section`，id `pii-guard-terms`）。
- 用户添加 / 删除词条，点「保存」后写入规则文件。
- 写入的文件就是 Python 脱敏服务的自定义规则来源，因此**保存后约 1 秒内生效**（`CustomRuleSet.refresh` 默认 1 秒轮询），工具结果与提示词都会先脱敏再进入模型上下文。

## 路由

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/dsh-pii-guard/terms` | 读取当前词条、规则文件路径与上限 |
| POST | `/api/dsh-pii-guard/terms/save` | 覆盖写入词条列表 |

写操作受三层围栏保护：loopback 来源、HTTP 方法、**同源证明**（`Sec-Fetch-Site: same-origin` 或同源 `Origin`，桌面壳转发时以宿主 Cookie 兜底）。任何一层不满足都返回 403 / 405。

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
- `priority: 0` 让用户词与内置高优先实体（身份证 / 统一社会信用代码 / 护照）同级，长词优先仍然生效。

**清空词表**不会写空数组，而是写一条永不匹配的占位规则（`pattern: "(?!)"`）。原因：规则加载器在一次重载产出 0 条规则时会保留上一版规则，空数组会让旧词继续被脱敏。

## 让规则真正被加载

`.agent-presets/presidio-pii/preset.json` 的 `config.custom_rules_path` 指向本插件的规则文件，`config.rules_reload_interval` 保持 `1.0`。

> 注意：规则来源路径在 Python 服务**首次构造引擎时**读取一次。改路径需要重启 DSH；改词条内容不需要，会在 1 秒内热更新。

## 安装

```text
plugin_manager action=install_bundle target="E:\Code\dsh-presidio-preset\plugins\dsh-pii-guard-terms"
```

裸绝对目录会被 pnpm 以 link 方式挂进 profile，改源码即时可见；Host 半体的模块代次可能仍需重启 DSH。

## 限制

- 词条上限 500 条，单条最长 200 字符，不允许控制字符。
- 词条按字面匹配，不支持通配符或正则。
- 词表本身是用户数据，落在一个 JSON 规则文件里；该文件不会被脱敏（它是屏蔽词定义，不是被屏蔽内容）。
