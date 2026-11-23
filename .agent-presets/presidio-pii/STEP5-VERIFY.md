# Step 5 最小端到端验证 — dsh-presidio-pii 统一守卫

**前置**：已安装统一插件 `dsh-presidio-pii` → 新会话选「PII 防护模式」→ 工作目录指向仓库根。

| 用例 | 通过判据 | 失败含义 |
| --- | --- | --- |
| 1 正向：read_redacted 明文 | 返回含 `⟦PII:PERSON:xxxx⟧`，无原文姓名/手机号明文 | 拦截未生效 |
| 2 负向：正常文本 | 无 PERSON/ID/PHONE/BANK 误报占位符 | 误伤过高 |
| 3 路径脱敏 | `displayPath` 仅保留 basename，无目录路径泄漏 | 路径清洗失效 |

## 验证命令（仓库根目录）

```powershell
node tests/js/plugin_unified.mjs
node tests/node/guard-fs-tools.mjs
node tests/js/plugin_display.mjs plugins/dsh-presidio-pii/lib/guard.js
node tests/js/plugin_jobs.mjs plugins/dsh-presidio-pii/lib/guard.js
```
