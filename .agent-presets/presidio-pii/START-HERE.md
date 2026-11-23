# 启动指引 — 新会话测试 PII 防护模式

本文件是「PII 防护模式」preset 的启动入口。

**用法**：GUI 新建会话 → Agent Preset 选「PII 防护模式」→ 工作目录指向本仓库根 → 使用下列核对命令或提示词。

## 自动化验证（推荐）

在仓库根目录执行（无硬编码路径）：

```powershell
pwsh -NoProfile -File tools/verify_install.ps1
node tests/js/plugin_unified.mjs
node tests/js/plugin_terms.mjs plugins/dsh-presidio-pii/lib/terms.js
node tests/js/plugin_display.mjs plugins/dsh-presidio-pii/lib/guard.js
node tests/js/plugin_jobs.mjs plugins/dsh-presidio-pii/lib/guard.js
node tests/node/guard-fs-tools.mjs
node tests/node/extended-fields.mjs
node tests/node/preset-runtime-types.mjs
```

## 新会话验证提示词

```
【任务】确认当前处于「PII 防护模式」且一体化插件 dsh-presidio-pii 运行正常：
1. 使用 ls 列出当前工作目录条目，确认仅暴露安全文件工具（read_redacted / write_raw / restore / ls）。
2. 读取 presidio-pii skill，核对内置 20 类实体与运行时守卫边界。
3. 使用 read_redacted 读取任意测试文本，确认 PII 已脱敏为 ⟦PII:TYPE:NNNN⟧ 占位符且 displayPath 仅保留文件名。
```
