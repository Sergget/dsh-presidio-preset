# 方案 B 交接清单（2026-11-10）

已完成（无需再动）：
- `presidio_pii/server.py`：`op=restore` 协议（full/mask）、redact 响应增量 `map` 下发、
  映射键口径与 `hooks.session_id()` 一致。
- `plugins/dsh-pii-guard/lib/index.js`（仓库副本）：`agent/assistant-stream` 监听器
  （prepend+global）、扣尾补头缓冲、`PII_GUARD_DISPLAY=full/mask/off`。
- `tests/js/plugin_display.mjs` 6 条显示冒烟全 PASS；`tests/js/plugin_jobs.mjs` 13 条不回归
  （mock 改为按事件名分发）。
- `tools/release_gate.py`：#4 由硬编码 SKIP 改为实现判定（现 PASS）；#5 源码断言加显示侧
  常量、冒烟加入 plugin_display.mjs。
- `docs/RELEASE-GATE.md` #4 → PASS；RUNBOOK 待定第 1 条已结。

需要用户接手（本沙箱无法完成）：

1. **同步插件到安装位**（DSH 运行中文件被锁）：
   完全退出 DSH → 托盘右键「完全退出」→ 然后：
   Copy-Item 'E:\Code\dsh-presidio-preset\plugins\dsh-pii-guard\lib\index.js' `
             'E:\Code\dsh_home\plugins\dsh-pii-guard\lib\index.js' -Force
   （脚本也会自动校验 drift。）

2. **重建 wheel 并更新清单**（沙箱 TEMP/venv 写权限受限，4 种构建方式全部被拦）：
   在正常 PowerShell 里：
   $env:SOURCE_DATE_EPOCH='1700000000'
   cd E:\Code\dsh-presidio-preset
   python -m pip wheel . --no-deps -w dist --disable-pip-version-check
   两次构建比对哈希一致后，把新 SHA256/字节数写进 release/presidio-pii-dsh-0.1.0.json
   （或跑 tools/release_gate.py --only 10 看 tree_digest_match 是否转 True）。
   注意：#9/门禁全量复跑也需要在正常环境做（本会话内 #6/#8/#9 是沙箱假阴性）。

3. **重启 DSH 验证显示还原**：重启选 presidio-pii 预设后，让模型 read 一份含 PII 的文件再
   复述其中的内容——GUI 里应显示原文（PII_GUARD_DISPLAY=full 默认）或打码值（=mask）；
   会话存储与下一轮模型上下文仍是占位符。切换设置改环境变量后需再次完全重启。

4. 全量门禁：python tools/release_gate.py --json <path>，确认 12 项状态与退出码。
