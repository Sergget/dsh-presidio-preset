# PII 防护模式 — 测试集与核对指南

本文档用于验证 PII 脱敏/还原链路是否正常，确保在源码仓库测试环境下不硬编码任何本机绝对路径。

## 一、Node 引擎与统一插件回归测试

在源仓库根目录执行以下命令（全部使用相对路径与 `import.meta.url` 自动定位）：

```powershell
node tests/node/extended-fields.mjs
node tests/node/guard-fs-tools.mjs
node tests/node/preset-runtime-types.mjs
node tests/node/protocol-smoke.mjs
node tests/js/plugin_unified.mjs
node tests/js/plugin_terms.mjs plugins/dsh-presidio-pii/lib/terms.js
node tests/js/plugin_display.mjs plugins/dsh-presidio-pii/lib/guard.js
node tests/js/plugin_jobs.mjs plugins/dsh-presidio-pii/lib/guard.js
```

## 二、可选 Office 语料测试（源仓库开发机）

素材位于源仓库 `testdata_v2/`（已 gitignore）。重建命令：

```powershell
New-Item -ItemType Directory -Force testdata_v2
python tools/gen_corpus_v2.py --out testdata_v2 --per-type 7 --seed 42
```

执行四格式核对前需用 `pwsh` 预建输出目录（使用相对当前仓库目录的路径）：

```powershell
New-Item -ItemType Directory -Force .\.pii_presidio_store\verify-artifacts
python tools/verify_check.py --files `
  testdata_v2/resume/resume-01.docx `
  testdata_v2/paper/paper-01.md `
  testdata_v2/report/report-07.pptx `
  testdata_v2/payroll/payroll-01.xlsx `
  --workdir .\.pii_presidio_store\verify-artifacts
```

## 三、红线

1. `*-redacted/`、`*.mapping.csv`、`.pii_presidio_store/`、`testdata_v2/truth.json` 含明文或真值，禁止提交、外传或贴入对话上下文。
2. 三项判定（无明文泄漏、还原逐字节一致、占位符清零）任一不通过时，禁止宣称链路就绪。
