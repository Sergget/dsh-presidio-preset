# Presidio PII Redactor for DeepSeek Harness

**English** | [简体中文](README.md)

A local, lightweight, reversible PII (Personally Identifiable Information) de-identification and restoration middleware designed for DeepSeek Harness (DSH). Inspired by Microsoft Presidio's modular architecture, this tool runs entirely offline on CPU with zero heavy ML dependencies (no spaCy/PyTorch required), using optimized regular expressions, checksum validations, and dictionary lookups.

## Features

- **Multi-Entity Recognition**: Identifies Chinese names, ID cards (18-digit with checksum and legacy 15-digit), mobile and landline numbers, emails, unified social credit codes, bank cards (Luhn-checked; failing checksums are kept at lower confidence rather than dropped), passports, license plates, IP/MAC addresses, province/city/county-level administrative regions (`LOCATION`), organizations (`ORGANIZATION`), and job titles (`JOB_TITLE`). A roster-specific pass covers explicit name-list chains (rare surnames, compound surnames, three-character names containing function characters, and `(26)`-style student-number suffixes) without relaxing the general-name filters.
- **Guard Re-renders Tool Values**: for tools with `presentationMeta` (e.g. the current `read` card), the DSH post-execute guard replaces the canonical `value` so `render()` and `presentationMeta()` are recomputed from redacted data. The model context, session-log `meta`, and GUI card all receive placeholders rather than raw lines.
- **Custom Rules**: extend recognition with JSON regex templates or Python code rules — `--rules FILE`, `PII_DSH_CUSTOM_RULES`, or `config.custom_rules_path` in the DSH preset. See [Custom Rules](#custom-rules).
- **Blocklist Settings Page**: installing `plugins/dsh-pii-guard-terms` adds a single "PII Protection" menu to DSH settings, where the blocklist and guard config are managed in separate areas of the same page. In the blocklist area, type a term or phrase, save, and it takes effect **within one second** — no restart. Terms are written to `.pii_presidio_store/user_terms_rules.json` (`entity_type` `USER_TERM`, matched literally) and wired into the engine through `config.custom_rules_path`. The endpoint only accepts same-origin loopback requests (loopback + `Sec-Fetch-Site`/Origin proof), up to 500 terms of 200 characters each.
- **PII Guard Settings**: the same "PII Protection" menu also provides four P0/P1 controls — display restore mode (`full`/`mask`/`off`), fail-open on service errors (troubleshooting only), a shell guard master switch, and a shell command allowlist (RegExp, validated before save). Values are stored in `.pii_presidio_store/guard-settings.json` (gitignored, no PII) and take effect on the **next tool call** — no restart; a missing key falls back to the process-start environment value. The save endpoint requires a loopback same-origin request with a valid session cookie, and rejects invalid regexes or display modes.
- **Variant Tolerant**: full-width digits and letters, separators inside numbers (`138 0013 8000`), line-broken IDs and names with inner spaces are normalized before matching, so non-standard formatting is still redacted — and restoration still maps back to the original text.
- **Boundary-Aware Filtering**: every match must sit on a word boundary, so mid-word fragments are rejected (`容要求` out of `内容要求`, `所有部` out of `所有部门`, `书馆` out of `图书馆`). With the optional jieba segmenter installed, candidates must also align with token boundaries and POS tags (`nr` for names, `ns` for places), which removes nearly all false positives.
- **Reversible Anonymization**: Replaces sensitive data with collision-resistant Unicode placeholders (e.g., `⟦PII:ID_NUMBER:0001⟧`).
- **SQLite Session Registry**: Tracks session-specific mappings in a lightweight local SQLite database to guarantee 100% loss-less text restoration after the LLM responds.
- **Office Document Support**: Hooks for `.docx`, `.pptx`, `.xlsx`, and plain text.
- **Wide Format Coverage**: redact/restore for `.docx` (paragraphs, tables, headers/footers, text boxes, comments, tracked changes, footnotes), `.xlsx` (cells and cell comments), `.pptx` (text frames, tables, notes), plus `.txt`, `.md`, `.csv`, `.json`, `.xml`, `.html`, `.eml`, `.rtf`. `.pdf`, `.doc` and `.xls` are detection-only — they can be scanned but not written back.
- **Whitelist**: protect specific keywords — `--whitelist FILE` (one term per line) or `--keep TERM` on the CLI, `PII_DSH_WHITELIST` for the DSH preset. Any detected entity that overlaps a protected term is left untouched.

## Installation & Deployment

> **Secure default (fail-closed)**: when the redaction service (Python side) fails, the guard plugin **blocks the affected tool call by default** rather than passing raw text through — temporarily unavailable is preferable to leaking PII. The settings page's "Fail open (troubleshooting only)" switch lets raw text through on service errors; it **significantly weakens protection** and should be turned off as soon as troubleshooting ends.

**Python versions**: **3.9 / 3.10 / 3.11 / 3.12 / 3.13** are supported (`pyproject.toml` declares `requires-python = ">=3.9"`). Check before installing:

```powershell
python --version   # must be 3.9~3.13
```

### One-shot install (recommended)

```powershell
# -Repo defaults to the script's directory, -DshHome defaults to $env:DSH_HOME
pwsh -NoProfile -File tools/install.ps1 -Repo . -DshHome $env:DSH_HOME

# Preview actions without writing anything
pwsh -NoProfile -File tools/install.ps1 -Repo . -DshHome $env:DSH_HOME -DryRun
```

The script substitutes the `__REPO__`/`__DSH_HOME__` placeholders in the `cordis.patch.yml` template with real paths and installs the guard plugin to `<DSH_HOME>/plugins/dsh-pii-guard/lib/index.js`. After installing, confirm inside a **DSH session** (not plain PowerShell) that `@local/dsh-presidio-pii-preset` and `dsh-pii-guard-terms` are enabled via `plugin_manager list_bundles`, then **fully restart DSH**.

> `bundle patch` is injected via `link` and does **not** write plugin entries into the profile patch file — not finding them by grepping profile config is expected. Use `plugin_manager list_bundles` to verify.

### Offline install (no network / intranet)

`release/` ships a prebuilt wheel (hash in the sibling manifest), so no heavy PyPI dependencies are needed:

```powershell
pip install --no-index --find-links release presidio_pii_dsh-0.1.0-py3-none-any.whl
```

### Post-install verification

```powershell
pwsh -NoProfile -File tools/verify_install.ps1 -Repo . -DshHome $env:DSH_HOME
```

Checks Python import, CLI demo, bundle enablement, plugin byte-identity and path drift. The `bundle enabled` item shows SKIP (with in-DSH verification guidance) when run in a shell without the `plugin_manager` command — this is not a failure.

### Network / git / SSL troubleshooting

If `git clone` or `pip install` fails on network or certificate errors:

1. Check proxy and CA chain: `git config --global http.sslVerify`; corporate networks may need `http.proxy` / `https.proxy` or a trusted CA certificate.
2. Bypass git: download the **zip archive** from the Release page or internal mirror, extract, then follow the one-shot install — the script does not depend on git.
3. Bypass PyPI: use the offline install above with the wheel in `release/`.

### Manual install (without the script)

1. `pip install -e .` (or the offline wheel).
2. Replace the `__REPO__`/`__DSH_HOME__` placeholders in `cordis.patch.yml` manually.
3. Copy `plugins/dsh-pii-guard/lib/index.js` to `<DSH_HOME>/plugins/dsh-pii-guard/lib/index.js`.
4. In a DSH session, `plugin_manager install_bundle` the preset bundle and `plugins/dsh-pii-guard-terms`, then restart DSH.

## Quick Start

```bash
cd dsh-presidio-preset
pip install -e .
pip install -e ".[segment]"   # optional: jieba segmentation, much better precision

# Run round-trip demo
python -m presidio_pii.cli --demo

# Redact a document (txt/md/docx/xlsx/pptx)
python -m presidio_pii.cli redact report.docx
# -> report-redacted/report.docx
#    report-redacted/report.docx.mapping.csv   (placeholder <-> original)
#    report-redacted/report.docx.session.csv   (session id / paths)

# Shorthand: a bare file path defaults to `redact`
python -m presidio_pii.cli report.docx

# -v shows stage progress and per-unit hits; -d sets the output directory
python -m presidio_pii.cli redact report.docx -v -d out/

# Restore (mapping read from the CSV next to the file; no database needed)
python -m presidio_pii.cli restore report-redacted/report.docx
# -> report-restored/report.docx
```

Output layout: redacted files land in `<name>-redacted/` next to the source, restored
files in `<name>-restored/`. `-o` writes to an explicit file path and is mutually
exclusive with `-d`. When run as a plain script the redaction correspondence lives in
`<file>.mapping.csv` (`idx,ptype,placeholder,original`, UTF-8 with BOM, Excel-ready), so a
redacted folder is self-contained and can be restored on another machine; the SQLite
registry under `.pii_presidio_store/` is only a fallback. The CLI keeps mappings in memory
by default (no per-row disk writes); pass `--session` to use the persistent SQLite registry
when one session must span several files. The DSH preset keeps its own storage format and
is unaffected.

## Custom Rules

Business identifiers outside the built-in entity set (employee IDs, member numbers,
order numbers) can be added without touching engine code. Two template kinds, mixed freely:

- **JSON regex templates** — `pattern`, `entity_type`, optional `score`, `priority`,
  `context_hint`, `negative_hint`, `validator`.
- **Python code rules** — a `.py` file exposing `analyze(text) -> [(start, end[, score])]`
  plus optional `ENTITY_TYPE` / `SCORE` / `PRIORITY`.

```bash
export PII_DSH_CUSTOM_RULES=/path/rules.json;/path/order_rule.py
python -m presidio_pii.cli redact doc.docx --rules rules.json
```

Custom rules match the original text, take part in whitelist exemption, overlap
arbitration and placeholder restoration exactly like built-in recognizers. Rules passed
explicitly via `--rules` are loaded strictly: a missing file or an invalid rule exits
non-zero instead of silently redacting without them.

`priority` (0-99, default 99) only decides equal-length overlaps — give a custom type a
smaller number than a built-in one to win the same span. Rule files are hot-reloaded: the
engine compares file signatures (mtime + size) at most once per second and swaps the
recognizers when a file changes; if a reload fails (file deleted, broken JSON, all rules
invalid) the previous rules stay in effect. Set `PII_DSH_RULES_RELOAD=0` to disable
automatic checks and call `reload_rules()` / `engine.reload_custom_rules()` for an
explicit reload.

See [`.agent-presets/presidio-pii/README.md`](.agent-presets/presidio-pii/README.md#自定义识别规则)
for the full field reference and agent workflow.

## Testing

```bash
pip install -e ".[dev]"
pytest tests/ -v                          # 228 regression cases

# Check real documents without DSH (leak check + lossless restore + zero placeholders, JSON report)
python tools/standalone_check.py report.docx roster.xlsx

# Simulate multi-turn conversation without DSH, logging structured sent/received events (JSONL)
python tools/dsh_sim.py --turn "Example user 'Jane Doe (alias)' has ID number 000000000000000000, look it up"

# Generate a synthetic test corpus (fake orgs/companies/names/IDs) split into small docx files
python tools/gen_test_corpus.py --base 项目建议书-redacted/项目建议书.docx --out testdata/ --parts 12

# Measure recall and false positives against the generated ground truth
python tools/eval_corpus.py --dir testdata/

# Multi-type corpus: resume / contract / official / report / paper / payroll / contacts (84 docs)
python tools/gen_corpus_v2.py --out testdata_v2 --per-type 12
python tools/eval_corpus.py --dir testdata_v2/
```

See [tools/README.md](tools/README.md) for details.

## Architecture

- **`presidio_pii/engine.py`**: Core redaction & restoration pipeline + priority overlap resolver.
- **`presidio_pii/chinese_recognizers.py`**: Custom Chinese PII recognizers (Presidio API compatible).
- **`presidio_pii/db.py`**: SQLite session mapping storage.
- **`presidio_pii/documents.py`**: Text-unit extraction/write-back for txt/docx/xlsx/pptx.
- **`presidio_pii/cli.py`**: Command-line interface.
- **`tools/`**: standalone document checker, DSH flow simulator, synthetic corpus generator and evaluator.
- **`docs/ROADMAP.md`**: development plan, including the optional NER model tiers.
- **`docs/RESEARCH-pii-protection.md`**: research charter (not yet implemented) — recognizer-level rule
  libraries × channel-level minimal tool surface, with measured field coverage, a read-channel inventory
  and a 73-item issue list.
- **`docs/SECURITY-NOTES.md`**: security boundaries and known risks — CLI plaintext mappings, `.py` rules
  executed via import, local database layout, known blind spots. **Read before deployment.**
- **`.agent-presets/presidio-pii/`**: DeepSeek Harness (DSH) agent preset integration — two
  forms coexist:
  - **`bundle/cordis.patch.yml` (authoritative source)**: the preset patch actually loaded by
    dsh 0.2.x — plugin list, tool switches and persona prefix all live here. Change this file
    only when changing preset behavior. It ships as a template with `__REPO__`/`__DSH_HOME__`
    placeholders, materialized by `tools/install.ps1`.
  - `agent.cordis.yml` + `preset.yml` + `skills/presidio-pii/SKILL.md`: **legacy** form, kept
    only for historical reference and older harness versions. dsh 0.2.x does not read
    `agent.cordis.yml` and it is no longer synced with the bundle (missing `pii-guard`,
    `tool-jobs`, `tool-schedule` entries). **Do not treat it as a config source** — edits there
    have no effect.
  - `preset.json` + `hook.py`: **DEPRECATED hook contract** (before_llm / after_llm). dsh 0.2.x
    does not mount Python hooks, so those callbacks never fire. `preset.json` itself is still
    a **live config source**: `entity_types`, `config.whitelist_path` and
    `config.custom_rules_path` are read by `presidio_pii/hooks.py` and written by the settings
    UI — do not delete it. The active redaction seam is the `dsh-pii-guard` runtime plugin.
- **`plugins/dsh-pii-guard/lib/index.js`**: DSH `tools/post-execute` interception plugin
  (read/grep/pwsh/job_output/job_list). The installed copy lives at
  `<DSH_HOME>/plugins/dsh-pii-guard/lib/index.js` and must stay byte-identical
  (enforced by gate #5); restart DSH fully after changing it.

## Release & gates

```powershell
# One-shot release gate (per-check PASS/FAIL/SKIP/MANUAL, evidence saved with --json)
python tools/release_gate.py --json "$env:TEMP/release_gate.json"
```

Criteria and outstanding items: [docs/RELEASE-GATE.md](docs/RELEASE-GATE.md).
Release/rollback steps: [docs/RELEASE-RUNBOOK.md](docs/RELEASE-RUNBOOK.md).
Plugin sync:

```powershell
Copy-Item plugins/dsh-pii-guard/lib/index.js <DSH_HOME>/plugins/dsh-pii-guard/lib/index.js -Force
```
