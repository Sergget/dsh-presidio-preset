# Presidio PII Redactor for DeepSeek Harness

**English** | [简体中文](README.zh-CN.md)

A local, lightweight, reversible PII (Personally Identifiable Information) de-identification and restoration middleware designed for DeepSeek Harness (DSH). Inspired by Microsoft Presidio's modular architecture, this tool runs entirely offline on CPU with zero heavy ML dependencies (no spaCy/PyTorch required), using optimized regular expressions, checksum validations, and dictionary lookups.

## Features

- **Multi-Entity Recognition**: Identifies Chinese names, ID cards (18-digit with checksum and legacy 15-digit), mobile and landline numbers, emails, unified social credit codes, bank cards (Luhn-checked; failing checksums are kept at lower confidence rather than dropped), passports, license plates, IP/MAC addresses, province/city/county-level administrative regions (`LOCATION`), organizations (`ORGANIZATION`), and job titles (`JOB_TITLE`).
- **Custom Rules**: extend recognition with JSON regex templates or Python code rules — `--rules FILE`, `PII_DSH_CUSTOM_RULES`, or `config.custom_rules_path` in the DSH preset. See [Custom Rules](#custom-rules).
- **Variant Tolerant**: full-width digits and letters, separators inside numbers (`138 0013 8000`), line-broken IDs and names with inner spaces are normalized before matching, so non-standard formatting is still redacted — and restoration still maps back to the original text.
- **Boundary-Aware Filtering**: every match must sit on a word boundary, so mid-word fragments are rejected (`容要求` out of `内容要求`, `所有部` out of `所有部门`, `委员` out of `政协委员`). With the optional jieba segmenter installed, candidates must also align with token boundaries and POS tags (`nr` for names, `ns` for places), which removes nearly all false positives.
- **Reversible Anonymization**: Replaces sensitive data with collision-resistant Unicode placeholders (e.g., `⟦PII:ID_NUMBER:0001⟧`).
- **SQLite Session Registry**: Tracks session-specific mappings in a lightweight local SQLite database to guarantee 100% loss-less text restoration after the LLM responds.
- **Office Document Support**: Hooks for `.docx`, `.pptx`, `.xlsx`, and plain text.
- **Wide Format Coverage**: redact/restore for `.docx` (paragraphs, tables, headers/footers, text boxes, comments, tracked changes, footnotes), `.xlsx` (cells and cell comments), `.pptx` (text frames, tables, notes), plus `.txt`, `.md`, `.csv`, `.json`, `.xml`, `.html`, `.eml`, `.rtf`. `.pdf`, `.doc` and `.xls` are detection-only — they can be scanned but not written back.
- **Whitelist**: protect specific keywords — `--whitelist FILE` (one term per line) or `--keep TERM` on the CLI, `PII_DSH_WHITELIST` for the DSH preset. Any detected entity that overlaps a protected term is left untouched.

## Quick Start

```bash
cd E:\Coding\dsh-presidio-preset
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

- **JSON regex templates** — `pattern`, `entity_type`, optional `score`, `context_hint`,
  `negative_hint`, `validator`.
- **Python code rules** — a `.py` file exposing `analyze(text) -> [(start, end[, score])]`
  plus optional `ENTITY_TYPE` / `SCORE`.

```bash
export PII_DSH_CUSTOM_RULES=/path/rules.json;/path/order_rule.py
python -m presidio_pii.cli redact doc.docx --rules rules.json
```

Custom rules match the original text, take part in whitelist exemption, overlap
arbitration and placeholder restoration exactly like built-in recognizers. Rules passed
explicitly via `--rules` are loaded strictly: a missing file or an invalid rule exits
non-zero instead of silently redacting without them. See
[`.agent-presets/presidio-pii/README.md`](.agent-presets/presidio-pii/README.md#自定义识别规则)
for the full field reference and agent workflow.

## Testing

```bash
pip install -e ".[dev]"
pytest tests/ -v                          # 105 regression cases

# Check real documents without DSH (leak check + lossless restore + zero placeholders, JSON report)
python tools/standalone_check.py report.docx roster.xlsx

# Simulate multi-turn conversation without DSH, logging structured sent/received events (JSONL)
python tools/dsh_sim.py --turn "张伟的身份证是110101199003077890,帮我查"

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
- **`.agent-presets/presidio-pii/`**: DeepSeek Harness (DSH) agent preset integration.
