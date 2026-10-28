# Presidio PII Redactor for DeepSeek Harness

A local, lightweight, reversible PII (Personally Identifiable Information) de-identification and restoration middleware designed for DeepSeek Harness (DSH). Inspired by Microsoft Presidio's modular architecture, this tool runs entirely offline on CPU with zero heavy ML dependencies (no spaCy/PyTorch required), using optimized regular expressions, checksum validations, and dictionary lookups.

## Features

- **Multi-Entity Recognition**: Identifies Chinese names, ID cards (with checksum validation), mobile numbers, emails, unified social credit codes, bank cards, county-level administrative regions (`LOCATION`), organizations (`ORGANIZATION`), and job titles (`JOB_TITLE`).
- **Reversible Anonymization**: Replaces sensitive data with collision-resistant Unicode placeholders (e.g., `⟦PII:ID_NUMBER:0001⟧`).
- **SQLite Session Registry**: Tracks session-specific mappings in a lightweight local SQLite database to guarantee 100% loss-less text restoration after the LLM responds.
- **Office Document Support**: Hooks for `.docx`, `.pptx`, `.xlsx`, and plain text.

## Quick Start

```bash
cd E:\Coding\dsh-presidio-preset
pip install -e .

# Run round-trip demo
python -m presidio_pii.cli --demo
```

## Architecture

- **`presidio_pii/engine.py`**: Core redaction & restoration pipeline + priority overlap resolver.
- **`presidio_pii/chinese_recognizers.py`**: Custom Chinese PII recognizers (Presidio API compatible).
- **`presidio_pii/db.py`**: SQLite session mapping storage.
- **`presidio_pii/cli.py`**: Command-line interface.
